"""B4 regression tests for the exact packet_in_handler source, without Ryu startup.

These tests execute the production method extracted from ryu_sdn.py. They use
real Scapy's OSPFv3_Hdr for the new implementation and compare dispatch against
the unmodified, bundled reference implementation. Network/Ryu objects are mocked.
"""

import ast
import copy
import ipaddress
from pathlib import Path
import socket
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from scapy.contrib.ospf import OSPFv3_Hdr
from scapy.error import Scapy_Exception


PROJECT_ROOT = Path(__file__).resolve().parents[1]
NEW_SOURCE = PROJECT_ROOT / 'ryu_sdn.py'
OLD_SOURCE = Path(__file__).with_name('ryu_sdn_before_b4.py')


class DummyEthernet:
    pass


class DummyIPv6:
    pass


class RyuPacketStub:
    def __init__(self, payload, *, src='fe80::1', dst='ff02::5', hop_limit=1,
                 nxt=89, raw_payload=True):
        self.eth = SimpleNamespace(src='02:00:00:00:00:02', dst='02:00:00:00:00:01')
        self.ipv6 = SimpleNamespace(src=src, dst=dst, hop_limit=hop_limit, nxt=nxt)
        self.payload = payload if raw_payload else object()
        self.protocols = [self.eth, self.ipv6, self.payload]

    def get_protocol(self, cls):
        if cls is DummyEthernet:
            return self.eth
        if cls is DummyIPv6:
            return self.ipv6
        return None


def load_exact_packet_in(source_file):
    """Compile only the submitted handler, without starting eventlet threads."""
    tree = ast.parse(source_file.read_text(encoding='utf-8'))
    controller = next(n for n in tree.body
                      if isinstance(n, ast.ClassDef) and n.name == 'OSPFv3Controller')
    method = copy.deepcopy(next(n for n in controller.body
                                if isinstance(n, ast.FunctionDef)
                                and n.name == 'packet_in_handler'))
    method.decorator_list = []
    fragment = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    return compile(fragment, str(source_file), 'exec')


class TestB4Handler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not NEW_SOURCE.exists() or not OLD_SOURCE.exists():
            raise RuntimeError(
                'Place ryu_sdn.py at project root and '
                'ryu_sdn_before_b4.py beside this test file.'
            )
        cls.new_code = load_exact_packet_in(NEW_SOURCE)
        cls.old_code = load_exact_packet_in(OLD_SOURCE)

    @staticmethod
    def wire_packet(packet_type=1, *, version=3, router_id='1.1.1.1',
                    area='0.0.0.0', instance=0, reserved=0, checksum=0xBEEF,
                    length=None, extra=b'', payload=None):
        min_len = {1: 36, 2: 28, 3: 28, 4: 20, 5: 36}.get(packet_type, 16)
        if payload is None:
            payload = bytes(min_len - 16)
        if length is None:
            length = 16 + len(payload)
        header = struct.pack(
            '!BBH4s4sHBB', version, packet_type, length,
            ipaddress.IPv4Address(router_id).packed,
            ipaddress.IPv4Address(area).packed, checksum, instance, reserved
        )
        return header + payload + extra

    def execute(self, reference=False, raw=None, *, src='fe80::1',
                dst='ff02::5', hop_limit=1, nxt=89, raw_payload=True,
                scapy_decoder=OSPFv3_Hdr):
        if raw is None:
            raw = self.wire_packet()
        packet_obj = RyuPacketStub(raw, src=src, dst=dst, hop_limit=hop_limit,
                                    nxt=nxt, raw_payload=raw_payload)
        callbacks = {k: Mock(name=k) for k in ('hello', 'dbd', 'lsr', 'lsu', 'lsack')}
        log = Mock()
        checksummed = []

        def checksum_stub(s, d, packet_bytes):
            checksummed.append((s, d, bytes(packet_bytes)))
            # Checksumming belongs to ospfv3.packet and is unchanged in B4.
            # The stub isolates only the dispatch/header parsing semantics.
            self.assertEqual(packet_bytes[12:14], b'\x00\x00')
            return 0xBEEF

        ns = {
            'packet': SimpleNamespace(Packet=lambda _: packet_obj),
            'ethernet': SimpleNamespace(ethernet=DummyEthernet),
            'ipv6': SimpleNamespace(ipv6=DummyIPv6),
            'cfg': SimpleNamespace(AREA_ID='0.0.0.0', INSTANCE_ID=0),
            'calculate_ospfv3_checksum': checksum_stub,
            'OSPFv3_Hdr': scapy_decoder,
            'Scapy_Exception': Scapy_Exception,
            'ipaddress': ipaddress,
            'socket': socket,
            'struct': struct,
        }
        exec(self.old_code if reference else self.new_code, ns)
        controller = SimpleNamespace(
            logger=log,
            handle_ospf_hello=callbacks['hello'],
            handle_ospf_dbd=callbacks['dbd'],
            handle_ospf_lsr=callbacks['lsr'],
            handle_ospf_lsu=callbacks['lsu'],
            handle_ospf_lsack=callbacks['lsack'],
        )
        event = SimpleNamespace(msg=SimpleNamespace(data=b'fake-ethernet',
                                                     match={'in_port': 7}))
        ns['packet_in_handler'](controller, event)
        dispatched = [(name, call.args, call.kwargs)
                      for name, callback in callbacks.items()
                      for call in callback.call_args_list]
        warnings = [(call.args, call.kwargs) for call in log.warning.call_args_list]
        return dispatched, warnings, checksummed

    def assert_unchanged(self, raw=None, *, expected_handler=None, **kwargs):
        new = self.execute(False, raw, **kwargs)
        old = self.execute(True, raw, **kwargs)
        self.assertEqual(new, old)
        if expected_handler is None:
            self.assertEqual(new[0], [])
        else:
            self.assertEqual(len(new[0]), 1)
            self.assertEqual(new[0][0][0], expected_handler)
        return new

    def test_hello(self):
        result = self.assert_unchanged(expected_handler='hello')
        self.assertEqual(result[0][0][1][0], 7)
        self.assertEqual(result[0][0][1][-2:], ('1.1.1.1', '0.0.0.0'))

    def test_dbd(self):
        result = self.assert_unchanged(self.wire_packet(2), expected_handler='dbd')
        self.assertEqual(result[0][0][1][4], 0x01010101)

    def test_lsr(self):
        self.assert_unchanged(self.wire_packet(3), expected_handler='lsr')

    def test_lsu(self):
        self.assert_unchanged(self.wire_packet(4), expected_handler='lsu')

    def test_lsack(self):
        self.assert_unchanged(self.wire_packet(5), expected_handler='lsack')

    def test_padding_outside_declared_packet(self):
        result = self.assert_unchanged(self.wire_packet(extra=b'\x11' * 12),
                                       expected_handler='hello')
        self.assertEqual(len(result[2][0][2]), 36)

    def test_unicast_hop_limit_64_remains_permitted(self):
        self.assert_unchanged(dst='fe80::10', hop_limit=64, expected_handler='hello')

    def test_multicast_ff02_6_hop_limit_1(self):
        self.assert_unchanged(dst='ff02::6', expected_handler='hello')

    def test_nonzero_reserved_byte_remains_accepted(self):
        self.assert_unchanged(self.wire_packet(reserved=255), expected_handler='hello')

    def test_alternate_router_id(self):
        result = self.assert_unchanged(self.wire_packet(2, router_id='203.0.113.77'),
                                       expected_handler='dbd')
        self.assertEqual(result[0][0][1][4], int(ipaddress.IPv4Address('203.0.113.77')))

    def test_too_short_header(self):
        self.assert_unchanged(raw=b'\x03\x01\x00')

    def test_declared_length_under_16(self):
        self.assert_unchanged(self.wire_packet(length=15))

    def test_declared_length_beyond_available(self):
        self.assert_unchanged(self.wire_packet(length=500))

    def test_bad_ospf_checksum(self):
        result = self.assert_unchanged(self.wire_packet(checksum=0xBEEE))
        self.assertEqual(len(result[1]), 1)

    def test_wrong_area_id(self):
        self.assert_unchanged(self.wire_packet(area='0.0.0.1'))

    def test_wrong_instance_id(self):
        self.assert_unchanged(self.wire_packet(instance=1))

    def test_non_link_local_source(self):
        self.assert_unchanged(src='2001:db8::1')

    def test_multicast_hop_limit_64(self):
        self.assert_unchanged(hop_limit=64)

    def test_multicast_hop_limit_0(self):
        self.assert_unchanged(hop_limit=0)

    def test_wrong_version(self):
        self.assert_unchanged(self.wire_packet(version=2))

    def test_unknown_type(self):
        self.assert_unchanged(self.wire_packet(6))

    def test_dbd_too_short_for_dispatch(self):
        self.assert_unchanged(self.wire_packet(2, payload=b''))

    def test_lsack_too_short_for_dispatch(self):
        self.assert_unchanged(self.wire_packet(5, payload=b''))

    def test_ospf_payload_must_be_bytes(self):
        self.assert_unchanged(raw_payload=False)

    def test_other_ipv6_next_header_does_not_dispatch(self):
        self.assert_unchanged(nxt=17)

    def test_real_scapy_header_decoder_is_used(self):
        seen = []

        class CapturingHeader:
            def __init__(self, raw):
                seen.append(bytes(raw))
                self.header = OSPFv3_Hdr(raw)

            def __getattr__(self, name):
                return getattr(self.header, name)

        raw = self.wire_packet(extra=b"\x99" * 4)
        dispatched, _, _ = self.execute(raw=raw, scapy_decoder=CapturingHeader)
        self.assertEqual(len(dispatched), 1)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0], raw[:16])

    def test_scapy_decode_error_is_caught(self):
        class BrokenHeader:
            def __init__(self, raw):
                raise Scapy_Exception('forced failure')
        dispatched, warnings, checks = self.execute(scapy_decoder=BrokenHeader)
        self.assertEqual(dispatched, [])
        self.assertEqual(checks, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn('invalid OSPFv3 header', warnings[0][0][0])

    def test_only_packet_in_handler_method_changed(self):
        def method_map(file):
            tree = ast.parse(file.read_text(encoding='utf-8'))
            node = next(x for x in tree.body
                        if isinstance(x, ast.ClassDef) and x.name == 'OSPFv3Controller')
            return {x.name: ast.dump(x, include_attributes=False)
                    for x in node.body if isinstance(x, ast.FunctionDef)}
        before = method_map(OLD_SOURCE)
        after = method_map(NEW_SOURCE)
        self.assertEqual(before.keys(), after.keys())
        changes = [n for n in before if before[n] != after[n]]
        self.assertEqual(changes, ['packet_in_handler'])


if __name__ == '__main__':
    unittest.main()
