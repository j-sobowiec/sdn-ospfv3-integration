"""B2: LSA parser compatibility, boundary, and negative tests.

Run from the project root:
    python -m unittest discover -s tests -p test_lsa_scapy.py -v

Keep tests/lsa_before_scapy.py as the immutable reference implementation.
"""

import importlib.util
import ipaddress
import logging
import socket
import struct
import unittest
from pathlib import Path

from ospfv3 import config as cfg
from ospfv3 import lsa as current
from ospfv3.local_lsa import LocalLSA


def load_reference():
    path = Path(__file__).with_name("lsa_before_scapy.py")
    spec = importlib.util.spec_from_file_location("lsa_before_scapy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reference = load_reference()


def header(lsa_type, body, length=None, age=1, sequence=0x80000001):
    actual_length = 20 + len(body)
    return struct.pack(
        "!HHIIIHH", age, lsa_type, 7, 0x01020304,
        sequence, 0x1234, actual_length if length is None else length,
    ) + body


def router_link(link_type, metric, intid, neighintid, neighbor, reserved=0):
    return struct.pack(
        "!BBHIII", link_type, reserved, metric,
        intid, neighintid, struct.unpack("!I", socket.inet_aton(neighbor))[0],
    )


def prefix_item(length, address, options=0, word=0):
    addr = ipaddress.IPv6Network((address, length), strict=False).network_address.packed
    payload_len = ((length + 31) // 32) * 4
    return struct.pack("!BBH", length, options, word) + addr[:payload_len]


def make_router(links=(), flags=0, options=0x13):
    return header(0x2001, bytes([flags]) + options.to_bytes(3, "big") + b"".join(links))


def make_link(prefixes=(), priority=1, options=0x13):
    body = (
        bytes([priority]) + options.to_bytes(3, "big")
        + socket.inet_pton(socket.AF_INET6, "fe80::10")
        + struct.pack("!I", len(prefixes))
        + b"".join(prefixes)
    )
    return header(0x0008, body)


def make_intra(prefixes=(), referenced_type=0x2001):
    body = struct.pack("!HHII", len(prefixes), referenced_type, 0, 0x01020304)
    return header(0x2009, body + b"".join(prefixes))


class FakeLSDB:
    def values(self):
        return [{
            "ls_type": 0x2001,
            "advertising_router": "1.1.1.1",
            "router_lsa": {"links": [{
                "type": 1,
                "neighbor_router_id": cfg.ROUTER_ID,
                "neighbor_interface_id": "0.0.0.1",
                "interface_id": "0.0.3.40",
            }]},
        }]


PARSERS = (
    (current.parse_ospfv3_router_lsa, reference.parse_ospfv3_router_lsa),
    (current.parse_ospfv3_link_lsa, reference.parse_ospfv3_link_lsa),
    (current.parse_ospfv3_intra_area_prefix_lsa, reference.parse_ospfv3_intra_area_prefix_lsa),
)


class TestPositiveLSA(unittest.TestCase):
    def check_unchanged(self, index, raw):
        candidate, old = PARSERS[index]
        self.assertEqual(candidate(raw), old(raw))

    def test_router_without_links(self):
        self.check_unchanged(0, make_router())

    def test_router_with_one_link(self):
        self.check_unchanged(0, make_router([
            router_link(1, 10, 1, 808, "1.1.1.1")
        ], flags=0x0B, options=0x230013))

    def test_router_multiple_link_types_and_reserved(self):
        self.check_unchanged(0, make_router([
            router_link(1, 10, 1, 2, "1.1.1.1", reserved=3),
            router_link(2, 20, 0x01020304, 0x10203040, "2.2.2.2"),
            router_link(4, 0xffff, 0xdeadbeef, 0x80000001, "3.3.3.3"),
            router_link(99, 8, 0, 1, "4.4.4.4"),
        ]))

    def test_link_without_prefixes(self):
        self.check_unchanged(1, make_link(priority=0, options=0x123456))

    def test_link_many_prefix_lengths(self):
        for length in (0, 1, 32, 33, 64, 65, 128):
            with self.subTest(length=length):
                self.check_unchanged(1, make_link([
                    prefix_item(length, "2001:db8:1234:5678::", 0x09, 0x1234)
                ]))

    def test_link_multiple_prefixes(self):
        self.check_unchanged(1, make_link([
            prefix_item(64, "2001:db8:1::", 0x01, 0x5678),
            prefix_item(128, "2001:db8::abcd", 0x02, 0xabcd),
            prefix_item(0, "::", 0x04, 0x1111),
        ]))

    def test_intra_without_prefixes(self):
        self.check_unchanged(2, make_intra())

    def test_intra_many_prefix_lengths(self):
        for length in (0, 1, 32, 33, 64, 65, 128):
            with self.subTest(length=length):
                self.check_unchanged(2, make_intra([
                    prefix_item(length, "2001:db8:1234:5678::", 0x07, 0x1234)
                ]))

    def test_intra_multiple_prefixes(self):
        self.check_unchanged(2, make_intra([
            prefix_item(64, "2001:db8:1::", 0x01, 10),
            prefix_item(128, "2001:db8::abcd", 0x02, 20),
            prefix_item(0, "::", 0x04, 30),
        ]))

    def test_local_lsa_fixtures(self):
        local = LocalLSA(FakeLSDB(), logging.getLogger("lsa-tests"))
        self.assertTrue(local.initialize("1.1.1.1"))
        for _, entry in local.items():
            mapping = {0x2001: 0, 0x0008: 1, 0x2009: 2}
            self.check_unchanged(mapping[entry["ls_type"]], entry["raw_lsa"])

    def test_semantic_helpers_unchanged(self):
        self.assertEqual(current.lsa_sequence_signed(0x80000001), -2147483647)
        self.assertEqual(current.next_ospfv3_lsa_sequence(0x80000001), 0x80000002)
        self.assertEqual(current.ospfv3_lsa_type_description(0x2001),
                         reference.ospfv3_lsa_type_description(0x2001))
        original = make_router()
        self.assertEqual(current.finalize_ospfv3_lsa_checksum(original),
                         reference.finalize_ospfv3_lsa_checksum(original))
        a = {"ls_sequence": 0x80000002, "ls_checksum": 3, "ls_age": 3}
        b = {"ls_sequence": 0x80000001, "ls_checksum": 4, "ls_age": 4}
        self.assertEqual(current.compare_lsa_instances(a, b), 1)


class TestMalformedLSA(unittest.TestCase):
    def reject(self, parser, data):
        with self.assertRaises(ValueError):
            parser(data)

    def test_router_too_short(self):
        self.reject(current.parse_ospfv3_router_lsa, make_router()[:23])

    def test_router_partial_link(self):
        self.reject(current.parse_ospfv3_router_lsa,
                    make_router() + b"\x00" * 8)

    def test_router_declared_length_mismatch(self):
        self.reject(current.parse_ospfv3_router_lsa,
                    make_router([router_link(1, 10, 1, 2, "1.1.1.1")])[:-1])

    def test_router_wrong_type(self):
        self.reject(current.parse_ospfv3_router_lsa, make_link())

    def test_link_too_short(self):
        self.reject(current.parse_ospfv3_link_lsa, make_link()[:43])

    def test_link_declared_length_mismatch(self):
        self.reject(current.parse_ospfv3_link_lsa,
                    make_link([prefix_item(64, "2001:db8:1::")])[:-1])

    def test_link_wrong_type(self):
        self.reject(current.parse_ospfv3_link_lsa, make_router())

    def test_link_bad_count(self):
        data = bytearray(make_link())
        data[40:44] = struct.pack("!I", 10)
        self.reject(current.parse_ospfv3_link_lsa, bytes(data))

    def test_link_truncated_prefix(self):
        data = make_link([prefix_item(128, "2001:db8:1::")])[:-2]
        data = data[:18] + len(data).to_bytes(2, "big") + data[20:]
        self.reject(current.parse_ospfv3_link_lsa, data)

    def test_link_prefix_length_out_of_range(self):
        data = bytearray(make_link([prefix_item(128, "2001:db8:1::")]))
        data[44] = 129
        self.reject(current.parse_ospfv3_link_lsa, bytes(data))

    def test_link_trailing_bytes(self):
        data = make_link() + b"\x00\x00\x00\x00"
        data = data[:18] + len(data).to_bytes(2, "big") + data[20:]
        self.reject(current.parse_ospfv3_link_lsa, data)

    def test_intra_too_short(self):
        self.reject(current.parse_ospfv3_intra_area_prefix_lsa, make_intra()[:31])

    def test_intra_wrong_type(self):
        self.reject(current.parse_ospfv3_intra_area_prefix_lsa, make_link())

    def test_intra_declared_length_mismatch(self):
        self.reject(current.parse_ospfv3_intra_area_prefix_lsa,
                    make_intra([prefix_item(64, "2001:db8:1::")])[:-1])

    def test_intra_bad_count(self):
        data = bytearray(make_intra())
        data[20:22] = struct.pack("!H", 3)
        self.reject(current.parse_ospfv3_intra_area_prefix_lsa, bytes(data))

    def test_intra_truncated_prefix(self):
        data = make_intra([prefix_item(128, "2001:db8:1::")])[:-2]
        data = data[:18] + len(data).to_bytes(2, "big") + data[20:]
        self.reject(current.parse_ospfv3_intra_area_prefix_lsa, data)

    def test_intra_prefix_length_out_of_range(self):
        data = bytearray(make_intra([prefix_item(128, "2001:db8:1::")]))
        data[32] = 129
        self.reject(current.parse_ospfv3_intra_area_prefix_lsa, bytes(data))

    def test_intra_trailing_bytes(self):
        data = make_intra() + b"\x00\x00\x00\x00"
        data = data[:18] + len(data).to_bytes(2, "big") + data[20:]
        self.reject(current.parse_ospfv3_intra_area_prefix_lsa, data)


if __name__ == "__main__":
    unittest.main()
