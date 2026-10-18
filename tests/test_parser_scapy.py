"""Contract and malformed-input tests for the Scapy OSPFv3 receive codec.

Place next to ryu_sdn.py and run:
    python -m unittest -v test_parser_scapy

The fixtures are constructed independently from ospfv3.packet so the receive
codec is not tested only against the matching Scapy transmitter.
"""

import logging
import socket
import struct
import unittest

from ospfv3.local_lsa import LocalLSA
from ospfv3 import config as cfg
from ospfv3.lsa import finalize_ospfv3_lsa_checksum
from ospfv3.parser import (
    parse_hello,
    parse_dbd,
    parse_lsr,
    parse_lsu,
    parse_lsack,
)


def router_id(value):
    return struct.unpack("!I", socket.inet_aton(value))[0]


def ospf_packet(packet_type, body):
    return struct.pack(
        "!BBHIIHBB", 3, packet_type, 16 + len(body),
        router_id("1.1.1.1"), 0, 0, 0, 0
    ) + body


def lsa_header(ls_type=0x2001, age=1, lsid="0.0.0.0",
               advertiser="1.1.1.1", seq=0x80000002, checksum=0x1234,
               length=20):
    return struct.pack(
        "!HHIIIHH", age, ls_type, router_id(lsid),
        router_id(advertiser), seq, checksum, length
    )


class LSDBFixture:
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


class ParserScapyTests(unittest.TestCase):
    def setUp(self):
        self.local = LocalLSA(LSDBFixture(), logging.getLogger("parser-tests"))
        self.assertTrue(self.local.initialize("1.1.1.1"))

    @staticmethod
    def decode(parse_function, packet):
        return parse_function(packet, len(packet))

    def test_hello_empty_neighbors(self):
        body = struct.pack("!IB3sHHII", 101, 1, b"\x00\x00\x13", 10, 40, 0, 0)
        p = ospf_packet(1, body)
        self.assertEqual(self.decode(parse_hello, p), {
            "interface_id": 101, "router_priority": 1, "options": 0x13,
            "hello_interval": 10, "dead_interval": 40,
            "designated_router": 0, "backup_designated_router": 0,
            "neighbors": [],
        })

    def test_hello_three_neighbors_and_nonzero_dr(self):
        neighbors = ["2.2.2.2", "3.3.3.3", "10.10.10.10"]
        body = struct.pack(
            "!IB3sHHII", 999, 7, b"\x00\x00\x13", 5, 25,
            router_id("1.2.3.4"), router_id("4.3.2.1")
        ) + b"".join(socket.inet_aton(n) for n in neighbors)
        result = self.decode(parse_hello, ospf_packet(1, body))
        self.assertEqual(result["neighbors"], neighbors)
        self.assertEqual(result["designated_router"], router_id("1.2.3.4"))
        self.assertEqual(result["backup_designated_router"], router_id("4.3.2.1"))
        self.assertEqual(result["interface_id"], 999)

    def test_dbd_empty(self):
        body = struct.pack("!B3sHBBI", 0, b"\x00\x00\x13", 1500, 0, 7, 0xabcdef12)
        result = self.decode(parse_dbd, ospf_packet(2, body))
        self.assertEqual(result, {
            "interface_mtu": 1500, "options": 0x13,
            "i_bit": True, "m_bit": True, "ms_bit": True,
            "dd_sequence": 0xabcdef12, "lsa_headers": [],
        })

    def test_dbd_three_summaries(self):
        body = struct.pack("!B3sHBBI", 0, b"\x00\x00\x13", 1500, 0, 1, 900)
        types = [0x0008, 0x2001, 0x2009]
        body += b"".join(lsa_header(ls_type=t) for t in types)
        result = self.decode(parse_dbd, ospf_packet(2, body))
        self.assertEqual([h["ls_type"] for h in result["lsa_headers"]], types)
        self.assertEqual(result["dd_sequence"], 900)
        self.assertEqual((result["i_bit"], result["m_bit"], result["ms_bit"]), (False, False, True))
        self.assertNotIn("raw_header", result["lsa_headers"][0])

    def test_lsr_one_and_three(self):
        req = lambda t: struct.pack("!HHII", 0, t, router_id("0.0.0.0"), router_id("1.1.1.1"))
        for types in ([0x2001], [0x2001, 0x0008, 0x2009]):
            with self.subTest(types=types):
                result = self.decode(parse_lsr, ospf_packet(3, b"".join(req(t) for t in types)))
                self.assertEqual([item["ls_type"] for item in result], types)
                self.assertEqual([item["advertising_router"] for item in result], ["1.1.1.1"] * len(types))

    def test_lsu_three_local_lsas(self):
        data = self.local.build_update_body()
        parsed = self.decode(parse_lsu, ospf_packet(4, data))
        self.assertEqual(len(parsed), 3)
        self.assertEqual({h["ls_type"] for h in parsed}, {0x0008, 0x2001, 0x2009})
        for header in parsed:
            self.assertEqual(len(header["raw_header"]), 20)
            self.assertEqual(header["advertising_router"], cfg.ROUTER_ID)
        self.assertTrue(any("router_lsa" in h for h in parsed))
        self.assertTrue(any("link_lsa" in h for h in parsed))
        self.assertTrue(any("intra_area_prefix_lsa" in h for h in parsed))

    def test_lsu_single_router_lsa(self):
        router_lsa = next(
            item["raw_lsa"] for item in self.local.values()
            if item["ls_type"] == 0x2001
        )
        data = struct.pack("!I", 1) + router_lsa
        parsed = self.decode(parse_lsu, ospf_packet(4, data))
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["ls_type"], 0x2001)
        self.assertEqual(len(parsed[0]["router_lsa"]["links"]), 1)

    def test_lsu_single_unknown_lsa_keeps_header(self):
        # Unknown function code is retained, without inventing LSA body fields.
        unknown = finalize_ospfv3_lsa_checksum(
            lsa_header(ls_type=0x200b, length=24) + b"\x00\x11\x22\x33"
        )
        parsed = self.decode(parse_lsu, ospf_packet(4, struct.pack("!I", 1) + unknown))
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["ls_type"], 0x200b)
        self.assertEqual(parsed[0]["raw_header"], unknown[:20])
        self.assertNotIn("router_lsa", parsed[0])

    def test_lsu_empty(self):
        self.assertEqual(self.decode(parse_lsu, ospf_packet(4, b"\x00\x00\x00\x00")), [])

    def test_lsack_one_and_three(self):
        for types in ([0x2001], [0x0008, 0x2001, 0x2009]):
            with self.subTest(types=types):
                data = b"".join(lsa_header(ls_type=t) for t in types)
                headers = self.decode(parse_lsack, ospf_packet(5, data))
                self.assertEqual([h["ls_type"] for h in headers], types)
                self.assertEqual(headers[0]["ls_sequence"], 0x80000002)
                self.assertEqual(headers[0]["ls_checksum"], 0x1234)
                self.assertNotIn("raw_header", headers[0])

    def test_extra_transport_padding_is_ignored(self):
        hello = ospf_packet(1, struct.pack("!IB3sHHII", 1, 1, b"\x00\x00\x13", 10, 40, 0, 0))
        self.assertEqual(parse_hello(hello + b"\x00" * 8, len(hello))["neighbors"], [])

    def test_wrong_pkt_len_and_truncation_rejected(self):
        p = ospf_packet(1, struct.pack("!IB3sHHII", 1, 1, b"\x00\x00\x13", 10, 40, 0, 0))
        with self.assertRaises(ValueError):
            parse_hello(p, len(p) + 1)
        with self.assertRaises(ValueError):
            parse_hello(p, len(p) - 1)
        with self.assertRaises(ValueError):
            parse_hello(p[:-1], len(p))
        with self.assertRaises(ValueError):
            parse_hello(p[:10], 36)

    def test_invalid_hello_neighbor_section_rejected(self):
        p = ospf_packet(1, struct.pack("!IB3sHHII", 1, 1, b"\x00\x00\x13", 10, 40, 0, 0) + b"\x01")
        with self.assertRaises(ValueError):
            self.decode(parse_hello, p)

    def test_dbd_partial_header_rejected(self):
        fixed = struct.pack("!B3sHBBI", 0, b"\x00\x00\x13", 1500, 0, 7, 123)
        p = ospf_packet(2, fixed + lsa_header()[:19])
        with self.assertRaises(ValueError):
            self.decode(parse_dbd, p)

    def test_lsr_empty_and_misaligned_rejected(self):
        for body in (b"", b"\x00" * 11, b"\x00" * 13):
            with self.subTest(size=len(body)), self.assertRaises(ValueError):
                self.decode(parse_lsr, ospf_packet(3, body))

    def test_lsack_empty_and_partial_rejected(self):
        for body in (b"", b"\x00" * 19, b"\x00" * 21):
            with self.subTest(size=len(body)), self.assertRaises(ValueError):
                self.decode(parse_lsack, ospf_packet(5, body))

    def test_lsu_bad_lsa_count(self):
        for body in (struct.pack("!I", 1), struct.pack("!I", 4) + self.local.build_update_body()[4:]):
            with self.subTest(size=len(body)), self.assertRaises(ValueError):
                self.decode(parse_lsu, ospf_packet(4, body))

    def test_lsu_zero_and_short_lengths(self):
        for bad_length in (0, 19):
            body = struct.pack("!I", 1) + lsa_header(length=bad_length)
            with self.subTest(length=bad_length), self.assertRaises(ValueError):
                self.decode(parse_lsu, ospf_packet(4, body))

    def test_lsu_overflow_and_trailing_bytes(self):
        beyond = struct.pack("!I", 1) + lsa_header(length=100)
        trailing = struct.pack("!I", 0) + b"\x00" * 4
        for body in (beyond, trailing):
            with self.subTest(size=len(body)), self.assertRaises(ValueError):
                self.decode(parse_lsu, ospf_packet(4, body))

    def test_lsu_count_larger_than_available_buffer(self):
        body = struct.pack("!I", 0xffffffff)
        with self.assertRaises(ValueError):
            self.decode(parse_lsu, ospf_packet(4, body))


if __name__ == "__main__":
    unittest.main()
