"""B2b — independent wire fixtures for checksum validation in received OSPFv3 LSUs.

Run from the project root with Scapy 2.7.0 installed:
    python -m unittest discover -s tests -p 'test_lsa_checksum_b2b.py' -v

The LSA vectors do not use the application's packet builders or checksum writer.
"""

import ipaddress
import socket
import struct
import unittest

from ospfv3.lsa import ospfv3_lsa_checksum
from ospfv3.parser import parse_lsu


def checksum_residue(lsa):
    """Independent Fletcher-255 receiver test: both sums must equal zero."""
    c0 = c1 = 0
    for octet in lsa[2:]:  # Skip LS Age, INCLUDE checksum octets.
        c0 = (c0 + octet) % 255
        c1 = (c1 + c0) % 255
    return c0, c1


def make_valid_checksum(lsa):
    """Create independent on-wire fixtures; production finalizer isn't used."""
    data = bytearray(lsa)
    data[16:18] = b"\x00\x00"
    c0 = c1 = 0
    for octet in data[2:]:
        c0 = (c0 + octet) % 255
        c1 = (c1 + c0) % 255
    checked_len = len(data) - 2
    x = ((checked_len - 15) * c0 - c1) % 255
    if x == 0:
        x = 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    data[16:18] = struct.pack("!BB", x, y)
    result = bytes(data)
    if checksum_residue(result) != (0, 0):
        raise AssertionError("independent fixture checksum invalid")
    return result


def ipv4(value):
    return int(ipaddress.IPv4Address(value))


def lsa_header(lsa_type, body, age=1, advertising_router="1.1.1.1", seq=0x80000001):
    return struct.pack(
        "!HHIIIHH", age, lsa_type, 0,
        ipv4(advertising_router), seq, 0, 20 + len(body)
    ) + body


def router_lsa():
    body = b"\x00\x00\x00\x13" + struct.pack(
        "!BBHIII", 1, 0, 10, 808, 1, ipv4("10.10.10.10")
    )
    return make_valid_checksum(lsa_header(0x2001, body))


def link_lsa():
    body = (
        b"\x01\x00\x00\x13"
        + socket.inet_pton(socket.AF_INET6, "fe80::1")
        + struct.pack("!I", 1)
        + struct.pack("!BBH", 64, 0, 0)
        + socket.inet_pton(socket.AF_INET6, "2001:db8:10::")[:8]
    )
    return make_valid_checksum(lsa_header(0x0008, body))


def intra_lsa():
    body = (
        struct.pack("!HHII", 1, 0x2001, 0, ipv4("1.1.1.1"))
        + struct.pack("!BBH", 64, 0, 10)
        + socket.inet_pton(socket.AF_INET6, "2001:db8:1::")[:8]
    )
    return make_valid_checksum(lsa_header(0x2009, body))


def unknown_lsa():
    return make_valid_checksum(lsa_header(0x200B, b"\x00\x11\x22\x33"))


def lsu_packet(*lsas):
    body = struct.pack("!I", len(lsas)) + b"".join(lsas)
    return struct.pack(
        "!BBHIIHBB", 3, 4, 16 + len(body),
        ipv4("1.1.1.1"), 0, 0, 0, 0,
    ) + body


def decode(*lsas):
    packet = lsu_packet(*lsas)
    return parse_lsu(packet, len(packet))


def altered(raw_lsa, index, mask=1):
    mutable = bytearray(raw_lsa)
    mutable[index] ^= mask
    return bytes(mutable)


class TestValidLSAChecksums(unittest.TestCase):
    def test_independent_checksum_residues(self):
        for lsa in (router_lsa(), link_lsa(), intra_lsa(), unknown_lsa()):
            with self.subTest(lsa_type=lsa[2:4].hex()):
                self.assertNotEqual(lsa[16:18], b"\x00\x00")
                self.assertEqual(checksum_residue(lsa), (0, 0))
                self.assertEqual(ospfv3_lsa_checksum(lsa), int.from_bytes(lsa[16:18], "big"))

    def test_all_three_known_lsas(self):
        entries = decode(router_lsa(), link_lsa(), intra_lsa())
        self.assertEqual([entry["ls_type"] for entry in entries], [0x2001, 0x0008, 0x2009])
        self.assertEqual(entries[0]["router_lsa"]["links"][0]["neighbor_router_id"], "10.10.10.10")
        self.assertEqual(entries[1]["link_lsa"]["prefixes"][0]["prefix"], "2001:db8:10::")
        self.assertEqual(entries[2]["intra_area_prefix_lsa"]["prefixes"][0]["prefix"], "2001:db8:1::")
        self.assertEqual(entries[0]["raw_header"], router_lsa()[:20])

    def test_unknown_type_valid_checksum_preserves_header(self):
        lsa = unknown_lsa()
        result = decode(lsa)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ls_type"], 0x200B)
        self.assertEqual(result[0]["raw_header"], lsa[:20])
        self.assertNotIn("router_lsa", result[0])

    def test_empty_lsu_is_unchanged(self):
        self.assertEqual(decode(), [])

    def test_ls_age_excluded_from_checksum(self):
        original = router_lsa()
        for age in (0, 10, 3599, 3600):
            with self.subTest(age=age):
                change = bytearray(original)
                struct.pack_into("!H", change, 0, age)
                self.assertEqual(checksum_residue(change), (0, 0))
                self.assertEqual(decode(bytes(change))[0]["ls_age"], age)

    def test_new_valid_instance_after_sequence_change(self):
        lsa = bytearray(router_lsa())
        struct.pack_into("!I", lsa, 12, 0x80000009)
        new = make_valid_checksum(lsa)
        self.assertEqual(decode(new)[0]["ls_sequence"], 0x80000009)

    def test_transport_padding_ignored(self):
        lsa = router_lsa()
        packet = lsu_packet(lsa)
        self.assertEqual(parse_lsu(packet + b"\x00" * 12, len(packet))[0]["ls_type"], 0x2001)

    def test_valid_unknown_and_known_in_one_lsu(self):
        self.assertEqual(
            [lsa["ls_type"] for lsa in decode(unknown_lsa(), router_lsa())],
            [0x200B, 0x2001],
        )


class TestInvalidLSAChecksums(unittest.TestCase):
    def assert_checksum_error(self, *lsas, ordinal=1):
        with self.assertRaisesRegex(ValueError, rf"invalid LSA checksum #{ordinal}"):
            decode(*lsas)

    def test_corrupt_router_body(self):
        self.assert_checksum_error(altered(router_lsa(), 25))

    def test_corrupt_link_body(self):
        self.assert_checksum_error(altered(link_lsa(), 26))

    def test_corrupt_intra_body(self):
        self.assert_checksum_error(altered(intra_lsa(), 36))

    def test_corrupt_header_advertising_router(self):
        self.assert_checksum_error(altered(router_lsa(), 11))

    def test_corrupt_header_sequence(self):
        self.assert_checksum_error(altered(router_lsa(), 15))

    def test_corrupt_header_type(self):
        self.assert_checksum_error(altered(router_lsa(), 3))

    def test_corrupt_checksum_high_byte(self):
        self.assert_checksum_error(altered(router_lsa(), 16))

    def test_corrupt_checksum_low_byte(self):
        self.assert_checksum_error(altered(router_lsa(), 17))

    def test_zero_checksum_rejected(self):
        lsa = bytearray(router_lsa())
        lsa[16:18] = b"\x00\x00"
        self.assert_checksum_error(bytes(lsa))

    def test_unknown_lsa_corrupt_body_rejected(self):
        self.assert_checksum_error(altered(unknown_lsa(), 22))

    def test_second_lsa_corrupt_rejected_with_index(self):
        self.assert_checksum_error(router_lsa(), altered(link_lsa(), 25), ordinal=2)

    def test_third_lsa_corrupt_rejected_with_index(self):
        self.assert_checksum_error(router_lsa(), link_lsa(), altered(intra_lsa(), 33), ordinal=3)

    def test_different_valid_lsas_cannot_borrow_checksum(self):
        first = bytearray(router_lsa())
        second = link_lsa()
        first[16:18] = second[16:18]
        self.assert_checksum_error(bytes(first))

    def test_new_instance_without_recomputing_checksum_rejected(self):
        lsa = bytearray(router_lsa())
        struct.pack_into("!I", lsa, 12, 0x80000009)
        self.assert_checksum_error(bytes(lsa))


if __name__ == "__main__":
    unittest.main()
