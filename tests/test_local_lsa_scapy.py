"""B3: Scapy local-LSA builder regression and protocol-field tests.

Run from the project root:
    python -m unittest discover -s tests -p 'test_local_lsa_scapy.py' -v

Keep tests/local_lsa_before_scapy.py as the immutable reference.
"""

import hashlib
import importlib.util
import ipaddress
import logging
import socket
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

from ospfv3 import config as cfg
from ospfv3.local_lsa import LocalLSA
from ospfv3.lsa import (
    parse_ospfv3_intra_area_prefix_lsa,
    parse_ospfv3_link_lsa,
    parse_ospfv3_router_lsa,
)


def load_reference():
    path = Path(__file__).with_name("local_lsa_before_scapy.py")
    spec = importlib.util.spec_from_file_location("local_lsa_before_scapy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.LocalLSA


OriginalLocalLSA = load_reference()
LOGGER = logging.getLogger("ospfv3-b3-test")
NEIGHBOR = "1.1.1.1"


class FakeLSDB:
    def __init__(self, neighbor=NEIGHBOR, neighbor_interface=808):
        self.neighbor = neighbor
        self.neighbor_interface = neighbor_interface

    def values(self):
        return [{
            "ls_type": 0x2001,
            "advertising_router": self.neighbor,
            "router_lsa": {"links": [{
                "type": 1,
                "neighbor_router_id": cfg.ROUTER_ID,
                "neighbor_interface_id": socket.inet_ntoa(
                    struct.pack("!I", cfg.INTERFACE_ID)
                ),
                "interface_id": socket.inet_ntoa(
                    struct.pack("!I", self.neighbor_interface)
                ),
            }]},
        }]


def new_pair(lsdb=None):
    if lsdb is None:
        lsdb = FakeLSDB()
    return LocalLSA(lsdb, LOGGER), OriginalLocalLSA(lsdb, LOGGER)


def lsa_header(data):
    return struct.unpack("!HHIIIHH", data[:20])


def fletcher_residue(data):
    """Independent Fletcher residue check, including the transmitted checksum."""
    c0 = c1 = 0
    for octet in data[2:]:  # LS Age is not part of the checksum
        c0 = (c0 + octet) % 255
        c1 = (c1 + c0) % 255
    return c0, c1


class TestWireFormat(unittest.TestCase):
    def assert_valid_lsa(self, data, ls_type, lsid, sequence):
        self.assertIsInstance(data, bytes)
        age, actual_type, actual_id, adv, seq, checksum, length = lsa_header(data)
        self.assertEqual(age, 0)
        self.assertEqual(actual_type, ls_type)
        self.assertEqual(actual_id, lsid)
        self.assertEqual(adv, struct.unpack("!I", socket.inet_aton(cfg.ROUTER_ID))[0])
        self.assertEqual(seq, sequence)
        self.assertNotEqual(checksum, 0)
        self.assertEqual(length, len(data))
        self.assertEqual(fletcher_residue(data), (0, 0))

    def test_golden_router(self):
        new, old = new_pair()
        built = new.build_router(NEIGHBOR)
        self.assertEqual(built, old.build_router(NEIGHBOR))
        self.assertEqual(hashlib.sha256(built).hexdigest(),
                         "aa39fbf505f38296d1b3d15a6d3fa1c187c7cc114582fa23564db5ed851cda2e")
        self.assert_valid_lsa(built, 0x2001, 0, cfg.INITIAL_SEQUENCE)
        fields = parse_ospfv3_router_lsa(built)
        self.assertEqual(fields["options"], cfg.OPTIONS)
        self.assertEqual(len(fields["links"]), 1)
        self.assertEqual(fields["links"][0]["metric"], cfg.INTERFACE_COST)
        self.assertEqual(fields["links"][0]["neighbor_router_id"], NEIGHBOR)
        self.assertEqual(fields["links"][0]["neighbor_interface_id"], "0.0.3.40")

    def test_golden_link(self):
        new, old = new_pair()
        built = new.build_link()
        self.assertEqual(built, old.build_link())
        self.assertEqual(hashlib.sha256(built).hexdigest(),
                         "f4c3805e716c1302b31c5d54dc6c97e62a9033f576e28eacafc4b3c15d333413")
        self.assert_valid_lsa(built, 0x0008, cfg.INTERFACE_ID, cfg.INITIAL_SEQUENCE)
        fields = parse_ospfv3_link_lsa(built)
        self.assertEqual(fields["router_priority"], cfg.ROUTER_PRIORITY)
        self.assertEqual(fields["link_local_address"], cfg.LINK_LOCAL)
        self.assertEqual(fields["options"], cfg.OPTIONS)
        self.assertEqual(fields["number_of_prefixes"], 1)
        self.assertEqual(fields["prefixes"][0]["prefix_length"], cfg.TRANSIT_PREFIX_LEN)
        self.assertEqual(fields["prefixes"][0]["reserved"], 0)

    def test_golden_prefix(self):
        new, old = new_pair()
        built = new.build_prefix()
        self.assertEqual(built, old.build_prefix())
        self.assertEqual(hashlib.sha256(built).hexdigest(),
                         "af0827e03f4c5957635f72a1d14874492e28abe7b1e75a8d7020e2f7303f41e0")
        self.assert_valid_lsa(built, 0x2009, 0, cfg.INITIAL_SEQUENCE)
        fields = parse_ospfv3_intra_area_prefix_lsa(built)
        self.assertEqual(fields["referenced_ls_type"], 0x2001)
        self.assertEqual(fields["referenced_advertising_router"], cfg.ROUTER_ID)
        self.assertEqual(fields["number_of_prefixes"], 1)
        self.assertEqual(fields["prefixes"][0]["metric"], cfg.LAN_PREFIX_METRIC)
        self.assertEqual(fields["prefixes"][0]["prefix_length"], cfg.LAN_PREFIX_LEN)

    def test_router_neighbor_interface_and_metric_variants(self):
        with patch.object(cfg, "INTERFACE_COST", 97), patch.object(cfg, "INTERFACE_ID", 37):
            new, old = new_pair(FakeLSDB(neighbor_interface=0x12345678))
            built = new.build_router(NEIGHBOR)
            self.assertEqual(built, old.build_router(NEIGHBOR))
            self.assert_valid_lsa(built, 0x2001, 0, cfg.INITIAL_SEQUENCE)
            link = parse_ospfv3_router_lsa(built)["links"][0]
            self.assertEqual(link["neighbor_interface_id"], "18.52.86.120")
            self.assertEqual(link["interface_id"], "0.0.0.37")
            self.assertEqual(link["metric"], 97)

    def test_sequence_variants(self):
        for sequence in (0x80000002, 0x800000FF, 0x7FFFFFFE):
            with self.subTest(sequence=sequence):
                new, old = new_pair()
                for x in (new, old):
                    x.router_sequence = sequence
                    x.link_sequence = sequence
                    x.prefix_sequence = sequence
                for func, lsa_type, lsid in (
                    ("build_router", 0x2001, 0),
                    ("build_link", 0x0008, cfg.INTERFACE_ID),
                    ("build_prefix", 0x2009, 0),
                ):
                    args = (NEIGHBOR,) if func == "build_router" else ()
                    raw = getattr(new, func)(*args)
                    self.assertEqual(raw, getattr(old, func)(*args))
                    self.assert_valid_lsa(raw, lsa_type, lsid, sequence)

    def test_prefix_lengths_link(self):
        for length in (0, 1, 32, 33, 64, 65, 128):
            with self.subTest(prefixlen=length):
                with patch.object(cfg, "TRANSIT_PREFIX_LEN", length):
                    new, old = new_pair()
                    raw = new.build_link()
                    self.assertEqual(raw, old.build_link())
                    self.assert_valid_lsa(raw, 0x0008, cfg.INTERFACE_ID, cfg.INITIAL_SEQUENCE)
                    fields = parse_ospfv3_link_lsa(raw)["prefixes"][0]
                    self.assertEqual(fields["prefix_length"], length)
                    net = ipaddress.IPv6Network((cfg.TRANSIT_PREFIX, length), strict=False)
                    self.assertEqual(fields["prefix"], net.network_address.compressed)

    def test_prefix_lengths_intra(self):
        for length in (0, 1, 32, 33, 64, 65, 128):
            with self.subTest(prefixlen=length):
                with patch.object(cfg, "LAN_PREFIX_LEN", length):
                    new, old = new_pair()
                    raw = new.build_prefix()
                    self.assertEqual(raw, old.build_prefix())
                    self.assert_valid_lsa(raw, 0x2009, 0, cfg.INITIAL_SEQUENCE)
                    fields = parse_ospfv3_intra_area_prefix_lsa(raw)["prefixes"][0]
                    self.assertEqual(fields["prefix_length"], length)
                    net = ipaddress.IPv6Network((cfg.LAN_PREFIX, length), strict=False)
                    self.assertEqual(fields["prefix"], net.network_address.compressed)

    def test_priority_and_options_variants(self):
        with patch.object(cfg, "ROUTER_PRIORITY", 7), patch.object(cfg, "OPTIONS", 0x123456):
            new, old = new_pair()
            for name in ("build_router", "build_link"):
                args = (NEIGHBOR,) if name == "build_router" else ()
                raw = getattr(new, name)(*args)
                self.assertEqual(raw, getattr(old, name)(*args))
                parsed = (parse_ospfv3_router_lsa(raw) if name == "build_router"
                          else parse_ospfv3_link_lsa(raw))
                self.assertEqual(parsed["options"], 0x123456)

    def test_nondefault_prefix_metric(self):
        with patch.object(cfg, "LAN_PREFIX_METRIC", 36), patch.object(cfg, "LAN_PREFIX_LEN", 65):
            new, old = new_pair()
            self.assertEqual(new.build_prefix(), old.build_prefix())
            self.assertEqual(parse_ospfv3_intra_area_prefix_lsa(new.build_prefix())
                             ["prefixes"][0]["metric"], 36)


class TestExistingProtocolSemantics(unittest.TestCase):
    def test_router_without_neighbor(self):
        new, old = new_pair()
        self.assertIsNone(new.build_router(None))
        self.assertEqual(new.build_router(None), old.build_router(None))

    def test_router_without_neighbor_interface_id(self):
        class NoLSDB:
            def values(self):
                return []
        new, old = new_pair(NoLSDB())
        self.assertIsNone(new.build_router(NEIGHBOR))
        self.assertIsNone(old.build_router(NEIGHBOR))
        self.assertFalse(new.initialize(NEIGHBOR))
        self.assertFalse(old.initialize(NEIGHBOR))

    def test_initialize_and_packet_body(self):
        new, old = new_pair()
        self.assertTrue(new.initialize(NEIGHBOR))
        self.assertTrue(old.initialize(NEIGHBOR))
        self.assertEqual(set(new.entries), set(old.entries))
        for key in new.entries:
            actual = dict(new.entries[key])
            expected = dict(old.entries[key])
            actual.pop("_originated_at")
            expected.pop("_originated_at")
            self.assertEqual(actual, expected)
        self.assertEqual(new.build_update_body(), old.build_update_body())
        body = new.build_update_body()
        self.assertEqual(struct.unpack("!I", body[:4])[0], 3)
        self.assertEqual(len(body), 4 + sum(len(lsa["raw_lsa"]) for lsa in new.values()))

    def test_reoriginate(self):
        new, old = new_pair()
        for x in (new, old):
            self.assertTrue(x.initialize(NEIGHBOR))
        previous = {k: v["raw_lsa"] for k, v in new.items()}
        self.assertTrue(new.reoriginate(NEIGHBOR, "test"))
        self.assertTrue(old.reoriginate(NEIGHBOR, "test"))
        self.assertEqual(new.build_update_body(), old.build_update_body())
        for key, value in new.items():
            self.assertNotEqual(value["raw_lsa"], previous[key])
            self.assertEqual(value["ls_sequence"], cfg.INITIAL_SEQUENCE + 1)
            self.assertEqual(fletcher_residue(value["raw_lsa"]), (0, 0))

    def test_recovery_before_initialize(self):
        new, old = new_pair()
        headers = [
            {"ls_type": typ, "link_state_id": ls_id,
             "advertising_router": cfg.ROUTER_ID, "ls_sequence": 0x8000000B}
            for typ, ls_id in (
                (0x2001, "0.0.0.0"), (0x0008, "0.0.0.1"), (0x2009, "0.0.0.0")
            )
        ]
        self.assertEqual(new.recover_sequences(headers, prepare_next=True),
                         old.recover_sequences(headers, prepare_next=True))
        self.assertEqual((new.router_sequence, new.link_sequence, new.prefix_sequence),
                         (0x8000000C, 0x8000000C, 0x8000000C))
        self.assertTrue(new.initialize(NEIGHBOR))
        self.assertTrue(old.initialize(NEIGHBOR))
        self.assertEqual(new.build_update_body(), old.build_update_body())

    def test_pending_body(self):
        new, old = new_pair()
        self.assertTrue(new.initialize(NEIGHBOR))
        self.assertTrue(old.initialize(NEIGHBOR))
        keys = sorted(new.entries)
        pending = {
            keys[0]: {"ls_sequence": cfg.INITIAL_SEQUENCE,
                      "ls_checksum": new.entries[keys[0]]["ls_checksum"]},
            keys[1]: {"ls_sequence": cfg.INITIAL_SEQUENCE + 1,
                      "ls_checksum": new.entries[keys[1]]["ls_checksum"]},
        }
        result = new.build_pending_body(pending)
        self.assertEqual(result, old.build_pending_body(pending))
        self.assertEqual(result[1], 1)
        self.assertEqual(struct.unpack("!I", result[0][:4])[0], 1)
        self.assertIsNone(new.build_pending_body({}))
        self.assertIsNone(new.build_pending_body({
            keys[0]: {"ls_sequence": 5, "ls_checksum": 5}}))

    def test_max_sequence_not_modified(self):
        new, old = new_pair()
        for x in (new, old):
            x.initialize(NEIGHBOR)
            x.router_sequence = 0x7FFFFFFF
        with self.assertRaises(ValueError):
            new.reoriginate(NEIGHBOR, "max-sequence")
        with self.assertRaises(ValueError):
            old.reoriginate(NEIGHBOR, "max-sequence")


if __name__ == "__main__":
    unittest.main()
