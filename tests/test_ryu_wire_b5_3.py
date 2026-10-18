"""Additional genuine Ryu packet serialization tests (requires working Ryu install).

These tests do not use b5_3_harness. Execute in user's ryu-env from project root.
"""
import importlib.util
import unittest

RYU_INSTALLED = importlib.util.find_spec('ryu') is not None

@unittest.skipUnless(RYU_INSTALLED, 'requires Ryu installed in the active Python environment')
class TestActualRyuWire(unittest.TestCase):
    def setUp(self):
        from dataplane import DataPlane
        from ospfv3 import config as cfg
        from ryu.lib.packet import ethernet, ipv6, icmpv6, packet
        self.dp=DataPlane()
        self.cfg=cfg
        self.ethernet=ethernet
        self.ipv6=ipv6
        self.icmpv6=icmpv6
        self.packet=packet
        self.host='2001:db8:1::100'
        self.mac='02:00:00:00:01:00'

    def na(self):
        wire=self.dp.build_neighbor_advertisement(self.mac,self.host,self.cfg.LAN_GATEWAY)
        self.assertIsInstance(wire, bytes)
        return self.packet.Packet(wire)

    def test_na_ethernet(self):
        eth=self.na().get_protocol(self.ethernet.ethernet)
        self.assertEqual(eth.src,self.cfg.ROUTER_MAC)
        self.assertEqual(eth.dst,self.mac)
        self.assertEqual(eth.ethertype,0x86dd)

    def test_na_ipv6_header(self):
        ip6=self.na().get_protocol(self.ipv6.ipv6)
        self.assertEqual((ip6.src, ip6.dst, ip6.nxt, ip6.hop_limit),
                         (self.cfg.LAN_GATEWAY,self.host,58,255))

    def test_na_icmpv6_type_and_target(self):
        icmp=self.na().get_protocol(self.icmpv6.icmpv6)
        self.assertEqual(icmp.type_,self.icmpv6.ND_NEIGHBOR_ADVERT)
        self.assertEqual(icmp.data.dst,self.cfg.LAN_GATEWAY)

    def test_na_target_link_layer_option(self):
        icmp=self.na().get_protocol(self.icmpv6.icmpv6)
        self.assertEqual(icmp.data.option.hw_src,self.cfg.ROUTER_MAC)

    def test_echo_reply_real_wire(self):
        original=self.icmpv6.echo(id_=0x12,seq=7,data=b'test-b5.3')
        wire=self.dp.build_echo_reply(self.mac,self.host,original)
        pkt=self.packet.Packet(wire)
        ip6=pkt.get_protocol(self.ipv6.ipv6)
        icmp=pkt.get_protocol(self.icmpv6.icmpv6)
        self.assertEqual((ip6.src,ip6.dst),(self.cfg.LAN_GATEWAY,self.host))
        self.assertEqual(icmp.type_,129)
        self.assertEqual((icmp.data.id,icmp.data.seq,icmp.data.data),
                         (0x12,7,b'test-b5.3'))

if __name__=='__main__':unittest.main()
