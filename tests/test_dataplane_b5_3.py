"""B5.3 — tests of actual DataPlane method bodies using isolated Ryu packet stand-ins."""
import ipaddress
import unittest
from b5_3_harness import (CFG, DataPlane, Ether, IP6, ICMP, ND, Echo, FRAMES,
                          LAN_IP, LAN_MAC, TRANSIT_IP, TRANSIT_MAC, Pkt,
                          ICMPV6, incoming)


def make_ndp(target=None, src=LAN_IP, mac=LAN_MAC, port=2,
             icmp_type=135, nd_object=True):
    target = target or CFG.LAN_GATEWAY
    ether = Ether(src=mac, dst='33:33:ff:00:00:01', ethertype=0x86dd)
    ip6 = IP6(src=src, dst='ff02::1:ff00:1', nxt=58, hop_limit=255)
    data = ND(dst=target) if nd_object else Echo(id_=1, seq=1, data=b'')
    packet = Pkt()
    packet.protocols = [ether, ip6, ICMP(type_=icmp_type, data=data)]
    return packet, ether, ip6, port


class TestLearning(unittest.TestCase):
    def setUp(self): self.dp = DataPlane()

    def test_initial_state(self):
        self.assertIsNone(self.dp.lan_port)
        self.assertEqual(self.dp.lan_hosts, {})
        self.assertIsNone(self.dp.transit_port)
        self.assertEqual(self.dp.transit_neighbors, {})

    def test_learn_transit_first_change(self):
        self.assertTrue(self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC))
        self.assertEqual(self.dp.transit_neighbors[TRANSIT_IP], TRANSIT_MAC)

    def test_learn_transit_same_identity_no_change(self):
        self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        self.assertFalse(self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC))

    def test_learn_transit_changed_mac(self):
        self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        self.assertTrue(self.dp.learn_transit_router(1, TRANSIT_IP, '02:00:00:aa:aa:aa'))

    def test_learn_transit_changed_port(self):
        self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        self.assertTrue(self.dp.learn_transit_router(3, TRANSIT_IP, TRANSIT_MAC))

    def test_learn_transit_changed_ipv6(self):
        self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        self.assertTrue(self.dp.learn_transit_router(1, 'fe80::2', TRANSIT_MAC))

    def test_learn_lan_host(self):
        self.assertTrue(self.dp.learn_lan_host(2, LAN_IP, LAN_MAC))
        self.assertEqual(self.dp.lan_port, 2)
        self.assertEqual(self.dp.lan_hosts[LAN_IP], LAN_MAC)

    def test_learn_second_lan_host(self):
        self.dp.learn_lan_host(2, LAN_IP, LAN_MAC)
        self.assertTrue(self.dp.learn_lan_host(2, '2001:db8:1::101', 'aa:bb:cc:dd:ee:02'))
        self.assertEqual(len(self.dp.lan_hosts), 2)

    def test_learn_host_updated_mac(self):
        self.dp.learn_lan_host(2, LAN_IP, LAN_MAC)
        self.assertTrue(self.dp.learn_lan_host(2, LAN_IP, 'aa:bb:cc:dd:ee:03'))
        self.assertEqual(self.dp.lan_hosts[LAN_IP], 'aa:bb:cc:dd:ee:03')

    def test_reject_non_lan_host(self):
        self.assertFalse(self.dp.learn_lan_host(2, '2001:db8:10::1', LAN_MAC))
        self.assertEqual(self.dp.lan_hosts, {})

    def test_reject_invalid_ipv6_host(self):
        self.assertFalse(self.dp.learn_lan_host(2, 'not-an-ip', LAN_MAC))
        self.assertIsNone(self.dp.lan_port)

    def test_reject_host_on_transit_port(self):
        self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        self.assertFalse(self.dp.learn_lan_host(1, LAN_IP, LAN_MAC))
        self.assertIsNone(self.dp.lan_port)

    def test_reject_host_from_other_lan_port(self):
        self.dp.learn_lan_host(2, LAN_IP, LAN_MAC)
        self.assertFalse(self.dp.learn_lan_host(3, '2001:db8:1::101', LAN_MAC))
        self.assertEqual(len(self.dp.lan_hosts), 1)

    def test_reset_transit_keeps_lan(self):
        self.dp.learn_lan_host(2, LAN_IP, LAN_MAC)
        self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        self.dp.reset_transit()
        self.assertIsNone(self.dp.transit_port)
        self.assertEqual(self.dp.transit_neighbors, {})
        self.assertEqual(self.dp.lan_hosts[LAN_IP], LAN_MAC)

    def test_full_reset(self):
        self.dp.learn_lan_host(2, LAN_IP, LAN_MAC)
        self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        self.dp.reset()
        self.assertEqual(self.dp.lan_hosts, {})
        self.assertEqual(self.dp.transit_neighbors, {})
        self.assertIsNone(self.dp.lan_port)


class TestNDP(unittest.TestCase):
    def setUp(self): self.dp = DataPlane()

    def call(self, **kw):
        args = make_ndp(**kw)
        return self.dp.handle_ndp(*args)

    def test_lan_ns_generates_na_and_learns_host(self):
        frame = self.call()
        self.assertIsInstance(frame, bytes)
        self.assertEqual(self.dp.lan_hosts[LAN_IP], LAN_MAC)
        self.assertEqual(self.dp.lan_port, 2)

    def test_lan_na_ethernet_fields(self):
        frame = self.call()
        eth = FRAMES[frame].get_protocol(Ether)
        self.assertEqual(eth.src, CFG.ROUTER_MAC)
        self.assertEqual(eth.dst, LAN_MAC)
        self.assertEqual(eth.ethertype, 0x86dd)

    def test_lan_na_ipv6_fields(self):
        frame = self.call()
        ipv6 = FRAMES[frame].get_protocol(IP6)
        self.assertEqual(ipv6.src, CFG.LAN_GATEWAY)
        self.assertEqual(ipv6.dst, LAN_IP)
        self.assertEqual(ipv6.hop_limit, 255)
        self.assertEqual(ipv6.nxt, 58)

    def test_lan_na_icmp_fields(self):
        frame = self.call()
        icmp = FRAMES[frame].get_protocol(ICMP)
        self.assertEqual(icmp.type_, 136)
        self.assertEqual(icmp.code, 0)
        self.assertEqual(icmp.data.dst, CFG.LAN_GATEWAY)
        self.assertEqual(icmp.data.res, 0x7)
        self.assertEqual(icmp.data.option.hw_src, CFG.ROUTER_MAC)

    def test_ignore_unknown_ns_target(self):
        self.assertIsNone(self.call(target='2001:db8:1::999'))
        self.assertEqual(self.dp.lan_hosts, {})

    def test_ignore_dad_unspecified_source(self):
        self.assertIsNone(self.call(src='::'))
        self.assertEqual(self.dp.lan_hosts, {})

    def test_reject_ns_from_outside_lan(self):
        self.assertIsNone(self.call(src='2001:db8:22::7'))
        self.assertEqual(self.dp.lan_hosts, {})

    def test_reject_lan_ns_from_verified_transit(self):
        self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        self.assertIsNone(self.call(port=1))
        self.assertEqual(self.dp.lan_hosts, {})

    def test_reject_lan_ns_other_port(self):
        self.call(port=2)
        self.assertIsNone(self.call(port=3, src='2001:db8:1::101'))

    def test_non_ns_icmp_ignored(self):
        self.assertIsNone(self.call(icmp_type=128))
        self.assertEqual(self.dp.lan_hosts, {})

    def test_wrong_ns_data_ignored(self):
        self.assertIsNone(self.call(nd_object=False))

    def test_absent_icmp_ignored(self):
        pkt = Pkt(); eth=Ether(src=LAN_MAC); ip6=IP6(src=LAN_IP)
        self.assertIsNone(self.dp.handle_ndp(pkt, eth, ip6, 2))

    def test_transit_ns_without_verified_hello_ignored(self):
        self.assertIsNone(self.call(target=CFG.LINK_LOCAL, port=1, src=TRANSIT_IP, mac=TRANSIT_MAC))

    def test_transit_ns_accepted_from_verified_peer(self):
        self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        frame = self.call(target=CFG.LINK_LOCAL, port=1, src=TRANSIT_IP, mac=TRANSIT_MAC)
        self.assertIsInstance(frame, bytes)
        self.assertEqual(FRAMES[frame].get_protocol(IP6).src, CFG.LINK_LOCAL)

    def test_transit_ns_reject_wrong_port(self):
        self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        self.assertIsNone(self.call(target=CFG.LINK_LOCAL, port=2, src=TRANSIT_IP, mac=TRANSIT_MAC))

    def test_transit_ns_reject_wrong_source(self):
        self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        self.assertIsNone(self.call(target=CFG.LINK_LOCAL, port=1, src='fe80::123', mac=TRANSIT_MAC))

    def test_transit_ns_reject_wrong_mac(self):
        self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        self.assertIsNone(self.call(target=CFG.LINK_LOCAL, port=1, src=TRANSIT_IP, mac=LAN_MAC))

    def test_transit_ns_after_reset_ignored(self):
        self.dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        self.dp.reset_transit()
        self.assertIsNone(self.call(target=CFG.LINK_LOCAL, port=1, src=TRANSIT_IP, mac=TRANSIT_MAC))


class TestEcho(unittest.TestCase):
    def setUp(self): self.dp = DataPlane()

    def call(self, **kw):
        src=kw.get('src', LAN_IP); dst=kw.get('dst', CFG.LAN_GATEWAY)
        port=kw.get('port', 2); typ=kw.get('type_',128)
        data=kw.get('data', Echo(id_=7, seq=4, data=b'abc'))
        eth=Ether(src=LAN_MAC, dst=CFG.ROUTER_MAC)
        ip6=IP6(src=src, dst=dst, nxt=58)
        packet=Pkt();packet.protocols=[eth,ip6,ICMP(type_=typ,data=data)]
        return self.dp.handle_echo_request(packet,eth,ip6,port)

    def test_gateway_echo_reply(self):
        self.assertIsInstance(self.call(), bytes)
        self.assertEqual(self.dp.lan_hosts[LAN_IP],LAN_MAC)

    def test_gateway_reply_identifiers(self):
        icmp=FRAMES[self.call()].get_protocol(ICMP)
        self.assertEqual(icmp.type_,129)
        self.assertEqual((icmp.data.id,icmp.data.seq,icmp.data.data),(7,4,b'abc'))

    def test_gateway_reply_addresses(self):
        ip6=FRAMES[self.call()].get_protocol(IP6)
        self.assertEqual((ip6.src,ip6.dst,ip6.hop_limit),(CFG.LAN_GATEWAY, LAN_IP,64))

    def test_reject_non_gateway_destination(self):
        self.assertIsNone(self.call(dst='2001:db8:1::55'))

    def test_reject_non_echo_request(self):
        self.assertIsNone(self.call(type_=129))

    def test_reject_invalid_echo_body(self):
        self.assertIsNone(self.call(data=ND(dst=CFG.LAN_GATEWAY)))

    def test_reject_outside_lan_source(self):
        self.assertIsNone(self.call(src='2001:db8:23::3'))

    def test_reject_echo_on_transit_port(self):
        self.dp.learn_transit_router(1, TRANSIT_IP,TRANSIT_MAC)
        self.assertIsNone(self.call(port=1))

    def test_reject_echo_on_other_lan_port(self):
        self.call(port=2)
        self.assertIsNone(self.call(port=3))

    def test_no_icmp(self):
        eth=Ether(src=LAN_MAC); ip6=IP6(src=LAN_IP, dst=CFG.LAN_GATEWAY)
        self.assertIsNone(self.dp.handle_echo_request(Pkt(),eth,ip6,2))


if __name__=='__main__': unittest.main()
