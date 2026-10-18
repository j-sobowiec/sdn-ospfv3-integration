"""B5.3 findings: expected failures, not production fixes."""
import unittest
from b5_3_harness import (LAN_IP, LAN_MAC, TRANSIT_IP, TRANSIT_MAC,
                          make_controller, packet_in, ns, DataPlane)
from test_dataplane_b5_3 import make_ndp

class TestKnownIssues(unittest.TestCase):
    @unittest.expectedFailure
    def test_tcp_first_packet_should_be_forwarded_when_route_known(self):
        ctl=make_controller(ready=False)
        ctl.data_plane.learn_transit_router(1,TRANSIT_IP,TRANSIT_MAC)
        frame=ns(src=LAN_IP,dst='2001:db8:23::3',proto=6)
        packet_in(ctl,frame,2)
        self.assertTrue(any(m.kind=='packet_out' for m in ctl.datapath.sent),
                        'Expected PacketOut for first TCP packet; not sent')

    @unittest.expectedFailure
    def test_udp_first_packet_should_be_forwarded_when_route_known(self):
        ctl=make_controller(ready=False)
        ctl.data_plane.learn_transit_router(1,TRANSIT_IP,TRANSIT_MAC)
        frame=ns(src=LAN_IP,dst='2001:db8:23::3',proto=17)
        packet_in(ctl,frame,2)
        self.assertTrue(any(m.kind=='packet_out' for m in ctl.datapath.sent),
                        'Expected PacketOut for first UDP packet; not sent')

    @unittest.expectedFailure
    def test_ndp_hop_limit_must_be_255(self):
        dp=DataPlane()
        pkt,eth,ip6,port=make_ndp()
        ip6.hop_limit=64
        self.assertIsNone(dp.handle_ndp(pkt,eth,ip6,port),
                          'RFC 4861 7.1.1: NS hop-limit !=255 must be discarded')

    @unittest.expectedFailure
    def test_ndp_icmp_code_must_be_zero(self):
        dp=DataPlane()
        pkt,eth,ip6,port=make_ndp()
        pkt.get_protocol(type(pkt.protocols[-1])).code=1
        self.assertIsNone(dp.handle_ndp(pkt,eth,ip6,port),
                          'RFC 4861 7.1.1: NS ICMPv6 Code !=0 must be discarded')

if __name__=='__main__':unittest.main()
