"""B5.3 — actual controller method bodies with isolated OF1.3/switch stand-ins."""
import unittest
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch
from b5_3_harness import (Controller, CFG, LAN_IP, LAN_MAC, TRANSIT_IP, TRANSIT_MAC,
                          ROUTE, OFP, flowmods, make_controller, packet_in, ns,
                          FRAMES, Ether, IP6, ICMP, ND, Echo, incoming)


def route(prefix='2001:db8:23::', length=64, nexthop='1.1.1.1', source='ospf', interface='transit'):
    return dict(prefix=prefix, prefix_length=length, next_hop=nexthop,
                source=source, interface=interface)


class TestFlowPreconditions(unittest.TestCase):
    def test_not_connected(self):
        ctl=make_controller();ctl.datapath=None
        self.assertFalse(ctl.try_install_ipv6_host_flows())

    def test_no_lan_port(self):
        ctl=make_controller();ctl.data_plane.lan_port=None
        self.assertFalse(ctl.try_install_ipv6_host_flows())
        self.assertEqual(ctl.datapath.sent,[])

    def test_no_lan_hosts(self):
        ctl=make_controller();ctl.data_plane.lan_hosts.clear()
        self.assertFalse(ctl.try_install_ipv6_host_flows())

    def test_no_transit_port(self):
        ctl=make_controller();ctl.data_plane.transit_port=None
        self.assertFalse(ctl.try_install_ipv6_host_flows())

    def test_no_transit_mac(self):
        ctl=make_controller();ctl.data_plane.transit_router_mac=None
        self.assertFalse(ctl.try_install_ipv6_host_flows())

    def test_ready_installs(self):
        ctl=make_controller()
        self.assertTrue(ctl.try_install_ipv6_host_flows())
        self.assertEqual(len(flowmods(ctl.datapath)),3)

    def test_idempotent_install(self):
        ctl=make_controller();ctl.try_install_ipv6_host_flows();ctl.datapath.sent.clear()
        self.assertFalse(ctl.try_install_ipv6_host_flows())
        self.assertEqual(ctl.datapath.sent,[])

    def test_multiple_hosts(self):
        ctl=make_controller();ctl.data_plane.learn_lan_host(2,'2001:db8:1::101','02:00:00:00:01:01')
        self.assertTrue(ctl.try_install_ipv6_host_flows())
        self.assertEqual(len(flowmods(ctl.datapath)),6)


class TestFlowDetails(unittest.TestCase):
    def setUp(self):
        self.ctl=make_controller()
        self.assertTrue(self.ctl.try_install_ipv6_host_flows())
        self.flows=flowmods(self.ctl.datapath)

    def test_gateway_flow_priority_200(self):
        f=next(f for f in self.flows if f.priority==200)
        self.assertEqual(f.match.ipv6_dst,CFG.LAN_GATEWAY)
        self.assertEqual(f.match.in_port,2)
        self.assertEqual(f.instructions[0].args[1][0].args[0],OFP.OFPP_CONTROLLER)

    def test_route_flow_priority_110(self):
        f=next(f for f in self.flows if f.priority==110)
        self.assertEqual(f.match.in_port,2)
        self.assertEqual(f.match.ipv6_src,LAN_IP)
        self.assertEqual(f.match.ipv6_dst,('2001:db8:23::','ffff:ffff:ffff:ffff::'))

    def test_route_flow_actions(self):
        f=next(f for f in self.flows if f.priority==110)
        actions=f.instructions[0].args[1]
        self.assertEqual([a.kind for a in actions],['dec_ttl','set_field','set_field','output'])
        self.assertEqual(actions[1].eth_src, CFG.ROUTER_MAC)
        self.assertEqual(actions[2].eth_dst, TRANSIT_MAC)
        self.assertEqual(actions[3].args[0],1)

    def test_reverse_flow_priority_100(self):
        f=next(f for f in self.flows if f.priority==100)
        self.assertEqual(f.match.in_port,1)
        self.assertEqual(f.match.ipv6_dst,LAN_IP)
        self.assertEqual(f.instructions[0].args[1][-1].args[0],2)

    def test_reverse_flow_destination_mac(self):
        f=next(f for f in self.flows if f.priority==100)
        actions=f.instructions[0].args[1]
        self.assertEqual(actions[2].eth_dst, LAN_MAC)

    def test_state_signature_recorded(self):
        signature=self.ctl.installed_ipv6_host_flows[LAN_IP]
        self.assertEqual(signature[:4],(LAN_MAC,2,TRANSIT_MAC,1))
        self.assertEqual(signature[4],(('2001:db8:23::',64,'1.1.1.1'),))

    def test_unrelated_connected_routes_not_installed(self):
        self.ctl.ipv6_routing_table['c'] = route(prefix='2001:db8:31::',source='connected')
        self.ctl.ipv6_routing_table['x'] = route(prefix='2001:db8:12::',interface='lan')
        self.ctl.datapath.sent.clear()
        self.assertFalse(self.ctl.try_install_ipv6_host_flows())
        self.assertFalse(self.ctl.datapath.sent)

    def test_changed_host_mac_reinstalls(self):
        self.ctl.datapath.sent.clear()
        new_mac='aa:bb:cc:dd:ee:01'
        self.assertTrue(self.ctl.install_ipv6_host_flows(LAN_IP,new_mac))
        reverse=next(f for f in flowmods(self.ctl.datapath) if f.priority==100)
        self.assertEqual(reverse.instructions[0].args[1][2].eth_dst,new_mac)

    def test_changed_transit_mac_reinstalls(self):
        self.ctl.datapath.sent.clear()
        self.ctl.data_plane.transit_router_mac='aa:bb:cc:dd:ee:02'
        self.assertTrue(self.ctl.try_install_ipv6_host_flows())
        f=next(f for f in flowmods(self.ctl.datapath) if f.priority==110)
        self.assertEqual(f.instructions[0].args[1][2].eth_dst,'aa:bb:cc:dd:ee:02')

    def test_changed_route_next_hop_triggers_reinstall(self):
        self.ctl.datapath.sent.clear()
        self.ctl.ipv6_routing_table[(ROUTE['prefix'],64)]['next_hop']='3.3.3.3'
        self.assertTrue(self.ctl.try_install_ipv6_host_flows())
        self.assertEqual(len(flowmods(self.ctl.datapath,OFP.OFPFC_DELETE_STRICT)),1)

    def test_withdraw_route_deletes_old_flow(self):
        self.ctl.datapath.sent.clear()
        self.ctl.ipv6_routing_table.clear()
        self.assertTrue(self.ctl.try_install_ipv6_host_flows())
        removed=flowmods(self.ctl.datapath,OFP.OFPFC_DELETE_STRICT)
        self.assertEqual(len(removed),1)
        self.assertEqual(removed[0].priority,110)
        self.assertEqual(removed[0].match.ipv6_dst,('2001:db8:23::','ffff:ffff:ffff:ffff::'))

    def test_removal_when_no_datapath_safe(self):
        self.ctl.datapath=None
        self.assertIsNone(self.ctl.delete_ipv6_route_flow(LAN_IP,'2001:db8:23::',64,2))
        self.assertIsNone(self.ctl.delete_ipv6_reverse_flow(LAN_IP,1))

    def test_reverse_delete_correct_port(self):
        self.ctl.datapath.sent.clear()
        self.ctl.delete_ipv6_reverse_flow(LAN_IP,1)
        f=flowmods(self.ctl.datapath)[0]
        self.assertEqual(f.command,OFP.OFPFC_DELETE_STRICT)
        self.assertEqual(f.priority,100)
        self.assertEqual(f.match.in_port,1)

    def test_reverse_delete_none_port_does_nothing(self):
        self.ctl.datapath.sent.clear()
        self.ctl.delete_ipv6_reverse_flow(LAN_IP,None)
        self.assertFalse(self.ctl.datapath.sent)

    def test_route_added_generates_second_route_flow(self):
        self.ctl.datapath.sent.clear()
        self.ctl.ipv6_routing_table[('2001:db8:12::',64)]=route('2001:db8:12::')
        self.assertTrue(self.ctl.try_install_ipv6_host_flows())
        self.assertEqual(len([f for f in flowmods(self.ctl.datapath) if f.priority==110]),2)


class TestPacketInAndBarrier(unittest.TestCase):
    def test_send_frame_when_disconnected(self):
        ctl=make_controller();ctl.datapath=None
        self.assertFalse(ctl.send_frame(b'abc',2))

    def test_send_frame_packet_out(self):
        ctl=make_controller()
        self.assertTrue(ctl.send_frame(b'abc',2))
        msg=ctl.datapath.sent[0]
        self.assertEqual(msg.kind,'packet_out')
        self.assertEqual(msg.data,b'abc')
        self.assertEqual(msg.actions[0].args[0],2)

    def test_ns_install_waits_for_barrier(self):
        ctl=make_controller(ready=False)
        ctl.data_plane.learn_transit_router(1,TRANSIT_IP,TRANSIT_MAC)
        frame=ns(src=LAN_IP,dst='ff02::1:ff00:1',data=ICMP(type_=135,data=ND(dst=CFG.LAN_GATEWAY)))
        packet_in(ctl,frame,2)
        self.assertEqual(len(flowmods(ctl.datapath)),3)
        self.assertEqual([x.kind for x in ctl.datapath.sent].count('barrier'),1)
        self.assertEqual([x.kind for x in ctl.datapath.sent].count('packet_out'),0)
        self.assertEqual(len(ctl.pending_ndp_barriers),1)

    def test_ns_barrier_reply_sends_na(self):
        ctl=make_controller(ready=False)
        ctl.data_plane.learn_transit_router(1,TRANSIT_IP,TRANSIT_MAC)
        frame=ns(src=LAN_IP,dst='ff02::1:ff00:1',data=ICMP(type_=135,data=ND(dst=CFG.LAN_GATEWAY)))
        packet_in(ctl,frame,2)
        xid=next(iter(ctl.pending_ndp_barriers))
        ctl.barrier_reply_handler(NS(msg=NS(xid=xid)))
        self.assertFalse(ctl.pending_ndp_barriers)
        self.assertEqual(ctl.datapath.sent[-1].kind,'packet_out')

    def test_unknown_barrier_ignored(self):
        ctl=make_controller()
        ctl.barrier_reply_handler(NS(msg=NS(xid=1234)))
        self.assertFalse(ctl.datapath.sent)

    def test_ns_without_route_still_acks(self):
        ctl=make_controller(ready=False,route=False)
        frame=ns(src=LAN_IP,dst='ff02::1:ff00:1',data=ICMP(type_=135,data=ND(dst=CFG.LAN_GATEWAY)))
        packet_in(ctl,frame,2)
        # No learned transit port: no flow install, NA sent immediately.
        self.assertEqual([x.kind for x in ctl.datapath.sent],['packet_out'])

    def test_echo_to_gateway_sends_reply(self):
        ctl=make_controller(ready=False,route=False)
        frame=ns(src=LAN_IP,dst=CFG.LAN_GATEWAY,data=ICMP(type_=128,data=Echo(id_=5,seq=8,data=b'hi')))
        packet_in(ctl,frame,2)
        self.assertEqual(ctl.datapath.sent[-1].kind,'packet_out')
        self.assertFalse(ctl.pending_ndp_barriers)

    def test_icmp_first_packet_matching_route_forwarded(self):
        ctl=make_controller(ready=False)
        ctl.data_plane.learn_transit_router(1,TRANSIT_IP,TRANSIT_MAC)
        frame=ns(src=LAN_IP,dst='2001:db8:23::3',proto=58,
                 data=ICMP(type_=128,data=Echo(id_=9,seq=1,data=b'abc')))
        packet_in(ctl,frame,2)
        msgs=[x for x in ctl.datapath.sent if x.kind=='packet_out']
        self.assertEqual(len(msgs),1)
        self.assertEqual(msgs[0].actions[-1].args[0],1)
        self.assertEqual(msgs[0].data,frame)

    def test_no_forward_without_route(self):
        ctl=make_controller(ready=False,route=False)
        ctl.data_plane.learn_transit_router(1,TRANSIT_IP,TRANSIT_MAC)
        frame=ns(src=LAN_IP,dst='2001:db8:99::1',proto=58,
                 data=ICMP(type_=128,data=Echo(id_=2,seq=2,data=b'')))
        packet_in(ctl,frame,2)
        self.assertFalse([x for x in ctl.datapath.sent if x.kind=='packet_out'])

    def test_no_forward_without_transit_mac(self):
        ctl=make_controller(ready=False)
        frame=ns(src=LAN_IP,dst='2001:db8:23::3',proto=58,
                 data=ICMP(type_=128,data=Echo(id_=2,seq=2,data=b'')))
        packet_in(ctl,frame,2)
        self.assertFalse([x for x in ctl.datapath.sent if x.kind=='packet_out'])

    def test_ipv6_tcp_first_packet_does_not_process_currently(self):
        """Characterization (not endorsement): documents observed ICMP-only path."""
        ctl=make_controller(ready=False)
        ctl.data_plane.learn_transit_router(1,TRANSIT_IP,TRANSIT_MAC)
        frame=ns(src=LAN_IP,dst='2001:db8:23::3',proto=6)
        packet_in(ctl,frame,2)
        self.assertFalse([x for x in ctl.datapath.sent if x.kind=='packet_out'])
        self.assertNotIn(LAN_IP,ctl.data_plane.lan_hosts)

    def test_ipv6_udp_first_packet_does_not_process_currently(self):
        ctl=make_controller(ready=False)
        ctl.data_plane.learn_transit_router(1,TRANSIT_IP,TRANSIT_MAC)
        frame=ns(src=LAN_IP,dst='2001:db8:23::3',proto=17)
        packet_in(ctl,frame,2)
        self.assertFalse([x for x in ctl.datapath.sent if x.kind=='packet_out'])
        self.assertNotIn(LAN_IP,ctl.data_plane.lan_hosts)

    def test_ospf_packet_not_handled_by_lan_data_path(self):
        ctl=make_controller(ready=False)
        frame=ns(src=LAN_IP,dst='2001:db8:23::3',proto=89)
        # no next payload - OSPF processing returns without modifying LAN state.
        packet_in(ctl,frame,2)
        self.assertEqual(ctl.data_plane.lan_hosts,{})




class StopAfterOneIteration(Exception): pass

class TestLifecycleAndFailure(unittest.TestCase):
    def test_switch_features_resets_state_and_installs_table_miss(self):
        ctl=make_controller()
        ctl.installed_ipv6_host_flows[LAN_IP]=('stale',)
        ctl.pending_ndp_barriers[42]={'frame':b'old'}
        ctl.local_lsa_ack_pending={'x':{'ls_sequence':1}}
        ctl.local_lsu_sent=True
        ctl.local_lsu_last_tx=10
        ctl.neighbor=NS(reset=MagicMock())
        ctl.lsdb=NS(clear_remote=MagicMock(return_value=False))
        ctl.local_lsa=[]
        event=NS(msg=NS(datapath=ctl.datapath))
        ctl.switch_features_handler(event)
        self.assertEqual(ctl.installed_ipv6_host_flows,{})
        self.assertEqual(ctl.pending_ndp_barriers,{})
        self.assertEqual(ctl.local_lsa_ack_pending,{})
        self.assertEqual(ctl.data_plane.lan_hosts,{})
        self.assertIsNone(ctl.data_plane.transit_port)
        self.assertFalse(ctl.local_lsu_sent)
        self.assertTrue(ctl.ospf_resync_required)
        self.assertEqual(len(flowmods(ctl.datapath)),2)
        self.assertEqual(flowmods(ctl.datapath)[0].command,OFP.OFPFC_DELETE)
        self.assertEqual(flowmods(ctl.datapath)[1].priority,0)
        ctl.neighbor.reset.assert_called_once()
        ctl.lsdb.clear_remote.assert_called_once_with(CFG.ROUTER_ID)

    def test_switch_features_route_change_recomputes(self):
        ctl=make_controller()
        ctl.neighbor=NS(reset=MagicMock())
        ctl.lsdb=NS(clear_remote=MagicMock(return_value=True))
        ctl.local_lsa=[]
        ctl.recompute_routing_state=MagicMock()
        ctl.switch_features_handler(NS(msg=NS(datapath=ctl.datapath)))
        ctl.recompute_routing_state.assert_called_once()

    def test_dead_neighbor_withdraws_reverse_flows_and_transit(self):
        ctl=make_controller()
        ctl.neighbor=NS(router_id='1.1.1.1',port=1,
                        dead_interval_expired=lambda _:True,
                        reset_adjacency=MagicMock())
        ctl.lsdb=NS(clear_remote=MagicMock(return_value=True))
        ctl.recompute_routing_state=MagicMock()
        ctl.local_lsa_ack_pending={'x':{'ls_sequence':1}}
        ctl.local_lsu_last_tx=9
        ctl.local_lsu_sent=True
        def sleep(_): raise StopAfterOneIteration()
        with patch.dict(Controller.neighbor_dead_loop.__globals__,{'hub':NS(sleep=sleep)}):
            with self.assertRaises(StopAfterOneIteration):
                ctl.neighbor_dead_loop()
        self.assertFalse(ctl.local_lsa_ack_pending)
        self.assertIsNone(ctl.local_lsu_last_tx)
        self.assertFalse(ctl.local_lsu_sent)
        self.assertIsNone(ctl.data_plane.transit_port)
        self.assertEqual(ctl.data_plane.lan_hosts[LAN_IP],LAN_MAC)
        ctl.lsdb.clear_remote.assert_called_once_with(CFG.ROUTER_ID)
        ctl.recompute_routing_state.assert_called_once()
        ctl.neighbor.reset_adjacency.assert_called_once()
        self.assertEqual(len(flowmods(ctl.datapath,OFP.OFPFC_DELETE_STRICT)),1)
        self.assertEqual(flowmods(ctl.datapath,OFP.OFPFC_DELETE_STRICT)[0].priority,100)

    def test_no_dead_neighbor_no_withdrawal(self):
        ctl=make_controller()
        ctl.neighbor=NS(router_id='1.1.1.1',port=1,
                        dead_interval_expired=lambda _:False,
                        reset_adjacency=MagicMock())
        ctl.lsdb=NS(clear_remote=MagicMock(return_value=True))
        def sleep(_): raise StopAfterOneIteration()
        with patch.dict(Controller.neighbor_dead_loop.__globals__,{'hub':NS(sleep=sleep)}):
            with self.assertRaises(StopAfterOneIteration):
                ctl.neighbor_dead_loop()
        ctl.lsdb.clear_remote.assert_not_called()
        ctl.neighbor.reset_adjacency.assert_not_called()
        self.assertEqual(ctl.data_plane.transit_port,1)

if __name__=='__main__':unittest.main()
