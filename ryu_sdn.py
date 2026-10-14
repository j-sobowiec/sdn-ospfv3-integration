from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ipv6
import struct
import socket
from ryu.lib.packet import ethernet
from ryu.lib import hub
import time
import ipaddress
from dataplane import DataPlane

from ospfv3 import config as cfg
from ospfv3.routing import Routing
from ospfv3.lsdb import LSDB
from ospfv3.local_lsa import LocalLSA
from ospfv3.neighbor import Neighbor
from ospfv3.parser import (
    parse_hello,
    parse_dbd,
    parse_lsr,
    parse_lsu,
    parse_lsack,
)
from ospfv3.lsa import (
    ospfv3_lsa_type_description,
)
from ospfv3.packet import (
    calculate_ospfv3_checksum,
    build_ospfv3_hello_frame,
    build_ospfv3_dbd_frame,
    build_ospfv3_lsr_frame,
    build_ospfv3_lsu_frame,
    build_ospfv3_lsack_frame,
)

class OSPFv3Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(OSPFv3Controller, self).__init__(*args, **kwargs)

        self.datapath = None
        self.data_plane = DataPlane()
        self.installed_ipv6_host_flows = {}
        self.pending_ndp_barriers = {}

        self.neighbor = Neighbor(self.logger)
        self.lsdb = LSDB(self.logger)
        self.routing = Routing(self.lsdb)
        self.ipv6_routing_table = {}
        self.local_lsa = LocalLSA(self.lsdb, self.logger)
        self.local_lsa_ack_pending = {}
        self.local_lsu_sent = False

        self.hello_thread = hub.spawn(self.hello_loop)
        
        self.lsdb_aging_thread = hub.spawn(self.lsdb_aging_loop)

        self.local_lsu_last_tx = None

        self.local_lsa_retransmission_thread = hub.spawn(
            self.local_lsa_retransmission_loop
        )

        self.local_lsa_refresh_thread = hub.spawn(
            self.local_lsa_refresh_loop
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapath = datapath

        self.installed_ipv6_host_flows.clear()
        self.pending_ndp_barriers.clear()

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(flow_mod)

        self.logger.info(
            "[OPENFLOW] switch connected DPID=%016x "
            "table-miss installed",
            datapath.id
        )

    @set_ev_cls(
        ofp_event.EventOFPBarrierReply,
        MAIN_DISPATCHER
    )
    def barrier_reply_handler(self, ev):
        xid = ev.msg.xid

        pending = self.pending_ndp_barriers.pop(
            xid,
            None
        )

        if pending is None:
            return

        frame = pending["frame"]
        out_port = pending["out_port"]
        destination_ipv6 = pending["destination_ipv6"]
        destination_mac = pending["destination_mac"]

        self.logger.info(
            "[DATA][BARRIER OK] xid=%s",
            xid
        )

        if self.send_frame(
            frame,
            out_port
        ):
            self.logger.info(
                "[NDP][NA TX] "
                "to=%s mac=%s port=%s",
                destination_ipv6,
                destination_mac,
                out_port
            )

    def try_install_ipv6_host_flows(self):
        self.logger.info(
            "[DATA][STATE] "
            "lan-port=%s hosts=%s "
            "transit-port=%s transit-mac=%s",
            self.data_plane.lan_port,
            self.data_plane.lan_hosts,
            self.data_plane.transit_port,
            self.data_plane.transit_router_mac
        )

        if self.datapath is None:
            self.logger.info(
                "[DATA][WAIT] datapath not ready"
            )
            return False

        if self.data_plane.lan_port is None:
            self.logger.info(
                "[DATA][WAIT] LAN port not learned"
            )
            return False

        if not self.data_plane.lan_hosts:
            self.logger.info(
                "[DATA][WAIT] no LAN hosts learned"
            )
            return False

        if self.data_plane.transit_port is None:
            self.logger.info(
                "[DATA][WAIT] transit port not learned"
            )
            return False

        if self.data_plane.transit_router_mac is None:
            self.logger.info(
                "[DATA][WAIT] transit router MAC not learned"
            )
            return False

        installed = False

        for host_ipv6, host_mac in (
            self.data_plane.lan_hosts.items()
        ):
            if self.install_ipv6_host_flows(
                host_ipv6,
                host_mac
            ):
                installed = True

        return installed

    def install_ipv6_host_flows(
        self,
        host_ipv6,
        host_mac
    ):
    
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        lan_port = self.data_plane.lan_port
        transit_port = self.data_plane.transit_port
        transit_mac = self.data_plane.transit_router_mac

        state = (
            host_mac,
            lan_port,
            transit_mac,
            transit_port
        )

        if (
            self.installed_ipv6_host_flows.get(host_ipv6)
            == state
        ):
            return False

        #
        # Local logical gateway:
        # packets addressed to 2001:db8:1::1
        # must still go to the controller.
        #
        match = parser.OFPMatch(
            in_port=lan_port,
            eth_type=0x86dd,
            ipv6_dst=cfg.LAN_GATEWAY
        )

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=200,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(flow_mod)

        #
        # LAN -> R1
        #
        match = parser.OFPMatch(
            in_port=lan_port,
            eth_type=0x86dd,
            ipv6_src=host_ipv6,
            eth_dst=cfg.ROUTER_MAC
        )

        actions = [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(
                eth_src=cfg.ROUTER_MAC
            ),
            parser.OFPActionSetField(
                eth_dst=transit_mac
            ),
            parser.OFPActionOutput(
                transit_port
            )
        ]

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(flow_mod)

        #
        # R1 -> LAN host
        #
        match = parser.OFPMatch(
            in_port=transit_port,
            eth_type=0x86dd,
            ipv6_dst=host_ipv6
        )

        actions = [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(
                eth_src=cfg.ROUTER_MAC
            ),
            parser.OFPActionSetField(
                eth_dst=host_mac
            ),
            parser.OFPActionOutput(
                lan_port
            )
        ]

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(flow_mod)

        self.installed_ipv6_host_flows[
            host_ipv6
        ] = state

        self.logger.info(
            "[DATA][FLOW INSTALL] host=%s mac=%s "
            "lan-port=%s transit-port=%s next-hop-mac=%s",
            host_ipv6,
            host_mac,
            lan_port,
            transit_port,
            transit_mac
        )

        return True
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        in_port = msg.match.get("in_port")

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)

        if ipv6_pkt and ipv6_pkt.nxt == 58:
            frame = self.data_plane.handle_ndp(
                pkt,
                eth_pkt,
                ipv6_pkt,
                in_port
            )

            if frame is not None:
                flows_installed = (
                    self.try_install_ipv6_host_flows()
                )

                if flows_installed:
                    datapath = self.datapath
                    parser = datapath.ofproto_parser

                    barrier = parser.OFPBarrierRequest(
                        datapath
                    )

                    datapath.set_xid(barrier)

                    self.pending_ndp_barriers[
                        barrier.xid
                    ] = {
                        "frame": frame,
                        "out_port": in_port,
                        "destination_ipv6": ipv6_pkt.src,
                        "destination_mac": eth_pkt.src
                    }

                    self.logger.info(
                        "[DATA][BARRIER WAIT] xid=%s",
                        barrier.xid
                    )

                    datapath.send_msg(barrier)

                else:
                    if self.send_frame(
                        frame,
                        in_port
                    ):
                        self.logger.info(
                            "[NDP][NA TX] "
                            "to=%s mac=%s port=%s",
                            ipv6_pkt.src,
                            eth_pkt.src,
                            in_port
                        )

                return

            frame = self.data_plane.handle_echo_request(
                pkt,
                eth_pkt,
                ipv6_pkt,
                in_port
            )

            if frame is not None:
                if self.send_frame(
                    frame,
                    in_port
                ):
                    self.logger.info(
                        "[ICMPv6][ECHO REPLY TX] "
                        "to=%s mac=%s port=%s",
                        ipv6_pkt.src,
                        eth_pkt.src,
                        in_port
                    )

                return
                
        if ipv6_pkt and ipv6_pkt.nxt == 89:
            transit_changed = (
                self.data_plane.learn_transit_router(
                    in_port=in_port,
                    ipv6_address=ipv6_pkt.src,
                    mac_address=eth_pkt.src
                )
            )

            if transit_changed:
                self.logger.info(
                    "[DATA][TRANSIT LEARN] "
                    "ipv6=%s mac=%s port=%s",
                    ipv6_pkt.src,
                    eth_pkt.src,
                    in_port
                )

                self.try_install_ipv6_host_flows()
                
            # Ethernet = 14 bajtów
            # IPv6 = 40 bajtów
            ospf_offset = 14 + 40

            ospf_data = msg.data[ospf_offset:]

            if len(ospf_data) >= 16:
                (
                    version,
                    pkt_type,
                    pkt_len,
                    router_id,
                    area_id,
                    checksum,
                    instance_id,
                    reserved
                ) = struct.unpack("!BBHIIHBB", ospf_data[:16])

                if pkt_len < 16 or pkt_len > len(ospf_data):
                    return

                ospf_for_checksum = bytearray(ospf_data[:pkt_len])
                ospf_for_checksum[12:14] = b"\x00\x00"

                calculated_checksum = calculate_ospfv3_checksum(
                    ipv6_pkt.src,
                    ipv6_pkt.dst,
                    bytes(ospf_for_checksum)
                )   

                if checksum != calculated_checksum:
                    self.logger.warning(
                        "[OSPF][WARN] invalid checksum "
                        "received=0x%04x calculated=0x%04x",
                        checksum,
                        calculated_checksum
                    )
                    return

                router_id_text = socket.inet_ntoa(
                    struct.pack("!I", router_id)
                )

                area_id_text = socket.inet_ntoa(
                    struct.pack("!I", area_id)
                )

                if version == 3 and pkt_type == 1 and pkt_len >= 36:

                    self.handle_ospf_hello(
                        in_port,
                        eth_pkt,
                        ipv6_pkt,
                        ospf_data,
                        pkt_len,
                        router_id_text,
                        area_id_text
                    )

                elif version == 3 and pkt_type == 2 and pkt_len >= 28:

                    self.handle_ospf_dbd(
                        in_port,
                        ipv6_pkt,
                        ospf_data,
                        pkt_len,
                        router_id,
                        router_id_text,
                        area_id_text
                    )

                elif version == 3 and pkt_type == 3 and pkt_len >= 28:
                    
                    self.handle_ospf_lsr(
                        in_port,
                        ipv6_pkt,
                        ospf_data,
                        pkt_len,
                        router_id_text,
                        area_id_text
                    )

                elif version == 3 and pkt_type == 4 and pkt_len >= 20:
                    self.handle_ospf_lsu(
                        in_port,
                        ipv6_pkt,
                        ospf_data,
                        pkt_len,
                        router_id_text,
                        area_id_text
                    )

                elif version == 3 and pkt_type == 5 and pkt_len >= 36:
                    self.handle_ospf_lsack(
                        in_port,
                        ipv6_pkt,
                        ospf_data,
                        pkt_len,
                        router_id_text,
                        area_id_text
                    )

    def handle_ospf_hello(
        self,
        in_port,
        eth_pkt,
        ipv6_pkt,
        ospf_data,
        pkt_len,
        router_id_text,
        area_id_text
    ):
        """
        Handles a received OSPFv3 Hello packet.
        """

        try:
            hello = parse_hello(
                ospf_data,
                pkt_len
            )
        except ValueError as exc:
            self.logger.warning(
                "[OSPF][HELLO] %s",
                exc
            )
            return

        interface_id = hello["interface_id"]
        router_priority = hello["router_priority"]
        options = hello["options"]
        hello_interval = hello["hello_interval"]
        dead_interval = hello["dead_interval"]
        neighbors = hello["neighbors"]

        self.neighbor.port = in_port
        self.neighbor.ipv6 = ipv6_pkt.src
        self.neighbor.mac = eth_pkt.src
        self.neighbor.router_id = router_id_text

        if router_id_text not in self.neighbor.router_ids:
            self.neighbor.router_ids.append(
                router_id_text
            )

            self.logger.info(
                "[OSPF][NEIGHBOR] discovered router=%s src=%s",
                router_id_text,
                ipv6_pkt.src
            )

            self.send_ospfv3_hello()

        self.log_hello(
            in_port,
            ipv6_pkt,
            pkt_len,
            router_id_text,
            area_id_text,
            interface_id,
            router_priority,
            options,
            hello_interval,
            dead_interval,
            neighbors
        )

    def handle_ospf_dbd(
        self,
        in_port,
        ipv6_pkt,
        ospf_data,
        pkt_len,
        router_id,
        router_id_text,
        area_id_text
    ):
        """
        Handles a received OSPFv3 Database Description packet.
        """

        try:
            dbd = parse_dbd(
                ospf_data,
                pkt_len
            )
        except ValueError as exc:
            self.logger.warning(
                "[OSPF][DBD] %s",
                exc
            )
            return

        interface_mtu = dbd["interface_mtu"]
        options = dbd["options"]
        i_bit = dbd["i_bit"]
        m_bit = dbd["m_bit"]
        ms_bit = dbd["ms_bit"]
        dd_sequence = dbd["dd_sequence"]
        lsa_headers = dbd["lsa_headers"]

        self.log_dbd(
            in_port,
            ipv6_pkt,
            router_id_text,
            area_id_text,
            interface_mtu,
            options,
            i_bit,
            m_bit,
            ms_bit,
            dd_sequence,
            lsa_headers
        )

        local_router_id = struct.unpack(
            "!I",
            socket.inet_aton(cfg.ROUTER_ID)
        )[0]

        is_initial_dbd = (
            i_bit
            and m_bit
            and ms_bit
            and pkt_len == 28
            and local_router_id > router_id
        )

        if is_initial_dbd:
            if (
                self.neighbor.dbd_negotiated
                or self.neighbor.dbd_exchange_complete
            ):
                self.reset_dbd_state(
                    "neighbor restarted ExStart"
                )

            self.logger.info(
                "[OSPF][DBD] ExStart "
                "local=%s peer=%s role=Master",
                cfg.ROUTER_ID,
                router_id_text
            )

            self.send_initial_dbd()

        elif (
            not self.neighbor.dbd_negotiated
            and not i_bit
            and not ms_bit
            and dd_sequence == self.neighbor.dbd_sequence
            and local_router_id > router_id
        ):
            self.logger.info(
                "[OSPF][DBD] negotiation-complete "
                "role=Master seq=0x%08x",
                dd_sequence
            )

            self.neighbor.dbd_negotiated = True
            self.neighbor.request_list = list(
                lsa_headers
            )

            self.logger.info(
                "[OSPF][DBD] request-list=%d",
                len(self.neighbor.request_list)
            )

            self.neighbor.dbd_sequence = (
                self.neighbor.dbd_sequence + 1
            ) & 0xffffffff

            self.send_exchange_dbd()

        elif (
            self.neighbor.dbd_negotiated
            and not self.neighbor.dbd_exchange_complete
            and not i_bit
            and not m_bit
            and not ms_bit
            and dd_sequence == self.neighbor.dbd_sequence
        ):
            self.neighbor.dbd_exchange_complete = True

            self.logger.info(
                "[OSPF][DBD] exchange-complete "
                "seq=0x%08x pending=%d",
                dd_sequence,
                len(self.neighbor.request_list)
            )

            if (
                self.neighbor.request_list
                and not self.neighbor.lsr_sent
            ):
                self.send_link_state_request()

    def handle_ospf_lsr(
        self,
        in_port,
        ipv6_pkt,
        ospf_data,
        pkt_len,
        router_id_text,
        area_id_text
    ):
        """
        Handles a received OSPFv3 Link State Request packet.
        """

        try:
            requests = parse_lsr(
                ospf_data,
                pkt_len
            )
        except ValueError as exc:
            self.logger.warning(
                "[OSPF][LSR RX] %s",
                exc
            )
            return

        self.logger.info(
            "[OSPF][LSR RX] router=%s src=%s port=%s "
            "area=%s count=%d",
            router_id_text,
            ipv6_pkt.src,
            in_port,
            area_id_text,
            len(requests)
        )

        requested_local_lsas = []
        requested_keys = set()

        for request in requests:
            key = (
                request["ls_type"],
                request["link_state_id"],
                request["advertising_router"]
            )

            local_lsa = self.local_lsa.get(key)
            local_match = local_lsa is not None

            self.logger.info(
                "  -> %s adv=%s lsid=%s local-match=%s",
                ospfv3_lsa_type_description(
                    request["ls_type"]
                ),
                request["advertising_router"],
                request["link_state_id"],
                local_match
            )

            if (
                local_lsa is not None
                and key not in requested_keys
            ):
                requested_local_lsas.append(
                    local_lsa
                )

                requested_keys.add(key)

        if requested_local_lsas:
            self.send_local_lsr_response(
                requested_local_lsas
            )

    def handle_ospf_lsu(
        self,
        in_port,
        ipv6_pkt,
        ospf_data,
        pkt_len,
        router_id_text,
        area_id_text
    ):
        """
        Handles a received OSPFv3 Link State Update packet.
        """

        try:
            lsu_lsa_headers = parse_lsu(
                ospf_data,
                pkt_len
            )
        except ValueError as exc:
            self.logger.warning(
                "[OSPF][LSU] %s",
                exc
            )
            return

        self.log_lsu(
            in_port,
            ipv6_pkt,
            pkt_len,
            router_id_text,
            area_id_text,
            lsu_lsa_headers
        )

        if lsu_lsa_headers:
            self.neighbor.update_request_list(
                lsu_lsa_headers
            )

            routing_changed = self.lsdb.update(
                lsu_lsa_headers
            )

            if routing_changed:
                self.recompute_routing_state()

            if not self.local_lsa:
                self.local_lsa.initialize(self.neighbor.router_id)

            self.send_ls_ack(
                lsu_lsa_headers
            )

            if (
                self.local_lsa
                and self.neighbor.dbd_exchange_complete
                and not self.neighbor.request_list
                and not self.local_lsu_sent
            ):
                if self.send_local_ls_update():
                    self.local_lsu_sent = True

    def handle_ospf_lsack(
        self,
        in_port,
        ipv6_pkt,
        ospf_data,
        pkt_len,
        router_id_text,
        area_id_text
    ):
        """
        Handles a received OSPFv3 Link State Acknowledgment packet.
        """

        try:
            lsa_headers = parse_lsack(
                ospf_data,
                pkt_len
            )
        except ValueError as exc:
            self.logger.warning(
                "[OSPF][LSAck RX] %s",
                exc
            )
            return

        self.logger.info(
            "[OSPF][LSAck RX] router=%s src=%s port=%s "
            "area=%s count=%d",
            router_id_text,
            ipv6_pkt.src,
            in_port,
            area_id_text,
            len(lsa_headers)
        )

        acknowledged_count = 0

        for lsa in lsa_headers:
            key = (
                lsa["ls_type"],
                lsa["link_state_id"],
                lsa["advertising_router"]
            )

            local_lsa = self.local_lsa.get(key)

            matched = (
                local_lsa is not None
                and local_lsa["ls_sequence"] == lsa["ls_sequence"]
                and local_lsa["ls_checksum"] == lsa["ls_checksum"]
            )

            self.logger.info(
                "  -> %s adv=%s lsid=%s "
                "seq=0x%08x checksum=0x%04x local-match=%s",
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["advertising_router"],
                lsa["link_state_id"],
                lsa["ls_sequence"],
                lsa["ls_checksum"],
                matched
            )

            pending_lsa = self.local_lsa_ack_pending.get(
                key
            )

            pending_match = (
                pending_lsa is not None
                and pending_lsa["ls_sequence"]
                == lsa["ls_sequence"]
                and pending_lsa["ls_checksum"]
                == lsa["ls_checksum"]
            )

            if pending_match:
                del self.local_lsa_ack_pending[key]
                acknowledged_count += 1

                self.logger.info(
                    "[OSPF][LSAck] acknowledged %s "
                    "adv=%s lsid=%s pending=%d",
                    ospfv3_lsa_type_description(
                        lsa["ls_type"]
                    ),
                    lsa["advertising_router"],
                    lsa["link_state_id"],
                    len(self.local_lsa_ack_pending)
                )

        if (
            acknowledged_count > 0
            and not self.local_lsa_ack_pending
        ):
            self.local_lsu_last_tx = None

            self.logger.info(
                "[OSPF][LSAck] all local LSAs acknowledged"
            )

    def send_frame(self, frame, out_port):
        """
        Sends a raw Ethernet frame through the specified OpenFlow port.
        """

        if self.datapath is None:
            return False

        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        packet_out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=frame
        )

        datapath.send_msg(packet_out)

        return True

    def send_ospfv3_hello(self):
        if self.neighbor.port is None:
            return

        frame = build_ospfv3_hello_frame(
            self.neighbor.router_ids
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return

        self.logger.info(
            "[OSPF][HELLO TX] port=%s neighbors=%s",
            self.neighbor.port,
            self.neighbor.router_ids
        )

    def hello_loop(self):
        while True:
            if self.datapath is not None and self.neighbor.port is not None:
                self.send_ospfv3_hello()

            hub.sleep(cfg.HELLO_INTERVAL)

    def send_initial_dbd(self):
        if self.neighbor.port is None:
            return

        frame = build_ospfv3_dbd_frame(
            self.neighbor.dbd_sequence,
            flags=0x07
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return

        self.logger.info(
            "[OSPF][DBD TX] initial "
            "seq=0x%08x flags=I,M,MS",
            self.neighbor.dbd_sequence
        )

    def send_exchange_dbd(self):
        if self.neighbor.port is None:
            return

        frame = build_ospfv3_dbd_frame(
            self.neighbor.dbd_sequence,
            flags=0x01
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return

        self.logger.info(
            "[OSPF][DBD TX] exchange "
            "seq=0x%08x flags=MS",
            self.neighbor.dbd_sequence
        )

    def reset_dbd_state(self, reason):
        self.neighbor.reset_exchange()

        self.local_lsa_ack_pending = {}
        self.local_lsu_last_tx = None
        self.local_lsu_sent = False

        self.logger.warning(
            "[OSPF][DBD] state reset reason=%s "
            "new-seq=0x%08x",
            reason,
            self.neighbor.dbd_sequence
        )

    def send_link_state_request(self):
        if self.neighbor.port is None:
            return

        if self.neighbor.ipv6 is None:
            return

        if self.neighbor.mac is None:
            return

        if not self.neighbor.request_list:
            self.logger.info(
                "[OSPF][LSR] no LSAs to request"
            )
            return

        frame = build_ospfv3_lsr_frame(
            self.neighbor.request_list,
            self.neighbor.ipv6,
            self.neighbor.mac
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return

        self.neighbor.lsr_sent = True

        self.logger.info(
            "[OSPF][LSR TX] to=%s count=%d",
            self.neighbor.ipv6,
            len(self.neighbor.request_list)
        )

        for lsa in self.neighbor.request_list:
            self.logger.info(
                "  -> %s adv=%s lsid=%s",
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["advertising_router"],
                lsa["link_state_id"]
            )

    def send_ls_ack(self, lsa_headers):
        if self.neighbor.port is None:
            return

        if self.neighbor.ipv6 is None:
            return

        if self.neighbor.mac is None:
            return

        if not lsa_headers:
            return

        frame = build_ospfv3_lsack_frame(
            lsa_headers,
            self.neighbor.ipv6,
            self.neighbor.mac
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return

        self.logger.info(
            "[OSPF][LSAck TX] to=%s count=%d",
            self.neighbor.ipv6,
            len(lsa_headers)
        )

    def lsdb_aging_loop(self):
        self.logger.info(
            "[OSPF][LSDB] aging loop started"
        )

        while True:
            hub.sleep(5)

            if not self.lsdb:
                continue

            routing_changed = self.lsdb.purge_expired()

            if routing_changed:
                self.logger.info(
                    "[OSPF][ROUTING] LSDB expiration triggered SPF"
                )

                self.recompute_routing_state()

    def recompute_routing_state(self):
        """
        Recalculates SPF and rebuilds the IPv6 routing table
        after a relevant LSDB change.
        """

        new_routes = self.routing.build_ipv6_routing_table()

        if new_routes == self.ipv6_routing_table:
            self.logger.info(
                "[OSPF][ROUTING] recalculated - no route changes"
            )
            return

        self.ipv6_routing_table = new_routes

        self.logger.info(
            "[OSPF][ROUTING] routing table changed"
        )

        self.log_spf_result()
        self.log_ipv6_routing_table()

    def send_local_ls_update(self):
        """
        Sends all locally originated LSAs to the OSPF neighbor
        in a single Link State Update packet.
        """

        if self.neighbor.port is None:
            return False

        if self.neighbor.ipv6 is None:
            return False

        if self.neighbor.mac is None:
            return False

        lsu_body = self.local_lsa.build_update_body()

        if lsu_body is None:
            return False

        frame = build_ospfv3_lsu_frame(
            lsu_body,
            self.neighbor.ipv6,
            self.neighbor.mac
        )

        self.local_lsa_ack_pending = {
            key: {
                "ls_sequence": lsa["ls_sequence"],
                "ls_checksum": lsa["ls_checksum"]
            }
            for key, lsa in self.local_lsa.items()
        }
        
        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            self.local_lsa_ack_pending = {}
            self.local_lsu_last_tx = None
            return False

        self.local_lsu_last_tx = time.monotonic()

        self.logger.info(
            "[OSPF][LSU TX] to=%s lsas=%d "
            "frame-length=%d pending-acks=%d",
            self.neighbor.ipv6,
            len(self.local_lsa),
            len(frame),
            len(self.local_lsa_ack_pending)
        )

        return True

    def send_local_lsr_response(self, local_lsas):
        """
        Sends an LSU containing locally originated LSAs
        requested by the OSPF neighbor.
        """

        if self.neighbor.port is None:
            return False

        if self.neighbor.ipv6 is None:
            return False

        if self.neighbor.mac is None:
            return False

        if not local_lsas:
            return False

        lsu_body = (
            struct.pack(
                "!I",
                len(local_lsas)
            )
            + b"".join(
                lsa["raw_lsa"]
                for lsa in local_lsas
            )
        )

        frame = build_ospfv3_lsu_frame(
            lsu_body,
            self.neighbor.ipv6,
            self.neighbor.mac
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return False

        self.logger.info(
            "[OSPF][LSR RESPONSE TX] to=%s "
            "lsas=%d frame-length=%d",
            self.neighbor.ipv6,
            len(local_lsas),
            len(frame)
        )

        for lsa in local_lsas:
            self.logger.info(
                "  -> %s adv=%s lsid=%s "
                "seq=0x%08x checksum=0x%04x",
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["advertising_router"],
                lsa["link_state_id"],
                lsa["ls_sequence"],
                lsa["ls_checksum"]
            )

        return True

    def send_local_lsa_retransmission(self):
        """
        Retransmits locally originated LSAs that have not yet
        been acknowledged by the OSPF neighbor.
        """

        if self.neighbor.port is None:
            return False

        if self.neighbor.ipv6 is None:
            return False

        if self.neighbor.mac is None:
            return False

        result = self.local_lsa.build_pending_body(self.local_lsa_ack_pending)

        if result is None:
            return False

        lsu_body, lsa_count = result

        frame = build_ospfv3_lsu_frame(
            lsu_body,
            self.neighbor.ipv6,
            self.neighbor.mac
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return False

        self.local_lsu_last_tx = time.monotonic()

        self.logger.info(
            "[OSPF][LSU RETX] to=%s lsas=%d "
            "frame-length=%d pending-acks=%d",
            self.neighbor.ipv6,
            lsa_count,
            len(frame),
            len(self.local_lsa_ack_pending)
        )

        return True

    def local_lsa_retransmission_loop(self):
        """
        Periodically retransmits unacknowledged local LSAs.
        """

        while True:
            hub.sleep(1)

            if not self.local_lsa_ack_pending:
                continue

            if self.local_lsu_last_tx is None:
                continue

            elapsed = (
                time.monotonic()
                - self.local_lsu_last_tx
            )

            if elapsed < cfg.RETRANSMIT_INTERVAL:
                continue

            self.send_local_lsa_retransmission()

    def local_lsa_refresh_loop(self):
        """
        Periodically refreshes locally originated LSAs.

        When the oldest local LSA reaches LSRefreshTime,
        all locally originated LSAs are reoriginated
        with newer sequence numbers.
        """

        while True:
            hub.sleep(1)

            if not self.local_lsa:
                continue

            if not self.neighbor.dbd_exchange_complete:
                continue

            if self.neighbor.request_list:
                continue

            if self.local_lsa_ack_pending:
                continue

            originated_times = [
                lsa.get("_originated_at")
                for lsa in self.local_lsa.values()
                if lsa.get("_originated_at") is not None
            ]

            if not originated_times:
                continue

            oldest_originated_at = min(
                originated_times
            )

            elapsed = (
                time.monotonic()
                - oldest_originated_at
            )

            if elapsed < cfg.LS_REFRESH_TIME:
                continue

            self.logger.info(
                "[OSPF][REFRESH] local LSAs reached "
                "refresh interval elapsed=%.1fs",
                elapsed
            )

            self.reoriginate_local_lsas(
                "periodic refresh"
            )

    def reoriginate_local_lsas(self, reason):
        if self.local_lsa_ack_pending:
            self.logger.warning(
                "[OSPF][REORIGINATE] postponed - "
                "previous local LSAs are still awaiting acknowledgment"
            )
            return False

        if not self.local_lsa.reoriginate(
            self.neighbor.router_id,
            reason
        ):
            return False

        return self.send_local_ls_update()

    def log_hello(
        self,
        in_port,
        ipv6_pkt,
        pkt_len,
        router_id_text,
        area_id_text,
        interface_id,
        priority,
        options,
        hello_interval,
        dead_interval,
        neighbors
    ):
        neighbors_text = ", ".join(neighbors) if neighbors else "-"

        self.logger.info(
            "\n[OSPF][HELLO RX] "
            "router=%s src=%s port=%s area=%s len=%d",
            router_id_text,
            ipv6_pkt.src,
            in_port,
            area_id_text,
            pkt_len
        )

        self.logger.info(
            "  ifid=%s priority=%d "
            "hello=%ds dead=%ds "
            "options=0x%06x neighbors=%s",
            interface_id,
            priority,
            hello_interval,
            dead_interval,
            options,
            neighbors_text
        )

    def log_dbd(
        self,
        in_port,
        ipv6_pkt,
        router_id_text,
        area_id_text,
        interface_mtu,
        options,
        i_bit,
        m_bit,
        ms_bit,
        dd_sequence,
        lsa_headers
    ):
        flags = []

        if i_bit:
            flags.append("I")

        if m_bit:
            flags.append("M")

        if ms_bit:
            flags.append("MS")

        flags_text = ",".join(flags) if flags else "-"

        self.logger.info(
            "\n[OSPF][DBD RX] "
            "router=%s src=%s port=%s area=%s",
            router_id_text,
            ipv6_pkt.src,
            in_port,
            area_id_text
        )

        self.logger.info(
            "  mtu=%d seq=0x%08x "
            "flags=%s options=0x%06x summaries=%d",
            interface_mtu,
            dd_sequence,
            flags_text,
            options,
            len(lsa_headers)
        )

        for lsa in lsa_headers:
            self.logger.info(
                "    -> %s adv=%s lsid=%s seq=0x%08x",
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["advertising_router"],
                lsa["link_state_id"],
                lsa["ls_sequence"]
            )
            
    def log_lsu(
        self,
        in_port,
        ipv6_pkt,
        pkt_len,
        router_id_text,
        area_id_text,
        lsa_headers
    ):
        self.logger.info(
            "\n[OSPF][LSU RX] "
            "router=%s src=%s port=%s area=%s "
            "lsas=%d len=%d",
            router_id_text,
            ipv6_pkt.src,
            in_port,
            area_id_text,
            len(lsa_headers),
            pkt_len
        )

        for index, lsa in enumerate(
            lsa_headers,
            start=1
        ):
            lsa_type = lsa["ls_type"]

            self.logger.info(
                "  #%d %s "
                "adv=%s "
                "lsid=%s "
                "seq=0x%08x "
                "age=%d",
                index,
                ospfv3_lsa_type_description(lsa_type),
                lsa["advertising_router"],
                lsa["link_state_id"],
                lsa["ls_sequence"],
                lsa["ls_age"]
            )

            # Router-LSA
            if lsa_type == 0x2001:
                router_lsa = lsa["router_lsa"]

                self.logger.info(
                    "     links=%d flags=0x%02x options=0x%06x",
                    len(router_lsa["links"]),
                    router_lsa["flags"],
                    router_lsa["options"]
                )

                for link in router_lsa["links"]:
                    self.logger.info(
                        "       -> router=%s "
                        "cost=%d "
                        "if=%s "
                        "neighbor_if=%s",
                        link["neighbor_router_id"],
                        link["metric"],
                        link["interface_id"],
                        link["neighbor_interface_id"]
                    )

            # Link-LSA
            elif lsa_type == 0x0008:
                link_lsa = lsa["link_lsa"]

                self.logger.info(
                    "     link_local=%s "
                    "priority=%d "
                    "prefixes=%d",
                    link_lsa["link_local_address"],
                    link_lsa["router_priority"],
                    link_lsa["number_of_prefixes"]
                )

                for prefix in link_lsa["prefixes"]:
                    self.logger.info(
                        "       -> %s/%d",
                        prefix["prefix"],
                        prefix["prefix_length"]
                    )

            # Intra-Area-Prefix-LSA
            elif lsa_type == 0x2009:
                prefix_lsa = lsa[
                    "intra_area_prefix_lsa"
                ]

                self.logger.info(
                    "     referenced=%s "
                    "router=%s "
                    "prefixes=%d",
                    ospfv3_lsa_type_description(
                        prefix_lsa["referenced_ls_type"]
                    ),
                    prefix_lsa[
                        "referenced_advertising_router"
                    ],
                    prefix_lsa["number_of_prefixes"]
                )

                for prefix in prefix_lsa["prefixes"]:
                    self.logger.info(
                        "       -> %s/%d cost=%d",
                        prefix["prefix"],
                        prefix["prefix_length"],
                        prefix["metric"]
                    )

    def log_spf_result(self):
        distances, previous = self.routing.run_spf()

        self.logger.info(
            "\n[OSPF][SPF] root=%s",
            cfg.ROUTER_ID
        )

        router_ids = [cfg.ROUTER_ID]

        router_ids.extend(
            sorted(
                router_id
                for router_id in distances
                if router_id != cfg.ROUTER_ID
            )
        )

        for router_id in router_ids:
            cost = distances[router_id]
            predecessor = previous[router_id]

            next_hop = self.routing.get_spf_next_hop(
                router_id,
                previous
            )

            self.logger.info(
                "  router=%s cost=%s "
                "predecessor=%s next-hop=%s",
                router_id,
                cost,
                predecessor,
                next_hop
            )

    def log_ipv6_routing_table(self):
        routes = self.ipv6_routing_table

        self.logger.info(
            "\n[OSPF][ROUTES] IPv6 routing table entries=%d",
            len(routes)
        )

        sorted_routes = sorted(
            routes.values(),
            key=lambda route: ipaddress.IPv6Network(
                (
                    route["prefix"],
                    route["prefix_length"]
                ),
                strict=False
            )
        )

        for route in sorted_routes:
            self.logger.info(
                "\n  %s/%d",
                route["prefix"],
                route["prefix_length"]
            )

            if route["source"] == "connected":
                self.logger.info(
                    "      source=connected interface=%s",
                    route["interface"]
                )
                continue

            self.logger.info(
                "      source=ospf cost=%d adv=%s",
                route["total_cost"],
                route["advertising_router"]
            )

            self.logger.info(
                "      next-hop=%s interface=%s",
                route["next_hop"],
                route["interface"]
            )