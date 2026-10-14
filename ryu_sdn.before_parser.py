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

from ospfv3 import config as cfg
from ospfv3.routing import Routing
from ospfv3.lsdb import LSDB
from ospfv3.local_lsa import LocalLSA
from ospfv3.neighbor import Neighbor
from ospfv3.lsa import (
    ospfv3_lsa_type_description,
    parse_ospfv3_router_lsa,
    parse_ospfv3_link_lsa,
    parse_ospfv3_intra_area_prefix_lsa,
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
            "Connected switch DPID=%016x",
            datapath.id
        )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        in_port = msg.match.get("in_port")

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)

        if ipv6_pkt and ipv6_pkt.nxt == 89:
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

        hello_data = ospf_data[16:36]

        (
            interface_id,
            router_priority,
            options_raw,
            hello_interval,
            dead_interval,
            designated_router,
            backup_designated_router
        ) = struct.unpack(
            "!IB3sHHII",
            hello_data
        )

        options = int.from_bytes(
            options_raw,
            byteorder="big"
        )

        neighbors = []

        neighbor_data = ospf_data[36:pkt_len]

        if len(neighbor_data) % 4 != 0:
            self.logger.warning(
                "[OSPF][HELLO] invalid neighbor-list length=%d",
                len(neighbor_data)
            )
            return

        for offset in range(
            0,
            len(neighbor_data),
            4
        ):
            neighbor_id = struct.unpack(
                "!I",
                neighbor_data[offset:offset + 4]
            )[0]

            neighbors.append(
                socket.inet_ntoa(
                    struct.pack(
                        "!I",
                        neighbor_id
                    )
                )
            )

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

        dbd_data = ospf_data[16:28]

        (
            reserved1,
            options_raw,
            interface_mtu,
            reserved2,
            flags,
            dd_sequence
        ) = struct.unpack(
            "!B3sHBBI",
            dbd_data
        )

        options = int.from_bytes(
            options_raw,
            byteorder="big"
        )

        i_bit = bool(flags & 0x04)
        m_bit = bool(flags & 0x02)
        ms_bit = bool(flags & 0x01)

        lsa_headers = []

        lsa_data = ospf_data[28:pkt_len]

        if len(lsa_data) % 20 != 0:
            self.logger.warning(
                "[OSPF][DBD] invalid LSA-summary length=%d",
                len(lsa_data)
            )
            return

        for offset in range(
            0,
            len(lsa_data),
            20
        ):
            (
                ls_age,
                ls_type,
                link_state_id,
                advertising_router,
                ls_sequence,
                ls_checksum,
                ls_length
            ) = struct.unpack(
                "!HHIIIHH",
                lsa_data[offset:offset + 20]
            )

            lsa_headers.append({
                "ls_age": ls_age,
                "ls_type": ls_type,
                "link_state_id": socket.inet_ntoa(
                    struct.pack(
                        "!I",
                        link_state_id
                    )
                ),
                "advertising_router": socket.inet_ntoa(
                    struct.pack(
                        "!I",
                        advertising_router
                    )
                ),
                "ls_sequence": ls_sequence,
                "ls_checksum": ls_checksum,
                "ls_length": ls_length
            })

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

        request_data_length = pkt_len - 16

        if (
            request_data_length <= 0
            or request_data_length % 12 != 0
        ):
            self.logger.warning(
                "[OSPF][LSR RX] invalid payload length=%d",
                request_data_length
            )
            return

        requests = []

        offset = 16

        while offset < pkt_len:
            (
                reserved,
                ls_type,
                link_state_id,
                advertising_router
            ) = struct.unpack(
                "!HHII",
                ospf_data[offset:offset + 12]
            )

            requests.append({
                "ls_type": ls_type,
                "link_state_id": socket.inet_ntoa(
                    struct.pack("!I", link_state_id)
                ),
                "advertising_router": socket.inet_ntoa(
                    struct.pack("!I", advertising_router)
                )
            })

            offset += 12

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

        number_of_lsas = struct.unpack(
            "!I",
            ospf_data[16:20]
        )[0]

        lsu_lsa_headers = []

        # 16 B OSPFv3 header
        #  4 B number of LSAs
        # --------------------
        # 20 B first LSA offset
        offset = 20

        for index in range(number_of_lsas):

            if offset + 20 > pkt_len:
                self.logger.warning(
                    "[OSPF][LSU] insufficient data for LSA header #%d",
                    index + 1
                )
                return

            raw_lsa_header = bytes(
                ospf_data[offset:offset + 20]
            )

            (
                ls_age,
                ls_type,
                link_state_id,
                advertising_router,
                ls_sequence,
                ls_checksum,
                ls_length
            ) = struct.unpack(
                "!HHIIIHH",
                raw_lsa_header
            )

            if ls_length < 20:
                self.logger.warning(
                    "[OSPF][LSU] invalid LSA length #%d: %d",
                    index + 1,
                    ls_length
                )
                return

            if offset + ls_length > pkt_len:
                self.logger.warning(
                    "[OSPF][LSU] LSA #%d exceeds packet boundary "
                    "(offset=%d length=%d packet=%d)",
                    index + 1,
                    offset,
                    ls_length,
                    pkt_len
                )
                return

            raw_lsa = bytes(
                ospf_data[offset:offset + ls_length]
            )

            lsa_header = {
                "ls_age": ls_age,
                "ls_type": ls_type,

                "link_state_id": socket.inet_ntoa(
                    struct.pack(
                        "!I",
                        link_state_id
                    )
                ),

                "advertising_router": socket.inet_ntoa(
                    struct.pack(
                        "!I",
                        advertising_router
                    )
                ),

                "ls_sequence": ls_sequence,
                "ls_checksum": ls_checksum,
                "ls_length": ls_length,

                # Used when generating LSAck.
                "raw_header": raw_lsa_header
            }

            if ls_type == 0x2001:
                try:
                    lsa_header["router_lsa"] = (
                        parse_ospfv3_router_lsa(
                            raw_lsa
                        )
                    )
                except ValueError as exc:
                    self.logger.warning(
                        "[OSPF][LSU] Router-LSA parse error #%d: %s",
                        index + 1,
                        exc
                    )
                    return

            elif ls_type == 0x0008:
                try:
                    lsa_header["link_lsa"] = (
                        parse_ospfv3_link_lsa(
                            raw_lsa
                        )
                    )
                except ValueError as exc:
                    self.logger.warning(
                        "[OSPF][LSU] Link-LSA parse error #%d: %s",
                        index + 1,
                        exc
                    )
                    return

            elif ls_type == 0x2009:
                try:
                    lsa_header["intra_area_prefix_lsa"] = (
                        parse_ospfv3_intra_area_prefix_lsa(
                            raw_lsa
                        )
                    )
                except ValueError as exc:
                    self.logger.warning(
                        "[OSPF][LSU] "
                        "Intra-Area-Prefix-LSA parse error #%d: %s",
                        index + 1,
                        exc
                    )
                    return

            lsu_lsa_headers.append(
                lsa_header
            )

            offset += ls_length

        if offset != pkt_len:
            self.logger.warning(
                "[OSPF][LSU] length mismatch "
                "parsed=%d packet=%d",
                offset,
                pkt_len
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

        ack_data_length = pkt_len - 16

        if ack_data_length <= 0 or ack_data_length % 20 != 0:
            self.logger.warning(
                "[OSPF][LSAck RX] invalid payload length=%d",
                ack_data_length
            )
            return

        lsa_headers = []

        offset = 16

        while offset < pkt_len:
            (
                ls_age,
                ls_type,
                link_state_id,
                advertising_router,
                ls_sequence,
                ls_checksum,
                ls_length
            ) = struct.unpack(
                "!HHIIIHH",
                ospf_data[offset:offset + 20]
            )

            lsa_headers.append({
                "ls_age": ls_age,
                "ls_type": ls_type,
                "link_state_id": socket.inet_ntoa(
                    struct.pack("!I", link_state_id)
                ),
                "advertising_router": socket.inet_ntoa(
                    struct.pack("!I", advertising_router)
                ),
                "ls_sequence": ls_sequence,
                "ls_checksum": ls_checksum,
                "ls_length": ls_length
            })

            offset += 20

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