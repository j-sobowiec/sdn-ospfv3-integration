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

OSPF_ROUTER_ID = "10.10.10.10"
OSPF_AREA_ID = "0.0.0.0"

OSPF_INSTANCE_ID = 0
OSPF_INTERFACE_ID = 1

OSPF_HELLO_INTERVAL = 10
OSPF_DEAD_INTERVAL = 40

OSPF_ROUTER_PRIORITY = 1
OSPF_OPTIONS = 0x000013

SDN_MAC = "02:00:00:00:00:01"
SDN_LINK_LOCAL = "fe80::10"

def build_ospfv3_hello():
    version = 3
    pkt_type = 1
    pkt_len = 36

    router_id = struct.unpack(
        "!I",
        socket.inet_aton(OSPF_ROUTER_ID)
    )[0]

    area_id = struct.unpack(
        "!I",
        socket.inet_aton(OSPF_AREA_ID)
    )[0]

    checksum = 0
    reserved = 0

    ospf_header = struct.pack(
        "!BBHIIHBB",
        version,
        pkt_type,
        pkt_len,
        router_id,
        area_id,
        checksum,
        OSPF_INSTANCE_ID,
        reserved
    )

    options = OSPF_OPTIONS.to_bytes(3, byteorder="big")

    hello_body = struct.pack(
        "!IB3sHHII",
        OSPF_INTERFACE_ID,
        OSPF_ROUTER_PRIORITY,
        options,
        OSPF_HELLO_INTERVAL,
        OSPF_DEAD_INTERVAL,
        0,  # DR
        0   # BDR
    )

    return ospf_header + hello_body

def calculate_ospfv3_checksum(src_ipv6, dst_ipv6, ospf_packet):
    pseudo_header = (
        socket.inet_pton(socket.AF_INET6, src_ipv6) +
        socket.inet_pton(socket.AF_INET6, dst_ipv6) +
        struct.pack("!I3xB", len(ospf_packet), 89)
    )

    data = pseudo_header + ospf_packet

    if len(data) % 2:
        data += b"\x00"

    checksum = 0

    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)

    return (~checksum) & 0xffff

class OSPFv3Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
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
            "Polaczono switch DPID=%016x",
            datapath.id
        )

        hello = build_ospfv3_hello()

        self.logger.info(
            "Zbudowano OSPFv3 Hello: %s bajtow",
            len(hello)
        )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        in_port = msg.match.get("in_port")

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)

        if ipv6_pkt and ipv6_pkt.nxt == 89:
            self.logger.info(
                "\n---------------- OSPFv3 ----------------\n"
                "port=%s \nsrc=%s \ndst=%s",
                in_port,
                ipv6_pkt.src,
                ipv6_pkt.dst
            )
            self.logger.info(
                "Ethernet:\n"
                "  src=%s\n" 
                "  dst=%s",
                eth_pkt.src,
                eth_pkt.dst
            )

            # Ethernet = 14 bajtów
            # IPv6 = 40 bajtów
            ospf_offset = 14 + 40

            ospf_data = msg.data[ospf_offset:]

            if len(ospf_data) >= 16:
                version, pkt_type, pkt_len, router_id, area_id, checksum, instance_id, reserved = \
                    struct.unpack("!BBHIIHBB", ospf_data[:16])

                ospf_for_checksum = bytearray(ospf_data[:pkt_len])

                ospf_for_checksum[12:14] = b"\x00\x00"

                calculated_checksum = calculate_ospfv3_checksum(
                    ipv6_pkt.src,
                    ipv6_pkt.dst,
                    bytes(ospf_for_checksum)
                )   

                self.logger.info(
                    "Checksum:\n"
                    "  received=0x%04x\n"
                    "  calculated=0x%04x\n"
                    "  valid=%s",
                    checksum,
                    calculated_checksum,
                    checksum == calculated_checksum
                )

                self.logger.info(
                    "Header:\n"
                    "  version=%s\n"
                    "  type=%s\n"
                    "  length=%s\n"
                    "  router_id=%s\n"
                    "  area_id=%s \n"
                    "  instance_id=%s",
                    version,
                    pkt_type,
                    pkt_len,
                    socket.inet_ntoa(struct.pack("!I", router_id)),
                    socket.inet_ntoa(struct.pack("!I", area_id)),
                    instance_id
                )

                if version == 3 and pkt_type == 1 and len(ospf_data) >= 36:
                    hello_data = ospf_data[16:36]

                (
                    interface_id,
                    router_priority,
                    options_raw,
                    hello_interval,
                    dead_interval,
                    designated_router,
                    backup_designated_router
                ) = struct.unpack("!IB3sHHII", hello_data)

                options = int.from_bytes(options_raw, byteorder="big")

                self.logger.info(
                    "Hello: \n  interface_id=%s \n  priority=%s \n  options=0x%06x "
                    "\n  hello_interval=%s \n  dead_interval=%s \n  DR=%s \n  BDR=%s",
                    interface_id,
                    router_priority,
                    options,
                    hello_interval,
                    dead_interval,
                    socket.inet_ntoa(struct.pack("!I", designated_router)),
                    socket.inet_ntoa(struct.pack("!I", backup_designated_router))
                )

                neighbors = []

                neighbor_data = ospf_data[36:pkt_len]

                for offset in range(0, len(neighbor_data), 4):
                    if offset + 4 <= len(neighbor_data):
                        neighbor_id = struct.unpack(
                            "!I",
                            neighbor_data[offset:offset + 4]
                        )[0]

                        neighbors.append(
                            socket.inet_ntoa(
                                struct.pack("!I", neighbor_id)
                            )
                        )

                self.logger.info(
                    "  neighbors=%s"
                    "\n----------------------------------------",
                    neighbors if neighbors else "None"
                )