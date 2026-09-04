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

OSPF_INTERFACE_MTU = 1500

def build_ospfv3_hello(neighbors=()):
    version = 3
    pkt_type = 1
    pkt_len = 36 + 4 * len(neighbors)

    router_id = struct.unpack(
        "!I",
        socket.inet_aton(OSPF_ROUTER_ID)
    )[0]

    area_id = struct.unpack(
        "!I",
        socket.inet_aton(OSPF_AREA_ID)
    )[0]

    # Najpierw budujemy pakiet z checksum = 0
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
    neighbor_data = b""

    for neighbor in neighbors:
        neighbor_data += socket.inet_aton(neighbor)

    ospf_packet = ospf_header + hello_body + neighbor_data

    # Liczymy checksum z uwzględnieniem IPv6 pseudo-header
    checksum = calculate_ospfv3_checksum(
        SDN_LINK_LOCAL,
        "ff02::5",
        ospf_packet
    )

    # Wstawiamy checksum do bajtów 12-13 nagłówka OSPFv3
    ospf_packet = bytearray(ospf_packet)

    ospf_packet[12:14] = struct.pack(
        "!H",
        checksum
    )

    return bytes(ospf_packet)

def build_ospfv3_dbd(dd_sequence, flags=0x07):
    version = 3
    pkt_type = 2
    pkt_len = 28

    router_id = struct.unpack(
        "!I",
        socket.inet_aton(OSPF_ROUTER_ID)
    )[0]

    area_id = struct.unpack(
        "!I",
        socket.inet_aton(OSPF_AREA_ID)
    )[0]

    ospf_header = struct.pack(
        "!BBHIIHBB",
        version,
        pkt_type,
        pkt_len,
        router_id,
        area_id,
        0,                  # checksum najpierw 0
        OSPF_INSTANCE_ID,
        0
    )

    options = OSPF_OPTIONS.to_bytes(3, byteorder="big")

    dbd_body = struct.pack(
        "!B3sHBBI",
        0,                  # reserved
        options,
        OSPF_INTERFACE_MTU,
        0,                  # reserved
        flags,
        dd_sequence
    )

    ospf_packet = ospf_header + dbd_body

    checksum = calculate_ospfv3_checksum(
        SDN_LINK_LOCAL,
        "ff02::5",
        ospf_packet
    )

    ospf_packet = bytearray(ospf_packet)
    ospf_packet[12:14] = struct.pack("!H", checksum)

    return bytes(ospf_packet)

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

def mac_to_bytes(mac):
    return bytes(
        int(part, 16)
        for part in mac.split(":")
    )

def build_ospfv3_hello_frame(neighbors=()):
    ospf_packet = build_ospfv3_hello(neighbors)

    # Ethernet
    eth_dst = mac_to_bytes("33:33:00:00:00:05")
    eth_src = mac_to_bytes(SDN_MAC)

    ethernet_header = struct.pack(
        "!6s6sH",
        eth_dst,
        eth_src,
        0x86DD       # EtherType IPv6
    )

    # IPv6
    version_tc_flow = 6 << 28

    ipv6_header = struct.pack(
        "!IHBB16s16s",
        version_tc_flow,
        len(ospf_packet),  
        89,                 # Next Header = OSPF
        1,                  # Hop Limit
        socket.inet_pton(
            socket.AF_INET6,
            SDN_LINK_LOCAL
        ),
        socket.inet_pton(
            socket.AF_INET6,
            "ff02::5"
        )
    )

    return ethernet_header + ipv6_header + ospf_packet

def build_ospfv3_dbd_frame(dd_sequence, flags=0x07):
    ospf_packet = build_ospfv3_dbd(
        dd_sequence,
        flags
    )

    ethernet_header = struct.pack(
        "!6s6sH",
        mac_to_bytes("33:33:00:00:00:05"),
        mac_to_bytes(SDN_MAC),
        0x86DD
    )

    ipv6_header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(ospf_packet),
        89,
        1,
        socket.inet_pton(
            socket.AF_INET6,
            SDN_LINK_LOCAL
        ),
        socket.inet_pton(
            socket.AF_INET6,
            "ff02::5"
        )
    )

    return ethernet_header + ipv6_header + ospf_packet

class OSPFv3Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(OSPFv3Controller, self).__init__(*args, **kwargs)

        self.datapath = None
        self.ospf_port = None
        self.ospf_neighbors = []

        self.dbd_sequence = int(
            time.time() * 1000
        ) & 0xffffffff

        self.dbd_negotiated = False
        self.lsa_request_list = []

        self.hello_thread = hub.spawn(self.hello_loop)

    def send_ospfv3_hello(self):
        if self.datapath is None or self.ospf_port is None:
            return

        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        frame = build_ospfv3_hello_frame(
            self.ospf_neighbors
        )

        actions = [
            parser.OFPActionOutput(self.ospf_port)
        ]

        packet_out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=frame
        )

        datapath.send_msg(packet_out)

        self.logger.info(
            "Wyslano Hello: port=%s neighbors=%s",
            self.ospf_port,
            self.ospf_neighbors
        )

    def hello_loop(self):
        while True:
            if self.datapath is not None and self.ospf_port is not None:
                self.send_ospfv3_hello()

            hub.sleep(OSPF_HELLO_INTERVAL)

    def send_initial_dbd(self):
        if self.datapath is None or self.ospf_port is None:
            return

        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        frame = build_ospfv3_dbd_frame(
            self.dbd_sequence,
            flags=0x07
        )

        actions = [
            parser.OFPActionOutput(
                self.ospf_port
            )
        ]

        packet_out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=frame
        )

        datapath.send_msg(packet_out)

        self.logger.info(
            "Wyslano initial DBD: "
            "I=1 M=1 MS=1 seq=0x%08x",
            self.dbd_sequence
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
            "Polaczono switch DPID=%016x",
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

                    if checksum == calculated_checksum:
                        neighbor_router_id = socket.inet_ntoa(
                            struct.pack("!I", router_id)
                        )

                        self.ospf_port = in_port

                        if neighbor_router_id not in self.ospf_neighbors:

                            self.ospf_neighbors.append(
                                neighbor_router_id
                            )

                            self.logger.info(
                                "Dodano sasiada OSPFv3: %s",
                                neighbor_router_id
                            )

                            self.send_ospfv3_hello()

                        self.logger.info(
                            "\n"
                            "---------------- OSPFv3 HELLO ----------------\n"
                            "port=%s\n"
                            "src=%s\n"
                            "dst=%s\n"
                            "Ethernet:\n"
                            "  src=%s\n"
                            "  dst=%s\n"
                            "Checksum:\n"
                            "  received=0x%04x\n"
                            "  calculated=0x%04x\n"
                            "  valid=%s\n"
                            "Header:\n"
                            "  version=%s\n"
                            "  type=%s\n"
                            "  length=%s\n"
                            "  router_id=%s\n"
                            "  area_id=%s\n"
                            "  instance_id=%s\n"
                            "Hello:\n"
                            "  interface_id=%s\n"
                            "  priority=%s\n"
                            "  options=0x%06x\n"
                            "  hello_interval=%s\n"
                            "  dead_interval=%s\n"
                            "  neighbors=%s\n"
                            "---------------------------------------------",
                            in_port,
                            ipv6_pkt.src,
                            ipv6_pkt.dst,
                            eth_pkt.src,
                            eth_pkt.dst,
                            checksum,
                            calculated_checksum,
                            checksum == calculated_checksum,
                            version,
                            pkt_type,
                            pkt_len,
                            socket.inet_ntoa(
                                struct.pack("!I", router_id)
                            ),
                            socket.inet_ntoa(
                                struct.pack("!I", area_id)
                            ),
                            instance_id,
                            interface_id,
                            router_priority,
                            options,
                            hello_interval,
                            dead_interval,
                            neighbors if neighbors else "brak"
                        )

                elif version == 3 and pkt_type == 2 and pkt_len >= 28:
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

                    for offset in range(0, len(lsa_data), 20):
                        if offset + 20 > len(lsa_data):
                            break

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

                        lsa_header = {
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
                        }

                        lsa_headers.append(lsa_header)

                    self.logger.info(
                        "\n"
                        "---------------- OSPFv3 DBD ----------------\n"
                        "port=%s\n"
                        "src=%s\n"
                        "dst=%s\n"
                        "Ethernet:\n"
                        "  src=%s\n"
                        "  dst=%s\n"
                        "Checksum:\n"
                        "  received=0x%04x\n"
                        "  calculated=0x%04x\n"
                        "  valid=%s\n"
                        "Header:\n"
                        "  version=%s\n"
                        "  type=%s\n"
                        "  length=%s\n"
                        "  router_id=%s\n"
                        "  area_id=%s\n"
                        "  instance_id=%s\n"
                        "DBD:\n"
                        "  interface_mtu=%s\n"
                        "  options=0x%06x\n"
                        "  flags=0x%02x\n"
                        "  I=%s\n"
                        "  M=%s\n"
                        "  MS=%s\n"
                        "  dd_sequence=0x%08x\n"
                        "---------------------------------------------",
                        in_port,
                        ipv6_pkt.src,
                        ipv6_pkt.dst,
                        eth_pkt.src,
                        eth_pkt.dst,
                        checksum,
                        calculated_checksum,
                        checksum == calculated_checksum,
                        version,
                        pkt_type,
                        pkt_len,
                        socket.inet_ntoa(
                            struct.pack("!I", router_id)
                        ),
                        socket.inet_ntoa(
                            struct.pack("!I", area_id)
                        ),
                        instance_id,
                        interface_mtu,
                        options,
                        flags,
                        i_bit,
                        m_bit,
                        ms_bit,
                        dd_sequence
                    )

                    if lsa_headers:
                        self.logger.info(
                            "LSA headers w DBD: %s",
                            len(lsa_headers)
                        )

                        for index, lsa in enumerate(lsa_headers, start=1):
                            self.logger.info(
                                "  LSA #%s: "
                                "type=0x%04x "
                                "link_state_id=%s "
                                "adv_router=%s "
                                "seq=0x%08x "
                                "age=%s "
                                "length=%s",
                                index,
                                lsa["ls_type"],
                                lsa["link_state_id"],
                                lsa["advertising_router"],
                                lsa["ls_sequence"],
                                lsa["ls_age"],
                                lsa["ls_length"]
                            )

                    local_router_id = struct.unpack(
                        "!I",
                        socket.inet_aton(OSPF_ROUTER_ID)
                    )[0]

                    # R1 wysyła początkowy DBD i również deklaruje się jako Master.
                    if (
                        i_bit
                        and m_bit
                        and ms_bit
                        and pkt_len == 28
                        and local_router_id > router_id
                        and not self.dbd_negotiated
                    ):
                        self.logger.info(
                            "ExStart: Router ID Ryu jest wyzszy. "
                            "Wysylam wlasny initial DBD."
                        )

                        self.send_initial_dbd()