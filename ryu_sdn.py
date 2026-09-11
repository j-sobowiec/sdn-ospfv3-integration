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

def build_ospfv3_lsr(lsa_requests, dst_ipv6):
    version = 3
    pkt_type = 3

    requests_data = b""

    for lsa in lsa_requests:
        link_state_id = struct.unpack(
            "!I",
            socket.inet_aton(lsa["link_state_id"])
        )[0]

        advertising_router = struct.unpack(
            "!I",
            socket.inet_aton(lsa["advertising_router"])
        )[0]

        requests_data += struct.pack(
            "!HHII",
            0,                          # reserved
            lsa["ls_type"],
            link_state_id,
            advertising_router
        )

    pkt_len = 16 + len(requests_data)

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
        0,                  # checksum tymczasowo 0
        OSPF_INSTANCE_ID,
        0
    )

    ospf_packet = ospf_header + requests_data

    checksum = calculate_ospfv3_checksum(
        SDN_LINK_LOCAL,
        dst_ipv6,
        ospf_packet
    )

    ospf_packet = bytearray(ospf_packet)
    ospf_packet[12:14] = struct.pack("!H", checksum)

    return bytes(ospf_packet)

def build_ospfv3_lsack(lsa_headers, dst_ipv6):
    version = 3
    pkt_type = 5

    ack_data = b""

    for lsa in lsa_headers:
        ack_data += lsa["raw_header"]

    pkt_len = 16 + len(ack_data)

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
        0,                  # checksum na razie 0
        OSPF_INSTANCE_ID,
        0
    )

    ospf_packet = ospf_header + ack_data

    checksum = calculate_ospfv3_checksum(
        SDN_LINK_LOCAL,
        dst_ipv6,
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

def build_ospfv3_lsr_frame(
    lsa_requests,
    dst_ipv6,
    dst_mac
):
    ospf_packet = build_ospfv3_lsr(
        lsa_requests,
        dst_ipv6
    )

    ethernet_header = struct.pack(
        "!6s6sH",
        mac_to_bytes(dst_mac),
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
            dst_ipv6
        )
    )

    return ethernet_header + ipv6_header + ospf_packet

def build_ospfv3_lsack_frame(
    lsa_headers,
    dst_ipv6,
    dst_mac
):
    ospf_packet = build_ospfv3_lsack(
        lsa_headers,
        dst_ipv6
    )

    ethernet_header = struct.pack(
        "!6s6sH",
        mac_to_bytes(dst_mac),
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
            dst_ipv6
        )
    )

    return ethernet_header + ipv6_header + ospf_packet

def ospfv3_lsa_type_description(ls_type):
    """Zwróć czytelną nazwę typu LSA oraz jego flooding scope."""

    lsa_names = {
        0x2001: "Router-LSA",
        0x2002: "Network-LSA",
        0x2003: "Inter-Area-Prefix-LSA",
        0x2004: "Inter-Area-Router-LSA",
        0x4005: "AS-External-LSA",
        0x2007: "NSSA-LSA",
        0x0008: "Link-LSA",
        0x2009: "Intra-Area-Prefix-LSA",
    }

    scope_names = {
        0x0000: "Link-local Scope",
        0x2000: "Area Scope",
        0x4000: "AS Scope",
        0x6000: "Reserved Scope",
    }

    name = lsa_names.get(
        ls_type,
        f"Unknown-LSA(function={ls_type & 0x1fff})"
    )

    scope = scope_names.get(
        ls_type & 0x6000,
        "Unknown Scope"
    )

    return f"{name}, {scope}"

def parse_ospfv3_router_lsa(raw_lsa):
    """
    Parsuje pelne OSPFv3 Router-LSA (LS Type 0x2001).

    raw_lsa zawiera:
      20 B - wspolny naglowek LSA
       4 B - Flags + Options
      Nx16 B - opisy linkow
    """

    if len(raw_lsa) < 24:
        raise ValueError(
            f"Router-LSA jest za krotkie: {len(raw_lsa)} B"
        )

    # Pole Length znajduje sie w ostatnich 2 bajtach
    # wspolnego 20-bajtowego naglowka LSA.
    ls_length = struct.unpack(
        "!H",
        raw_lsa[18:20]
    )[0]

    if ls_length != len(raw_lsa):
        raise ValueError(
            f"Router-LSA: LS Length={ls_length}, "
            f"rzeczywista dlugosc={len(raw_lsa)}"
        )

    # Pierwszy bajt body = flagi routera.
    flags = raw_lsa[20]

    # Kolejne 3 bajty = Options.
    options = int.from_bytes(
        raw_lsa[21:24],
        byteorder="big"
    )

    link_data_length = ls_length - 24

    # Kazdy opis linku Router-LSA ma dokladnie 16 B.
    if link_data_length % 16 != 0:
        raise ValueError(
            "Router-LSA: czesc z opisami linkow "
            f"ma niepoprawna dlugosc {link_data_length} B"
        )

    links = []

    offset = 24

    while offset < ls_length:
        (
            link_type,
            reserved,
            metric,
            interface_id,
            neighbor_interface_id,
            neighbor_router_id
        ) = struct.unpack(
            "!BBHIII",
            raw_lsa[offset:offset + 16]
        )

        link_type_names = {
            1: "Point-to-Point",
            2: "Transit Network",
            3: "Reserved",
            4: "Virtual Link",
        }

        links.append({
            "type": link_type,
            "type_name": link_type_names.get(
                link_type,
                "Unknown"
            ),
            "reserved": reserved,
            "metric": metric,

            "interface_id": socket.inet_ntoa(
                struct.pack("!I", interface_id)
            ),

            "neighbor_interface_id": socket.inet_ntoa(
                struct.pack("!I", neighbor_interface_id)
            ),

            "neighbor_router_id": socket.inet_ntoa(
                struct.pack("!I", neighbor_router_id)
            ),
        })

        offset += 16

    return {
        "flags": flags,
        "options": options,
        "links": links,
    }

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
        self.dbd_exchange_complete = False
        self.lsa_request_list = []

        self.ospf_neighbor_ipv6 = None
        self.ospf_neighbor_mac = None
        self.lsr_sent = False

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

    def send_exchange_dbd(self):
        if self.datapath is None or self.ospf_port is None:
            return

        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        frame = build_ospfv3_dbd_frame(
            self.dbd_sequence,
            flags=0x01
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
            "Wyslano Exchange DBD: "
            "I=0 M=0 MS=1 seq=0x%08x",
            self.dbd_sequence
        )

    def reset_dbd_state(self, reason):
        old_sequence = self.dbd_sequence

        self.dbd_negotiated = False
        self.dbd_exchange_complete = False
        self.lsa_request_list = []
        self.lsr_sent = False

        self.dbd_sequence = (
            int(time.time() * 1000)
        ) & 0xffffffff

        # zabezpieczenie, gdy reset nastąpi w tej samej milisekundzie
        if self.dbd_sequence == old_sequence:
            self.dbd_sequence = (
                old_sequence + 1
            ) & 0xffffffff

        self.logger.warning(
            "Reset stanu DBD: %s. "
            "Nowy DD sequence=0x%08x",
            reason,
            self.dbd_sequence
        )

    def send_link_state_request(self):
        if self.datapath is None or self.ospf_port is None:
            return

        if self.ospf_neighbor_ipv6 is None:
            return

        if self.ospf_neighbor_mac is None:
            return

        if not self.lsa_request_list:
            self.logger.info(
                "LSR: brak LSA do pobrania."
            )
            return

        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        frame = build_ospfv3_lsr_frame(
            self.lsa_request_list,
            self.ospf_neighbor_ipv6,
            self.ospf_neighbor_mac
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

        self.lsr_sent = True

        self.logger.info(
            "Wyslano OSPFv3 LSR: %d LSA do %s",
            len(self.lsa_request_list),
            self.ospf_neighbor_ipv6
        )

        for index, lsa in enumerate(
            self.lsa_request_list,
            start=1
        ):
            self.logger.info(
                "  Request #%d: "
                "type=0x%04x (%s) "
                "link_state_id=%s "
                "adv_router=%s",
                index,
                lsa["ls_type"],
                ospfv3_lsa_type_description(lsa["ls_type"]),
                lsa["link_state_id"],
                lsa["advertising_router"]
            )

    def send_ls_ack(self, lsa_headers):
        if self.datapath is None or self.ospf_port is None:
            return

        if self.ospf_neighbor_ipv6 is None:
            return

        if self.ospf_neighbor_mac is None:
            return

        if not lsa_headers:
            return

        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        frame = build_ospfv3_lsack_frame(
            lsa_headers,
            self.ospf_neighbor_ipv6,
            self.ospf_neighbor_mac
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
            "Wyslano OSPFv3 LSAck: %d LSA do %s",
            len(lsa_headers),
            self.ospf_neighbor_ipv6
        )

        for index, lsa in enumerate(
            lsa_headers,
            start=1
        ):
            self.logger.info(
                "  ACK #%d: "
                "type=0x%04x (%s) "
                "link_state_id=%s "
                "adv_router=%s "
                "seq=0x%08x",
                index,
                lsa["ls_type"],
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["link_state_id"],
                lsa["advertising_router"],
                lsa["ls_sequence"]
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

                if checksum != calculated_checksum:
                    self.logger.warning(
                        "OSPFv3: niepoprawny checksum "
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
                        self.ospf_neighbor_ipv6 = ipv6_pkt.src
                        self.ospf_neighbor_mac = eth_pkt.src

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
                                "type=0x%04x (%s) "
                                "link_state_id=%s "
                                "adv_router=%s "
                                "seq=0x%08x "
                                "age=%s "
                                "length=%s",
                                index,
                                lsa["ls_type"],
                                ospfv3_lsa_type_description(lsa["ls_type"]),
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
                    is_initial_dbd = (
                        i_bit
                        and m_bit
                        and ms_bit
                        and pkt_len == 28
                        and local_router_id > router_id
                    )

                    if is_initial_dbd:

                        # Sąsiad rozpoczął ExStart ponownie po wcześniejszej
                        # negocjacji lub zakończonym Exchange.
                        if (
                            self.dbd_negotiated
                            or self.dbd_exchange_complete
                        ):
                            self.reset_dbd_state(
                                "sasiad rozpoczal ponownie ExStart"
                            )

                        self.logger.info(
                            "ExStart: Router ID Ryu jest wyzszy. "
                            "Wysylam initial DBD."
                        )

                        self.send_initial_dbd()

                    elif (
                        not self.dbd_negotiated
                        and not i_bit
                        and not ms_bit
                        and dd_sequence == self.dbd_sequence
                        and local_router_id > router_id
                    ):
                        self.logger.info(
                            "DBD: negocjacja Master/Slave zakonczona. "
                            "Ryu jest Masterem."
                        )

                        self.dbd_negotiated = True

                        self.lsa_request_list = list(lsa_headers)

                        self.logger.info(
                            "DBD: zapisano %d LSA do Link State Request List.",
                            len(self.lsa_request_list)
                        )

                        self.dbd_sequence = (
                            self.dbd_sequence + 1
                        ) & 0xffffffff

                        self.send_exchange_dbd()

                    elif (
                        self.dbd_negotiated
                        and not self.dbd_exchange_complete
                        and not i_bit
                        and not m_bit
                        and not ms_bit
                        and dd_sequence == self.dbd_sequence
                    ):
                        self.dbd_exchange_complete = True

                        self.logger.info(
                            "DBD: Exchange zakonczony poprawnie. "
                            "Otrzymano potwierdzenie seq=0x%08x",
                            dd_sequence
                        )

                        self.logger.info(
                            "LSA oczekujace na pobranie: %d",
                            len(self.lsa_request_list)
                        )

                        if (
                            self.lsa_request_list
                            and not self.lsr_sent
                        ):
                            self.send_link_state_request()
                elif version == 3 and pkt_type == 4 and pkt_len >= 20:

                    number_of_lsas = struct.unpack(
                        "!I",
                        ospf_data[16:20]
                    )[0]

                    lsu_lsa_headers = []

                    # 16 B = OSPFv3 header
                    #  4 B = liczba LSA
                    # ------------------
                    # 20 B = poczatek pierwszego LSA
                    offset = 20

                    for index in range(number_of_lsas):

                        # Każde LSA musi mieć przynajmniej 20-bajtowy nagłówek.
                        if offset + 20 > pkt_len:
                            self.logger.warning(
                                "LSU: za malo danych na naglowek LSA #%d",
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

                        # Dlugosc LSA zawiera jego 20-bajtowy naglowek.
                        if ls_length < 20:
                            self.logger.warning(
                                "LSU: niepoprawna dlugosc LSA #%d: %d",
                                index + 1,
                                ls_length
                            )
                            return

                        if offset + ls_length > pkt_len:
                            self.logger.warning(
                                "LSU: LSA #%d wychodzi poza pakiet "
                                "(offset=%d length=%d pkt_len=%d)",
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
                                struct.pack("!I", link_state_id)
                            ),
                            "advertising_router": socket.inet_ntoa(
                                struct.pack("!I", advertising_router)
                            ),
                            "ls_sequence": ls_sequence,
                            "ls_checksum": ls_checksum,
                            "ls_length": ls_length,

                            # Przyda się za chwilę do LSAck.
                            "raw_header": raw_lsa_header
                        }

                        if ls_type == 0x2001:
                            try:
                                lsa_header["router_lsa"] = (
                                    parse_ospfv3_router_lsa(raw_lsa)
                                )
                            except ValueError as exc:
                                self.logger.warning(
                                    "LSU: blad parsowania Router-LSA #%d: %s",
                                    index + 1,
                                    exc
                                )
                                return
    
                        lsu_lsa_headers.append(lsa_header)

                        # UWAGA:
                        # przechodzimy o CALA dlugosc LSA,
                        # a nie o 20 bajtow.
                        offset += ls_length

                    self.logger.info(
                        "\n---------------- OSPFv3 LSU ----------------\n"
                        "port=%s\n"
                        "src=%s\n"
                        "dst=%s\n"
                        "length=%d\n"
                        "router_id=%s\n"
                        "area_id=%s\n"
                        "LSU: number_of_lsas=%d",
                        in_port,
                        ipv6_pkt.src,
                        ipv6_pkt.dst,
                        pkt_len,
                        router_id_text,
                        area_id_text,
                        number_of_lsas
                    )

                    for index, lsa in enumerate(
                        lsu_lsa_headers,
                        start=1
                    ):
                        self.logger.info(
                            "  LSA #%d: "
                            "type=0x%04x (%s) "
                            "link_state_id=%s "
                            "adv_router=%s "
                            "seq=0x%08x "
                            "age=%d "
                            "checksum=0x%04x "
                            "length=%d",
                            index,
                            lsa["ls_type"],
                            ospfv3_lsa_type_description(lsa["ls_type"]),
                            lsa["link_state_id"],
                            lsa["advertising_router"],
                            lsa["ls_sequence"],
                            lsa["ls_age"],
                            lsa["ls_checksum"],
                            lsa["ls_length"]
                        )

                        if lsa["ls_type"] == 0x2001:
                            router_lsa = lsa["router_lsa"]

                            self.logger.info(
                                "    Router-LSA body: "
                                "flags=0x%02x "
                                "options=0x%06x "
                                "links=%d",
                                router_lsa["flags"],
                                router_lsa["options"],
                                len(router_lsa["links"])
                            )

                            for link_index, link in enumerate(
                                router_lsa["links"],
                                start=1
                            ):
                                self.logger.info(
                                    "      Link #%d: "
                                    "type=%d (%s) "
                                    "metric=%d "
                                    "interface_id=%s "
                                    "neighbor_interface_id=%s "
                                    "neighbor_router_id=%s",
                                    link_index,
                                    link["type"],
                                    link["type_name"],
                                    link["metric"],
                                    link["interface_id"],
                                    link["neighbor_interface_id"],
                                    link["neighbor_router_id"]
                                )

                    self.logger.info(
                        "---------------------------------------------"
                    )

                    if lsu_lsa_headers:
                        self.send_ls_ack(lsu_lsa_headers)