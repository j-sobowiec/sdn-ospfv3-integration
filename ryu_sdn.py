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
OSPF_MAX_AGE = 3600
OSPF_MAX_AGE_DIFF = 900

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
            f"Router-LSA is too short: {len(raw_lsa)} B"
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
            f"actual length={len(raw_lsa)}"
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
            "Router-LSA: link description section "
            f"has invalid length {link_data_length} B"
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

def parse_ospfv3_link_lsa(raw_lsa):
    if len(raw_lsa) < 44:
        raise ValueError(
            f"Link-LSA is too short: {len(raw_lsa)} B"
        )

    router_priority = raw_lsa[20]

    options = int.from_bytes(
        raw_lsa[21:24],
        byteorder="big"
    )

    link_local_address = socket.inet_ntop(
        socket.AF_INET6,
        raw_lsa[24:40]
    )

    number_of_prefixes = struct.unpack(
        "!I",
        raw_lsa[40:44]
    )[0]

    prefixes = []

    # Prefiksy zaczynaja sie po:
    # 20 B LSA header
    # 24 B stalej czesci Link-LSA
    offset = 44

    for index in range(number_of_prefixes):

        # Kazdy wpis prefiksu ma najpierw 4 B:
        # PrefixLength + PrefixOptions + Reserved
        if offset + 4 > len(raw_lsa):
            raise ValueError(
                f"Link-LSA: insufficient data for prefix #{index + 1}"
            )

        prefix_length = raw_lsa[offset]
        prefix_options = raw_lsa[offset + 1]

        reserved = struct.unpack(
            "!H",
            raw_lsa[offset + 2:offset + 4]
        )[0]

        if prefix_length > 128:
            raise ValueError(
                f"Link-LSA: invalid prefix length: {prefix_length}"
            )

        # Adres prefiksu jest zapisany w wielokrotnosci 32 bitow.
        prefix_bytes_length = (
            (prefix_length + 31) // 32
        ) * 4

        prefix_start = offset + 4
        prefix_end = prefix_start + prefix_bytes_length

        if prefix_end > len(raw_lsa):
            raise ValueError(
                f"Link-LSA: prefix #{index + 1} exceeds LSA boundary"
            )

        prefix_bytes = bytes(
            raw_lsa[prefix_start:prefix_end]
        )

        # Uzupelniamy zerami do pelnego adresu IPv6.
        full_ipv6 = prefix_bytes.ljust(16, b"\x00")

        prefix_address = socket.inet_ntop(
            socket.AF_INET6,
            full_ipv6
        )

        prefixes.append({
            "prefix_length": prefix_length,
            "prefix_options": prefix_options,
            "reserved": reserved,
            "prefix": prefix_address,
        })

        offset = prefix_end

    return {
        "router_priority": router_priority,
        "options": options,
        "link_local_address": link_local_address,
        "number_of_prefixes": number_of_prefixes,
        "prefixes": prefixes,
    }

def parse_ospfv3_intra_area_prefix_lsa(raw_lsa):
    if len(raw_lsa) < 32:
        raise ValueError(
            f"Intra-Area-Prefix-LSA is too short: {len(raw_lsa)} B"
        )

    # Stala czesc body zaczyna sie po 20-bajtowym LSA header.
    number_of_prefixes, referenced_ls_type = struct.unpack(
        "!HH",
        raw_lsa[20:24]
    )

    referenced_link_state_id = struct.unpack(
        "!I",
        raw_lsa[24:28]
    )[0]

    referenced_advertising_router = struct.unpack(
        "!I",
        raw_lsa[28:32]
    )[0]

    prefixes = []

    # 20 B LSA header
    # 12 B stalej czesci Intra-Area-Prefix-LSA
    offset = 32

    for index in range(number_of_prefixes):

        # PrefixLength + PrefixOptions + Metric = 4 B
        if offset + 4 > len(raw_lsa):
            raise ValueError(
                f"Intra-Area-Prefix-LSA: "
                f"insufficient data for prefix #{index + 1}"
            )

        prefix_length = raw_lsa[offset]
        prefix_options = raw_lsa[offset + 1]

        metric = struct.unpack(
            "!H",
            raw_lsa[offset + 2:offset + 4]
        )[0]

        if prefix_length > 128:
            raise ValueError(
                f"Intra-Area-Prefix-LSA: "
                f"invalid prefix length {prefix_length}"
            )

        # Prefix jest kodowany w wielokrotnosci 32 bitow.
        prefix_bytes_length = (
            (prefix_length + 31) // 32
        ) * 4

        prefix_start = offset + 4
        prefix_end = prefix_start + prefix_bytes_length

        if prefix_end > len(raw_lsa):
            raise ValueError(
                f"Intra-Area-Prefix-LSA: "
                f"prefix #{index + 1} exceeds LSA boundary"
            )

        prefix_bytes = bytes(
            raw_lsa[prefix_start:prefix_end]
        )

        full_ipv6 = prefix_bytes.ljust(
            16,
            b"\x00"
        )

        prefix_address = socket.inet_ntop(
            socket.AF_INET6,
            full_ipv6
        )

        prefixes.append({
            "prefix": prefix_address,
            "prefix_length": prefix_length,
            "prefix_options": prefix_options,
            "metric": metric,
        })

        offset = prefix_end

    return {
        "number_of_prefixes": number_of_prefixes,

        "referenced_ls_type": referenced_ls_type,

        "referenced_link_state_id": socket.inet_ntoa(
            struct.pack(
                "!I",
                referenced_link_state_id
            )
        ),

        "referenced_advertising_router": socket.inet_ntoa(
            struct.pack(
                "!I",
                referenced_advertising_router
            )
        ),

        "prefixes": prefixes,
    }

def lsa_sequence_signed(sequence):
    """
    LS Sequence Number w OSPF jest porownywany jako signed 32-bit.
    """
    return struct.unpack(
        "!i",
        struct.pack("!I", sequence)
    )[0]


def compare_lsa_instances(first, second):
    """
    Porownuje dwie instancje tego samego LSA.

    Zwraca:
       1  -> first jest nowsze
       0  -> obie instancje sa traktowane jako identyczne
      -1  -> second jest nowsze
    """

    first_seq = lsa_sequence_signed(
        first["ls_sequence"]
    )

    second_seq = lsa_sequence_signed(
        second["ls_sequence"]
    )

    # 1. LS Sequence Number
    if first_seq > second_seq:
        return 1

    if first_seq < second_seq:
        return -1

    # 2. LS Checksum
    if first["ls_checksum"] > second["ls_checksum"]:
        return 1

    if first["ls_checksum"] < second["ls_checksum"]:
        return -1

    first_age = first["ls_age"]
    second_age = second["ls_age"]

    # 3. MaxAge
    if (
        first_age == OSPF_MAX_AGE
        and second_age != OSPF_MAX_AGE
    ):
        return 1

    if (
        second_age == OSPF_MAX_AGE
        and first_age != OSPF_MAX_AGE
    ):
        return -1

    # 4. Duza roznica LS Age:
    # mlodsze LSA (mniejsze age) jest nowsze.
    if abs(first_age - second_age) > OSPF_MAX_AGE_DIFF:

        if first_age < second_age:
            return 1

        if first_age > second_age:
            return -1

    # 5. W pozostalych przypadkach
    # instancje sa traktowane jako identyczne.
    return 0

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
            "[OSPF][HELLO TX] port=%s neighbors=%s",
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
            "[OSPF][DBD TX] initial "
            "seq=0x%08x flags=I,M,MS",
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
            "[OSPF][DBD TX] exchange "
            "seq=0x%08x flags=MS",
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
            "[OSPF][LSR TX] to=%s count=%d",
            self.ospf_neighbor_ipv6,
            len(self.lsa_request_list)
        )

        for index, lsa in enumerate(
            self.lsa_request_list,
            start=1
        ):
            self.logger.info(
                "  -> %s adv=%s lsid=%s",
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["advertising_router"],
                lsa["link_state_id"]
            )

    def update_lsa_request_list(self, received_lsa_headers):
        """
        Usuwa z lsa_request_list te LSA, które zostały
        już odebrane w LSU.
        """
        if not self.lsa_request_list:
            return

        remaining_requests = []

        for request in self.lsa_request_list:
            request_satisfied = False

            for received in received_lsa_headers:
                same_lsa = (
                    request["ls_type"] == received["ls_type"]
                    and request["link_state_id"] == received["link_state_id"]
                    and request["advertising_router"]
                    == received["advertising_router"]
                )

                if not same_lsa:
                    continue

                comparison = compare_lsa_instances(
                    received,
                    request
                )

                if comparison >= 0:
                    request_satisfied = True
                    break

            if not request_satisfied:
                remaining_requests.append(request)

        old_count = len(self.lsa_request_list)
        new_count = len(remaining_requests)

        self.lsa_request_list = remaining_requests

        if new_count != old_count:
            self.logger.info(
                "[OSPF][LSR] received=%d pending=%d",
                old_count - new_count,
                new_count
            )

        if old_count > 0 and new_count == 0:
            self.logger.info(
                "[OSPF][LSR] request-list complete"
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
            "[OSPF][LSAck TX] to=%s count=%d",
            self.ospf_neighbor_ipv6,
            len(lsa_headers)
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

                    if len(neighbor_data) % 4 != 0:
                        self.logger.warning(
                            "[OSPF][HELLO] invalid neighbor-list length=%d",
                            len(neighbor_data)
                        )
                        return

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


                    self.ospf_port = in_port
                    self.ospf_neighbor_ipv6 = ipv6_pkt.src
                    self.ospf_neighbor_mac = eth_pkt.src

                    if router_id_text not in self.ospf_neighbors:
                        self.ospf_neighbors.append(router_id_text)

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

                    if len(lsa_data) % 20 != 0:
                        self.logger.warning(
                            "[OSPF][DBD] invalid LSA-summary length=%d",
                            len(lsa_data)
                        )
                        return

                    for offset in range(0, len(lsa_data), 20):
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

                    # UWAGA:
                    # logowanie dopiero PO sparsowaniu wszystkich naglowkow LSA
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
                                "neighbor restarted ExStart"
                            )

                        self.logger.info(
                            "[OSPF][DBD] ExStart "
                            "local=%s peer=%s role=Master",
                            OSPF_ROUTER_ID,
                            router_id_text
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
                            "[OSPF][DBD] negotiation-complete "
                            "role=Master seq=0x%08x",
                            dd_sequence
                        )

                        self.dbd_negotiated = True

                        self.lsa_request_list = list(lsa_headers)

                        self.logger.info(
                            "[OSPF][DBD] request-list=%d",
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
                            "[OSPF][DBD] exchange-complete seq=0x%08x pending=%d",
                            dd_sequence,
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

                        # Dlugosc LSA zawiera jego 20-bajtowy naglowek.
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
                                    "[OSPF][LSU] Router-LSA parse error #%d: %s",
                                    index + 1,
                                    exc
                                )
                                return
                            
                        elif ls_type == 0x0008:
                            try:
                                lsa_header["link_lsa"] = (
                                    parse_ospfv3_link_lsa(raw_lsa)
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
                                    "[OSPF][LSU] Intra-Area-Prefix-LSA parse error #%d: %s",
                                    index + 1,
                                    exc
                                )
                                return
                            
                        lsu_lsa_headers.append(lsa_header)

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
                        self.update_lsa_request_list(lsu_lsa_headers)
                        self.send_ls_ack(lsu_lsa_headers)