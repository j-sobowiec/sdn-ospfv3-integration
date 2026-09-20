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
import heapq
import ipaddress

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

SDN_TRANSIT_PREFIX = "2001:db8:10::"
SDN_TRANSIT_PREFIX_LENGTH = 64
SDN_TRANSIT_IPV6 = "2001:db8:10::2"

SDN_LAN_PREFIX = "2001:db8:1::"
SDN_LAN_PREFIX_LENGTH = 64
SDN_LAN_GATEWAY = "2001:db8:1::1"

OSPF_INTERFACE_MTU = 1500
OSPF_MAX_AGE = 3600
OSPF_MAX_AGE_DIFF = 900

OSPF_INITIAL_SEQUENCE = 0x80000001

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

def ospfv3_lsa_checksum(lsa_bytes):
    """
    Calculates the Fletcher checksum for an OSPFv3 LSA.

    The LS Age field is excluded from the checksum calculation.
    The checksum field itself must be treated as zero.
    """

    if len(lsa_bytes) < 20:
        raise ValueError("LSA is too short for checksum calculation")

    data = bytearray(lsa_bytes)

    # LSA checksum field is located at bytes 16-17.
    data[16] = 0
    data[17] = 0

    c0 = 0
    c1 = 0

    # LS Age occupies bytes 0-1 and is excluded.
    for value in data[2:]:
        c0 = (c0 + value) % 255
        c1 = (c1 + c0) % 255

    checksum_data_length = len(data) - 2

    x = (
        (checksum_data_length - 15) * c0 - c1
    ) % 255

    if x <= 0:
        x += 255

    y = 510 - c0 - x

    if y > 255:
        y -= 255

    return (x << 8) | y

def finalize_ospfv3_lsa_checksum(lsa_bytes):
    """
    Inserts the calculated Fletcher checksum
    into an OSPFv3 LSA.
    """

    data = bytearray(lsa_bytes)

    if len(data) < 20:
        raise ValueError("LSA is too short")

    data[16] = 0
    data[17] = 0

    checksum = ospfv3_lsa_checksum(data)

    struct.pack_into(
        "!H",
        data,
        16,
        checksum
    )

    return bytes(data)

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

        self.lsdb = {}
        self.ipv6_routing_table = {}

        self.local_router_lsa_sequence = OSPF_INITIAL_SEQUENCE
        self.local_prefix_lsa_sequence = OSPF_INITIAL_SEQUENCE
        self.local_link_lsa_sequence = OSPF_INITIAL_SEQUENCE

        self.ospf_neighbor_router_id = None

        self.hello_thread = hub.spawn(self.hello_loop)
        
        self.lsdb_aging_thread = hub.spawn(self.lsdb_aging_loop)

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

    def update_lsdb(self, received_lsa_headers):
        """
        Installs new LSAs in the local LSDB and replaces
        existing entries only when a newer instance is received.
        """
        routing_changed = False

        for received in received_lsa_headers:
            key = (
                received["ls_type"],
                received["link_state_id"],
                received["advertising_router"]
            )

            current = self.lsdb.get(key)

            current_for_comparison = None

            if current is not None:
                current_for_comparison = dict(current)

                current_for_comparison["ls_age"] = (
                    self.get_lsdb_lsa_age(current)
                )

            if received["ls_age"] >= OSPF_MAX_AGE:
                if current_for_comparison is not None:
                    comparison = compare_lsa_instances(
                        received,
                        current_for_comparison
                    )

                    if comparison >= 0:
                        del self.lsdb[key]

                        if received["ls_type"] in (0x2001, 0x2009):
                            routing_changed = True

                        self.logger.info(
                            "[OSPF][LSDB] flushed %s "
                            "adv=%s lsid=%s",
                            ospfv3_lsa_type_description(
                                received["ls_type"]
                            ),
                            received["advertising_router"],
                            received["link_state_id"]
                        )

                continue

            # LSA nie istnieje jeszcze w LSDB.
            if current is None:
                self.lsdb[key] = self.install_lsa_in_lsdb(received)

                if received["ls_type"] in (0x2001, 0x2009):
                    routing_changed = True

                self.logger.info(
                    "[OSPF][LSDB] installed %s "
                    "adv=%s lsid=%s seq=0x%08x",
                    ospfv3_lsa_type_description(
                        received["ls_type"]
                    ),
                    received["advertising_router"],
                    received["link_state_id"],
                    received["ls_sequence"]
                )

                continue
            
            current_for_comparison = dict(current)

            current_for_comparison["ls_age"] = (
                self.get_lsdb_lsa_age(current)
            )

            comparison = compare_lsa_instances(
                received,
                current_for_comparison
            )

            # Otrzymalismy nowsza instancje tego samego LSA.
            if comparison > 0:
                old_sequence = current["ls_sequence"]

                self.lsdb[key] = self.install_lsa_in_lsdb(received)

                if received["ls_type"] in (0x2001, 0x2009):
                    routing_changed = True

                self.logger.info(
                    "[OSPF][LSDB] updated %s "
                    "adv=%s lsid=%s "
                    "seq=0x%08x -> 0x%08x",
                    ospfv3_lsa_type_description(
                        received["ls_type"]
                    ),
                    received["advertising_router"],
                    received["link_state_id"],
                    old_sequence,
                    received["ls_sequence"]
                )

            # comparison == 0:
            # identyczna instancja - nic nie robimy.
            #
            # comparison < 0:
            # starsza instancja - rowniez nic nie robimy.

        if routing_changed:
            self.recompute_routing_state()
            
    def install_lsa_in_lsdb(self, lsa):
        entry = dict(lsa)

        entry["_age_base"] = lsa["ls_age"]
        entry["_age_timestamp"] = time.monotonic()

        return entry

    def get_lsdb_lsa_age(self, lsa):
        base_age = lsa.get(
            "_age_base",
            lsa["ls_age"]
        )

        timestamp = lsa.get(
            "_age_timestamp"
        )

        if timestamp is None:
            return base_age

        elapsed = int(
            time.monotonic() - timestamp
        )

        return min(
            OSPF_MAX_AGE,
            base_age + elapsed
        )

    def purge_expired_lsas(self):
        """
        Removes LSAs that reached MaxAge.

        Returns True if the removal affects routing
        and SPF should be recalculated.
        """

        expired_keys = []
        routing_changed = False

        for key, lsa in self.lsdb.items():
            current_age = self.get_lsdb_lsa_age(lsa)

            if current_age >= OSPF_MAX_AGE:
                expired_keys.append(key)

        for key in expired_keys:
            lsa = self.lsdb.pop(key)

            if lsa["ls_type"] in (0x2001, 0x2009):
                routing_changed = True

            self.logger.info(
                "[OSPF][LSDB] removed expired %s "
                "adv=%s lsid=%s age=%ds",
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["advertising_router"],
                lsa["link_state_id"],
                OSPF_MAX_AGE
            )

        return routing_changed

    def lsdb_aging_loop(self):
        self.logger.info(
            "[OSPF][LSDB] aging loop started"
        )

        while True:
            hub.sleep(5)

            if not self.lsdb:
                continue

            routing_changed = self.purge_expired_lsas()

            if routing_changed:
                self.logger.info(
                    "[OSPF][ROUTING] LSDB expiration triggered SPF"
                )

                self.recompute_routing_state()

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

    def log_lsdb_snapshot(self):
        self.logger.info(
            "\n[OSPF][LSDB] snapshot entries=%d",
            len(self.lsdb)
        )

        for lsa in self.lsdb.values():
            current_age = self.get_lsdb_lsa_age(lsa)

            self.logger.info(
                "  %s adv=%s lsid=%s "
                "seq=0x%08x age=%ds",
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["advertising_router"],
                lsa["link_state_id"],
                lsa["ls_sequence"],
                current_age
            )

    def build_router_graph(self):
        """
        Builds the router-level topology graph from Router-LSAs
        currently stored in the LSDB.
        """

        graph = {}

        for lsa in self.lsdb.values():

            # We only need Router-LSAs here.
            if lsa["ls_type"] != 0x2001:
                continue

            router_lsa = lsa.get("router_lsa")

            if router_lsa is None:
                continue

            router_id = lsa["advertising_router"]

            if router_id not in graph:
                graph[router_id] = []

            for link in router_lsa["links"]:

                # For now we only use point-to-point links.
                if link["type"] != 1:
                    continue

                neighbor_router_id = link["neighbor_router_id"]

                graph[router_id].append({
                    "neighbor": neighbor_router_id,
                    "cost": link["metric"],
                    "interface_id": link["interface_id"],
                    "neighbor_interface_id": (
                        link["neighbor_interface_id"]
                    )
                })

                # Ensure the neighbor also exists as a graph node,
                # even if we do not have its Router-LSA yet.
                if neighbor_router_id not in graph:
                    graph[neighbor_router_id] = []

                if neighbor_router_id == OSPF_ROUTER_ID:

                    reverse_exists = any(
                        existing["neighbor"] == router_id
                        for existing in graph[OSPF_ROUTER_ID]
                    )

                    if not reverse_exists:
                        graph[OSPF_ROUTER_ID].append({
                            "neighbor": router_id,
                            "cost": link["metric"],
                            "interface_id": (
                                link["neighbor_interface_id"]
                            ),
                            "neighbor_interface_id": (
                                link["interface_id"]
                            )
                        })
        return graph

    def run_spf(self):
        """
        Runs Dijkstra SPF using the local OSPF Router ID
        as the root of the topology graph.
        """

        graph = self.build_router_graph()
        root = OSPF_ROUTER_ID

        if root not in graph:
            return {}, {}

        distances = {
            router_id: float("inf")
            for router_id in graph
        }

        previous = {
            router_id: None
            for router_id in graph
        }

        distances[root] = 0

        queue = [
            (0, root)
        ]

        while queue:
            current_cost, current_router = heapq.heappop(queue)

            if current_cost > distances[current_router]:
                continue

            for link in graph[current_router]:
                neighbor = link["neighbor"]
                link_cost = link["cost"]

                new_cost = current_cost + link_cost

                if new_cost < distances[neighbor]:
                    distances[neighbor] = new_cost
                    previous[neighbor] = current_router

                    heapq.heappush(
                        queue,
                        (new_cost, neighbor)
                    )

        return distances, previous

    def get_spf_next_hop(self, destination, previous):
        """
        Returns the first router after the SPF root
        on the path toward destination.
        """

        root = OSPF_ROUTER_ID

        if destination == root:
            return None

        if destination not in previous:
            return None

        if previous[destination] is None:
            return None

        current = destination

        while previous[current] != root:
            current = previous[current]

            if current is None:
                return None

        return current

    def collect_prefix_advertisements(self):
        """
        Collects IPv6 prefix advertisements from
        Intra-Area-Prefix-LSAs stored in the LSDB.
        """

        advertisements = []

        for lsa in self.lsdb.values():

            # Intra-Area-Prefix-LSA
            if lsa["ls_type"] != 0x2009:
                continue

            prefix_lsa = lsa.get("intra_area_prefix_lsa")

            if prefix_lsa is None:
                continue

            advertising_router = lsa["advertising_router"]

            for prefix in prefix_lsa["prefixes"]:
                advertisements.append({
                    "prefix": prefix["prefix"],
                    "prefix_length": prefix["prefix_length"],
                    "metric": prefix["metric"],
                    "advertising_router": advertising_router
                })

        return advertisements

    def build_ipv6_routing_table(self):
        """
        Builds the IPv6 routing table from SPF results
        and Intra-Area-Prefix-LSA advertisements.
        """

        distances, previous = self.run_spf()
        advertisements = self.collect_prefix_advertisements()

        routes = {}

        # Locally connected IPv6 networks.
        connected_routes = [
            {
                "prefix": SDN_TRANSIT_PREFIX,
                "prefix_length": SDN_TRANSIT_PREFIX_LENGTH,
                "interface": "transit"
            },
            {
                "prefix": SDN_LAN_PREFIX,
                "prefix_length": SDN_LAN_PREFIX_LENGTH,
                "interface": "lan"
            }
        ]

        for connected in connected_routes:
            prefix_key = (
                connected["prefix"],
                connected["prefix_length"]
            )

            routes[prefix_key] = {
                "prefix": connected["prefix"],
                "prefix_length": connected["prefix_length"],
                "source": "connected",
                "advertising_router": None,
                "router_cost": 0,
                "prefix_metric": 0,
                "total_cost": 0,
                "next_hop": None,
                "interface": connected["interface"]
            }

        for advertisement in advertisements:
            advertising_router = advertisement[
                "advertising_router"
            ]

            if advertising_router not in distances:
                continue

            router_cost = distances[advertising_router]

            if router_cost == float("inf"):
                continue

            prefix_metric = advertisement["metric"]

            total_cost = router_cost + prefix_metric

            next_hop = self.get_spf_next_hop(
                advertising_router,
                previous
            )

            prefix_key = (
                advertisement["prefix"],
                advertisement["prefix_length"]
            )

            candidate = {
                "prefix": advertisement["prefix"],
                "prefix_length": advertisement["prefix_length"],
                "source": "ospf",
                "advertising_router": advertising_router,
                "router_cost": router_cost,
                "prefix_metric": prefix_metric,
                "total_cost": total_cost,
                "next_hop": next_hop,
                "interface": "transit"
            }

            current = routes.get(prefix_key)

            # A connected route always takes precedence
            # over a route learned through OSPF.
            if (
                current is not None
                and current["source"] == "connected"
            ):
                continue

            if current is None:
                routes[prefix_key] = candidate
                continue

            # Lower total OSPF cost wins.
            if candidate["total_cost"] < current["total_cost"]:
                routes[prefix_key] = candidate

            # Deterministic tie-break for equal-cost candidates.
            elif (
                candidate["total_cost"]
                == current["total_cost"]
                and candidate["advertising_router"]
                < current["advertising_router"]
            ):
                routes[prefix_key] = candidate

        return routes

    def recompute_routing_state(self):
        """
        Recalculates SPF and rebuilds the IPv6 routing table
        after a relevant LSDB change.
        """

        new_routes = self.build_ipv6_routing_table()

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

    def log_router_graph(self):
        graph = self.build_router_graph()

        self.logger.info(
            "\n[OSPF][TOPOLOGY] router graph nodes=%d",
            len(graph)
        )

        router_ids = sorted(
            router_id
            for router_id in graph.keys()
            if router_id != OSPF_ROUTER_ID
        )

        if OSPF_ROUTER_ID in graph:
            router_ids.append(OSPF_ROUTER_ID)

        for router_id in router_ids:
            links = graph[router_id]

            if not links:
                self.logger.info(
                    "  router=%s links=0",
                    router_id
                )
                continue

            self.logger.info(
                "  router=%s links=%d",
                router_id,
                len(links)
            )

            for link in links:
                self.logger.info(
                    "    -> %s cost=%d "
                    "if=%s neighbor_if=%s",
                    link["neighbor"],
                    link["cost"],
                    link["interface_id"],
                    link["neighbor_interface_id"]
                )

    def log_spf_result(self):
        distances, previous = self.run_spf()

        self.logger.info(
            "\n[OSPF][SPF] root=%s",
            OSPF_ROUTER_ID
        )

        router_ids = [OSPF_ROUTER_ID]

        router_ids.extend(
            sorted(
                router_id
                for router_id in distances
                if router_id != OSPF_ROUTER_ID
            )
        )

        for router_id in router_ids:
            cost = distances[router_id]
            predecessor = previous[router_id]

            next_hop = self.get_spf_next_hop(
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
    def log_prefix_advertisements(self):
        advertisements = self.collect_prefix_advertisements()

        self.logger.info(
            "\n[OSPF][PREFIXES] advertisements=%d",
            len(advertisements)
        )

        advertisements.sort(
            key=lambda item: (
                item["advertising_router"],
                item["prefix"],
                item["prefix_length"]
            )
        )

        for entry in advertisements:
            self.logger.info(
                "  %s/%d adv=%s metric=%d",
                entry["prefix"],
                entry["prefix_length"],
                entry["advertising_router"],
                entry["metric"]
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
                    self.ospf_neighbor_router_id = router_id_text

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

                        calculated_lsa_checksum = ospfv3_lsa_checksum(
                            raw_lsa
                        )

                        self.logger.info(
                            "[OSPF][LSA CHECKSUM] "
                            "type=%s received=0x%04x "
                            "calculated=0x%04x valid=%s",
                            ospfv3_lsa_type_description(ls_type),
                            ls_checksum,
                            calculated_lsa_checksum,
                            ls_checksum == calculated_lsa_checksum
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
                        self.update_lsdb(lsu_lsa_headers)
                        self.send_ls_ack(lsu_lsa_headers)