import socket
import struct

from ospfv3 import config as cfg


def mac_to_bytes(mac):
    return bytes(
        int(part, 16)
        for part in mac.split(":")
    )

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

def build_ospfv3_packet(pkt_type, body, dst_ipv6):
    """
    Builds a complete OSPFv3 packet:
        common OSPF header + packet-specific body + checksum.
    """

    pkt_len = 16 + len(body)

    router_id = struct.unpack(
        "!I",
        socket.inet_aton(cfg.ROUTER_ID)
    )[0]

    area_id = struct.unpack(
        "!I",
        socket.inet_aton(cfg.AREA_ID)
    )[0]

    ospf_header = struct.pack(
        "!BBHIIHBB",
        3,                  # Version
        pkt_type,
        pkt_len,
        router_id,
        area_id,
        0,                  # Checksum filled later
        cfg.INSTANCE_ID,
        0                   # Reserved
    )

    ospf_packet = ospf_header + body

    checksum = calculate_ospfv3_checksum(
        cfg.LINK_LOCAL,
        dst_ipv6,
        ospf_packet
    )

    ospf_packet = bytearray(ospf_packet)

    struct.pack_into(
        "!H",
        ospf_packet,
        12,
        checksum
    )

    return bytes(ospf_packet)

def build_ospfv3_hello(neighbors=()):
    options = cfg.OPTIONS.to_bytes(
        3,
        byteorder="big"
    )

    hello_body = struct.pack(
        "!IB3sHHII",
        cfg.INTERFACE_ID,
        cfg.ROUTER_PRIORITY,
        options,
        cfg.HELLO_INTERVAL,
        cfg.DEAD_INTERVAL,
        0,      # DR
        0       # BDR
    )

    neighbor_data = b"".join(
        socket.inet_aton(neighbor)
        for neighbor in neighbors
    )

    body = hello_body + neighbor_data

    return build_ospfv3_packet(
        pkt_type=1,
        body=body,
        dst_ipv6="ff02::5"
    )

def build_ospfv3_dbd(dd_sequence, flags=0x07):
    options = cfg.OPTIONS.to_bytes(
        3,
        byteorder="big"
    )

    body = struct.pack(
        "!B3sHBBI",
        0,                  # Reserved
        options,
        cfg.INTERFACE_MTU,
        0,                  # Reserved
        flags,
        dd_sequence
    )

    return build_ospfv3_packet(
        pkt_type=2,
        body=body,
        dst_ipv6="ff02::5"
    )

def build_ospfv3_lsr(lsa_requests, dst_ipv6):
    requests_data = b""

    for lsa in lsa_requests:
        link_state_id = struct.unpack(
            "!I",
            socket.inet_aton(
                lsa["link_state_id"]
            )
        )[0]

        advertising_router = struct.unpack(
            "!I",
            socket.inet_aton(
                lsa["advertising_router"]
            )
        )[0]

        requests_data += struct.pack(
            "!HHII",
            0,                          # Reserved
            lsa["ls_type"],
            link_state_id,
            advertising_router
        )

    return build_ospfv3_packet(
        pkt_type=3,
        body=requests_data,
        dst_ipv6=dst_ipv6
    )

def build_ospfv3_lsu(lsu_body, dst_ipv6):
    """
    Builds an OSPFv3 Link State Update packet.
    """

    return build_ospfv3_packet(
        pkt_type=4,
        body=lsu_body,
        dst_ipv6=dst_ipv6
    )

def build_ospfv3_lsack(lsa_headers, dst_ipv6):
    ack_data = b"".join(
        lsa["raw_header"]
        for lsa in lsa_headers
    )

    return build_ospfv3_packet(
        pkt_type=5,
        body=ack_data,
        dst_ipv6=dst_ipv6
    )

def build_ospfv3_frame(
    ospf_packet,
    dst_ipv6,
    dst_mac
):
    """
    Builds an Ethernet + IPv6 frame carrying an OSPFv3 packet.
    """

    ethernet_header = struct.pack(
        "!6s6sH",
        mac_to_bytes(dst_mac),
        mac_to_bytes(cfg.ROUTER_MAC),
        0x86DD
    )

    ipv6_header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(ospf_packet),
        89,     # Next Header = OSPF
        1,      # Hop Limit
        socket.inet_pton(
            socket.AF_INET6,
            cfg.LINK_LOCAL
        ),
        socket.inet_pton(
            socket.AF_INET6,
            dst_ipv6
        )
    )

    return ethernet_header + ipv6_header + ospf_packet

def build_ospfv3_hello_frame(neighbors=()):
    ospf_packet = build_ospfv3_hello(
        neighbors
    )

    return build_ospfv3_frame(
        ospf_packet=ospf_packet,
        dst_ipv6="ff02::5",
        dst_mac="33:33:00:00:00:05"
    )

def build_ospfv3_dbd_frame(dd_sequence, flags=0x07):
    ospf_packet = build_ospfv3_dbd(
        dd_sequence,
        flags
    )

    return build_ospfv3_frame(
        ospf_packet=ospf_packet,
        dst_ipv6="ff02::5",
        dst_mac="33:33:00:00:00:05"
    )

def build_ospfv3_lsr_frame(
    lsa_requests,
    dst_ipv6,
    dst_mac
):
    ospf_packet = build_ospfv3_lsr(
        lsa_requests,
        dst_ipv6
    )

    return build_ospfv3_frame(
        ospf_packet=ospf_packet,
        dst_ipv6=dst_ipv6,
        dst_mac=dst_mac
    )

def build_ospfv3_lsu_frame(
    lsu_body,
    dst_ipv6,
    dst_mac
):
    """
    Builds an Ethernet + IPv6 frame carrying
    an OSPFv3 Link State Update packet.
    """

    ospf_packet = build_ospfv3_lsu(
        lsu_body,
        dst_ipv6
    )

    return build_ospfv3_frame(
        ospf_packet=ospf_packet,
        dst_ipv6=dst_ipv6,
        dst_mac=dst_mac
    )

def build_ospfv3_lsack_frame(
    lsa_headers,
    dst_ipv6,
    dst_mac
):
    ospf_packet = build_ospfv3_lsack(
        lsa_headers,
        dst_ipv6
    )

    return build_ospfv3_frame(
        ospf_packet=ospf_packet,
        dst_ipv6=dst_ipv6,
        dst_mac=dst_mac
    )
