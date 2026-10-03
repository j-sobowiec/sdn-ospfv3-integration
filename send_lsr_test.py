import socket
import struct
import subprocess


IFACE = "r1-eth2"

SRC_ROUTER_ID = "1.1.1.1"
DST_ROUTER_ID = "10.10.10.10"

AREA_ID = "0.0.0.0"

DST_IPV6 = "fe80::10"
DST_MAC = "02:00:00:00:00:01"

LS_TYPE = 0x2001
LINK_STATE_ID = "0.0.0.0"


def checksum(data):
    if len(data) % 2:
        data += b"\x00"

    value = 0

    for offset in range(0, len(data), 2):
        value += (
            data[offset] << 8
        ) + data[offset + 1]

        value = (
            value & 0xffff
        ) + (
            value >> 16
        )

    return (~value) & 0xffff


def get_link_local_address():
    output = subprocess.check_output(
        [
            "ip",
            "-6",
            "-o",
            "addr",
            "show",
            "dev",
            IFACE,
            "scope",
            "link",
        ],
        text=True
    )

    for line in output.splitlines():
        fields = line.split()

        if "inet6" not in fields:
            continue

        index = fields.index("inet6")

        return fields[index + 1].split("/")[0]

    raise RuntimeError(
        f"No IPv6 link-local address on {IFACE}"
    )


def get_interface_mac():
    sock = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW
    )

    sock.bind((IFACE, 0))

    mac = sock.getsockname()[4]

    sock.close()

    return mac


def mac_to_bytes(mac):
    return bytes(
        int(part, 16)
        for part in mac.split(":")
    )


src_ipv6 = get_link_local_address()
src_mac = get_interface_mac()

router_id = struct.unpack(
    "!I",
    socket.inet_aton(SRC_ROUTER_ID)
)[0]

area_id = struct.unpack(
    "!I",
    socket.inet_aton(AREA_ID)
)[0]

link_state_id = struct.unpack(
    "!I",
    socket.inet_aton(LINK_STATE_ID)
)[0]

advertising_router = struct.unpack(
    "!I",
    socket.inet_aton(DST_ROUTER_ID)
)[0]


# One OSPFv3 Link State Request entry:
#
#   2 B reserved
#   2 B LS Type
#   4 B Link State ID
#   4 B Advertising Router

lsr_body = struct.pack(
    "!HHII",
    0,
    LS_TYPE,
    link_state_id,
    advertising_router
)


# OSPFv3 header.
ospf_length = 16 + len(lsr_body)

ospf_header = struct.pack(
    "!BBHIIHBB",
    3,              # Version
    3,              # Type = Link State Request
    ospf_length,
    router_id,
    area_id,
    0,              # Checksum filled below
    0,              # Instance ID
    0               # Reserved
)

ospf_packet = ospf_header + lsr_body


# OSPFv3 checksum uses the IPv6 pseudo-header.
pseudo_header = (
    socket.inet_pton(
        socket.AF_INET6,
        src_ipv6
    )
    + socket.inet_pton(
        socket.AF_INET6,
        DST_IPV6
    )
    + struct.pack(
        "!I3xB",
        len(ospf_packet),
        89
    )
)

ospf_checksum = checksum(
    pseudo_header + ospf_packet
)

ospf_packet = bytearray(ospf_packet)

struct.pack_into(
    "!H",
    ospf_packet,
    12,
    ospf_checksum
)

ospf_packet = bytes(ospf_packet)


# IPv6 header.
ipv6_header = struct.pack(
    "!IHBB16s16s",
    6 << 28,
    len(ospf_packet),
    89,             # OSPF
    1,              # Hop Limit
    socket.inet_pton(
        socket.AF_INET6,
        src_ipv6
    ),
    socket.inet_pton(
        socket.AF_INET6,
        DST_IPV6
    )
)


# Ethernet header.
ethernet_header = struct.pack(
    "!6s6sH",
    mac_to_bytes(DST_MAC),
    src_mac,
    0x86DD
)

frame = (
    ethernet_header
    + ipv6_header
    + ospf_packet
)


sock = socket.socket(
    socket.AF_PACKET,
    socket.SOCK_RAW
)

sock.bind((IFACE, 0))

sent = sock.send(frame)

sock.close()


print(
    f"Sent OSPFv3 LSR: "
    f"src={src_ipv6} "
    f"dst={DST_IPV6} "
    f"type=0x{LS_TYPE:04x} "
    f"lsid={LINK_STATE_ID} "
    f"adv={DST_ROUTER_ID} "
    f"ospf-length={len(ospf_packet)} "
    f"frame-length={sent}"
)