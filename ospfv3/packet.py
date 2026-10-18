"""OSPFv3 packet builders used by the Ryu controller.

Scapy handles the wire format; the controller handles the OSPF protocol state.
Every public builder keeps the interface of the previous implementation.
"""

from scapy.contrib.ospf import (
    OSPFv3_DBDesc,
    OSPFv3_Hdr,
    OSPFv3_Hello,
    OSPFv3_LSA_Hdr,
    OSPFv3_LSAck,
    OSPFv3_LSReq,
    OSPFv3_LSReq_Item,
    OSPFv3_LSUpd,
)
from scapy.layers.inet6 import IPv6, in6_chksum
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from ospfv3 import config as cfg


OSPF_PROTOCOL = 89
ALL_SPF_ROUTERS = "ff02::5"
ALL_SPF_ROUTERS_MAC = "33:33:00:00:00:05"


def calculate_ospfv3_checksum(src_ipv6, dst_ipv6, ospf_packet):
    """Return the OSPFv3 checksum (caller provides zeroed checksum bytes)."""
    ipv6 = IPv6(src=src_ipv6, dst=dst_ipv6, nh=OSPF_PROTOCOL)
    return in6_chksum(OSPF_PROTOCOL, ipv6, ospf_packet)


def _serialize_ospf(pkt_type, payload, dst_ipv6):
    ipv6 = IPv6(
        src=cfg.LINK_LOCAL,
        dst=dst_ipv6,
        nh=OSPF_PROTOCOL,
        hlim=1,
    )
    ospf = OSPFv3_Hdr(
        type=pkt_type,
        src=cfg.ROUTER_ID,
        area=cfg.AREA_ID,
        instance=cfg.INSTANCE_ID,
    )

    # The IPv6 underlayer is required for Scapy's OSPFv3 checksum.
    return bytes(ipv6 / ospf / payload)[40:]


def build_ospfv3_packet(pkt_type, body, dst_ipv6):
    """Build an OSPFv3 packet from an already encoded packet body."""
    return _serialize_ospf(pkt_type, Raw(body), dst_ipv6)


def build_ospfv3_hello(neighbors=()):
    hello = OSPFv3_Hello(
        intid=cfg.INTERFACE_ID,
        prio=cfg.ROUTER_PRIORITY,
        options=cfg.OPTIONS,
        hellointerval=cfg.HELLO_INTERVAL,
        deadinterval=cfg.DEAD_INTERVAL,
        router="0.0.0.0",
        backup="0.0.0.0",
        neighbors=list(neighbors),
    )
    return _serialize_ospf(1, hello, ALL_SPF_ROUTERS)


def build_ospfv3_dbd(dd_sequence, flags=0x07):
    dbd = OSPFv3_DBDesc(
        options=cfg.OPTIONS,
        mtu=cfg.INTERFACE_MTU,
        dbdescr=flags,
        ddseq=dd_sequence,
        lsaheaders=[],
    )
    return _serialize_ospf(2, dbd, ALL_SPF_ROUTERS)


def build_ospfv3_lsr(lsa_requests, dst_ipv6):
    requests = [
        OSPFv3_LSReq_Item(
            type=lsa["ls_type"],
            id=lsa["link_state_id"],
            adrouter=lsa["advertising_router"],
        )
        for lsa in lsa_requests
    ]
    return _serialize_ospf(3, OSPFv3_LSReq(requests=requests), dst_ipv6)


def build_ospfv3_lsu(lsu_body, dst_ipv6):
    """Wrap the existing LS Update body; LSA encoding migrates separately."""
    if len(lsu_body) < 4:
        raise ValueError("LSU body must contain a 4-byte LSA count")

    count = int.from_bytes(lsu_body[:4], byteorder="big")
    lsu = OSPFv3_LSUpd(lsacount=count) / Raw(lsu_body[4:])
    return _serialize_ospf(4, lsu, dst_ipv6)


def build_ospfv3_lsack(lsa_headers, dst_ipv6):
    headers = [
        OSPFv3_LSA_Hdr(lsa["raw_header"])
        for lsa in lsa_headers
    ]
    return _serialize_ospf(5, OSPFv3_LSAck(lsaheaders=headers), dst_ipv6)


def build_ospfv3_frame(ospf_packet, dst_ipv6, dst_mac):
    """Encapsulate an already encoded OSPFv3 packet in Ethernet/IPv6."""
    return bytes(
        Ether(src=cfg.ROUTER_MAC, dst=dst_mac)
        / IPv6(
            src=cfg.LINK_LOCAL,
            dst=dst_ipv6,
            nh=OSPF_PROTOCOL,
            hlim=1,
        )
        / Raw(ospf_packet)
    )


def build_ospfv3_hello_frame(neighbors=()):
    return build_ospfv3_frame(
        build_ospfv3_hello(neighbors),
        ALL_SPF_ROUTERS,
        ALL_SPF_ROUTERS_MAC,
    )


def build_ospfv3_dbd_frame(dd_sequence, flags=0x07):
    return build_ospfv3_frame(
        build_ospfv3_dbd(dd_sequence, flags),
        ALL_SPF_ROUTERS,
        ALL_SPF_ROUTERS_MAC,
    )


def build_ospfv3_lsr_frame(lsa_requests, dst_ipv6, dst_mac):
    return build_ospfv3_frame(
        build_ospfv3_lsr(lsa_requests, dst_ipv6),
        dst_ipv6,
        dst_mac,
    )


def build_ospfv3_lsu_frame(lsu_body, dst_ipv6, dst_mac):
    return build_ospfv3_frame(
        build_ospfv3_lsu(lsu_body, dst_ipv6),
        dst_ipv6,
        dst_mac,
    )


def build_ospfv3_lsack_frame(lsa_headers, dst_ipv6, dst_mac):
    return build_ospfv3_frame(
        build_ospfv3_lsack(lsa_headers, dst_ipv6),
        dst_ipv6,
        dst_mac,
    )