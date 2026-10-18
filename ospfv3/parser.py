"""Decode OSPFv3 packets into the dictionaries used by the controller."""

from ipaddress import IPv4Address
import struct

from scapy.contrib.ospf import (
    OSPFv3_DBDesc,
    OSPFv3_Hdr,
    OSPFv3_Hello,
    OSPFv3_LSA_Hdr,
    OSPFv3_LSAck,
    OSPFv3_LSReq,
    OSPFv3_LSUpd,
)
from scapy.error import Scapy_Exception

from ospfv3.lsa import (
    parse_ospfv3_router_lsa,
    parse_ospfv3_link_lsa,
    parse_ospfv3_intra_area_prefix_lsa,
    ospfv3_lsa_checksum,
)


def _packet_bytes(ospf_data, pkt_len, minimum_length):
    """Limit Scapy to the declared OSPF length (excluding Ethernet padding)."""
    if pkt_len < minimum_length:
        raise ValueError(f"packet is shorter than {minimum_length} bytes")
    if len(ospf_data) < pkt_len:
        raise ValueError(
            f"truncated OSPF packet: declared={pkt_len} available={len(ospf_data)}"
        )
    if len(ospf_data) < 16:
        raise ValueError("packet is shorter than OSPF header")
    if int.from_bytes(ospf_data[2:4], "big") != pkt_len:
        raise ValueError("OSPF header length differs from pkt_len")
    return bytes(ospf_data[:pkt_len])


def _decode_packet(ospf_data, pkt_len, minimum_length, packet_class):
    raw_packet = _packet_bytes(ospf_data, pkt_len, minimum_length)
    try:
        packet = OSPFv3_Hdr(raw_packet)
        if not isinstance(packet.payload, packet_class):
            raise ValueError(f"expected {packet_class.__name__} payload")
        return packet.payload
    except (Scapy_Exception, struct.error, IndexError, TypeError) as exc:
        raise ValueError(f"unable to decode OSPFv3 packet: {exc}") from exc


def _lsa_header_fields(header):
    return {
        "ls_age": int(header.age),
        "ls_type": int(header.type),
        "link_state_id": header.id,
        "advertising_router": header.adrouter,
        "ls_sequence": int(header.seq),
        "ls_checksum": int(header.chksum),
        "ls_length": int(header.len),
    }


def _parse_lsa_header(raw_header, include_raw=False):
    if len(raw_header) != 20:
        raise ValueError("LSA header must contain exactly 20 bytes")

    try:
        header = OSPFv3_LSA_Hdr(bytes(raw_header))
    except (Scapy_Exception, struct.error, IndexError, ValueError, TypeError) as exc:
        raise ValueError(f"invalid LSA header: {exc}") from exc

    result = _lsa_header_fields(header)
    if include_raw:
        result["raw_header"] = bytes(raw_header)
    return result


def parse_hello(ospf_data, pkt_len):
    raw = _packet_bytes(ospf_data, pkt_len, 36)
    if (pkt_len - 36) % 4 != 0:
        raise ValueError(f"invalid neighbor-list length={pkt_len - 36}")

    hello = _decode_packet(raw, pkt_len, 36, OSPFv3_Hello)
    neighbors = list(hello.neighbors)
    if len(neighbors) != (pkt_len - 36) // 4:
        raise ValueError("Hello neighbor count does not match payload length")

    return {
        "interface_id": int(hello.intid),
        "router_priority": int(hello.prio),
        "options": int(hello.options),
        "hello_interval": int(hello.hellointerval),
        "dead_interval": int(hello.deadinterval),
        # The existing controller receives DR/BDR as 32-bit integers.
        "designated_router": int(IPv4Address(hello.router)),
        "backup_designated_router": int(IPv4Address(hello.backup)),
        "neighbors": neighbors,
    }


def parse_dbd(ospf_data, pkt_len):
    raw = _packet_bytes(ospf_data, pkt_len, 28)
    if (pkt_len - 28) % 20 != 0:
        raise ValueError(f"invalid LSA-summary length={pkt_len - 28}")

    dbd = _decode_packet(raw, pkt_len, 28, OSPFv3_DBDesc)
    # The field list is decoded by Scapy with the OSPF header as underlayer.
    lsa_headers = list(dbd.lsaheaders or ())
    if len(lsa_headers) != (pkt_len - 28) // 20:
        raise ValueError("DBD summary count does not match payload length")
    headers = [_lsa_header_fields(header) for header in lsa_headers]
    flags = int(dbd.dbdescr)

    return {
        "interface_mtu": int(dbd.mtu),
        "options": int(dbd.options),
        "i_bit": bool(flags & 0x04),
        "m_bit": bool(flags & 0x02),
        "ms_bit": bool(flags & 0x01),
        "dd_sequence": int(dbd.ddseq),
        "lsa_headers": headers,
    }


def parse_lsr(ospf_data, pkt_len):
    raw = _packet_bytes(ospf_data, pkt_len, 16)
    request_length = pkt_len - 16
    if request_length <= 0 or request_length % 12 != 0:
        raise ValueError(f"invalid payload length={request_length}")

    requests_packet = _decode_packet(raw, pkt_len, 28, OSPFv3_LSReq)
    requests = list(requests_packet.requests or ())
    if len(requests) != request_length // 12:
        raise ValueError("LSR item count does not match payload length")

    return [
        {
            "ls_type": int(item.type),
            "link_state_id": item.id,
            "advertising_router": item.adrouter,
        }
        for item in requests
    ]


def parse_lsu(ospf_data, pkt_len):
    raw = _packet_bytes(ospf_data, pkt_len, 20)
    # Decode only the Scapy count field. Decoding the full Scapy LSUpd list
    # here could interpret unsupported LSA types differently from lsa.py.
    try:
        remainder, number_of_lsas = OSPFv3_LSUpd.fields_desc[0].getfield(
            None, raw[16:20]
        )
    except (Scapy_Exception, struct.error, IndexError, ValueError, TypeError) as exc:
        raise ValueError(f"invalid LSU LSA count: {exc}") from exc
    if remainder:
        raise ValueError("invalid LSU count field length")

    lsa_headers = []
    offset = 20

    for index in range(number_of_lsas):
        if offset + 20 > pkt_len:
            raise ValueError(f"insufficient data for LSA header #{index + 1}")

        raw_header = raw[offset:offset + 20]
        lsa = _parse_lsa_header(raw_header, include_raw=True)
        ls_length = lsa["ls_length"]
        if ls_length < 20:
            raise ValueError(f"invalid LSA length #{index + 1}: {ls_length}")
        if offset + ls_length > pkt_len:
            raise ValueError(
                f"LSA #{index + 1} exceeds packet boundary "
                f"(offset={offset} length={ls_length} packet={pkt_len})"
            )

        raw_lsa = raw[offset:offset + ls_length]

        # Verify each complete LSA before decoding or exposing it to the LSDB.
        # Fletcher covers the LSA header and body, but not LS Age (bytes 0-1).
        expected_checksum = ospfv3_lsa_checksum(raw_lsa)
        if lsa["ls_checksum"] != expected_checksum:
            raise ValueError(
                f"invalid LSA checksum #{index + 1}: "
                f"received=0x{lsa['ls_checksum']:04x}, "
                f"calculated=0x{expected_checksum:04x}"
            )

        ls_type = lsa["ls_type"]

        if ls_type == 0x2001:
            try:
                lsa["router_lsa"] = parse_ospfv3_router_lsa(raw_lsa)
            except ValueError as exc:
                raise ValueError(f"Router-LSA parse error #{index + 1}: {exc}") from exc
        elif ls_type == 0x0008:
            try:
                lsa["link_lsa"] = parse_ospfv3_link_lsa(raw_lsa)
            except ValueError as exc:
                raise ValueError(f"Link-LSA parse error #{index + 1}: {exc}") from exc
        elif ls_type == 0x2009:
            try:
                lsa["intra_area_prefix_lsa"] = parse_ospfv3_intra_area_prefix_lsa(
                    raw_lsa
                )
            except ValueError as exc:
                raise ValueError(
                    f"Intra-Area-Prefix-LSA parse error #{index + 1}: {exc}"
                ) from exc

        lsa_headers.append(lsa)
        offset += ls_length

    if offset != pkt_len:
        raise ValueError(f"length mismatch parsed={offset} packet={pkt_len}")

    return lsa_headers


def parse_lsack(ospf_data, pkt_len):
    raw = _packet_bytes(ospf_data, pkt_len, 16)
    ack_length = pkt_len - 16
    if ack_length <= 0 or ack_length % 20 != 0:
        raise ValueError(f"invalid payload length={ack_length}")

    ack = _decode_packet(raw, pkt_len, 36, OSPFv3_LSAck)
    headers = list(ack.lsaheaders or ())
    if len(headers) != ack_length // 20:
        raise ValueError("LSAck header count does not match payload length")
    return [_lsa_header_fields(header) for header in headers]
