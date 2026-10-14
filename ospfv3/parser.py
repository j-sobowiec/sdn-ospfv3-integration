import socket
import struct

from ospfv3.lsa import (
    parse_ospfv3_router_lsa,
    parse_ospfv3_link_lsa,
    parse_ospfv3_intra_area_prefix_lsa,
)


def _router_id_text(value):
    return socket.inet_ntoa(
        struct.pack("!I", value)
    )


def _parse_lsa_header(raw_header, include_raw=False):
    if len(raw_header) != 20:
        raise ValueError(
            "LSA header must contain exactly 20 bytes"
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
        raw_header
    )

    result = {
        "ls_age": ls_age,
        "ls_type": ls_type,
        "link_state_id": _router_id_text(
            link_state_id
        ),
        "advertising_router": _router_id_text(
            advertising_router
        ),
        "ls_sequence": ls_sequence,
        "ls_checksum": ls_checksum,
        "ls_length": ls_length
    }

    if include_raw:
        result["raw_header"] = bytes(
            raw_header
        )

    return result


def parse_hello(ospf_data, pkt_len):
    if pkt_len < 36:
        raise ValueError(
            "packet is shorter than Hello header"
        )

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

    neighbor_data = ospf_data[36:pkt_len]

    if len(neighbor_data) % 4 != 0:
        raise ValueError(
            "invalid neighbor-list length="
            f"{len(neighbor_data)}"
        )

    neighbors = []

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
            _router_id_text(neighbor_id)
        )

    return {
        "interface_id": interface_id,
        "router_priority": router_priority,
        "options": options,
        "hello_interval": hello_interval,
        "dead_interval": dead_interval,
        "designated_router": designated_router,
        "backup_designated_router":
            backup_designated_router,
        "neighbors": neighbors
    }


def parse_dbd(ospf_data, pkt_len):
    if pkt_len < 28:
        raise ValueError(
            "packet is shorter than DBD header"
        )

    (
        reserved1,
        options_raw,
        interface_mtu,
        reserved2,
        flags,
        dd_sequence
    ) = struct.unpack(
        "!B3sHBBI",
        ospf_data[16:28]
    )

    options = int.from_bytes(
        options_raw,
        byteorder="big"
    )

    lsa_data = ospf_data[28:pkt_len]

    if len(lsa_data) % 20 != 0:
        raise ValueError(
            "invalid LSA-summary length="
            f"{len(lsa_data)}"
        )

    lsa_headers = []

    for offset in range(
        0,
        len(lsa_data),
        20
    ):
        lsa_headers.append(
            _parse_lsa_header(
                lsa_data[offset:offset + 20]
            )
        )

    return {
        "interface_mtu": interface_mtu,
        "options": options,
        "i_bit": bool(flags & 0x04),
        "m_bit": bool(flags & 0x02),
        "ms_bit": bool(flags & 0x01),
        "dd_sequence": dd_sequence,
        "lsa_headers": lsa_headers
    }


def parse_lsr(ospf_data, pkt_len):
    request_length = pkt_len - 16

    if (
        request_length <= 0
        or request_length % 12 != 0
    ):
        raise ValueError(
            "invalid payload length="
            f"{request_length}"
        )

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
            "link_state_id": _router_id_text(
                link_state_id
            ),
            "advertising_router":
                _router_id_text(
                    advertising_router
                )
        })

        offset += 12

    return requests


def parse_lsu(ospf_data, pkt_len):
    if pkt_len < 20:
        raise ValueError(
            "packet is shorter than LSU header"
        )

    number_of_lsas = struct.unpack(
        "!I",
        ospf_data[16:20]
    )[0]

    lsa_headers = []

    offset = 20

    for index in range(number_of_lsas):
        if offset + 20 > pkt_len:
            raise ValueError(
                "insufficient data for LSA "
                f"header #{index + 1}"
            )

        raw_header = bytes(
            ospf_data[offset:offset + 20]
        )

        lsa = _parse_lsa_header(
            raw_header,
            include_raw=True
        )

        ls_length = lsa["ls_length"]

        if ls_length < 20:
            raise ValueError(
                "invalid LSA length "
                f"#{index + 1}: {ls_length}"
            )

        if offset + ls_length > pkt_len:
            raise ValueError(
                f"LSA #{index + 1} exceeds "
                "packet boundary "
                f"(offset={offset} "
                f"length={ls_length} "
                f"packet={pkt_len})"
            )

        raw_lsa = bytes(
            ospf_data[
                offset:offset + ls_length
            ]
        )

        ls_type = lsa["ls_type"]

        if ls_type == 0x2001:
            try:
                lsa["router_lsa"] = (
                    parse_ospfv3_router_lsa(
                        raw_lsa
                    )
                )
            except ValueError as exc:
                raise ValueError(
                    "Router-LSA parse error "
                    f"#{index + 1}: {exc}"
                ) from exc

        elif ls_type == 0x0008:
            try:
                lsa["link_lsa"] = (
                    parse_ospfv3_link_lsa(
                        raw_lsa
                    )
                )
            except ValueError as exc:
                raise ValueError(
                    "Link-LSA parse error "
                    f"#{index + 1}: {exc}"
                ) from exc

        elif ls_type == 0x2009:
            try:
                lsa["intra_area_prefix_lsa"] = (
                    parse_ospfv3_intra_area_prefix_lsa(
                        raw_lsa
                    )
                )
            except ValueError as exc:
                raise ValueError(
                    "Intra-Area-Prefix-LSA "
                    "parse error "
                    f"#{index + 1}: {exc}"
                ) from exc

        lsa_headers.append(lsa)

        offset += ls_length

    if offset != pkt_len:
        raise ValueError(
            "length mismatch "
            f"parsed={offset} packet={pkt_len}"
        )

    return lsa_headers


def parse_lsack(ospf_data, pkt_len):
    ack_length = pkt_len - 16

    if (
        ack_length <= 0
        or ack_length % 20 != 0
    ):
        raise ValueError(
            "invalid payload length="
            f"{ack_length}"
        )

    headers = []

    offset = 16

    while offset < pkt_len:
        headers.append(
            _parse_lsa_header(
                ospf_data[offset:offset + 20]
            )
        )

        offset += 20

    return headers
