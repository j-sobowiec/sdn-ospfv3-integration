import socket
import struct

from scapy.contrib.ospf import (
    OSPFv3_Intra_Area_Prefix_LSA,
    OSPFv3_Link_LSA,
    OSPFv3_Router_LSA,
)

from ospfv3 import config as cfg


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


def _check_lsa_header(raw_lsa, expected_type, min_length, name):
    if len(raw_lsa) < min_length:
        raise ValueError(f"{name} is too short: {len(raw_lsa)} B")

    lsa_type = int.from_bytes(raw_lsa[2:4], "big")
    if lsa_type != expected_type:
        raise ValueError(f"{name}: unexpected LS Type=0x{lsa_type:04x}")

    declared_length = int.from_bytes(raw_lsa[18:20], "big")
    if declared_length != len(raw_lsa):
        raise ValueError(
            f"{name}: LS Length={declared_length}, "
            f"actual length={len(raw_lsa)}"
        )


def _check_prefixes(raw_lsa, count, start, name):
    """Validate on-wire entry boundaries before Scapy decodes the list."""
    remaining = len(raw_lsa) - start
    if count > remaining // 4:
        raise ValueError(f"{name}: prefix count exceeds available data")

    offset = start
    for index in range(count):
        if offset + 4 > len(raw_lsa):
            raise ValueError(f"{name}: insufficient data for prefix #{index + 1}")

        prefix_length = raw_lsa[offset]
        if prefix_length > 128:
            raise ValueError(f"{name}: invalid prefix length {prefix_length}")

        address_length = ((prefix_length + 31) // 32) * 4
        offset += 4 + address_length
        if offset > len(raw_lsa):
            raise ValueError(f"{name}: prefix #{index + 1} exceeds LSA boundary")

    if offset != len(raw_lsa):
        raise ValueError(f"{name}: trailing bytes after prefix list")


def _decode_lsa(lsa_class, raw_lsa, name):
    try:
        return lsa_class(bytes(raw_lsa))
    except Exception as exc:
        raise ValueError(f"{name}: Scapy decode error: {exc}") from exc


def _interface_id_text(value):
    return socket.inet_ntoa(struct.pack("!I", value))


def _ipv6_prefix_address(value):
    # Scapy's IP6PrefixField can expose a CIDR string or (address, length).
    if isinstance(value, tuple):
        value = value[0]
    address = str(value).split("/", 1)[0]
    return socket.inet_ntop(
        socket.AF_INET6, socket.inet_pton(socket.AF_INET6, address)
    )


def parse_ospfv3_router_lsa(raw_lsa):
    name = "Router-LSA"
    _check_lsa_header(raw_lsa, 0x2001, 24, name)

    link_length = len(raw_lsa) - 24
    if link_length % 16:
        raise ValueError(
            f"{name}: link description section has invalid length {link_length} B"
        )

    lsa = _decode_lsa(OSPFv3_Router_LSA, raw_lsa, name)
    if len(lsa.linklist) != link_length // 16:
        raise ValueError(f"{name}: inconsistent link descriptions")

    link_type_names = {
        1: "Point-to-Point",
        2: "Transit Network",
        3: "Reserved",
        4: "Virtual Link",
    }

    links = [
        {
            "type": int(link.type),
            "type_name": link_type_names.get(int(link.type), "Unknown"),
            "reserved": int(link.reserved),
            "metric": int(link.metric),
            "interface_id": _interface_id_text(link.intid),
            "neighbor_interface_id": _interface_id_text(link.neighintid),
            "neighbor_router_id": link.neighbor,
        }
        for link in lsa.linklist
    ]

    return {
        "flags": int(lsa.flags),
        "options": int(lsa.options),
        "links": links,
    }


def parse_ospfv3_link_lsa(raw_lsa):
    name = "Link-LSA"
    _check_lsa_header(raw_lsa, 0x0008, 44, name)

    prefix_count = int.from_bytes(raw_lsa[40:44], "big")
    _check_prefixes(raw_lsa, prefix_count, 44, name)

    lsa = _decode_lsa(OSPFv3_Link_LSA, raw_lsa, name)
    if len(lsa.prefixlist) != prefix_count:
        raise ValueError(f"{name}: inconsistent prefix count")

    prefixes = [
        {
            "prefix_length": int(item.prefixlen),
            "prefix_options": int(item.prefixoptions),
            # Scapy reuses the Prefix Item's metric field for this reserved word.
            "reserved": int(item.metric),
            "prefix": _ipv6_prefix_address(item.prefix),
        }
        for item in lsa.prefixlist
    ]

    return {
        "router_priority": int(lsa.prio),
        "options": int(lsa.options),
        "link_local_address": lsa.lladdr,
        "number_of_prefixes": int(lsa.prefixes),
        "prefixes": prefixes,
    }


def parse_ospfv3_intra_area_prefix_lsa(raw_lsa):
    name = "Intra-Area-Prefix-LSA"
    _check_lsa_header(raw_lsa, 0x2009, 32, name)

    prefix_count = int.from_bytes(raw_lsa[20:22], "big")
    _check_prefixes(raw_lsa, prefix_count, 32, name)

    lsa = _decode_lsa(OSPFv3_Intra_Area_Prefix_LSA, raw_lsa, name)
    if len(lsa.prefixlist) != prefix_count:
        raise ValueError(f"{name}: inconsistent prefix count")

    prefixes = [
        {
            "prefix": _ipv6_prefix_address(item.prefix),
            "prefix_length": int(item.prefixlen),
            "prefix_options": int(item.prefixoptions),
            "metric": int(item.metric),
        }
        for item in lsa.prefixlist
    ]

    return {
        "number_of_prefixes": int(lsa.prefixes),
        "referenced_ls_type": int(lsa.reflstype),
        "referenced_link_state_id": lsa.reflsid,
        "referenced_advertising_router": lsa.refadrouter,
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
        first_age == cfg.MAX_AGE
        and second_age != cfg.MAX_AGE
    ):
        return 1

    if (
        second_age == cfg.MAX_AGE
        and first_age != cfg.MAX_AGE
    ):
        return -1

    # 4. Duza roznica LS Age:
    # mlodsze LSA (mniejsze age) jest nowsze.
    if abs(first_age - second_age) > cfg.MAX_AGE_DIFF:

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

def next_ospfv3_lsa_sequence(sequence):
    """
    Returns the next valid OSPF LSA sequence number.

    Sequence numbers are stored as unsigned 32-bit values,
    but OSPF compares them as signed 32-bit integers.
    """

    if not 0 <= sequence <= 0xffffffff:
        raise ValueError(
            "OSPF LSA sequence number is outside uint32 range"
        )

    if sequence == 0x80000000:
        raise ValueError(
            "0x80000000 is a reserved OSPF LSA sequence number"
        )

    if sequence == 0x7fffffff:
        raise ValueError(
            "OSPF LSA sequence number reached MaxSequenceNumber"
        )

    return (sequence + 1) & 0xffffffff

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
