import socket
import struct

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
