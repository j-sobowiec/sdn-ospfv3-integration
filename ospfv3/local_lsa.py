import ipaddress
import socket
import struct
import time

from scapy.contrib.ospf import (
    OSPFv3_Intra_Area_Prefix_LSA,
    OSPFv3_Link,
    OSPFv3_Link_LSA,
    OSPFv3_Prefix_Item,
    OSPFv3_Router_LSA,
)

from ospfv3 import config as cfg
from ospfv3.lsa import (
    finalize_ospfv3_lsa_checksum,
    next_ospfv3_lsa_sequence,
    ospfv3_lsa_type_description,
    lsa_sequence_signed,
)


class LocalLSA:
    def __init__(self, lsdb, logger):
        self.lsdb = lsdb
        self.logger = logger

        self.entries = {}

        self.router_sequence = cfg.INITIAL_SEQUENCE
        self.link_sequence = cfg.INITIAL_SEQUENCE
        self.prefix_sequence = cfg.INITIAL_SEQUENCE

    def __bool__(self):
        return bool(self.entries)

    def __len__(self):
        return len(self.entries)

    def get(self, key):
        return self.entries.get(key)

    def items(self):
        return self.entries.items()

    def values(self):
        return self.entries.values()

    def clear(self):
        self.entries.clear()

    def recover_sequences(
        self,
        lsa_headers,
        prepare_next
    ):
        """
        Recovers sequence state from self-originated LSA summaries
        learned from an OSPF neighbor.

        When local LSAs do not exist yet, prepare_next=True makes
        the next locally originated instance newer than the copy
        stored by the neighbor.

        When local LSAs already exist, prepare_next=False only moves
        the sequence floor forward. A later reorigination performs
        the actual increment.
        """

        interface_lsid = socket.inet_ntoa(
            struct.pack(
                "!I",
                cfg.INTERFACE_ID
            )
        )

        changed = False
        recovered = 0

        for lsa in lsa_headers:
            if (
                lsa["advertising_router"]
                != cfg.ROUTER_ID
            ):
                continue

            sequence_attribute = None

            if (
                lsa["ls_type"] == 0x2001
                and lsa["link_state_id"] == "0.0.0.0"
            ):
                sequence_attribute = "router_sequence"

            elif (
                lsa["ls_type"] == 0x0008
                and lsa["link_state_id"] == interface_lsid
            ):
                sequence_attribute = "link_sequence"

            elif (
                lsa["ls_type"] == 0x2009
                and lsa["link_state_id"] == "0.0.0.0"
            ):
                sequence_attribute = "prefix_sequence"

            if sequence_attribute is None:
                continue

            observed_sequence = lsa["ls_sequence"]
            candidate_sequence = observed_sequence

            if prepare_next:
                try:
                    candidate_sequence = (
                        next_ospfv3_lsa_sequence(
                            observed_sequence
                        )
                    )
                except ValueError as exc:
                    self.logger.warning(
                        "[OSPF][SELF LSA] "
                        "cannot recover sequence: %s",
                        exc
                    )
                    continue

            current_sequence = getattr(
                self,
                sequence_attribute
            )

            if (
                lsa_sequence_signed(candidate_sequence)
                > lsa_sequence_signed(current_sequence)
            ):
                setattr(
                    self,
                    sequence_attribute,
                    candidate_sequence
                )

                changed = True

            recovered += 1

            self.logger.info(
                "[OSPF][SELF LSA] recovered "
                "type=0x%04x lsid=%s "
                "observed=0x%08x prepared=0x%08x",
                lsa["ls_type"],
                lsa["link_state_id"],
                observed_sequence,
                getattr(
                    self,
                    sequence_attribute
                )
            )

        return changed, recovered

    def get_neighbor_interface_id(self, neighbor_router_id):
        if neighbor_router_id is None:
            return None

        local_interface_id = socket.inet_ntoa(
            struct.pack("!I", cfg.INTERFACE_ID)
        )

        for lsa in self.lsdb.values():
            if lsa["ls_type"] != 0x2001:
                continue

            if lsa["advertising_router"] != neighbor_router_id:
                continue

            router_lsa = lsa.get("router_lsa")

            if router_lsa is None:
                continue

            for link in router_lsa["links"]:
                if link["type"] != 1:
                    continue

                if link["neighbor_router_id"] != cfg.ROUTER_ID:
                    continue

                if link["neighbor_interface_id"] != local_interface_id:
                    continue

                return struct.unpack(
                    "!I",
                    socket.inet_aton(link["interface_id"])
                )[0]

        return None

    def build_router(self, neighbor_router_id):
        if neighbor_router_id is None:
            self.logger.warning(
                "[OSPF][LOCAL LSA] cannot build Router-LSA: "
                "neighbor Router ID is unknown"
            )
            return None

        neighbor_interface_id = self.get_neighbor_interface_id(
            neighbor_router_id
        )

        if neighbor_interface_id is None:
            self.logger.warning(
                "[OSPF][LOCAL LSA] cannot build Router-LSA: "
                "neighbor Interface ID is unknown"
            )
            return None

        lsa = OSPFv3_Router_LSA(
            age=0,
            type=0x2001,
            id="0.0.0.0",
            adrouter=cfg.ROUTER_ID,
            seq=self.router_sequence,
            chksum=0,
            flags=0,
            options=cfg.OPTIONS,
            linklist=[
                OSPFv3_Link(
                    type=1,
                    reserved=0,
                    metric=cfg.INTERFACE_COST,
                    intid=cfg.INTERFACE_ID,
                    neighintid=neighbor_interface_id,
                    neighbor=neighbor_router_id,
                )
            ],
        )

        return finalize_ospfv3_lsa_checksum(bytes(lsa))

    def build_prefix(self):
        network = ipaddress.IPv6Network(
            f"{cfg.LAN_PREFIX}/{cfg.LAN_PREFIX_LEN}",
            strict=False,
        )

        lsa = OSPFv3_Intra_Area_Prefix_LSA(
            age=0,
            type=0x2009,
            id="0.0.0.0",
            adrouter=cfg.ROUTER_ID,
            seq=self.prefix_sequence,
            chksum=0,
            prefixes=1,
            reflstype=0x2001,
            reflsid="0.0.0.0",
            refadrouter=cfg.ROUTER_ID,
            prefixlist=[
                OSPFv3_Prefix_Item(
                    prefixlen=cfg.LAN_PREFIX_LEN,
                    prefixoptions=0,
                    metric=cfg.LAN_PREFIX_METRIC,
                    prefix=f"{network.network_address}/{cfg.LAN_PREFIX_LEN}",
                )
            ],
        )

        return finalize_ospfv3_lsa_checksum(bytes(lsa))

    def build_link(self):
        network = ipaddress.IPv6Network(
            f"{cfg.TRANSIT_PREFIX}/{cfg.TRANSIT_PREFIX_LEN}",
            strict=False,
        )

        interface_lsid = socket.inet_ntoa(
            struct.pack("!I", cfg.INTERFACE_ID)
        )

        lsa = OSPFv3_Link_LSA(
            age=0,
            type=0x0008,
            id=interface_lsid,
            adrouter=cfg.ROUTER_ID,
            seq=self.link_sequence,
            chksum=0,
            prio=cfg.ROUTER_PRIORITY,
            options=cfg.OPTIONS,
            lladdr=cfg.LINK_LOCAL,
            prefixes=1,
            prefixlist=[
                OSPFv3_Prefix_Item(
                    prefixlen=cfg.TRANSIT_PREFIX_LEN,
                    prefixoptions=0,
                    metric=0,
                    prefix=f"{network.network_address}/{cfg.TRANSIT_PREFIX_LEN}",
                )
            ],
        )

        return finalize_ospfv3_lsa_checksum(bytes(lsa))

    def install(self, raw_lsa):
        if len(raw_lsa) < 20:
            raise ValueError(
                "Local LSA is too short"
            )

        (
            ls_age,
            ls_type,
            link_state_id,
            advertising_router,
            sequence,
            checksum,
            length
        ) = struct.unpack(
            "!HHIIIHH",
            raw_lsa[:20]
        )

        link_state_id = socket.inet_ntoa(
            struct.pack("!I", link_state_id)
        )

        advertising_router = socket.inet_ntoa(
            struct.pack("!I", advertising_router)
        )

        key = (
            ls_type,
            link_state_id,
            advertising_router
        )

        self.entries[key] = {
            "ls_age": ls_age,
            "ls_type": ls_type,
            "link_state_id": link_state_id,
            "advertising_router": advertising_router,
            "ls_sequence": sequence,
            "ls_checksum": checksum,
            "ls_length": length,
            "raw_lsa": raw_lsa,
            "_originated_at": time.monotonic()
        }

    def initialize(self, neighbor_router_id):
        if self.entries:
            return True

        if self.get_neighbor_interface_id(
            neighbor_router_id
        ) is None:
            return False

        router_lsa = self.build_router(
            neighbor_router_id
        )

        if router_lsa is None:
            return False

        self.install(router_lsa)
        self.install(self.build_link())
        self.install(self.build_prefix())

        self.logger.info(
            "[OSPF][LOCAL LSDB] initialized entries=%d",
            len(self.entries)
        )

        for _, lsa in sorted(
            self.entries.items(),
            key=lambda item: item[0]
        ):
            self.logger.info(
                "  -> %s adv=%s lsid=%s "
                "seq=0x%08x checksum=0x%04x length=%d",
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["advertising_router"],
                lsa["link_state_id"],
                lsa["ls_sequence"],
                lsa["ls_checksum"],
                lsa["ls_length"]
            )

        return True

    def build_update_body(self):
        if not self.entries:
            return None

        lsas = [
            entry["raw_lsa"]
            for _, entry in sorted(
                self.entries.items(),
                key=lambda item: item[0]
            )
        ]

        return (
            struct.pack("!I", len(lsas))
            + b"".join(lsas)
        )

    def build_pending_body(self, pending):
        if not pending:
            return None

        lsas = []

        for key in sorted(pending):
            local_lsa = self.entries.get(key)
            pending_lsa = pending[key]

            if local_lsa is None:
                continue

            same_instance = (
                local_lsa["ls_sequence"]
                == pending_lsa["ls_sequence"]
                and local_lsa["ls_checksum"]
                == pending_lsa["ls_checksum"]
            )

            if same_instance:
                lsas.append(
                    local_lsa["raw_lsa"]
                )

        if not lsas:
            return None

        body = (
            struct.pack("!I", len(lsas))
            + b"".join(lsas)
        )

        return body, len(lsas)

    def reoriginate(self, neighbor_router_id, reason):
        if not self.entries:
            self.logger.warning(
                "[OSPF][REORIGINATE] local LSDB is empty"
            )
            return False

        if self.get_neighbor_interface_id(
            neighbor_router_id
        ) is None:
            self.logger.warning(
                "[OSPF][REORIGINATE] "
                "neighbor interface ID unavailable"
            )
            return False

        self.router_sequence = (
            next_ospfv3_lsa_sequence(
                self.router_sequence
            )
        )

        self.link_sequence = (
            next_ospfv3_lsa_sequence(
                self.link_sequence
            )
        )

        self.prefix_sequence = (
            next_ospfv3_lsa_sequence(
                self.prefix_sequence
            )
        )

        router_lsa = self.build_router(
            neighbor_router_id
        )

        if router_lsa is None:
            return False

        link_lsa = self.build_link()
        prefix_lsa = self.build_prefix()

        self.entries.clear()

        self.install(router_lsa)
        self.install(link_lsa)
        self.install(prefix_lsa)

        self.logger.info(
            "[OSPF][REORIGINATE] reason=%s entries=%d",
            reason,
            len(self.entries)
        )

        for _, lsa in sorted(
            self.entries.items(),
            key=lambda item: item[0]
        ):
            self.logger.info(
                "  -> %s adv=%s lsid=%s "
                "seq=0x%08x checksum=0x%04x",
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["advertising_router"],
                lsa["link_state_id"],
                lsa["ls_sequence"],
                lsa["ls_checksum"]
            )

        return True
