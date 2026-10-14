import time

from ospfv3 import config as cfg
from ospfv3.lsa import (
    compare_lsa_instances,
    ospfv3_lsa_type_description,
)


class LSDB:
    def __init__(self, logger):
        self.entries = {}
        self.logger = logger

    def __bool__(self):
        return bool(self.entries)

    def __len__(self):
        return len(self.entries)

    def values(self):
        return self.entries.values()

    def items(self):
        return self.entries.items()

    def get(self, key):
        return self.entries.get(key)

    def _install(self, lsa):
        entry = dict(lsa)

        entry["_age_base"] = lsa["ls_age"]
        entry["_age_timestamp"] = time.monotonic()

        return entry

    def get_age(self, lsa):
        base_age = lsa.get(
            "_age_base",
            lsa["ls_age"]
        )

        timestamp = lsa.get("_age_timestamp")

        if timestamp is None:
            return base_age

        elapsed = int(
            time.monotonic() - timestamp
        )

        return min(
            cfg.MAX_AGE,
            base_age + elapsed
        )

    def update(self, received_lsas):
        """
        Installs new LSAs and replaces an existing entry only
        when a newer instance is received.

        Returns True when the change affects routing.
        """
        routing_changed = False

        for received in received_lsas:
            key = (
                received["ls_type"],
                received["link_state_id"],
                received["advertising_router"]
            )

            current = self.entries.get(key)

            current_for_comparison = None

            if current is not None:
                current_for_comparison = dict(current)
                current_for_comparison["ls_age"] = self.get_age(current)

            if received["ls_age"] >= cfg.MAX_AGE:
                if current_for_comparison is not None:
                    comparison = compare_lsa_instances(
                        received,
                        current_for_comparison
                    )

                    if comparison >= 0:
                        del self.entries[key]

                        if received["ls_type"] in (0x2001, 0x2009):
                            routing_changed = True

                        self.logger.info(
                            "[OSPF][LSDB] flushed %s adv=%s lsid=%s",
                            ospfv3_lsa_type_description(
                                received["ls_type"]
                            ),
                            received["advertising_router"],
                            received["link_state_id"]
                        )

                continue

            if current is None:
                self.entries[key] = self._install(received)

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

            comparison = compare_lsa_instances(
                received,
                current_for_comparison
            )

            if comparison > 0:
                old_sequence = current["ls_sequence"]

                self.entries[key] = self._install(received)

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

        return routing_changed

    def purge_expired(self):
        """
        Removes LSAs that reached MaxAge.

        Returns True when the removal affects routing.
        """
        expired_keys = []
        routing_changed = False

        for key, lsa in self.entries.items():
            if self.get_age(lsa) >= cfg.MAX_AGE:
                expired_keys.append(key)

        for key in expired_keys:
            lsa = self.entries.pop(key)

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
                cfg.MAX_AGE
            )

        return routing_changed

    def clear_remote(self, local_router_id):
        removed = 0

        for key, lsa in list(self.entries.items()):
            if lsa.get("advertising_router") == local_router_id:
                continue

            del self.entries[key]
            removed += 1

        if removed:
            self.logger.info(
                "[OSPF][LSDB] cleared remote entries=%d",
                removed
            )

        return removed > 0