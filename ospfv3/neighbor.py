import time

from ospfv3.lsa import compare_lsa_instances


class Neighbor:
    def __init__(self, logger):
        self.logger = logger

        self.port = None
        self.router_id = None
        self.ipv6 = None
        self.mac = None

        self.router_ids = []

        self.dbd_sequence = self._new_dbd_sequence()
        self.dbd_negotiated = False
        self.dbd_exchange_complete = False

        self.request_list = []
        self.lsr_sent = False

    @staticmethod
    def _new_dbd_sequence():
        return int(
            time.time() * 1000
        ) & 0xffffffff

    def reset_exchange(self):
        old_sequence = self.dbd_sequence

        self.dbd_negotiated = False
        self.dbd_exchange_complete = False

        self.request_list = []
        self.lsr_sent = False

        self.dbd_sequence = self._new_dbd_sequence()

        if self.dbd_sequence == old_sequence:
            self.dbd_sequence = (
                old_sequence + 1
            ) & 0xffffffff

    def update_request_list(self, received_lsas):
        if not self.request_list:
            return

        remaining = []

        for request in self.request_list:
            satisfied = False

            for received in received_lsas:
                same_lsa = (
                    request["ls_type"]
                    == received["ls_type"]
                    and request["link_state_id"]
                    == received["link_state_id"]
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
                    satisfied = True
                    break

            if not satisfied:
                remaining.append(request)

        old_count = len(self.request_list)
        new_count = len(remaining)

        self.request_list = remaining

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

    def reset(self):
        self.port = None
        self.router_id = None
        self.ipv6 = None
        self.mac = None
        self.router_ids = []

        self.reset_exchange()