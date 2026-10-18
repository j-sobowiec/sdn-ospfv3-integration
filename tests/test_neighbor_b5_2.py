"""B5.2: deterministic unit tests of the existing OSPFv3 Neighbor state.

Uses the real Neighbor class and the real compare_lsa_instances helper.
No FRR/Containernet/Ryu instance is started and no production files are modified.
Fixtures represent *already parsed and validated* LSA headers (as delivered by
ospfv3.parser), not raw wire packets.

Run from the project root:
    python -m unittest discover -s tests -p 'test_neighbor_b5_2.py' -v
"""

import copy
import logging
import random
import unittest
from unittest.mock import Mock, patch

from ospfv3 import config as cfg
from ospfv3.lsa import compare_lsa_instances
from ospfv3.neighbor import Neighbor

S0 = cfg.INITIAL_SEQUENCE
R1, R2, R3 = "1.1.1.1", "2.2.2.2", "3.3.3.3"


def summary(*, ls_type=0x2001, lsid="0.0.0.0", adv=R1,
            seq=S0, checksum=0x1111, age=100):
    """Return only the fields used by Neighbor.update_request_list()."""
    return {
        "ls_type": ls_type,
        "link_state_id": lsid,
        "advertising_router": adv,
        "ls_sequence": seq,
        "ls_checksum": checksum,
        "ls_age": age,
    }


def identify(lsa):
    return (lsa["ls_type"], lsa["link_state_id"], lsa["advertising_router"])


class NeighborBase(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)
        self.neighbor = Neighbor(self.logger)

    def set_peer(self):
        n = self.neighbor
        n.port = 7
        n.router_id = R1
        n.ipv6 = "fe80::1"
        n.mac = "02:00:00:00:00:aa"
        n.router_ids = [R1, R2]
        n.last_hello_received = 100.0
        n.dbd_negotiated = True
        n.dbd_exchange_complete = True
        n.request_list = [summary()]
        n.lsr_sent = True
        return n


class TestInitialization(NeighborBase):
    def test_peer_identity_starts_empty(self):
        n = self.neighbor
        self.assertIsNone(n.port)
        self.assertIsNone(n.router_id)
        self.assertIsNone(n.ipv6)
        self.assertIsNone(n.mac)
        self.assertEqual(n.router_ids, [])
        self.assertIsNone(n.last_hello_received)

    def test_exchange_flags_and_requests_start_empty(self):
        n = self.neighbor
        self.assertFalse(n.dbd_negotiated)
        self.assertFalse(n.dbd_exchange_complete)
        self.assertFalse(n.lsr_sent)
        self.assertEqual(n.request_list, [])

    def test_logger_identity_preserved(self):
        self.assertIs(self.neighbor.logger, self.logger)

    def test_initial_dbd_sequence_uses_millisecond_clock(self):
        with patch("ospfv3.neighbor.time.time", return_value=1234.567):
            sequence = Neighbor._new_dbd_sequence()
        self.assertEqual(sequence, int(1234.567 * 1000))

    def test_dbd_sequence_is_unsigned_32_bit(self):
        with patch("ospfv3.neighbor.time.time", return_value=4_300_000.0):
            sequence = Neighbor._new_dbd_sequence()
        self.assertEqual(sequence, 4_300_000_000 & 0xffffffff)
        self.assertTrue(0 <= sequence <= 0xffffffff)

    def test_instances_do_not_share_neighbor_lists(self):
        other = Neighbor(Mock(spec=logging.Logger))
        self.neighbor.router_ids.append(R1)
        self.neighbor.request_list.append(summary())
        self.assertEqual(other.router_ids, [])
        self.assertEqual(other.request_list, [])


class TestHelloDeadTimer(NeighborBase):
    def test_no_hello_never_expires_even_if_clock_advances(self):
        with patch("ospfv3.neighbor.time.monotonic", return_value=999999.0):
            self.assertFalse(self.neighbor.dead_interval_expired(cfg.DEAD_INTERVAL))

    def test_mark_hello_records_monotonic_not_wall_clock(self):
        with patch("ospfv3.neighbor.time.monotonic", return_value=145.25):
            self.neighbor.mark_hello_received()
        self.assertEqual(self.neighbor.last_hello_received, 145.25)

    def test_dead_interval_not_expired_immediately_after_hello(self):
        with patch("ospfv3.neighbor.time.monotonic", return_value=100.0):
            self.neighbor.mark_hello_received()
            self.assertFalse(self.neighbor.dead_interval_expired(cfg.DEAD_INTERVAL))

    def test_dead_interval_not_expired_just_before_boundary(self):
        self.neighbor.last_hello_received = 100.0
        with patch("ospfv3.neighbor.time.monotonic", return_value=100.0 + cfg.DEAD_INTERVAL - 0.001):
            self.assertFalse(self.neighbor.dead_interval_expired(cfg.DEAD_INTERVAL))

    def test_dead_interval_expires_at_exact_boundary(self):
        self.neighbor.last_hello_received = 100.0
        with patch("ospfv3.neighbor.time.monotonic", return_value=100.0 + cfg.DEAD_INTERVAL):
            self.assertTrue(self.neighbor.dead_interval_expired(cfg.DEAD_INTERVAL))

    def test_dead_interval_expires_after_boundary(self):
        self.neighbor.last_hello_received = 100.0
        with patch("ospfv3.neighbor.time.monotonic", return_value=100.0 + cfg.DEAD_INTERVAL + 99):
            self.assertTrue(self.neighbor.dead_interval_expired(cfg.DEAD_INTERVAL))

    def test_new_hello_refreshes_dead_timer(self):
        self.neighbor.last_hello_received = 100.0
        with patch("ospfv3.neighbor.time.monotonic", return_value=100.0 + cfg.DEAD_INTERVAL - 1):
            self.neighbor.mark_hello_received()
        with patch("ospfv3.neighbor.time.monotonic", return_value=100.0 + cfg.DEAD_INTERVAL + 1):
            self.assertFalse(self.neighbor.dead_interval_expired(cfg.DEAD_INTERVAL))

    def test_expiration_check_is_predicate_without_implicit_reset(self):
        n = self.set_peer()
        with patch("ospfv3.neighbor.time.monotonic", return_value=100.0 + cfg.DEAD_INTERVAL):
            self.assertTrue(n.dead_interval_expired(cfg.DEAD_INTERVAL))
        self.assertEqual(n.router_id, R1)
        self.assertTrue(n.dbd_negotiated)
        self.assertEqual(n.request_list, [summary()])

    def test_reset_adjacency_disables_expiration_until_next_hello(self):
        self.set_peer()
        self.neighbor.reset_adjacency()
        with patch("ospfv3.neighbor.time.monotonic", return_value=999.0):
            self.assertFalse(self.neighbor.dead_interval_expired(cfg.DEAD_INTERVAL))


class TestDBDExchangeReset(NeighborBase):
    def test_reset_exchange_clears_all_exchange_state(self):
        n = self.set_peer()
        with patch.object(Neighbor, "_new_dbd_sequence", return_value=0x12345678):
            n.reset_exchange()
        self.assertFalse(n.dbd_negotiated)
        self.assertFalse(n.dbd_exchange_complete)
        self.assertFalse(n.lsr_sent)
        self.assertEqual(n.request_list, [])
        self.assertEqual(n.dbd_sequence, 0x12345678)

    def test_reset_exchange_preserves_peer_identity_port_and_hello(self):
        n = self.set_peer()
        n.reset_exchange()
        self.assertEqual((n.port, n.router_id, n.ipv6, n.mac),
                         (7, R1, "fe80::1", "02:00:00:00:00:aa"))
        self.assertEqual(n.router_ids, [R1, R2])
        self.assertEqual(n.last_hello_received, 100.0)

    def test_reset_exchange_same_clock_sequence_increments(self):
        n = self.set_peer()
        n.dbd_sequence = 0x12345678
        with patch.object(Neighbor, "_new_dbd_sequence", return_value=0x12345678):
            n.reset_exchange()
        self.assertEqual(n.dbd_sequence, 0x12345679)

    def test_reset_exchange_equal_max_sequence_wraps_to_zero(self):
        n = self.set_peer()
        n.dbd_sequence = 0xffffffff
        with patch.object(Neighbor, "_new_dbd_sequence", return_value=0xffffffff):
            n.reset_exchange()
        self.assertEqual(n.dbd_sequence, 0)

    def test_reset_exchange_different_clock_sequence_kept(self):
        n = self.set_peer()
        n.dbd_sequence = 5
        with patch.object(Neighbor, "_new_dbd_sequence", return_value=9):
            n.reset_exchange()
        self.assertEqual(n.dbd_sequence, 9)

    def test_reset_exchange_clears_requests_without_mutating_old_list(self):
        n = self.set_peer()
        old_list = n.request_list
        n.reset_exchange()
        self.assertIsNot(n.request_list, old_list)
        self.assertEqual(len(old_list), 1)
        self.assertEqual(n.request_list, [])


class TestRequestListIdentity(NeighborBase):
    def test_empty_request_list_is_noop_and_does_not_log(self):
        self.neighbor.update_request_list([summary()])
        self.assertEqual(self.neighbor.request_list, [])
        self.logger.info.assert_not_called()

    def test_no_received_lsas_keeps_request(self):
        req = summary()
        self.neighbor.request_list = [req]
        self.neighbor.update_request_list([])
        self.assertEqual(self.neighbor.request_list, [req])
        self.logger.info.assert_not_called()

    def test_different_ls_type_does_not_satisfy(self):
        self.neighbor.request_list = [summary()]
        self.neighbor.update_request_list([summary(ls_type=0x2009)])
        self.assertEqual(len(self.neighbor.request_list), 1)

    def test_different_lsid_does_not_satisfy(self):
        self.neighbor.request_list = [summary()]
        self.neighbor.update_request_list([summary(lsid="0.0.0.1")])
        self.assertEqual(len(self.neighbor.request_list), 1)

    def test_different_advertiser_does_not_satisfy(self):
        self.neighbor.request_list = [summary()]
        self.neighbor.update_request_list([summary(adv=R2)])
        self.assertEqual(len(self.neighbor.request_list), 1)

    def test_mismatched_lsa_never_reaches_instance_comparator(self):
        self.neighbor.request_list = [summary()]
        with patch("ospfv3.neighbor.compare_lsa_instances", side_effect=AssertionError("unexpected compare")):
            self.neighbor.update_request_list([
                summary(ls_type=0x0008), summary(adv=R2), summary(lsid="0.0.0.2")
            ])
        self.assertEqual(len(self.neighbor.request_list), 1)

    def test_unknown_lsa_type_can_be_matched_by_three_field_identity(self):
        self.neighbor.request_list = [summary(ls_type=0x200b)]
        self.neighbor.update_request_list([summary(ls_type=0x200b)])
        self.assertEqual(self.neighbor.request_list, [])


class TestRequestListInstanceOrdering(NeighborBase):
    def expect_remaining(self, request, received, *, remaining):
        self.neighbor.request_list = [request]
        self.neighbor.update_request_list([received])
        self.assertEqual(len(self.neighbor.request_list), 1 if remaining else 0)

    def test_same_instance_satisfies(self):
        self.expect_remaining(summary(), summary(), remaining=False)

    def test_newer_sequence_satisfies_even_with_lower_checksum(self):
        self.expect_remaining(summary(seq=S0, checksum=0xffff),
                              summary(seq=S0 + 1, checksum=0), remaining=False)

    def test_older_sequence_does_not_satisfy_even_with_higher_checksum(self):
        self.expect_remaining(summary(seq=S0 + 1, checksum=0),
                              summary(seq=S0, checksum=0xffff), remaining=True)

    def test_higher_checksum_at_same_sequence_satisfies(self):
        self.expect_remaining(summary(checksum=0x1111),
                              summary(checksum=0x1112), remaining=False)

    def test_lower_checksum_at_same_sequence_does_not_satisfy(self):
        self.expect_remaining(summary(checksum=0x1112),
                              summary(checksum=0x1111), remaining=True)

    def test_equal_sequence_checksum_small_age_difference_satisfies(self):
        self.expect_remaining(summary(age=100), summary(age=200), remaining=False)

    def test_equal_sequence_checksum_maxage_is_newer(self):
        self.expect_remaining(summary(age=100), summary(age=cfg.MAX_AGE), remaining=False)

    def test_equal_sequence_checksum_old_age_cannot_beat_requested_maxage(self):
        self.expect_remaining(summary(age=cfg.MAX_AGE), summary(age=100), remaining=True)

    def test_large_age_difference_younger_received_satisfies(self):
        self.expect_remaining(summary(age=cfg.MAX_AGE_DIFF + 110), summary(age=100),
                              remaining=False)

    def test_large_age_difference_older_received_does_not_satisfy(self):
        self.expect_remaining(summary(age=100), summary(age=cfg.MAX_AGE_DIFF + 110),
                              remaining=True)

    def test_age_difference_at_exact_threshold_is_equivalent(self):
        self.expect_remaining(summary(age=100), summary(age=100 + cfg.MAX_AGE_DIFF),
                              remaining=False)

    def test_signed_sequence_ordering_satisfies_newer_positive_number(self):
        self.expect_remaining(summary(seq=0x80000001), summary(seq=0x7fffffff),
                              remaining=False)

    def test_signed_sequence_ordering_rejects_older_negative_number(self):
        self.expect_remaining(summary(seq=0x7fffffff), summary(seq=0x80000001),
                              remaining=True)


class TestRequestListBatchAndLogging(NeighborBase):
    def test_multiple_requests_only_matched_keys_removed(self):
        req1, req2, req3 = summary(adv=R1), summary(adv=R2), summary(adv=R3)
        self.neighbor.request_list = [req1, req2, req3]
        self.neighbor.update_request_list([summary(adv=R3), summary(adv=R1)])
        self.assertEqual(self.neighbor.request_list, [req2])

    def test_multiple_received_same_key_older_then_equal(self):
        self.neighbor.request_list = [summary(seq=S0 + 1)]
        self.neighbor.update_request_list([summary(seq=S0), summary(seq=S0 + 1)])
        self.assertEqual(self.neighbor.request_list, [])

    def test_multiple_received_same_key_equal_then_older(self):
        self.neighbor.request_list = [summary(seq=S0 + 1)]
        self.neighbor.update_request_list([summary(seq=S0 + 1), summary(seq=S0)])
        self.assertEqual(self.neighbor.request_list, [])

    def test_duplicate_requested_keys_both_satisfied(self):
        request = summary()
        self.neighbor.request_list = [request, copy.deepcopy(request)]
        self.neighbor.update_request_list([summary()])
        self.assertEqual(self.neighbor.request_list, [])

    def test_received_and_requested_dicts_not_modified(self):
        request = summary(age=123)
        received = summary(age=77)
        original_req = copy.deepcopy(request)
        original_rcv = copy.deepcopy(received)
        self.neighbor.request_list = [request]
        self.neighbor.update_request_list([received])
        self.assertEqual(request, original_req)
        self.assertEqual(received, original_rcv)

    def test_partial_progress_log(self):
        self.neighbor.request_list = [summary(adv=R1), summary(adv=R2)]
        self.neighbor.update_request_list([summary(adv=R1)])
        self.logger.info.assert_called_once_with("[OSPF][LSR] received=%d pending=%d", 1, 1)

    def test_completion_logs_progress_and_completion(self):
        self.neighbor.request_list = [summary()]
        self.neighbor.update_request_list([summary()])
        self.assertEqual(self.logger.info.call_count, 2)
        self.logger.info.assert_any_call("[OSPF][LSR] received=%d pending=%d", 1, 0)
        self.logger.info.assert_any_call("[OSPF][LSR] request-list complete")

    def test_unsatisfied_only_does_not_log_progress(self):
        self.neighbor.request_list = [summary(seq=S0 + 1)]
        self.neighbor.update_request_list([summary(seq=S0)])
        self.logger.info.assert_not_called()

    def test_large_batch_deterministic_expected_remaining(self):
        rng = random.Random(20261018)
        requests = [summary(lsid=f"0.0.{i // 256}.{i % 256}", seq=S0 + rng.randrange(3))
                    for i in range(200)]
        received = []
        expected = []
        for i, req in enumerate(requests):
            if i % 4 == 0:
                received.append(dict(req))
            elif i % 4 == 1:
                received.append(dict(req, ls_sequence=req["ls_sequence"] + 1))
            elif i % 4 == 2:
                received.append(dict(req, ls_sequence=req["ls_sequence"] - 1))
                expected.append(req)
            else:
                expected.append(req)
        rng.shuffle(received)
        self.neighbor.request_list = requests
        self.neighbor.update_request_list(received)
        self.assertEqual(self.neighbor.request_list, expected)

    def test_received_same_key_but_old_instance_is_retained_while_other_removed(self):
        req1 = summary(adv=R1, seq=S0 + 1)
        req2 = summary(adv=R2, seq=S0)
        self.neighbor.request_list = [req1, req2]
        self.neighbor.update_request_list([summary(adv=R1, seq=S0), summary(adv=R2, seq=S0)])
        self.assertEqual(self.neighbor.request_list, [req1])

    def test_comparator_called_only_for_matching_lsa(self):
        self.neighbor.request_list = [summary()]
        with patch("ospfv3.neighbor.compare_lsa_instances", wraps=compare_lsa_instances) as spy:
            self.neighbor.update_request_list([summary(adv=R2), summary()])
        spy.assert_called_once()


class TestAdjacencyReset(NeighborBase):
    def test_reset_adjacency_clears_peer_identity_but_keeps_port(self):
        n = self.set_peer()
        n.reset_adjacency()
        self.assertEqual(n.port, 7)
        self.assertIsNone(n.router_id)
        self.assertIsNone(n.ipv6)
        self.assertIsNone(n.mac)
        self.assertEqual(n.router_ids, [])
        self.assertIsNone(n.last_hello_received)

    def test_reset_adjacency_clears_exchange_state(self):
        n = self.set_peer()
        n.reset_adjacency()
        self.assertFalse(n.dbd_negotiated)
        self.assertFalse(n.dbd_exchange_complete)
        self.assertFalse(n.lsr_sent)
        self.assertEqual(n.request_list, [])

    def test_reset_clears_port_and_neighbor_state(self):
        n = self.set_peer()
        n.reset()
        self.assertIsNone(n.port)
        self.assertIsNone(n.router_id)
        self.assertIsNone(n.ipv6)
        self.assertEqual(n.router_ids, [])
        self.assertFalse(n.dbd_negotiated)
        self.assertEqual(n.request_list, [])

    def test_reset_adjacency_can_be_followed_by_new_hello(self):
        n = self.set_peer()
        n.reset_adjacency()
        with patch("ospfv3.neighbor.time.monotonic", return_value=200.0):
            n.mark_hello_received()
        self.assertEqual(n.last_hello_received, 200.0)
        self.assertFalse(n.dbd_negotiated)

    def test_reset_is_idempotent_for_state(self):
        n = self.set_peer()
        n.reset()
        first = (n.port, n.router_id, n.ipv6, n.mac, n.last_hello_received,
                 tuple(n.router_ids), tuple(n.request_list), n.dbd_negotiated,
                 n.dbd_exchange_complete, n.lsr_sent)
        n.reset()
        second = (n.port, n.router_id, n.ipv6, n.mac, n.last_hello_received,
                  tuple(n.router_ids), tuple(n.request_list), n.dbd_negotiated,
                  n.dbd_exchange_complete, n.lsr_sent)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
