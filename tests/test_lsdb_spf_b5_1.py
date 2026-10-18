"""B5.1: standalone, deterministic tests of existing LSDB and SPF logic.

Only standard-library unittest is used. Production files are not replaced or
patched persistently. The fixtures emulate already validated parser dicts.
"""

import copy
import logging
import random
import unittest
from unittest.mock import patch

from ospfv3 import config as cfg
from ospfv3.lsa import compare_lsa_instances, next_ospfv3_lsa_sequence
from ospfv3.lsdb import LSDB
from ospfv3.routing import Routing

ROOT = cfg.ROUTER_ID
R1, R2, R3, R4 = "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"
S0, S1, S2 = cfg.INITIAL_SEQUENCE, cfg.INITIAL_SEQUENCE + 1, cfg.INITIAL_SEQUENCE + 2


def link(peer, cost=10, *, kind=1, intid="0.0.0.1", peer_intid="0.0.0.2"):
    return {
        "type": kind,
        "type_name": "Point-to-Point" if kind == 1 else "Transit Network",
        "reserved": 0,
        "metric": cost,
        "interface_id": intid,
        "neighbor_interface_id": peer_intid,
        "neighbor_router_id": peer,
    }


def lsa(*, ls_type=0x2001, router=R1, lsid="0.0.0.0", seq=S0,
        age=1, checksum=0x0123, **body):
    """Parser-compatible LSA entry; not a raw, unverified packet fixture."""
    entry = {
        "ls_age": age,
        "ls_type": ls_type,
        "link_state_id": lsid,
        "advertising_router": router,
        "ls_sequence": seq,
        "ls_checksum": checksum,
        "ls_length": 40,
    }
    entry.update(body)
    return entry


def router_lsa(router, *links, **kwargs):
    return lsa(router=router, router_lsa={"flags": 0, "options": cfg.OPTIONS,
                                             "links": list(links)}, **kwargs)


def prefix_lsa(router, *prefixes, **kwargs):
    data = [{"prefix": p, "prefix_length": plen, "prefix_options": 0,
             "metric": metric} for p, plen, metric in prefixes]
    return lsa(ls_type=0x2009, router=router,
               intra_area_prefix_lsa={
                   "number_of_prefixes": len(data),
                   "referenced_ls_type": 0x2001,
                   "referenced_link_state_id": "0.0.0.0",
                   "referenced_advertising_router": router,
                   "prefixes": data,
               }, **kwargs)


def link_lsa(router=R1, **kwargs):
    return lsa(ls_type=0x0008, router=router, lsid="0.0.0.1",
               link_lsa={"router_priority": 1, "options": cfg.OPTIONS,
                         "link_local_address": "fe80::1",
                         "number_of_prefixes": 0, "prefixes": []}, **kwargs)


def key(entry):
    return (entry["ls_type"], entry["link_state_id"], entry["advertising_router"])


def put(db, *entries):
    return db.update(entries)


def triangle(db):
    """R1<->ROOT and R1/R2/R3 complete triangle; cost=10 per hop."""
    put(db,
        router_lsa(R1, link(ROOT), link(R2), link(R3)),
        router_lsa(R2, link(R1), link(R3)),
        router_lsa(R3, link(R1), link(R2)),
    )


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.db = LSDB(logging.getLogger("ospfv3.b5_1.tests"))
        self.routing = Routing(self.db)


class TestLSDBInstallAndInstances(BaseCase):
    def test_starts_empty(self):
        self.assertFalse(self.db)
        self.assertEqual(len(self.db), 0)
        self.assertEqual(list(self.db.items()), [])

    def test_install_router_affects_routing(self):
        item = router_lsa(R1, link(ROOT))
        self.assertTrue(put(self.db, item))
        self.assertEqual(len(self.db), 1)
        self.assertIn("_age_timestamp", self.db.get(key(item)))

    def test_install_prefix_affects_routing(self):
        self.assertTrue(put(self.db, prefix_lsa(R1, ("2001:db8:12::", 64, 10))))

    def test_install_link_does_not_affect_routing(self):
        self.assertFalse(put(self.db, link_lsa()))
        self.assertEqual(len(self.db), 1)

    def test_unknown_type_stored_but_no_spf_signal(self):
        self.assertFalse(put(self.db, lsa(ls_type=0x200b)))
        self.assertEqual(len(self.db), 1)

    def test_duplicate_same_instance_ignored(self):
        item = router_lsa(R1, link(ROOT))
        put(self.db, item)
        old = self.db.get(key(item))
        self.assertFalse(put(self.db, copy.deepcopy(item)))
        self.assertIs(self.db.get(key(item)), old)

    def test_older_sequence_ignored(self):
        item = router_lsa(R1, link(ROOT), seq=S1)
        put(self.db, item)
        old = self.db.get(key(item))
        self.assertFalse(put(self.db, router_lsa(R1, link(ROOT, 99), seq=S0)))
        self.assertIs(self.db.get(key(item)), old)

    def test_newer_sequence_replaces_and_signals(self):
        old = router_lsa(R1, link(ROOT, 10), seq=S0)
        put(self.db, old)
        updated = router_lsa(R1, link(ROOT, 22), seq=S1)
        self.assertTrue(put(self.db, updated))
        self.assertEqual(self.db.get(key(old))["router_lsa"]["links"][0]["metric"], 22)

    def test_higher_checksum_breaks_same_sequence_tie(self):
        item = router_lsa(R1, link(ROOT), checksum=0x1111)
        put(self.db, item)
        self.assertTrue(put(self.db, router_lsa(R1, link(ROOT, 12), checksum=0x1112)))
        self.assertEqual(self.db.get(key(item))["ls_checksum"], 0x1112)

    def test_lower_checksum_same_sequence_is_ignored(self):
        item = router_lsa(R1, link(ROOT), checksum=0x1112)
        put(self.db, item)
        self.assertFalse(put(self.db, router_lsa(R1, link(ROOT, 13), checksum=0x1111)))
        self.assertEqual(self.db.get(key(item))["ls_checksum"], 0x1112)

    def test_signed_sequence_order(self):
        first = router_lsa(R1, link(ROOT), seq=S0)
        put(self.db, first)
        self.assertTrue(put(self.db, router_lsa(R1, link(ROOT, 13), seq=0x7fffffff)))
        self.assertFalse(put(self.db, router_lsa(R1, link(ROOT, 14), seq=0x80000002)))
        self.assertEqual(self.db.get(key(first))["ls_sequence"], 0x7fffffff)

    def test_maxage_absent_entry_never_inserted(self):
        self.assertFalse(put(self.db, router_lsa(R1, link(ROOT), age=cfg.MAX_AGE)))
        self.assertEqual(len(self.db), 0)

    def test_maxage_same_instance_flushes(self):
        item = router_lsa(R1, link(ROOT), seq=S0)
        put(self.db, item)
        self.assertTrue(put(self.db, router_lsa(R1, link(ROOT), seq=S0,
                                               age=cfg.MAX_AGE)))
        self.assertIsNone(self.db.get(key(item)))

    def test_maxage_old_sequence_cannot_flush_newer(self):
        item = router_lsa(R1, link(ROOT), seq=S2)
        put(self.db, item)
        self.assertFalse(put(self.db, router_lsa(R1, link(ROOT), seq=S0,
                                                age=cfg.MAX_AGE)))
        self.assertIn(key(item), self.db.entries)

    def test_maxage_link_flush_does_not_trigger_spf(self):
        item = link_lsa()
        put(self.db, item)
        self.assertFalse(put(self.db, link_lsa(age=cfg.MAX_AGE)))
        self.assertIsNone(self.db.get(key(item)))

    def test_key_separates_advertiser_type_and_lsid(self):
        self.assertTrue(put(self.db,
                            router_lsa(R1), router_lsa(R2),
                            prefix_lsa(R1),
                            router_lsa(R1, lsid="0.0.0.1")))
        self.assertEqual(len(self.db), 4)

    def test_install_copies_top_level_dictionary(self):
        original = router_lsa(R1, link(ROOT))
        put(self.db, original)
        original["ls_sequence"] = S2
        self.assertEqual(self.db.get(key(original))["ls_sequence"], S0)


class TestLSDBAgeAndClear(BaseCase):
    def test_age_elapsed_uses_monotonic_integer_seconds(self):
        with patch("ospfv3.lsdb.time.monotonic", return_value=100.0):
            item = router_lsa(R1, age=12)
            put(self.db, item)
        with patch("ospfv3.lsdb.time.monotonic", return_value=102.99):
            self.assertEqual(self.db.get_age(self.db.get(key(item))), 14)

    def test_age_is_capped_at_max_age(self):
        with patch("ospfv3.lsdb.time.monotonic", return_value=100.0):
            item = router_lsa(R1, age=cfg.MAX_AGE - 1)
            put(self.db, item)
        with patch("ospfv3.lsdb.time.monotonic", return_value=100000.0):
            self.assertEqual(self.db.get_age(self.db.get(key(item))), cfg.MAX_AGE)

    def test_uninstalled_entry_age_is_base_age(self):
        self.assertEqual(self.db.get_age(router_lsa(R1, age=77)), 77)

    def test_expiration_exact_maxage_removes_router(self):
        with patch("ospfv3.lsdb.time.monotonic", return_value=100.0):
            item = router_lsa(R1, link(ROOT), age=cfg.MAX_AGE - 3)
            put(self.db, item)
        with patch("ospfv3.lsdb.time.monotonic", return_value=103.0):
            self.assertTrue(self.db.purge_expired())
        self.assertFalse(self.db)

    def test_purge_before_maxage_keeps_entry(self):
        with patch("ospfv3.lsdb.time.monotonic", return_value=100.0):
            item = prefix_lsa(R1, ("2001:db8:12::", 64, 10), age=cfg.MAX_AGE - 3)
            put(self.db, item)
        with patch("ospfv3.lsdb.time.monotonic", return_value=102.0):
            self.assertFalse(self.db.purge_expired())
        self.assertIn(key(item), self.db.entries)

    def test_purge_only_link_does_not_trigger_routing_change(self):
        with patch("ospfv3.lsdb.time.monotonic", return_value=100.0):
            item = link_lsa(age=cfg.MAX_AGE - 1)
            put(self.db, item)
        with patch("ospfv3.lsdb.time.monotonic", return_value=101.0):
            self.assertFalse(self.db.purge_expired())
        self.assertFalse(self.db)

    def test_purge_multiple_and_retains_nonexpired(self):
        with patch("ospfv3.lsdb.time.monotonic", return_value=100.0):
            a = router_lsa(R1, age=cfg.MAX_AGE - 5)
            b = link_lsa(R2, age=cfg.MAX_AGE - 5)
            c = prefix_lsa(R3, ("2001:db8:31::", 64, 10), age=10)
            put(self.db, a, b, c)
        with patch("ospfv3.lsdb.time.monotonic", return_value=105.0):
            self.assertTrue(self.db.purge_expired())
        self.assertEqual(set(self.db.entries), {key(c)})

    def test_replacement_resets_age_baseline(self):
        with patch("ospfv3.lsdb.time.monotonic", return_value=100.0):
            item = router_lsa(R1, age=400, seq=S0)
            put(self.db, item)
        with patch("ospfv3.lsdb.time.monotonic", return_value=200.0):
            newer = router_lsa(R1, age=2, seq=S1)
            self.assertTrue(put(self.db, newer))
        with patch("ospfv3.lsdb.time.monotonic", return_value=201.0):
            self.assertEqual(self.db.get_age(self.db.get(key(item))), 3)

    def test_clear_remote_preserves_self_and_removes_all_remote_types(self):
        mine = router_lsa(ROOT)
        remote = router_lsa(R1)
        remote_link = link_lsa(R2)
        put(self.db, mine, remote, remote_link)
        self.assertTrue(self.db.clear_remote(ROOT))
        self.assertEqual(set(self.db.entries), {key(mine)})

    def test_clear_remote_when_nothing_remote(self):
        put(self.db, router_lsa(ROOT))
        self.assertFalse(self.db.clear_remote(ROOT))

    def test_update_compares_against_dynamically_aged_instance(self):
        with patch("ospfv3.lsdb.time.monotonic", return_value=100.0):
            original = router_lsa(R1, age=2000)
            put(self.db, original)
        # Same sequence+checksum, but age differs by > MAX_AGE_DIFF;
        # younger received LSA replaces currently aged LSDB instance.
        with patch("ospfv3.lsdb.time.monotonic", return_value=1200.0):
            self.assertTrue(put(self.db, router_lsa(R1, age=100)))
        self.assertEqual(self.db.get(key(original))["_age_base"], 100)


class TestSequenceComparator(BaseCase):
    def test_sequence_dominates_checksum_and_age(self):
        old = router_lsa(R1, seq=S0, checksum=0xffff, age=cfg.MAX_AGE)
        new = router_lsa(R1, seq=S1, checksum=0, age=1)
        self.assertEqual(compare_lsa_instances(new, old), 1)
        self.assertEqual(compare_lsa_instances(old, new), -1)

    def test_checksum_dominates_age_when_sequence_equal(self):
        high = router_lsa(R1, checksum=0xff00, age=500)
        low = router_lsa(R1, checksum=0x0100, age=1)
        self.assertEqual(compare_lsa_instances(high, low), 1)

    def test_maxage_breaks_equal_sequence_checksum(self):
        maxage = router_lsa(R1, age=cfg.MAX_AGE)
        normal = router_lsa(R1, age=1)
        self.assertEqual(compare_lsa_instances(maxage, normal), 1)
        self.assertEqual(compare_lsa_instances(normal, maxage), -1)

    def test_large_age_difference_prefers_younger(self):
        self.assertEqual(compare_lsa_instances(router_lsa(R1, age=30),
                                               router_lsa(R1, age=1500)), 1)

    def test_small_age_difference_is_equivalent(self):
        self.assertEqual(compare_lsa_instances(router_lsa(R1, age=50),
                                               router_lsa(R1, age=51)), 0)

    def test_sequence_end_boundaries(self):
        self.assertEqual(next_ospfv3_lsa_sequence(S0), S1)
        self.assertEqual(next_ospfv3_lsa_sequence(0xffffffff), 0)
        for invalid in (0x80000000, 0x7fffffff, -1, 0x100000000):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                next_ospfv3_lsa_sequence(invalid)


class TestSPFAndIPv6Routing(BaseCase):
    def test_empty_lsdb_yields_only_connected_routes(self):
        distances, previous = self.routing.run_spf()
        self.assertEqual(distances, {ROOT: 0})
        self.assertEqual(previous, {ROOT: None})
        table = self.routing.build_ipv6_routing_table()
        self.assertEqual(set(table), {(cfg.LAN_PREFIX, cfg.LAN_PREFIX_LEN),
                                      (cfg.TRANSIT_PREFIX, cfg.TRANSIT_PREFIX_LEN)})
        self.assertTrue(all(r["source"] == "connected" for r in table.values()))

    def test_ignores_non_router_and_non_p2p_graph_links(self):
        put(self.db, link_lsa(), router_lsa(R1, link(R2, kind=2)))
        graph = self.routing.build_router_graph()
        self.assertIn(R1, graph)
        self.assertEqual(graph[R1], [])
        self.assertNotIn(R2, graph)

    def test_local_root_created_using_remote_router_link(self):
        put(self.db, router_lsa(R1, link(ROOT, 10,
                                         intid="0.0.3.40", peer_intid="0.0.0.1")))
        graph = self.routing.build_router_graph()
        self.assertEqual(graph[ROOT][0]["neighbor"], R1)
        self.assertEqual(graph[ROOT][0]["interface_id"], "0.0.0.1")
        self.assertEqual(graph[ROOT][0]["neighbor_interface_id"], "0.0.3.40")
        self.assertEqual(self.routing.run_spf()[0][R1], 10)

    def test_triangle_spf_and_predecessors(self):
        triangle(self.db)
        distances, previous = self.routing.run_spf()
        self.assertEqual({r: distances[r] for r in (ROOT, R1, R2, R3)},
                         {ROOT: 0, R1: 10, R2: 20, R3: 20})
        self.assertEqual(previous[R1], ROOT)
        self.assertEqual(previous[R2], R1)
        self.assertEqual(previous[R3], R1)
        self.assertEqual(self.routing.get_spf_next_hop(R2, previous), R1)
        self.assertIsNone(self.routing.get_spf_next_hop(ROOT, previous))

    def test_cheapest_path_not_fewest_hops(self):
        put(self.db, router_lsa(R1, link(ROOT, 10), link(R2, 50), link(R3, 5)),
            router_lsa(R3, link(R1, 5), link(R2, 5)),
            router_lsa(R2, link(R1, 50), link(R3, 5)))
        distances, previous = self.routing.run_spf()
        self.assertEqual(distances[R2], 20)
        self.assertEqual(previous[R2], R3)
        self.assertEqual(self.routing.get_spf_next_hop(R2, previous), R1)

    def test_unreachable_router_and_its_prefix_omitted(self):
        put(self.db, router_lsa(R1, link(ROOT)), router_lsa(R4),
            prefix_lsa(R4, ("2001:db8:44::", 64, 8)))
        distances, previous = self.routing.run_spf()
        self.assertEqual(distances[R4], float("inf"))
        self.assertIsNone(self.routing.get_spf_next_hop(R4, previous))
        self.assertNotIn(("2001:db8:44::", 64), self.routing.build_ipv6_routing_table())

    def test_unknown_router_prefix_omitted(self):
        put(self.db, prefix_lsa(R4, ("2001:db8:44::", 64, 8)))
        self.assertNotIn(("2001:db8:44::", 64), self.routing.build_ipv6_routing_table())

    def test_full_triangle_route_costs_and_next_hop(self):
        triangle(self.db)
        put(self.db,
            prefix_lsa(R1, ("2001:db8:12::", 64, 10), ("2001:db8:31::", 64, 10)),
            prefix_lsa(R2, ("2001:db8:23::", 64, 10)),
            prefix_lsa(R3, ("2001:db8:32::", 64, 10)))
        routes = self.routing.build_ipv6_routing_table()
        self.assertEqual(routes[("2001:db8:12::", 64)]["total_cost"], 20)
        self.assertEqual(routes[("2001:db8:23::", 64)]["total_cost"], 30)
        self.assertEqual(routes[("2001:db8:32::", 64)]["total_cost"], 30)
        self.assertEqual(routes[("2001:db8:23::", 64)]["next_hop"], R1)
        self.assertEqual(routes[("2001:db8:23::", 64)]["router_cost"], 20)
        self.assertEqual(routes[("2001:db8:23::", 64)]["prefix_metric"], 10)

    def test_connected_route_wins_over_remote_advertisement(self):
        put(self.db, router_lsa(R1, link(ROOT)),
            prefix_lsa(R1, (cfg.LAN_PREFIX, cfg.LAN_PREFIX_LEN, 1),
                       (cfg.TRANSIT_PREFIX, cfg.TRANSIT_PREFIX_LEN, 1)))
        table = self.routing.build_ipv6_routing_table()
        self.assertEqual(table[(cfg.LAN_PREFIX, cfg.LAN_PREFIX_LEN)]["source"], "connected")
        self.assertEqual(table[(cfg.TRANSIT_PREFIX, cfg.TRANSIT_PREFIX_LEN)]["source"], "connected")

    def test_lower_cost_prefix_advertisement_wins(self):
        triangle(self.db)
        put(self.db, prefix_lsa(R2, ("2001:db8:99::", 64, 2)),
            prefix_lsa(R3, ("2001:db8:99::", 64, 9)))
        route = self.routing.build_ipv6_routing_table()[("2001:db8:99::", 64)]
        self.assertEqual((route["advertising_router"], route["total_cost"]), (R2, 22))

    def test_equal_cost_tie_break_stable_across_lsa_order(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                db = LSDB(logging.getLogger("ospfv3.b5_1.tests"))
                triangle(db)
                prefixes = [prefix_lsa(R3, ("2001:db8:99::", 64, 5)),
                            prefix_lsa(R2, ("2001:db8:99::", 64, 5))]
                db.update(list(reversed(prefixes)) if reverse else prefixes)
                route = Routing(db).build_ipv6_routing_table()[("2001:db8:99::", 64)]
                self.assertEqual(route["advertising_router"], R2)

    def test_overlapping_prefix_lengths_coexist(self):
        put(self.db, router_lsa(R1, link(ROOT)),
            prefix_lsa(R1, ("2001:db8:aa::", 48, 2),
                       ("2001:db8:aa:1::", 64, 3)))
        table = self.routing.build_ipv6_routing_table()
        self.assertIn(("2001:db8:aa::", 48), table)
        self.assertIn(("2001:db8:aa:1::", 64), table)
        # LPM packet matching is in OpenFlow/controller (B5.3), not this module.

    def test_prefix_list_order_does_not_change_routes(self):
        put(self.db, router_lsa(R1, link(ROOT)))
        a = prefix_lsa(R1, ("2001:db8:aa::", 64, 4),
                       ("2001:db8:bb::", 64, 9))
        put(self.db, a)
        first = self.routing.build_ipv6_routing_table()
        put(self.db, prefix_lsa(R1, ("2001:db8:bb::", 64, 9),
                                ("2001:db8:aa::", 64, 4), seq=S1))
        self.assertEqual(self.routing.build_ipv6_routing_table(), first)

    def test_missing_parsed_router_or_prefix_body_is_ignored(self):
        put(self.db, lsa(ls_type=0x2001, router=R1),
            lsa(ls_type=0x2009, router=R2))
        table = self.routing.build_ipv6_routing_table()
        self.assertEqual(len(table), 2)

    def test_remote_prefix_disappears_on_maxage_flush(self):
        rt = router_lsa(R1, link(ROOT))
        pref = prefix_lsa(R1, ("2001:db8:99::", 64, 10))
        put(self.db, rt, pref)
        self.assertIn(("2001:db8:99::", 64), self.routing.build_ipv6_routing_table())
        self.assertTrue(put(self.db,
                            prefix_lsa(R1, ("2001:db8:99::", 64, 10), age=cfg.MAX_AGE)))
        self.assertNotIn(("2001:db8:99::", 64), self.routing.build_ipv6_routing_table())

    def test_remote_prefix_disappears_on_router_flush(self):
        rt = router_lsa(R1, link(ROOT))
        pref = prefix_lsa(R1, ("2001:db8:99::", 64, 10))
        put(self.db, rt, pref)
        self.assertTrue(put(self.db, router_lsa(R1, link(ROOT), age=cfg.MAX_AGE)))
        self.assertNotIn(("2001:db8:99::", 64), self.routing.build_ipv6_routing_table())

    def test_reorigination_changes_spf_costs(self):
        triangle(self.db)
        pref = prefix_lsa(R2, ("2001:db8:23::", 64, 10))
        put(self.db, pref)
        before = self.routing.build_ipv6_routing_table()[("2001:db8:23::", 64)]
        self.assertEqual(before["total_cost"], 30)
        put(self.db, router_lsa(R1, link(ROOT), link(R2, 30), link(R3, 10), seq=S1))
        # R1->R3->R2 is now cheaper than R1->R2.
        after = self.routing.build_ipv6_routing_table()[("2001:db8:23::", 64)]
        self.assertEqual(after["total_cost"], 40)

    def test_spf_against_independent_bellman_ford_on_100_graphs(self):
        """Randomized, reproducible comparison to a separate shortest-path method."""
        rng = random.Random(0xB51)
        routers = [R1, R2, R3, R4]
        for topology_index in range(100):
            with self.subTest(topology=topology_index):
                adj = {r: [] for r in routers}
                weighted_edges = [(ROOT, R1, 10)]
                for i, source in enumerate(routers):
                    for target in routers[i + 1:]:
                        if rng.random() < 0.60:
                            cost = rng.randint(1, 40)
                            adj[source].append(link(target, cost))
                            adj[target].append(link(source, cost))
                            weighted_edges.extend([(source, target, cost),
                                                   (target, source, cost)])
                adj[R1].append(link(ROOT, 10))
                database = LSDB(logging.getLogger("ospfv3.b5_1.tests"))
                database.update([router_lsa(r, *links) for r, links in adj.items()])
                got_distances, _ = Routing(database).run_spf()
                expected = {r: float("inf") for r in [ROOT] + routers}
                expected[ROOT] = 0
                # Bellman-Ford relaxation, independently of heapq/Dijkstra.
                for _ in range(len(expected) - 1):
                    for source, dest, weight in weighted_edges:
                        expected[dest] = min(expected[dest], expected[source] + weight)
                self.assertEqual(got_distances, expected)

    def test_clear_remote_removes_remote_routes_not_connected(self):
        triangle(self.db)
        put(self.db, prefix_lsa(R2, ("2001:db8:23::", 64, 10)))
        self.assertIn(("2001:db8:23::", 64), self.routing.build_ipv6_routing_table())
        self.db.clear_remote(ROOT)
        routes = self.routing.build_ipv6_routing_table()
        self.assertNotIn(("2001:db8:23::", 64), routes)
        self.assertIn((cfg.LAN_PREFIX, cfg.LAN_PREFIX_LEN), routes)
        self.assertIn((cfg.TRANSIT_PREFIX, cfg.TRANSIT_PREFIX_LEN), routes)


if __name__ == "__main__":
    unittest.main()
