"""Optional, non-regression diagnostics. Known limitations, NOT production fixes.

These are *expected failures* on the uploaded source and intentionally are
not matched by the normal `test_*.py` discovery pattern.

Run explicitly: python -m unittest -v tests.diagnose_b5_1_known_issues
("-s tests" discovery need not locate this file.)
"""

import logging
import unittest

from ospfv3.lsdb import LSDB
from ospfv3.routing import Routing
from test_lsdb_spf_b5_1 import ROOT, R1, R2, link, router_lsa, prefix_lsa


class TestObservedLimitations(unittest.TestCase):
    def setUp(self):
        self.db = LSDB(logging.getLogger("ospfv3.b5_1.diagnostics"))
        self.routing = Routing(self.db)

    @unittest.expectedFailure
    def test_unidirectional_router_edge_without_reverse_lsa_not_routable(self):
        # RFC 5340 section 4.8.1: transit vertices must be bidirectional.
        # R2 has no Router-LSA confirming R2->R1 connectivity.
        self.db.update([
            router_lsa(R1, link(ROOT), link(R2)),
            prefix_lsa(R2, ("2001:db8:77::", 64, 10)),
        ])
        self.assertNotIn(("2001:db8:77::", 64),
                         self.routing.build_ipv6_routing_table())

    @unittest.expectedFailure
    def test_nu_bit_prefix_not_installed_as_unicast_route(self):
        # RFC 5340 section 4.8.1: NU-bit ('no-unicast') should be excluded.
        self.db.update([
            router_lsa(R1, link(ROOT)),
            prefix_lsa(R1, ("2001:db8:88::", 64, 10)),
        ])
        p = next(v for v in self.db.values() if v["ls_type"] == 0x2009)
        p["intra_area_prefix_lsa"]["prefixes"][0]["prefix_options"] = 0x01
        self.assertNotIn(("2001:db8:88::", 64),
                         self.routing.build_ipv6_routing_table())

    @unittest.expectedFailure
    def test_lsdb_nested_content_is_snapshot_at_installation(self):
        # Current LSDB._install uses dict(lsa), a shallow copy.
        original = router_lsa(R1, link(ROOT, 10))
        self.db.update([original])
        original["router_lsa"]["links"][0]["metric"] = 99
        stored = next(v for v in self.db.values() if v["ls_type"] == 0x2001)
        self.assertEqual(stored["router_lsa"]["links"][0]["metric"], 10)


if __name__ == "__main__":
    unittest.main()
