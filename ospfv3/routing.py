import heapq

from ospfv3 import config as cfg


class Routing:
    def __init__(self, lsdb):
        self.lsdb = lsdb


    def build_router_graph(self):
        """
        Builds the router-level topology graph from Router-LSAs
        currently stored in the LSDB.
        """

        graph = {}

        for lsa in self.lsdb.values():

            # We only need Router-LSAs here.
            if lsa["ls_type"] != 0x2001:
                continue

            router_lsa = lsa.get("router_lsa")

            if router_lsa is None:
                continue

            router_id = lsa["advertising_router"]

            if router_id not in graph:
                graph[router_id] = []

            for link in router_lsa["links"]:

                # For now we only use point-to-point links.
                if link["type"] != 1:
                    continue

                neighbor_router_id = link["neighbor_router_id"]

                graph[router_id].append({
                    "neighbor": neighbor_router_id,
                    "cost": link["metric"],
                    "interface_id": link["interface_id"],
                    "neighbor_interface_id": (
                        link["neighbor_interface_id"]
                    )
                })

                # Ensure the neighbor also exists as a graph node,
                # even if we do not have its Router-LSA yet.
                if neighbor_router_id not in graph:
                    graph[neighbor_router_id] = []

                if neighbor_router_id == cfg.ROUTER_ID:

                    reverse_exists = any(
                        existing["neighbor"] == router_id
                        for existing in graph[cfg.ROUTER_ID]
                    )

                    if not reverse_exists:
                        graph[cfg.ROUTER_ID].append({
                            "neighbor": router_id,
                            "cost": link["metric"],
                            "interface_id": (
                                link["neighbor_interface_id"]
                            ),
                            "neighbor_interface_id": (
                                link["interface_id"]
                            )
                        })
        return graph

    def run_spf(self):
        """
        Runs Dijkstra SPF using the local OSPF Router ID
        as the root of the topology graph.
        """

        graph = self.build_router_graph()
        root = cfg.ROUTER_ID

        if root not in graph:
            return {}, {}

        distances = {
            router_id: float("inf")
            for router_id in graph
        }

        previous = {
            router_id: None
            for router_id in graph
        }

        distances[root] = 0

        queue = [
            (0, root)
        ]

        while queue:
            current_cost, current_router = heapq.heappop(queue)

            if current_cost > distances[current_router]:
                continue

            for link in graph[current_router]:
                neighbor = link["neighbor"]
                link_cost = link["cost"]

                new_cost = current_cost + link_cost

                if new_cost < distances[neighbor]:
                    distances[neighbor] = new_cost
                    previous[neighbor] = current_router

                    heapq.heappush(
                        queue,
                        (new_cost, neighbor)
                    )

        return distances, previous

    def get_spf_next_hop(self, destination, previous):
        """
        Returns the first router after the SPF root
        on the path toward destination.
        """

        root = cfg.ROUTER_ID

        if destination == root:
            return None

        if destination not in previous:
            return None

        if previous[destination] is None:
            return None

        current = destination

        while previous[current] != root:
            current = previous[current]

            if current is None:
                return None

        return current

    def collect_prefix_advertisements(self):
        """
        Collects IPv6 prefix advertisements from
        Intra-Area-Prefix-LSAs stored in the LSDB.
        """

        advertisements = []

        for lsa in self.lsdb.values():

            # Intra-Area-Prefix-LSA
            if lsa["ls_type"] != 0x2009:
                continue

            prefix_lsa = lsa.get("intra_area_prefix_lsa")

            if prefix_lsa is None:
                continue

            advertising_router = lsa["advertising_router"]

            for prefix in prefix_lsa["prefixes"]:
                advertisements.append({
                    "prefix": prefix["prefix"],
                    "prefix_length": prefix["prefix_length"],
                    "metric": prefix["metric"],
                    "advertising_router": advertising_router
                })

        return advertisements

    def build_ipv6_routing_table(self):
        """
        Builds the IPv6 routing table from SPF results
        and Intra-Area-Prefix-LSA advertisements.
        """

        distances, previous = self.run_spf()
        advertisements = self.collect_prefix_advertisements()

        routes = {}

        # Locally connected IPv6 networks.
        connected_routes = [
            {
                "prefix": cfg.TRANSIT_PREFIX,
                "prefix_length": cfg.TRANSIT_PREFIX_LEN,
                "interface": "transit"
            },
            {
                "prefix": cfg.LAN_PREFIX,
                "prefix_length": cfg.LAN_PREFIX_LEN,
                "interface": "lan"
            }
        ]

        for connected in connected_routes:
            prefix_key = (
                connected["prefix"],
                connected["prefix_length"]
            )

            routes[prefix_key] = {
                "prefix": connected["prefix"],
                "prefix_length": connected["prefix_length"],
                "source": "connected",
                "advertising_router": None,
                "router_cost": 0,
                "prefix_metric": 0,
                "total_cost": 0,
                "next_hop": None,
                "interface": connected["interface"]
            }

        for advertisement in advertisements:
            advertising_router = advertisement[
                "advertising_router"
            ]

            if advertising_router not in distances:
                continue

            router_cost = distances[advertising_router]

            if router_cost == float("inf"):
                continue

            prefix_metric = advertisement["metric"]

            total_cost = router_cost + prefix_metric

            next_hop = self.get_spf_next_hop(
                advertising_router,
                previous
            )

            prefix_key = (
                advertisement["prefix"],
                advertisement["prefix_length"]
            )

            candidate = {
                "prefix": advertisement["prefix"],
                "prefix_length": advertisement["prefix_length"],
                "source": "ospf",
                "advertising_router": advertising_router,
                "router_cost": router_cost,
                "prefix_metric": prefix_metric,
                "total_cost": total_cost,
                "next_hop": next_hop,
                "interface": "transit"
            }

            current = routes.get(prefix_key)

            # A connected route always takes precedence
            # over a route learned through OSPF.
            if (
                current is not None
                and current["source"] == "connected"
            ):
                continue

            if current is None:
                routes[prefix_key] = candidate
                continue

            # Lower total OSPF cost wins.
            if candidate["total_cost"] < current["total_cost"]:
                routes[prefix_key] = candidate

            # Deterministic tie-break for equal-cost candidates.
            elif (
                candidate["total_cost"]
                == current["total_cost"]
                and candidate["advertising_router"]
                < current["advertising_router"]
            ):
                routes[prefix_key] = candidate

        return routes
