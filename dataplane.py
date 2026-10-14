from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv6
from ryu.lib.packet import icmpv6
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types

from ospfv3 import config as cfg
import ipaddress

class DataPlane:
    def __init__(self):
        self.lan_port = None
        self.lan_hosts = {}

        self.transit_port = None
        self.transit_neighbors = {}

        self.transit_router_mac = None
        self.transit_router_ipv6 = None

        self.lan_network = ipaddress.IPv6Network(
            f"{cfg.LAN_PREFIX}/{cfg.LAN_PREFIX_LEN}",
            strict=False
        )

    def learn_transit_router(
        self,
        in_port,
        ipv6_address,
        mac_address
    ):
        changed = (
            self.transit_port != in_port
            or self.transit_router_mac != mac_address
            or self.transit_router_ipv6 != ipv6_address
        )

        self.transit_port = in_port
        self.transit_router_mac = mac_address
        self.transit_router_ipv6 = ipv6_address

        self.transit_neighbors[
            ipv6_address
        ] = mac_address

        return changed

    def handle_ndp(
        self,
        pkt,
        eth_pkt,
        ipv6_pkt,
        in_port
    ):
        icmp_pkt = pkt.get_protocol(
            icmpv6.icmpv6
        )

        if icmp_pkt is None:
            return None

        if icmp_pkt.type_ != icmpv6.ND_NEIGHBOR_SOLICIT:
            return None

        if not isinstance(
            icmp_pkt.data,
            icmpv6.nd_neighbor
        ):
            return None

        target = icmp_pkt.data.dst

        if target not in (
            cfg.LAN_GATEWAY,
            cfg.LINK_LOCAL
        ):
            return None

        if ipv6_pkt.src == "::":
            return None

        if target == cfg.LAN_GATEWAY:
            self.lan_port = in_port

            source_ipv6 = ipaddress.IPv6Address(
                ipv6_pkt.src
            )

            if source_ipv6 in self.lan_network:
                self.lan_hosts[
                    ipv6_pkt.src
                ] = eth_pkt.src

        elif target == cfg.LINK_LOCAL:
            self.transit_port = in_port
            self.transit_neighbors[ipv6_pkt.src] = eth_pkt.src

            self.transit_router_mac = eth_pkt.src
            self.transit_router_ipv6 = ipv6_pkt.src

        return self.build_neighbor_advertisement(
            destination_mac=eth_pkt.src,
            destination_ipv6=ipv6_pkt.src,
            target_ipv6=target
        )

    def build_neighbor_advertisement(
        self,
        destination_mac,
        destination_ipv6,
        target_ipv6
    ):
        pkt = packet.Packet()

        pkt.add_protocol(
            ethernet.ethernet(
                dst=destination_mac,
                src=cfg.ROUTER_MAC,
                ethertype=ether_types.ETH_TYPE_IPV6
            )
        )

        pkt.add_protocol(
            ipv6.ipv6(
                src=target_ipv6,
                dst=destination_ipv6,
                nxt=58,
                hop_limit=255
            )
        )

        option = icmpv6.nd_option_tla(
            hw_src=cfg.ROUTER_MAC
        )

        neighbor = icmpv6.nd_neighbor(
            res=0x7,
            dst=target_ipv6,
            option=option
        )

        pkt.add_protocol(
            icmpv6.icmpv6(
                type_=icmpv6.ND_NEIGHBOR_ADVERT,
                code=0,
                csum=0,
                data=neighbor
            )
        )

        pkt.serialize()

        return bytes(pkt.data)

    def build_echo_reply(
        self,
        destination_mac,
        destination_ipv6,
        echo_data
    ):
        pkt = packet.Packet()

        pkt.add_protocol(
            ethernet.ethernet(
                dst=destination_mac,
                src=cfg.ROUTER_MAC,
                ethertype=ether_types.ETH_TYPE_IPV6
            )
        )

        pkt.add_protocol(
            ipv6.ipv6(
                src=cfg.LAN_GATEWAY,
                dst=destination_ipv6,
                nxt=58,
                hop_limit=64
            )
        )

        reply_data = icmpv6.echo(
            id_=echo_data.id,
            seq=echo_data.seq,
            data=echo_data.data
        )

        pkt.add_protocol(
            icmpv6.icmpv6(
                type_=129,
                code=0,
                csum=0,
                data=reply_data
            )
        )

        pkt.serialize()

        return bytes(pkt.data)
    
    def handle_echo_request(
        self,
        pkt,
        eth_pkt,
        ipv6_pkt,
        in_port
    ):
        """
        Handles ICMPv6 Echo Request addressed to the
        logical SDN LAN gateway.

        Returns a serialized Echo Reply frame or None.
        """

        icmp_pkt = pkt.get_protocol(
            icmpv6.icmpv6
        )

        if icmp_pkt is None:
            return None

        # ICMPv6 Echo Request = 128
        if icmp_pkt.type_ != 128:
            return None

        if ipv6_pkt.dst != cfg.LAN_GATEWAY:
            return None

        if not isinstance(
            icmp_pkt.data,
            icmpv6.echo
        ):
            return None

        self.lan_port = in_port

        source_ipv6 = ipaddress.IPv6Address(
            ipv6_pkt.src
        )

        if source_ipv6 in self.lan_network:
            self.lan_hosts[
                ipv6_pkt.src
            ] = eth_pkt.src

        return self.build_echo_reply(
            destination_mac=eth_pkt.src,
            destination_ipv6=ipv6_pkt.src,
            echo_data=icmp_pkt.data
        )