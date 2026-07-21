#!/usr/bin/env python3

import os
import shlex

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Containernet
from mininet.node import OVSSwitch


FRR_IMAGE = os.environ.get("FRR_IMAGE", "frrouting/frr:latest")

DAEMONS = """\
zebra=yes
bgpd=no
ospfd=no
ospf6d=yes
ripd=no
ripngd=no
isisd=no
pimd=no
pim6d=no
ldpd=no
nhrpd=no
eigrpd=no
babeld=no
sharpd=no
staticd=no
pbrd=no
bfdd=no
fabricd=no
vrrpd=no
pathd=no
mgmtd=no

vtysh_enable=yes
zebra_options=" -s 90000000 --daemon -A 127.0.0.1"
ospf6d_options=" --daemon -A ::1"
"""


def write_file(node, path, text):
    """Zapisz krótki plik tekstowy wewnątrz kontenera."""
    node.cmd("mkdir -p /etc/frr /run/frr")
    node.cmd(f"printf '%s' {shlex.quote(text)} > {shlex.quote(path)}")


def make_frr_config(hostname, router_id, active_interfaces, passive_interfaces=()):
    """Zbuduj minimalną zintegrowaną konfigurację FRR."""
    lines = [
        "frr defaults traditional",
        f"hostname {hostname}",
        "service integrated-vtysh-config",
        "log stdout",
        "!",
    ]

    for interface in active_interfaces:
        lines += [
            f"interface {interface}",
            " ipv6 ospf6 area 0.0.0.0",
            " ipv6 ospf6 network point-to-point",
            "!",
        ]

    for interface in passive_interfaces:
        lines += [
            f"interface {interface}",
            " ipv6 ospf6 area 0.0.0.0",
            " ipv6 ospf6 passive",
            "!",
        ]

    lines += [
        "router ospf6",
        f" ospf6 router-id {router_id}",
        " log-adjacency-changes",
        "!",
        "line vty",
        "!",
    ]
    return "\n".join(lines) + "\n"


def configure_router(router, addresses, router_id, active_interfaces,
                     passive_interfaces=()):
    """Skonfiguruj IPv6, forwarding i pliki FRR przed startem demonów."""
    router.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null")
    router.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null")
    router.cmd("sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null")

    for interface, address in addresses.items():
        router.cmd(f"ip link set dev {interface} up")
        router.cmd(f"ip -4 addr flush dev {interface}")
        router.cmd(f"ip -6 addr replace {address} dev {interface}")

    config = make_frr_config(
        router.name,
        router_id,
        active_interfaces,
        passive_interfaces,
    )

    write_file(router, "/etc/frr/daemons", DAEMONS)
    write_file(router, "/etc/frr/frr.conf", config)
    router.cmd("chown -R frr:frr /etc/frr /run/frr")
    router.cmd("chmod 640 /etc/frr/daemons /etc/frr/frr.conf")


def main():
    net = Containernet(controller=None, switch=OVSSwitch)

    info("*** Dodawanie routerów FRR\n")
    docker_params = dict(
        ip=None,
        dimage=FRR_IMAGE,
        dcmd="/bin/bash",
        cap_add=["net_admin", "net_raw", "sys_admin"],
        rm=True,
    )
    r1 = net.addDocker("r1", **docker_params)
    r2 = net.addDocker("r2", **docker_params)
    r3 = net.addDocker("r3", **docker_params)

    info("*** Dodawanie OVS i hosta\n")
    s1 = net.addSwitch("s1", cls=OVSSwitch, failMode="standalone")
    h1 = net.addHost("h1", ip=None)

    info("*** Tworzenie pełnego trójkąta routerów\n")
    net.addLink(r1, r2, intfName1="r1-eth0", intfName2="r2-eth0")
    net.addLink(r2, r3, intfName1="r2-eth1", intfName2="r3-eth0")
    net.addLink(r3, r1, intfName1="r3-eth1", intfName2="r1-eth1")

    info("*** Podłączanie R1 do s1 i h1\n")
    net.addLink(r1, s1, intfName1="r1-eth2", intfName2="s1-eth1")
    net.addLink(s1, h1, intfName1="s1-eth2", intfName2="h1-eth0")

    info("*** Konfiguracja IPv6 i OSPFv3\n")
    configure_router(
        r1,
        {
            "r1-eth0": "2001:db8:12::1/64",
            "r1-eth1": "2001:db8:31::1/64",
            "r1-eth2": "2001:db8:1::1/64",
        },
        router_id="1.1.1.1",
        active_interfaces=("r1-eth0", "r1-eth1"),
        passive_interfaces=("r1-eth2",),
    )
    configure_router(
        r2,
        {
            "r2-eth0": "2001:db8:12::2/64",
            "r2-eth1": "2001:db8:23::2/64",
        },
        router_id="2.2.2.2",
        active_interfaces=("r2-eth0", "r2-eth1"),
    )
    configure_router(
        r3,
        {
            "r3-eth0": "2001:db8:23::3/64",
            "r3-eth1": "2001:db8:31::3/64",
        },
        router_id="3.3.3.3",
        active_interfaces=("r3-eth0", "r3-eth1"),
    )

    h1.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null")
    h1.cmd("ip link set dev h1-eth0 up")
    h1.cmd("ip -4 addr flush dev h1-eth0")
    h1.cmd("ip -6 addr replace 2001:db8:1::100/64 dev h1-eth0")
    h1.cmd(
        "ip -6 route replace default via 2001:db8:1::1 dev h1-eth0"
    )

    try:
        info("*** Start sieci i demonów zebra/ospf6d\n")
        net.start()

        info("\n*** Przykładowe polecenia w CLI:\n")
        info("r1 vtysh -c 'show ipv6 ospf6 neighbor'\n")
        info("r2 vtysh -c 'show ipv6 route ospf6'\n")
        info("h1 ping -6 -c 3 2001:db8:23::3\n\n")
        CLI(net)
    finally:
        info("*** Zatrzymywanie sieci\n")
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()