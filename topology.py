#!/usr/bin/env python3

import os
import shlex
import time

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Containernet
from mininet.node import OVSSwitch, RemoteController


FRR_IMAGE = os.environ.get("FRR_IMAGE", "frrouting/frr:latest")

DAEMONS = """\
zebra=yes
ospf6d=yes
vtysh_enable=no

zebra_options="-A 127.0.0.1 -s 90000000"
ospf6d_options="-A ::1"
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
        "router ospf6",
        f" ospf6 router-id {router_id}",
        " log-adjacency-changes",
        "exit",
        "!",
    ]

    for interface in active_interfaces:
        lines += [
            f"interface {interface}",
            " ipv6 ospf6 area 0.0.0.0",
            " ipv6 ospf6 network point-to-point",
            "exit",
            "!",
        ]

    for interface in passive_interfaces:
        lines += [
            f"interface {interface}",
            " ipv6 ospf6 area 0.0.0.0",
            " ipv6 ospf6 passive",
            "exit",
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
    write_file(router, "/etc/frr/vtysh.conf", "service integrated-vtysh-config\n")
    router.cmd("chown -R frr:frr /etc/frr /run/frr")
    router.cmd(
        "if getent group frrvty >/dev/null 2>&1; then "
        "chown frr:frrvty /etc/frr/vtysh.conf; fi"
    )
    router.cmd(
        "chmod 640 /etc/frr/daemons /etc/frr/frr.conf "
        "/etc/frr/vtysh.conf"
    )


def start_frr(router):

    """Uruchom FRR i wczytaj /etc/frr/frr.conf."""
    output = router.cmd(
        "if [ -x /usr/lib/frr/frrinit.sh ]; then "
        "/usr/lib/frr/frrinit.sh start; "
        "elif [ -x /etc/init.d/frr ]; then "
        "/etc/init.d/frr start; "
        "else "
        "echo 'Nie znaleziono skryptu startowego FRR'; "
        "fi"
    )
    if output.strip():
        info(f"*** {router.name}: {output.strip()}\n")

    # Daj demonom czas na utworzenie gniazd /run/frr/*.vty.
    time.sleep(2)

    # Nie przerywamy programu przez pidof/kill -0, ponieważ w części
    # obrazów kontenerowych dają one fałszywy wynik mimo działających demonów.
    sockets = router.cmd("ls /run/frr/*.vty 2>/dev/null")
    if "zebra.vty" not in sockets or "ospf6d.vty" not in sockets:
        info(
            f"*** WARNING: no VTY sockets on {router.name}:\n"
            f"{sockets}\n"
        )

    info(f"*** {router.name}: finished starting FRR\n")


def main():
    net = Containernet(controller=None, switch=OVSSwitch)

    try:
        net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653
        )

        info("*** Adding FRR routers\n")
        docker_params = dict(
            ip=None,
            dimage=FRR_IMAGE,
            dcmd="/bin/bash",
            cap_add=["net_admin", "net_raw", "sys_admin"],
            sysctls={"net.ipv6.conf.all.disable_ipv6": "0",
            "net.ipv6.conf.default.disable_ipv6": "0",
            "net.ipv6.conf.all.forwarding": "1",
            "net.ipv6.conf.default.forwarding": "1",
            },
            
            rm=True,
        )
        r1 = net.addDocker("r1", **docker_params)
        r2 = net.addDocker("r2", **docker_params)
        r3 = net.addDocker("r3", **docker_params)

        info("*** Adding OVS and host\n")

        s1 = net.addSwitch(
        "s1",
        cls=OVSSwitch,
        protocols="OpenFlow13",
        failMode="secure",
        dpid="0000000000000001"
        )

        h1 = net.addHost("h1", ip=None)

        info("*** Creating full triangle of routers\n")
        net.addLink(r1, r2, intfName1="r1-eth0", intfName2="r2-eth0")
        net.addLink(r2, r3, intfName1="r2-eth1", intfName2="r3-eth0")
        net.addLink(r3, r1, intfName1="r3-eth1", intfName2="r1-eth1")

        info("*** Connecting R1 to s1 and h1\n")
        net.addLink(r1, s1, intfName1="r1-eth2")
        net.addLink(s1, h1)

        info("*** IPv6 and OSPFv3 configuration\n")
        configure_router(
            r1,
            {
                "r1-eth0": "2001:db8:12::1/64",
                "r1-eth1": "2001:db8:31::1/64",
                "r1-eth2": "2001:db8:1::1/64",
            },
            router_id="1.1.1.1",
            active_interfaces=("r1-eth0", "r1-eth1", "r1-eth2"),
            passive_interfaces=(),
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

    
        info("*** Starting routers and daemons\n")
        net.start()

        info("*** Controler s1:\n")
        info(s1.cmd("ovs-vsctl get-controller s1"))

        info("*** OpenFlow flows:\n")
        info(s1.cmd("ovs-ofctl -O OpenFlow13 dump-flows s1"))

        for router in (r1, r2, r3):
            start_frr(router)

        info("\n*** Example commands in CLI:\n")
        info("r1 vtysh -c 'show ipv6 ospf6 neighbor'\n")
        info("r2 vtysh -c 'show ipv6 route ospf6'\n")
        info("h1 ping -6 -c 3 2001:db8:23::3\n\n")
        CLI(net)
    finally:
        info("*** Stopping network\n")
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()
