import os
import time
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController, OVSKernelSwitch, Node, OVSSwitch
from mininet.log import setLogLevel, info

def Network():
    # PATCH DLA PYTHON 3.12 / MININET BŁĘDU OVSVersion
    OVSSwitch.OVSVersion = "2.0.0"

    net = Mininet(switch=OVSKernelSwitch)

    # REWOLUCJA SDN: Dodajemy zdalny kontroler, pod który podepniesz swój sterownik Ryu
    info('*** Adding Remote SDN Controller...\n')
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info('*** Cleaning up old containers...\n')
    os.system("docker rm -f r1 r2 r3 2>/dev/null")

    info('*** Starting VyOS containers with /sbin/init process...\n')
    os.system("docker run -d --rm --name r1 --network=none --privileged --sysctl net.ipv6.conf.all.forwarding=1 -v /lib/modules:/lib/modules vyos:2026-rolling /sbin/init")
    os.system("docker run -d --rm --name r2 --network=none --privileged --sysctl net.ipv6.conf.all.forwarding=1 -v /lib/modules:/lib/modules vyos:2026-rolling /sbin/init")
    os.system("docker run -d --rm --name r3 --network=none --privileged --sysctl net.ipv6.conf.all.forwarding=1 -v /lib/modules:/lib/modules vyos:2026-rolling /sbin/init")

    info('*** Waiting 5 seconds for VyOS systems initialization...\n')
    time.sleep(5)

    # Pobieramy PID procesów
    pid_r1 = int(os.popen("docker inspect -f '{{.State.Pid}}' r1").read().strip())
    pid_r2 = int(os.popen("docker inspect -f '{{.State.Pid}}' r2").read().strip())
    pid_r3 = int(os.popen("docker inspect -f '{{.State.Pid}}' r3").read().strip())

    info('*** Mapping containers into Mininet topology...\n')
    r1 = net.addHost('r1', cls=Node, pid=pid_r1)
    r2 = net.addHost('r2', cls=Node, pid=pid_r2)
    r3 = net.addHost('r3', cls=Node, pid=pid_r3)

    # Host bez IP w konfiguratorze - nadamy mu IPv6 ręcznie poniżej
    h1 = net.addHost('h1', ip=None)
    
    # Switch w trybie secure - bez kontrolera Ryu nie przepuści żadnego pakietu!
    s1 = net.addSwitch('s1', failMode='secure')

    info('*** Connecting devices in a ring...\n')
    net.addLink(r1, r2)
    net.addLink(r2, r3)
    net.addLink(r3, r1)
    net.addLink(r1, s1)
    net.addLink(s1, h1)

    info('*** Starting network...\n')
    net.start()

    # Konfiguracja adresacji IPv6 na hoście końcowym
    info('*** Configuring IPv6 on host h1...\n')
    h1.cmd('ip -6 addr add 2001:db8:100::10/64 dev h1-eth0')
    h1.cmd('ip -6 route add default via 2001:db8:100::1')
    info('*** Configuring OSPFv3 on VyOS routers...\n')

    # --- KONFIGURACJA RUTERA R1 ---
    os.system("docker exec -t r1 /bin/bash -c 'vbash -c \"configure; "
              "set interfaces dummy dum0 address 2001:db8:1::1/128; "
              "set interfaces ethernet eth0 address 2001:db8:12::1/64; " 
              "set interfaces ethernet eth1 address 2001:db8:13::1/64; "
              "set interfaces ethernet eth2 address 2001:db8:100::1/64; " # Sieć LAN dla h1
              "set protocols ospfv3 parameters router-id 1.1.1.1; "
              "set protocols ospfv3 area 0.0.0.0 interface eth0; "
              "set protocols ospfv3 area 0.0.0.0 interface eth1; "
              "set protocols ospfv3 area 0.0.0.0 interface eth2; "
              "set protocols ospfv3 area 0.0.0.0 interface dum0; "
              "commit; save\"'")

    # --- KONFIGURACJA RUTERA R2 ---
    os.system("docker exec -t r2 /bin/bash -c 'vbash -c \"configure; "
              "set interfaces dummy dum0 address 2001:db8:2::1/128; "
              "set interfaces ethernet eth0 address 2001:db8:12::2/64; "
              "set interfaces ethernet eth1 address 2001:db8:13::2/64; "
              "set protocols ospfv3 parameters router-id 2.2.2.2; "
              "set protocols ospfv3 area 0.0.0.0 interface eth0; "
              "set protocols ospfv3 area 0.0.0.0 interface eth1; "
              "set protocols ospfv3 area 0.0.0.0 interface dum0; "
              "commit; save\"'")

    # --- KONFIGURACJA RUTERA R3 ---
    os.system("docker exec -t r3 /bin/bash -c 'vbash -c \"configure; "
              "set interfaces dummy dum0 address 2001:db8:3::1/128; "
              "set interfaces ethernet eth0 address 2001:db8:12::3/64; "
              "set interfaces ethernet eth1 address 2001:db8:13::3/64; "
              "set protocols ospfv3 parameters router-id 3.3.3.3; "
              "set protocols ospfv3 area 0.0.0.0 interface eth0; "
              "set protocols ospfv3 area 0.0.0.0 interface eth1; "
              "set protocols ospfv3 area 0.0.0.0 interface dum0; "
              "commit; save\"'")

    #Poprawic aby Ospf dzialal z poziomu kodu!!!!!!
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    Network()