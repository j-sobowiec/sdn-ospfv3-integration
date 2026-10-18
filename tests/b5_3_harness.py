"""B5.3 isolated harness: executes UNMODIFIED class/method ASTs from project files.

Mocks replace Ryu serialization and the switch only. No controller threads, FRR,
network namespaces, Scapy or installed Ryu are required for these isolated tests.
"""
import ast
import copy
import ipaddress
import logging
import runpy
import os
from pathlib import Path
import socket
import struct
import time
from types import SimpleNamespace as NS

ROOT = Path(os.environ.get('B53_PROJECT_ROOT', Path(__file__).resolve().parents[1]))
DATA_PATH = Path(os.environ.get('B53_DP_SOURCE', ROOT / 'dataplane.py'))
CTRL_PATH = Path(os.environ.get('B53_CTRL_SOURCE', ROOT / 'ryu_sdn.py'))

CFG = NS(ROUTER_ID='10.10.10.10', LAN_PREFIX='2001:db8:1::', LAN_PREFIX_LEN=64,
         LAN_GATEWAY='2001:db8:1::1', LINK_LOCAL='fe80::10',
         ROUTER_MAC='02:00:00:00:00:01', DEAD_INTERVAL=40)
# In a real project take the *actual* topology constants from config.py.
_CONFIG_FILE = Path(os.environ.get('B53_CFG_SOURCE', ROOT / 'ospfv3' / 'config.py'))
if _CONFIG_FILE.is_file():
    _values = runpy.run_path(str(_CONFIG_FILE))
    CFG = NS(**{k: v for k, v in _values.items() if k.isupper()})

LAN_IP = '2001:db8:1::100'
LAN_MAC = '02:00:00:00:01:00'
TRANSIT_IP = 'fe80::1'
TRANSIT_MAC = '02:00:00:00:10:01'
ROUTE = {'prefix':'2001:db8:23::', 'prefix_length':64, 'source':'ospf',
         'next_hop':'1.1.1.1', 'interface':'transit', 'total_cost':30,
         'advertising_router':'2.2.2.2'}

class Wire:
    def __init__(self, **kw):
        vars(self).update(kw)

class Ether(Wire): pass
class IP6(Wire): pass
class ICMP(Wire): pass
class ND(Wire): pass
class Echo(Wire):
    @property
    def id(self): return self.id_
class TLA(Wire): pass

FRAMES = {}
class Pkt:
    _count = 0
    def __init__(self, incoming=None):
        if incoming is not None:
            reference = FRAMES[incoming]
            self.protocols = list(reference.protocols)
        else:
            self.protocols = []
        self.data = None
    def add_protocol(self, protocol):
        self.protocols.append(protocol)
    def get_protocol(self, kind):
        return next((p for p in self.protocols if isinstance(p, kind)), None)
    def serialize(self):
        Pkt._count += 1
        self.data = ('B53:%s' % Pkt._count).encode()
        FRAMES[self.data] = self

def incoming(*protocols):
    packet = Pkt()
    packet.protocols.extend(protocols)
    packet.serialize()
    return packet.data

PACKET = NS(Packet=Pkt)
ETHERNET = NS(ethernet=Ether)
IPV6 = NS(ipv6=IP6)
ICMPV6 = NS(icmpv6=ICMP, nd_neighbor=ND, echo=Echo,
            nd_option_tla=TLA, ND_NEIGHBOR_SOLICIT=135, ND_NEIGHBOR_ADVERT=136)
ETH_TYPES = NS(ETH_TYPE_IPV6=0x86dd)

class OFMsg:
    def __init__(self, kind, *args, **kw):
        self.kind = kind
        self.args = args
        vars(self).update(kw)

class OFParser:
    @staticmethod
    def OFPMatch(**kw): return OFMsg('match', **kw)
    @staticmethod
    def OFPActionOutput(*a): return OFMsg('output', *a)
    @staticmethod
    def OFPActionDecNwTtl(): return OFMsg('dec_ttl')
    @staticmethod
    def OFPActionSetField(**kw): return OFMsg('set_field', **kw)
    @staticmethod
    def OFPInstructionActions(*a): return OFMsg('instruction', *a)
    @staticmethod
    def OFPFlowMod(**kw): return OFMsg('flow', **kw)
    @staticmethod
    def OFPPacketOut(**kw): return OFMsg('packet_out', **kw)
    @staticmethod
    def OFPBarrierRequest(dp): return OFMsg('barrier', dp)

OFP = NS(OFP_VERSION=4, OFPFC_DELETE=3, OFPFC_DELETE_STRICT=4,
         OFPP_ANY=0xffffffff, OFPG_ANY=0xffffffff,
         OFPP_CONTROLLER=0xfffffffd, OFPCML_NO_BUFFER=0xffff,
         OFPIT_APPLY_ACTIONS=4, OFP_NO_BUFFER=0xffffffff)

class Switch:
    def __init__(self):
        self.ofproto = OFP
        self.ofproto_parser = OFParser()
        self.sent = []
        self.id = 1
        self._xid = 1
    def send_msg(self, msg):
        self.sent.append(msg)
    def set_xid(self, msg):
        msg.xid = self._xid
        self._xid += 1

def load_class(path, name, globals_dict):
    source = path.read_text(encoding='utf8')
    tree = ast.parse(source, filename=str(path))
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name)
    node = copy.deepcopy(node)
    node.bases = []  # Avoid starting Ryu app: all original method bodies are unchanged.
    node.decorator_list = []
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            item.decorator_list = [d for d in item.decorator_list
                                   if isinstance(d, ast.Name) and d.id in ('staticmethod', 'classmethod')]
    mod = ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[]))
    namespace = dict(globals_dict)
    exec(compile(mod, str(path), 'exec'), namespace)
    return namespace[name]

BASE = dict(cfg=CFG, ipaddress=ipaddress, packet=PACKET, ethernet=ETHERNET,
            ipv6=IPV6, icmpv6=ICMPV6, ether_types=ETH_TYPES,
            struct=struct, socket=socket, time=time,
            ofproto_v1_3=NS(OFP_VERSION=OFP.OFP_VERSION))
DataPlane = load_class(DATA_PATH, 'DataPlane', BASE)
Controller = load_class(CTRL_PATH, 'OSPFv3Controller', {**BASE, 'DataPlane':DataPlane})

def make_controller(route=True, ready=True):
    ctl = Controller.__new__(Controller)
    ctl.logger = logging.getLogger('B5_3')
    ctl.datapath = Switch()
    ctl.data_plane = DataPlane()
    ctl.ipv6_routing_table = {}
    ctl.installed_ipv6_host_flows = {}
    ctl.pending_ndp_barriers = {}
    ctl.local_lsa_ack_pending = {}
    ctl.local_lsu_sent = False
    ctl.local_lsu_last_tx = None
    if route:
        ctl.ipv6_routing_table[(ROUTE['prefix'], 64)] = dict(ROUTE)
    if ready:
        ctl.data_plane.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        ctl.data_plane.learn_lan_host(2, LAN_IP, LAN_MAC)
    return ctl

def flowmods(dp, command=None):
    results = [x for x in dp.sent if x.kind == 'flow']
    return results if command is None else [x for x in results if getattr(x,'command',None)==command]

def ns(src=LAN_IP, dst='2001:db8:23::3', proto=58, eth_src=LAN_MAC,
       eth_dst=CFG.ROUTER_MAC, data=None):
    protos = [Ether(src=eth_src, dst=eth_dst, ethertype=0x86dd),
              IP6(src=src, dst=dst, nxt=proto, hop_limit=64)]
    if data is not None:
        protos.append(data)
    return incoming(*protos)

def packet_in(ctl, frame, port=2):
    event = NS(msg=NS(data=frame, match={'in_port':port}, datapath=ctl.datapath))
    return ctl.packet_in_handler(event)
