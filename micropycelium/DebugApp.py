try:
    from Packager import (
        enum,
        Packager,
        Address,
        Application,
        Interface,
        Event,
        dTree,
        dCPL,
        MODEM_INTERSECT_INTERVAL,
        MODEM_INTERSECT_RTX_TIMES,
    )
except ImportError:
    from .Packager import (
        enum,
        Packager,
        Address,
        Application,
        Interface,
        Event,
        dTree,
        dCPL,
        MODEM_INTERSECT_INTERVAL,
        MODEM_INTERSECT_RTX_TIMES,
    )
from collections import deque, namedtuple
from hashlib import sha256
from random import randint
from struct import pack, unpack
from time import time, time_ns
from typing import Callable
# save_imports
import json


DebugOp = enum(
    REQUEST_NODE_INFO = 0,
    REQUEST_PEER_LIST = 1,
    REQUEST_ROUTES = 2,
    REQUEST_NEXT_HOP = 3,
    RESPOND_NODE_INFO = 100,
    RESPOND_PEER_LIST = 101,
    RESPOND_ROUTES = 102,
    RESPOND_NEXT_HOP = 103,
)
_inverse_op = {
    DebugOp.REQUEST_NODE_INFO: 'REQUEST_NODE_INFO',
    DebugOp.REQUEST_PEER_LIST: 'REQUEST_PEER_LIST',
    DebugOp.REQUEST_ROUTES: 'REQUEST_ROUTES',
    DebugOp.REQUEST_NEXT_HOP: 'REQUEST_NEXT_HOP',
    DebugOp.RESPOND_NODE_INFO: 'RESPOND_NODE_INFO',
    DebugOp.RESPOND_PEER_LIST: 'RESPOND_PEER_LIST',
    DebugOp.RESPOND_ROUTES: 'RESPOND_ROUTES',
    DebugOp.RESPOND_NEXT_HOP: 'RESPOND_NEXT_HOP',
}
DebugMessage = namedtuple('DebugMessage', ['op', 'nonce', 'from_id', 'data'])

gossip_app_id = bytes.fromhex('849969c1f22797d66f5a94db2afe634a')
seen_dm: deque[DebugMessage] = deque([], 10)


def serialize_dm(dm: DebugMessage):
    return pack(f'!BH32s{len(dm.data)}s', dm.op, dm.nonce, dm.from_id, dm.data)

def deserialize_dm(blob: bytes) -> DebugMessage:
    return DebugMessage(*unpack(f'!BH32s{len(blob) - 35}s', blob))

def receive_debug(app: Application, blob: bytes, intrfc: Interface, mac: bytes):
    dm = deserialize_dm(blob)
    if dm.op == DebugOp.REQUEST_NODE_INFO:
        DebugApp.invoke('handle_request_node_info', dm)
    elif dm.op == DebugOp.REQUEST_PEER_LIST:
        DebugApp.invoke('handle_request_peer_list', dm)
    elif dm.op == DebugOp.REQUEST_ROUTES:
        DebugApp.invoke('handle_request_routes', dm)
    elif dm.op == DebugOp.REQUEST_NEXT_HOP:
        DebugApp.invoke('handle_request_next_hop', dm)
    elif dm.op == DebugOp.RESPOND_NODE_INFO:
        DebugApp.invoke('handle_response', dm)
    elif dm.op == DebugOp.RESPOND_PEER_LIST:
        DebugApp.invoke('handle_response', dm)
    elif dm.op == DebugOp.RESPOND_ROUTES:
        DebugApp.invoke('handle_response', dm)
    elif dm.op == DebugOp.RESPOND_NEXT_HOP:
        DebugApp.invoke('handle_response', dm)

def handle_request_node_info(dm: DebugMessage):
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return
    info = {
        'node_id': Packager.node_id.hex(),
        'node_addrs': [str(addr) for addr in Packager.node_addrs],
        'apps': [app.id.hex() for app in Packager.apps.values()],
    }
    topic_id = sha256(DebugApp.id + dm.from_id).digest()[:16]
    new_dm = DebugMessage(
        DebugOp.RESPOND_NODE_INFO, dm.nonce, Packager.node_id, json.dumps(info).encode()
    )
    Gossip.invoke('publish', topic_id, serialize_dm(new_dm))

def handle_request_peer_list(dm: DebugMessage):
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return
    info = {
        'node_id': Packager.node_id.hex(),
        'peers': {
            pid.hex(): [str(addr) for addr in peer.addrs]
            for pid, peer in Packager.peers.items()
        },
    }
    topic_id = sha256(DebugApp.id + dm.from_id).digest()[:16]
    new_dm = DebugMessage(
        DebugOp.RESPOND_PEER_LIST, dm.nonce, Packager.node_id, json.dumps(info).encode()
    )
    Gossip.invoke('publish', topic_id, serialize_dm(new_dm))

def handle_request_routes(dm: DebugMessage):
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return
    info = {
        'node_id': Packager.node_id.hex(),
        'routes': {
            str(addr): pid.hex()
            for addr, pid in Packager.routes.items()
        },
    }
    topic_id = sha256(DebugApp.id + dm.from_id).digest()[:16]
    new_dm = DebugMessage(
        DebugOp.RESPOND_ROUTES, dm.nonce, Packager.node_id, json.dumps(info).encode()
    )
    Gossip.invoke('publish', topic_id, serialize_dm(new_dm))

def handle_request_next_hop(dm: DebugMessage):
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return
    metric, tree_state, addr = unpack('!?B16s', dm.data)
    next_hop = Packager.next_hop(tree_state, Address(tree_state, addr), metric)
    info = {
        'next_hop': (next_hop[0].id.hex(), str(next_hop[1]))
            if next_hop is not None else None,
    }
    topic_id = sha256(DebugApp.id + dm.from_id).digest()[:16]
    new_dm = DebugMessage(
        DebugOp.RESPOND_NEXT_HOP, dm.nonce, Packager.node_id, json.dumps(info).encode()
    )
    Gossip.invoke('publish', topic_id, serialize_dm(new_dm))

def handle_response(dm: DebugMessage):
    try:
        info = json.loads(dm.data.decode())
    except:
        info = {'error': 'Invalid JSON received', 'data': dm.data}
    result = {
        'op': _inverse_op.get(dm.op, 'UNKNOWN'),
        'from_id': dm.from_id.hex(),
    }
    result.update(info)
    DebugApp.invoke('output', result)
    seen_dm.append(dm)

def request_debug_info(op: int, peer_id: bytes):
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return
    peer_id = peer_id if type(peer_id) is bytes else bytes.fromhex(peer_id)
    topic_id = sha256(DebugApp.id + peer_id).digest()[:16]
    nonce = randint(0, 2**16 - 1)
    dm = DebugMessage(op, nonce, Packager.node_id, b'')
    Gossip.invoke('publish', topic_id, serialize_dm(dm))


def start_debug_app():
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is not None:
        topic_id = sha256(DebugApp.id + Packager.node_id).digest()[:16]
        Gossip.invoke('subscribe', topic_id, DebugApp.id)

def stop_debug_app():
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is not None:
        topic_id = sha256(DebugApp.id + Packager.node_id).digest()[:16]
        Gossip.invoke('unsubscribe', topic_id, DebugApp.id)

DebugApp = Application(
    name='DebugApp',
    description='Debug App',
    version=0,
    receive_func=receive_debug,
    callbacks={
        'handle_request_node_info': lambda _, dm: handle_request_node_info(dm),
        'handle_request_peer_list': lambda _, dm: handle_request_peer_list(dm),
        'handle_request_routes': lambda _, dm: handle_request_routes(dm),
        'handle_request_next_hop': lambda _, dm: handle_request_next_hop(dm),
        'handle_response': lambda _, dm: handle_response(dm),
        'deserialize': lambda _, blob: deserialize_dm(blob),
        'serialize': lambda _, dm: serialize_dm(dm),
        'request': lambda _, op, peer_id: request_debug_info(op, peer_id),
        'start': lambda _: start_debug_app(),
        'stop': lambda _: stop_debug_app(),
        'get_seen': lambda _: seen_dm,
    }
)

Packager.add_application(DebugApp)
