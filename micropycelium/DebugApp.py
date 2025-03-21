try:
    from Packager import (
        enum,
        Packager,
        Address,
        Application,
        Interface,
        Event,
        # dTree,
        # dCPL,
        # MODEM_INTERSECT_INTERVAL,
        # MODEM_INTERSECT_RTX_TIMES,
        time_ms,
    )
except ImportError:
    from .Packager import (
        enum,
        Packager,
        Address,
        Application,
        Interface,
        Event,
        # dTree,
        # dCPL,
        # MODEM_INTERSECT_INTERVAL,
        # MODEM_INTERSECT_RTX_TIMES,
        time_ms,
    )
from collections import deque, namedtuple
from hashlib import sha256
from machine import reset
from random import randint
from struct import pack, unpack
from time import time

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
    OK = 200,
    REQUIRE_REFLECT = 254,
    REQUIRE_RESET = 255,
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
    DebugOp.OK: 'OK',
    DebugOp.REQUIRE_REFLECT: 'REQUIRE_REFLECT',
    DebugOp.REQUIRE_RESET: 'REQUIRE_RESET',
}
DebugMessage = namedtuple('DebugMessage', ['op', 'ts', 'nonce', 'from_id', 'data'])

gossip_app_id = bytes.fromhex('849969c1f22797d66f5a94db2afe634a')
seen_results: deque[dict] = deque([], 10)
def debug_auth_check(data: bytes):
    auth_hash1 = sha256(data).digest()[:16]
    auth_hash2 = sha256(data[1:]).digest()[:16]
    expected = bytes.fromhex('32549bff6d8404c4d121b589f4d24ac6')
    return auth_hash1 == expected or auth_hash2 == expected

def serialize_dm(dm: DebugMessage):
    return pack(f'!BIH32s{len(dm.data)}s', dm.op, dm.ts, dm.nonce, dm.from_id, dm.data)

def deserialize_dm(blob: bytes) -> DebugMessage:
    return DebugMessage(*unpack(f'!BIH32s{len(blob) - 39}s', blob))

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
    elif dm.op == DebugOp.OK:
        DebugApp.invoke('handle_response', dm)
    else:
        DebugApp.invoke('handle_require', dm)

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
        DebugOp.RESPOND_NODE_INFO, int(time()), dm.nonce, Packager.node_id, json.dumps(info).encode()
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
        DebugOp.RESPOND_PEER_LIST, int(time()), dm.nonce, Packager.node_id, json.dumps(info).encode()
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
        DebugOp.RESPOND_ROUTES, int(time()), dm.nonce, Packager.node_id, json.dumps(info).encode()
    )
    Gossip.invoke('publish', topic_id, serialize_dm(new_dm))

def handle_request_next_hop(dm: DebugMessage):
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return
    metric, tree_state, addr = unpack('!BB16s', dm.data)
    next_hop = Packager.next_hop(Address(tree_state, addr), metric)
    info = {
        'next_hop': (next_hop[0].id.hex(), str(next_hop[1]))
            if next_hop is not None else None,
    }
    topic_id = sha256(DebugApp.id + dm.from_id).digest()[:16]
    Gossip.invoke('publish', topic_id, serialize_dm(DebugMessage(
        DebugOp.RESPOND_NEXT_HOP, int(time()), dm.nonce, Packager.node_id,
        json.dumps(info).encode()
    )))

def handle_require(dm: DebugMessage):
    if not debug_auth_check(dm.data):
        print('DebugApp: REQUIRE_* received with invalid auth data; ignoring')
        return
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return
    topic_id = sha256(DebugApp.id + dm.from_id).digest()[:16]
    if dm.op == DebugOp.REQUIRE_RESET:
        print('DebugApp: REQUIRE_RESET received; scheduling reset')
        Packager.queue_event(Event(
            time_ms() + 200,
            b'reset',
            reset
        ))
        Gossip.invoke('publish', topic_id, serialize_dm(DebugMessage(
            DebugOp.OK, int(time()), dm.nonce, Packager.node_id,
            json.dumps({'op': 'REQUIRE_RESET'}).encode()
        )))
    elif dm.op == DebugOp.REQUIRE_REFLECT:
        print('DebugApp: REQUIRE_REFLECT received')
        op = dm.data[0]
        Gossip.invoke('publish', topic_id, serialize_dm(DebugMessage(
            op, int(time()), dm.nonce, Packager.node_id, dm.data[1:]
        )))
    else:
        print('DebugApp: REQUIRE_* received with unknown op; ignoring')

def handle_response(dm: DebugMessage):
    if len(dm.data):
        try:
            info = json.loads(dm.data.decode())
        except:
            info = {'error': 'Invalid JSON received', 'data': dm.data}
    else:
        info = {}
    result = {
        'op': _inverse_op.get(dm.op, 'UNKNOWN'),
        'from_id': dm.from_id.hex(),
    }
    result.update(info)
    DebugApp.invoke('output', result)
    seen_results.append(result)

def request_debug_info(op: int, peer_id: bytes, data: bytes = b''):
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return
    peer_id = peer_id if type(peer_id) is bytes else bytes.fromhex(peer_id)
    topic_id = sha256(DebugApp.id + peer_id).digest()[:16]
    nonce = randint(0, 2**16 - 1)
    dm = DebugMessage(op, int(time()), nonce, Packager.node_id, data)
    Gossip.invoke('publish', topic_id, serialize_dm(dm))

def require_action(op: int, peer_id: bytes, data: bytes):
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return
    peer_id = peer_id if type(peer_id) is bytes else bytes.fromhex(peer_id)
    topic_id = sha256(DebugApp.id + peer_id).digest()[:16]
    nonce = randint(0, 2**16 - 1)
    dm = DebugMessage(op, int(time()), nonce, Packager.node_id, data)
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
        'handle_require': lambda _, dm: handle_require(dm),
        'request': lambda _, op, peer_id, *args: request_debug_info(op, peer_id, *args),
        'require': lambda _, op, peer_id, data: require_action(op, peer_id, data),
        'deserialize': lambda _, blob: deserialize_dm(blob),
        'serialize': lambda _, dm: serialize_dm(dm),
        'start': lambda _: start_debug_app(),
        'stop': lambda _: stop_debug_app(),
        'get_seen': lambda _: seen_results,
        'auth_check': lambda _, data: debug_auth_check(data),
    }
)

Packager.add_application(DebugApp)
