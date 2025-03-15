try:
    from Packager import (
        Packager,
        Address,
        Application,
        Interface,
        Event,
        MODEM_INTERSECT_INTERVAL,
        MODEM_INTERSECT_RTX_TIMES,
    )
except ImportError:
    from .Packager import (
        Packager,
        Address,
        Application,
        Interface,
        Event,
        MODEM_INTERSECT_INTERVAL,
        MODEM_INTERSECT_RTX_TIMES,
    )
from binascii import crc32
from collections import deque, namedtuple
from hashlib import sha256
from random import randint
from struct import pack, unpack
from time import time


def enum(**enums):
    """Enum workaround for micropython. CC BY-SA 4.0
        https://stackoverflow.com/a/1695250
    """
    return type('Enum', (), enums)

PingOp = enum(
    REQUEST = 0,
    RESPOND = 1,
    GOSSIP_REQUEST = 2,
    GOSSIP_RESPOND = 3,
)

PingMessage = namedtuple(
    "PingMessage",
    ['op', 'nonce', 'ts1', 'ts2', 'ts3', 'tree_state', 'address', 'node_id']
)

ping_responses: deque[PingMessage] = deque([], 10)
gossip_app_id = bytes.fromhex('849969c1f22797d66f5a94db2afe634a')

def serialize_pm(pm: PingMessage) -> bytes:
    return pack(
        '!BBIIIB16s32s',
        pm.op,
        pm.nonce,
        pm.ts1,
        pm.ts2,
        pm.ts3,
        pm.tree_state,
        pm.address,
        pm.node_id
    )

def deserialize_pm(blob: bytes) -> PingMessage:
    return PingMessage(*unpack('!BBIIIB16s32s', blob))

def receive_pm(app: Application, blob: bytes, intrfc: Interface, mac: bytes):
    pm = deserialize_pm(blob)
    if pm.op == PingOp.REQUEST:
        if pm.node_id is not None and pm.node_id != Packager.node_id:
            Packager.add_route(pm.node_id, Address(pm.tree_state, address=pm.address))
        Ping.invoke('respond', pm)
    elif pm.op == PingOp.RESPOND:
        Ping.invoke('response_received', pm)

def ping_request(node_id: bytes|str) -> bool:
    """Send a ping request to the given node id. Returns False if it
        cannot be sent (no route to the node or no local address).
    """
    if len(Packager.node_addrs) == 0:
        return False
    node_id = bytes.fromhex(node_id) if type(node_id) == str else node_id
    pm = PingMessage(
        PingOp.REQUEST,
        randint(0, 255),
        int(time()),
        0,
        0,
        Packager.node_addrs[-1].tree_state,
        Packager.node_addrs[-1].address,
        Packager.node_id
    )
    return Packager.send(Ping.id, serialize_pm(pm), node_id)

def ping_respond(pm: PingMessage):
    """Send a ping response using the information in the ping message."""
    pm = PingMessage(
        PingOp.RESPOND,
        pm.nonce,
        pm.ts1,
        int(time()),
        0,
        pm.tree_state,
        pm.address,
        pm.node_id
    )
    return Packager.send(Ping.id, serialize_pm(pm), pm.node_id)

def ping_response_received(pm: PingMessage):
    ping_responses.append(PingMessage(
        pm.op,
        pm.nonce,
        pm.ts1,
        pm.ts2,
        int(time()),
        pm.tree_state,
        pm.address,
        pm.node_id
    ))

def ping_gossip_request(node_id: bytes|str) -> bool:
    """Send a gossip request to the given node id. Returns False if the
        gossip application is not found or if the local node has no
        address.
    """
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None or len(Packager.node_addrs) == 0:
        return False
    node_id = bytes.fromhex(node_id) if type(node_id) == str else node_id
    pm = PingMessage(
        PingOp.GOSSIP_REQUEST,
        randint(0, 255),
        int(time()),
        0,
        0,
        Packager.node_addrs[-1].tree_state,
        Packager.node_addrs[-1].address,
        Packager.node_id
    )
    topic_id = sha256(Ping.id + node_id).digest()[:16]
    Gossip.invoke('publish', topic_id, serialize_pm(pm))
    return True

def ping_gossip_respond(pm: PingMessage) -> bool:
    """Send a gossip response using the information in the ping message."""
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return False
    pm = PingMessage(
        PingOp.GOSSIP_RESPOND,
        pm.nonce,
        pm.ts1,
        int(time()),
        0,
        pm.tree_state,
        pm.address,
        pm.node_id
    )
    topic_id = sha256(Ping.id + pm.node_id).digest()[:16]
    Gossip.invoke('publish', topic_id, serialize_pm(pm))
    return True

def ping_gossip_response_received(pm: PingMessage):
    ping_responses.append(PingMessage(
        pm.op,
        pm.nonce,
        pm.ts1,
        pm.ts2,
        int(time()),
        pm.tree_state,
        pm.address,
        pm.node_id
    ))

def ping_list_routes():
    """List all routes known to this node."""
    print('Routes (node_id: address):')
    for addr, node_id in Packager.routes.items():
        print(f'\t{node_id.hex()}: {addr.coords} {addr.address.hex()}')

def start():
    """Subscribe to the gossip topic."""
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return False
    topic_id = sha256(Ping.id + Packager.node_id).digest()[:16]
    Gossip.invoke('subscribe', topic_id, Ping.id)

def stop():
    """Unsubscribe from the gossip topic."""
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return False
    topic_id = sha256(Ping.id + Packager.node_id).digest()[:16]
    Gossip.invoke('unsubscribe', topic_id, Ping.id)

Ping = Application(
    name='Ping',
    description='Dev Ping App',
    version=0,
    receive_func=receive_pm,
    callbacks={
        'request': lambda _, node_id: ping_request(node_id),
        'respond': lambda _, pm: ping_respond(pm),
        'response_received': lambda _, pm: ping_response_received(pm),
        'gossip_request': lambda _, node_id: ping_gossip_request(node_id),
        'gossip_respond': lambda _, pm: ping_gossip_respond(pm),
        'gossip_response_received': lambda _, pm: ping_gossip_response_received(pm),
        'serialize_pm': lambda _, pm: serialize_pm(pm),
        'deserialize_pm': lambda _, blob: deserialize_pm(blob),
        'start': lambda _: start(),
        'stop': lambda _: stop(),
        'list_routes': lambda _: ping_list_routes(),
        'get_ping_responses': lambda _: ping_responses,
    }
)

Packager.add_application(Ping)
