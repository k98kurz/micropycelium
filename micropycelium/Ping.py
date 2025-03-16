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
from binascii import crc32
from collections import deque, namedtuple
from hashlib import sha256
from random import randint
from struct import pack, unpack
from time import time, time_ns
from typing import Callable


PingOp = enum(
    REQUEST = 0,
    RESPOND = 1,
    GOSSIP_REQUEST = 2,
    GOSSIP_RESPOND = 3,
)

PingMessage = namedtuple(
    "PingMessage",
    ['op', 'nonce', 'metric', 'ts1', 'ts2', 'ts3', 'tree_state', 'address', 'node_id']
)

ping_responses: deque[PingMessage] = deque([], 10)
gossip_app_id = bytes.fromhex('849969c1f22797d66f5a94db2afe634a')

def serialize_pm(pm: PingMessage) -> bytes:
    return pack(
        '!BBBQQQB16s32s',
        pm.op,
        pm.nonce,
        pm.metric,
        pm.ts1,
        pm.ts2,
        pm.ts3,
        pm.tree_state,
        pm.address,
        pm.node_id
    )

def deserialize_pm(blob: bytes) -> PingMessage:
    return PingMessage(*unpack('!BBBQQQB16s32s', blob))

def receive_pm(app: Application, blob: bytes, intrfc: Interface, mac: bytes):
    pm = deserialize_pm(blob)
    if pm.op == PingOp.REQUEST:
        if pm.node_id is not None and pm.node_id != Packager.node_id:
            Packager.add_route(pm.node_id, Address(pm.tree_state, address=pm.address))
        Ping.invoke('respond', pm)
    elif pm.op == PingOp.RESPOND:
        Ping.invoke('response_received', pm)
    elif pm.op == PingOp.GOSSIP_REQUEST:
        Ping.invoke('gossip_respond', pm)
    elif pm.op == PingOp.GOSSIP_RESPOND:
        Ping.invoke('gossip_response_received', pm)

def ping_request(
        node_id: bytes|str, metric: int = dTree, nonce: int|None = None
    ) -> bool:
    """Send a ping request to the given node id. Returns False if it
        cannot be sent (no route to the node or no local address).
    """
    if len(Packager.node_addrs) == 0:
        return False
    node_id = bytes.fromhex(node_id) if type(node_id) == str else node_id
    pm = PingMessage(
        PingOp.REQUEST,
        nonce if nonce is not None else randint(0, 255),
        metric,
        int(time_ns() / 1_000_000),
        0,
        0,
        Packager.node_addrs[-1].tree_state,
        Packager.node_addrs[-1].address,
        Packager.node_id
    )
    return Packager.send(Ping.id, serialize_pm(pm), node_id, metric=metric)

def ping_respond(pm: PingMessage):
    """Send a ping response using the information in the ping message."""
    pm = PingMessage(
        PingOp.RESPOND,
        pm.nonce,
        pm.metric,
        pm.ts1,
        int(time_ns() / 1_000_000),
        0,
        pm.tree_state,
        pm.address,
        pm.node_id
    )
    return Packager.send(Ping.id, serialize_pm(pm), pm.node_id, metric=pm.metric)

def ping_response_received(pm: PingMessage):
    ping_responses.append(PingMessage(
        pm.op,
        pm.nonce,
        pm.metric,
        pm.ts1,
        pm.ts2,
        int(time_ns() / 1_000_000),
        pm.tree_state,
        pm.address,
        pm.node_id
    ))

def ping_gossip_request(node_id: bytes|str, nonce: int|None = None) -> bool:
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
        nonce if nonce is not None else randint(0, 255),
        0,
        int(time_ns() / 1_000_000),
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
        pm.metric,
        pm.ts1,
        int(time_ns() / 1_000_000),
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
        pm.metric,
        pm.ts1,
        pm.ts2,
        int(time_ns() / 1_000_000),
        pm.tree_state,
        pm.address,
        pm.node_id
    ))

def ping_list_routes():
    """List all routes known to this node."""
    print('Routes (node_id: address):')
    for addr, node_id in Packager.routes.items():
        print(f'\t{node_id.hex()}: {addr.coords} {addr.address.hex()}')

def report_ping_test(
        nonce: int, mode: str, expected_count: int, remote_id: bytes|str,
        remote_addr: Address|None = None, callback: Callable|None = None
    ) -> dict:
    """Generate a report of the ping test results."""
    # take all relevant pms, then put the rest back
    pms = []
    while len(ping_responses):
        pms.append(ping_responses.popleft())
    relevant_pms = []
    while len(pms):
        pm = pms.pop()
        if pm.nonce == nonce:
            relevant_pms.append(pm)
        else:
            ping_responses.append(pm)
    # generate report
    count = len(relevant_pms)
    if count == 0:
        report = {
            'error': 'no responses',
            'remote_id': remote_id if type(remote_id) == str else remote_id.hex(),
            'remote_addr': remote_addr,
            'mode': mode,
            'expected_count': expected_count,
            'success_rate': '0%',
        }
        if callback is not None:
            callback(report)
        return report
    report = {
        'mode': mode,
        'remote_id': remote_id if type(remote_id) == str else remote_id.hex(),
        'remote_addr': remote_addr,
        'count': count,
        'expected_count': expected_count,
        'success_rate': f"{int(count / expected_count * 100)}%",
        'there': {
            'min': 10**9,
            'max': 0,
            'avg': 0,
        },
        'back': {
            'min': 10**9,
            'max': 0,
            'avg': 0,
        },
        'round_trip': {
            'min': 10**9,
            'max': 0,
            'avg': 0,
        }
    }
    for pm in relevant_pms:
        delay = pm.ts3 - pm.ts1
        there = pm.ts2 - pm.ts1
        back = pm.ts3 - pm.ts2
        # round trip
        if delay < report['round_trip']['min']:
            report['round_trip']['min'] = delay
        if delay > report['round_trip']['max']:
            report['round_trip']['max'] = delay
        report['round_trip']['avg'] += delay
        # there
        if there < report['there']['min']:
            report['there']['min'] = there
        if there > report['there']['max']:
            report['there']['max'] = there
        report['there']['avg'] += there
        # back
        if back < report['back']['min']:
            report['back']['min'] = back
        if back > report['back']['max']:
            report['back']['max'] = back
        report['back']['avg'] += back
    report['round_trip']['avg'] /= count
    report['there']['avg'] /= count
    report['back']['avg'] /= count
    if callback is not None:
        callback(report)
    return report

def run_ping_test(
        node_id: bytes|str, count: int = 4, timeout: int = 30,
        addr: Address|None = None, metric: int = dTree,
        callback: Callable|None = None
    ):
    """Ping a node count times, scheduling a series of pings after a
        delays calculated by multiplying the index by the timeout. Also
        schedules generation of a report after timeout * count seconds.
    """
    node_id = bytes.fromhex(node_id) if type(node_id) == str else node_id
    topic_id = sha256(Ping.id + node_id).digest()[:16]
    topic_id += PingOp.REQUEST.to_bytes(1, 'big')
    nonce = randint(0, 255)
    now = int(time_ns() / 1_000_000)
    addr = addr if addr is not None else Packager.inverse_routes.get(node_id, [None])[-1]
    for i in range(count):
        Packager.new_events.append(Event(
            now + timeout * i * 1000,
            topic_id + i.to_bytes(1, 'big'),
            ping_request,
            node_id,
            metric,
            nonce,
        ))
    Packager.new_events.append(Event(
        now + timeout * count * 1000,
        topic_id + count.to_bytes(1, 'big'),
        report_ping_test,
        nonce,
        'routed dTree' if metric == dTree else 'routed dCPL' if metric == dCPL else 'unknown metric',
        count,
        node_id,
        addr,
        callback,
    ))

def run_gossip_ping_test(
        node_id: bytes|str, count: int = 4, timeout: int = 60,
        addr: Address|None = None,
        callback: Callable|None = None
    ):
    """Ping a node count times through Gossip, scheduling a series of
        pings after a delays calculated by multiplying the index by the
        timeout. Also schedules generation of a report after timeout *
        count seconds.
    """
    node_id = bytes.fromhex(node_id) if type(node_id) == str else node_id
    topic_id = sha256(Ping.id + node_id).digest()[:16]
    topic_id += PingOp.GOSSIP_REQUEST.to_bytes(1, 'big')
    nonce = randint(0, 255)
    now = int(time_ns() / 1_000_000)
    for i in range(count):
        Packager.new_events.append(Event(
            now + timeout * i * 1000,
            topic_id + i.to_bytes(1, 'big'),
            ping_gossip_request,
            node_id,
            nonce,
        ))
    Packager.new_events.append(Event(
        now + timeout * count * 1000,
        topic_id + count.to_bytes(1, 'big'),
        report_ping_test,
        nonce,
        'gossip',
        count,
        node_id,
        addr,
        callback,
    ))

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
        'ping': lambda _, *args, **kwargs: run_ping_test(*args, **kwargs),
        'gossip_ping': lambda _, *args, **kwargs: run_gossip_ping_test(*args, **kwargs),
        'report_ping_test': lambda _, *args, **kwargs: report_ping_test(*args, **kwargs),
        'get_ping_responses': lambda _: ping_responses,
    }
)

Packager.add_application(Ping)
