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
        dCPL,
        dTree,
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
        dCPL,
        dTree,
    )
from collections import deque, namedtuple
from hashlib import sha256
from machine import reset
from random import randint
from struct import pack, unpack
from time import time
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
    # ERROR = 199,
    OK = 200,
    AUTH_ERROR = 201,
    REQUIRE_SET_PW = 251,
    REQUIRE_BAN = 252,
    REQUIRE_UNBAN = 253,
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
    # DebugOp.ERROR: 'ERROR',
    DebugOp.OK: 'OK',
    DebugOp.AUTH_ERROR: 'AUTH_ERROR',
    DebugOp.REQUIRE_SET_PW: 'REQUIRE_SET_PW',
    DebugOp.REQUIRE_BAN: 'REQUIRE_BAN',
    DebugOp.REQUIRE_UNBAN: 'REQUIRE_UNBAN',
    DebugOp.REQUIRE_REFLECT: 'REQUIRE_REFLECT',
    DebugOp.REQUIRE_RESET: 'REQUIRE_RESET',
}
DebugMessage = namedtuple('DebugMessage', ['op', 'ts', 'nonce', 'from_id', 'data'])

gossip_app_id = bytes.fromhex('849969c1f22797d66f5a94db2afe634a')
seen_results: deque[dict] = deque([], 4)

def debug_auth_check(data: bytes):
    auth_hash1 = sha256(data).digest()[:16]
    l = data[0]
    auth_hash2 = sha256(data[l+1:]).digest()[:16]
    expected = DebugApp.params['admin_pass_hash']
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
    elif dm.op == DebugOp.AUTH_ERROR:
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
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return
    topic_id = sha256(DebugApp.id + dm.from_id).digest()[:16]
    if not debug_auth_check(dm.data):
        DebugApp.invoke('output', 'DebugApp: REQUIRE_* received with invalid auth data; ignoring')
        Gossip.invoke('publish', topic_id, serialize_dm(DebugMessage(
            DebugOp.AUTH_ERROR, int(time()), dm.nonce, Packager.node_id,
            json.dumps({'op': _inverse_op[dm.op], 'error': 'AUTH_ERROR'}).encode()
        )))
        return
    if dm.op == DebugOp.REQUIRE_RESET:
        DebugApp.invoke('output', 'DebugApp: REQUIRE_RESET received; scheduling reset')
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
        DebugApp.invoke('output', 'DebugApp: REQUIRE_REFLECT received')
        op = dm.data[1]
        Gossip.invoke('publish', topic_id, serialize_dm(DebugMessage(
            op, int(time()), dm.nonce, Packager.node_id, dm.data[2:]
        )))
    elif dm.op == DebugOp.REQUIRE_BAN:
        DebugApp.invoke('output', 'DebugApp: REQUIRE_BAN received')
        node_id = dm.data[1:33]
        Packager.ban(node_id)
        Gossip.invoke('publish', topic_id, serialize_dm(DebugMessage(
            DebugOp.OK, int(time()), dm.nonce, Packager.node_id,
            json.dumps({'op': 'REQUIRE_BAN', 'node_id': node_id.hex()}).encode()
        )))
    elif dm.op == DebugOp.REQUIRE_UNBAN:
        DebugApp.invoke('output', 'DebugApp: REQUIRE_UNBAN received')
        node_id = dm.data[1:33]
        Packager.unban(node_id)
        Gossip.invoke('publish', topic_id, serialize_dm(DebugMessage(
            DebugOp.OK, int(time()), dm.nonce, Packager.node_id,
            json.dumps({'op': 'REQUIRE_UNBAN', 'node_id': node_id.hex()}).encode()
        )))
    elif dm.op == DebugOp.REQUIRE_SET_PW:
        DebugApp.invoke('output', 'DebugApp: REQUIRE_SET_PW received')
        l = dm.data[0]
        new_pasw = dm.data[1:1+l]
        DebugApp.params['admin_pass_hash'] = sha256(new_pasw).digest()[:16]
        Gossip.invoke('publish', topic_id, serialize_dm(DebugMessage(
            DebugOp.OK, int(time()), dm.nonce, Packager.node_id,
            json.dumps({'op': 'REQUIRE_SET_PW'}).encode()
        )))
    else:
        DebugApp.invoke('output', 'DebugApp: REQUIRE_* received with unknown op; ignoring')

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

def require_action(op: int, peer_id: bytes, pasw: bytes, more: bytes = b''):
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is None:
        return
    peer_id = peer_id if type(peer_id) is bytes else bytes.fromhex(peer_id)
    topic_id = sha256(DebugApp.id + peer_id).digest()[:16]
    nonce = randint(0, 2**16 - 1)
    data = len(more).to_bytes(1, 'big') + more + pasw
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

def hexify(thing):
    if type(thing) is list:
        return [hexify(i) for i in thing]
    elif type(thing) is tuple:
        return tuple(hexify(i) for i in thing)
    elif type(thing) is bytes:
        return thing.hex()
    elif type(thing) is dict:
        return {hexify(k): hexify(v) for k, v in thing.items()}
    elif type(thing) in (int, float):
        return thing
    else:
        return thing if type(thing) is str else repr(thing)

async def _debug_command(cmd: list[str]):
    """Debug a node."""
    if len(cmd) < 2:
        print('debug - missing a required arg')
        return
    nid = bytes.fromhex(cmd[0])
    cmd[1] = cmd[1].lower()
    nh_addr = b''
    if cmd[1] not in ('info', 'peers', 'routes', 'next_hop'):
        print(f'debug - unknown mode {cmd[1]}')
        return
    if cmd[1] == 'info':
        op = DebugOp.REQUEST_NODE_INFO
    elif cmd[1] == 'peers':
        op = DebugOp.REQUEST_PEER_LIST
    elif cmd[1] == 'routes':
        op = DebugOp.REQUEST_ROUTES
    elif cmd[1] == 'next_hop':
        if len(cmd) < 4:
            print('debug next_hop - missing a required arg')
            return
        nh_addr = Address.from_str(cmd[2])
        metric = dCPL if 'cpl' in cmd[3].lower() else dTree
        nh_addr = pack('!BB16s', metric, nh_addr.tree_state, nh_addr.address)
        op = DebugOp.REQUEST_NEXT_HOP
    output = DebugApp.params['console_output']
    DebugApp.add_hook('output', lambda *args: output(args[1]))
    DebugApp.add_hook(
        'request',
        lambda *args: output(f'DebugApp.request sent: {hexify(args[1:])}')
    )
    DebugApp.invoke('request', op, nid, nh_addr)
    await DebugApp.params['console_wait'](2)

async def _admin_command(cmd: list[str]):
    """Execute admin command on a node."""
    if len(cmd) < 3:
        print('admin - missing a required arg')
        return
    nid = bytes.fromhex(cmd[0])
    pasw = cmd[1].encode()
    cmd[2] = cmd[2].lower()
    if cmd[2] == 'reset':
        op = DebugOp.REQUIRE_RESET
        DebugApp.invoke('require', op, nid, pasw)
        await DebugApp.params['console_wait'](1)
    elif cmd[2] in ('ban', 'unban'):
        if len(cmd) < 4:
            print('admin - missing a required arg')
            return
        op = DebugOp.REQUIRE_BAN if cmd[2] == 'ban' else DebugOp.REQUIRE_UNBAN
        pid = bytes.fromhex(cmd[3])
        if len(pid) != 32:
            print('admin - invalid peer_id')
            return
        DebugApp.invoke('require', op, nid, pasw, pid)
        await DebugApp.params['console_wait'](1)
    elif cmd[2] == 'set_pw':
        if len(cmd) < 3:
            print('admin - missing a required arg')
            return
        new_pasw = cmd[3].encode()
        op = DebugOp.REQUIRE_SET_PW
        DebugApp.invoke('require', op, nid, pasw, new_pasw)
        await DebugApp.params['console_wait'](1)
    else:
        print(f'admin - unknown subcommand {cmd[2]}')
        return

async def _local_admin_command(cmd: list[str]):
    """Execute admin command on the local node."""
    if len(cmd) < 2:
        print('local_admin - missing a required arg')
        return
    pasw = cmd[1].encode()
    DebugApp.params['admin_pass_hash'] = sha256(pasw).digest()[:16]
    print('local_admin - admin password set')

def register_debug_cmds(
        add_command: Callable, add_alias: Callable, wait: Callable,
        output: Callable
    ):
    """Register console commands."""
    DebugApp.params['console_wait'] = wait
    DebugApp.params['console_output'] = output
    add_command(
        'debug',
        _debug_command,
        'debug [node_id] [info|peers|routes|next_hop addr metric] - get ' +
            'debug info from a node'
    )
    add_command(
        'admin',
        _admin_command,
        'admin [node_id] [passwd] [set_pw passwd|reset|ban peer_id|unban peer_id] ' +
            '- execute an admin command on a node'
    )
    add_command(
        'local_admin',
        _local_admin_command,
        'local_admin [set_pw passwd] - set the local admin password'
    )

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
        'require': lambda _, op, peer_id, pasw, *args: require_action(op, peer_id, pasw, *args),
        'deserialize': lambda _, blob: deserialize_dm(blob),
        'serialize': lambda _, dm: serialize_dm(dm),
        'start': lambda _: start_debug_app(),
        'stop': lambda _: stop_debug_app(),
        'get_seen': lambda _: seen_results,
        'auth_check': lambda _, data: debug_auth_check(data),
        'register_commands': lambda _, *args, **kwargs: register_debug_cmds(*args, **kwargs),
    },
    params={
        'admin_pass_hash': bytes.fromhex('32549bff6d8404c4d121b589f4d24ac6'),
    }
)

Packager.add_application(DebugApp)
