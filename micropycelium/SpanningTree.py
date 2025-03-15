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
from random import randint
from struct import pack, unpack
from time import time


def enum(**enums):
    """Enum workaround for micropython. CC BY-SA 4.0
        https://stackoverflow.com/a/1695250
    """
    return type('Enum', (), enums)

TreeOp = enum(
    SEND = 0,
    RESPOND = 15,
    REQUEST_ADDRESS_ASSIGNMENT = 240,
    ASSIGN_ADDRESS = 255,
)

def tree_state(claim: bytes):
    return crc32(claim).to_bytes(4, 'big')[0]

root_id_targets = (
    b'1234' * 8,
    b'4321' * 8,
    b'5678' * 8,
    b'8765' * 8,
)
now = lambda: int(time()*1000)
TreeMessage = namedtuple("TreeMessage", ['op', 'claim', 'address', 'node_id'])
seen_tm: deque[TreeMessage] = deque([], 10)
tree_app_id = b''
gossip_app_id = bytes.fromhex('849969c1f22797d66f5a94db2afe634a')
tree_maintenance_rounds = 0

current_children: dict[bytes, int] = {} # map of child peer ids to coordinates
current_parent: bytes = b''
# tuple of (claim, dTree from root, peer_id)
known_claims: deque[tuple[bytes, int, bytes]] = deque([], 10)

# elect self as initial root
current_best_root_id = Packager.node_id
Packager.set_addr(Address(tree_state(Packager.node_id), coords=[]))

def xor(b1: bytes, b2: bytes) -> bytes:
    """XOR two equal-length byte strings together."""
    b3 = bytearray()
    for i in range(len(b1)):
        b3.append(b1[i] ^ b2[i])

    return bytes(b3)

def claim_score(node_id: bytes, overlay_idx: int = 0) -> int:
    """Calculate the distance from the target root id. Lower is better."""
    return int.from_bytes(xor(node_id, root_id_targets[overlay_idx]), 'big')

def serialize_tm(tmsg: TreeMessage):
    return pack('!B32s16s32s', tmsg.op, tmsg.claim, tmsg.address, tmsg.node_id)

def deserialize_tm(blob: bytes) -> TreeMessage:
    op, claim, address, node_id = unpack('!B32s16s32s', blob)
    return TreeMessage(op, claim, address, node_id)

def lwst_avlbl_coord() -> int|None:
    vals = set(current_children.values())
    for i in range(1, 136):
        if i not in vals:
            return i
    return None

def remove_peer(_, pid: bytes):
    # remove the peer from the current children
    if pid in current_children:
        del current_children[pid]
    # remove the peer from the known claims
    claims = list(known_claims)
    known_claims.clear()
    for claim, dTree, peer_id in claims:
        if peer_id != pid:
            known_claims.append((claim, dTree, peer_id))

def receive_tm(app: Application, blob: bytes, intrfc: Interface, mac: bytes):
    global current_best_root_id, current_parent
    tmsg = deserialize_tm(blob)
    seen_tm.append(tmsg)
    peer_id = Packager.inverse_peers.get((mac, intrfc.id), None)
    their_score = claim_score(tmsg.claim)
    our_score = claim_score(current_best_root_id)

    if tmsg.op == TreeOp.SEND:
        if tmsg.node_id is not None and tmsg.node_id != Packager.node_id:
            Packager.add_route(
                tmsg.node_id, Address(tree_state(tmsg.claim), address=tmsg.address)
            )
            if tmsg.node_id != peer_id:
                # gossip message for app/service discovery; do not respond
                return
        if their_score < our_score:
            # add the claim to the known claims
            addr = Address(tree_state(tmsg.claim), address=tmsg.address)
            root = Address(tree_state(tmsg.claim), coords=[])
            known_claims.append((tmsg.claim, addr.dTree(root, addr), peer_id))
        elif our_score < their_score:
            # we have a better claim, so respond with it
            SpanningTree.invoke('respond', peer_id)
    elif tmsg.op == TreeOp.RESPOND:
        # received a response to a periodic broadcast
        if their_score < our_score:
            # add the claim to the known claims
            addr = Address(tree_state(tmsg.claim), address=tmsg.address)
            root = Address(tree_state(tmsg.claim), coords=[])
            known_claims.append((tmsg.claim, addr.dTree(root, addr), peer_id))
    elif tmsg.op == TreeOp.REQUEST_ADDRESS_ASSIGNMENT:
        # received an address assignment request
        if tree_state(tmsg.claim) == Packager.node_addrs[-1].tree_state:
            # respond with the address assignment
            coords = list(Packager.node_addrs[-1].coords)
            coord = lwst_avlbl_coord()
            if coord is None or peer_id is None:
                # no available coordinates, or peer_id not found, so reject the request
                return
            coords.append(coord)
            current_children[peer_id] = coord
            SpanningTree.invoke('assign_address', peer_id, coords)
    elif tmsg.op == TreeOp.ASSIGN_ADDRESS:
        # received an address assignment response
        if their_score < our_score and tmsg.node_id != Packager.node_id:
            # accept the address and set the new best claim
            current_best_root_id = tmsg.claim
            current_parent = peer_id
            current_children.clear()
            Packager.set_addr(Address(tree_state(tmsg.claim), tmsg.address))
        else:
            # we have a better claim, so respond with it
            SpanningTree.invoke('respond', peer_id)

def broadcast_tree_message():
    tmsg = TreeMessage(
        TreeOp.SEND,
        current_best_root_id,
        Packager.node_addrs[-1].address,
        Packager.node_id
    )
    Packager.broadcast(tree_app_id, serialize_tm(tmsg))

def send_tree_message(pid: bytes):
    tmsg = TreeMessage(
        TreeOp.SEND,
        current_best_root_id,
        Packager.node_addrs[-1].address,
        Packager.node_id
    )
    Packager.send(tree_app_id, serialize_tm(tmsg), pid)

def respond_tree_message(pid: bytes):
    tmsg = TreeMessage(
        TreeOp.RESPOND,
        current_best_root_id,
        Packager.node_addrs[-1].address,
        Packager.node_id
    )
    Packager.send(tree_app_id, serialize_tm(tmsg), pid)

def request_address_assignment(pid: bytes, claim: bytes):
    tmsg = TreeMessage(
        TreeOp.REQUEST_ADDRESS_ASSIGNMENT,
        claim,
        b'\x00' * 16,
        Packager.node_id
    )
    Packager.send(tree_app_id, serialize_tm(tmsg), pid)

def assign_address(pid: bytes, coords: list[int]):
    addr = Address(tree_state(current_best_root_id), coords=coords)
    tmsg = TreeMessage(
        TreeOp.ASSIGN_ADDRESS,
        current_best_root_id,
        addr.address,
        Packager.node_id
    )
    Packager.send(tree_app_id, serialize_tm(tmsg), pid)

def periodic_tree_message(count: int):
    """Broadcasts count times with a 30ms delay between."""
    if count <= 0:
        return schedule_tree_maintenance()
    SpanningTree.invoke('broadcast')
    Packager.new_events.append(Event(
        now() + MODEM_INTERSECT_INTERVAL,
        tree_app_id,
        periodic_tree_message,
        count - 1
    ))

def send_gossip_tree_message(addr: Address|None = None):
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is not None:
        tm = TreeMessage(
            TreeOp.SEND,
            current_best_root_id,
            addr.address if addr is not None else Packager.node_addrs[-1].address,
            Packager.node_id
        )
        Gossip.invoke('publish', tree_app_id, serialize_tm(tm))

def maintain_tree():
    """Maintains the spanning tree: 1) when a parent has disconnected,
        reset the local state; 2) if there is no parent and there are
        known claims, request an address assignment from the best claim;
        3) begin the periodic_tree_message event; 4) send a gossip
        message every 5th maintenance event.
    """
    global current_best_root_id, current_parent, current_children, tree_maintenance_rounds

    # check if parent has disconnected
    if current_parent != b'':
        if current_parent not in Packager.peers:
            # parent has disconnected, reset the local state
            current_best_root_id = Packager.node_id
            current_parent = b''
            current_children.clear()
            Packager.set_addr(Address(tree_state(Packager.node_id), coords=[]))

    # check if there is no parent and there are known claims
    if current_parent == b'' and len(known_claims) > 0:
        # get the best known claim (and shortest distance from root)
        claims = list(known_claims)
        claims.sort(key=lambda t: claim_score(t[0]) + t[1])
        best_claim, _, peer_id = claims[0]
        if claim_score(best_claim) < claim_score(Packager.node_id):
            # request an address assignment from the best claim
            SpanningTree.invoke('request_address_assignment', peer_id, best_claim)
            # schedule the next maintenance event
            schedule_tree_maintenance()
        else:
            # we have the best claim, so begin broadcasting it
            periodic_tree_message(MODEM_INTERSECT_RTX_TIMES)
    else:
        # begin broadcasting
        periodic_tree_message(MODEM_INTERSECT_RTX_TIMES)

    tree_maintenance_rounds += 1
    if tree_maintenance_rounds >= 5:
        tree_maintenance_rounds = 0
        send_gossip_tree_message()

def schedule_tree_maintenance():
    """Schedules the tree maintenance event for 60s in the future."""
    if tree_app_id+b's' in Packager.schedule:
        return
    Packager.new_events.append(Event(
        now() + 60_000,
        tree_app_id+b's',
        maintain_tree,
    ))

def set_addr_gossip_callback(_, addr: Address):
    send_gossip_tree_message(addr)

def schedule_start():
    """Schedules the app to start broadcasting with a random delay up to 30s."""
    global current_best_root_id
    if tree_app_id+b's' in Packager.schedule:
        return
    Packager.add_hook('remove_peer', remove_peer)
    current_best_root_id = Packager.node_id
    Packager.set_addr(Address(tree_state(Packager.node_id), coords=[]))
    Packager.new_events.append(Event(
        now() + randint(0, 30) * 1000,
        tree_app_id + b's',
        maintain_tree,
    ))
    Gossip = Packager.apps.get(gossip_app_id, None)
    Packager.add_hook('set_addr', set_addr_gossip_callback)
    if Gossip is not None:
        Gossip.invoke('subscribe', tree_app_id, tree_app_id)

def stop():
    """Cancels all events and removes all hooks."""
    Packager.remove_hook('remove_peer', remove_peer)
    Packager.remove_hook('set_addr', set_addr_gossip_callback)
    Packager.cancel_events.append(tree_app_id)
    Packager.cancel_events.append(tree_app_id+b's')
    Gossip = Packager.apps.get(gossip_app_id, None)
    if Gossip is not None:
        Gossip.invoke('unsubscribe', tree_app_id, tree_app_id)

SpanningTree = Application(
    name='SpanningTree',
    description='Dev SpanningTree App',
    version=0,
    receive_func=receive_tm,
    callbacks={
        'broadcast': lambda _: broadcast_tree_message(),
        'send': lambda _, pid: send_tree_message(pid),
        'respond': lambda _, pid: respond_tree_message(pid),
        'request_address_assignment': lambda _, pid, claim: request_address_assignment(pid, claim),
        'assign_address': lambda _, pid, coords: assign_address(pid, coords),
        'remove_peer': remove_peer,
        'maintain_tree': lambda _: maintain_tree(),
        'schedule_tree_maintenance': lambda _: schedule_tree_maintenance(),
        'serialize': lambda _, tm: serialize_tm(tm),
        'deserialize': lambda _, blob: deserialize_tm(blob),
        'start': lambda _: schedule_start(),
        'stop': lambda _: stop(),
        'claim_score': lambda _, claim: claim_score(claim),
        'get_known_claims': lambda _: known_claims,
        'get_current_children': lambda _: current_children,
        'get_current_parent': lambda _: current_parent,
        'get_current_best_root_id': lambda _: current_best_root_id,
        'send_gossip_tree_message': lambda _: send_gossip_tree_message(),
        'get_seen': lambda _: seen_tm,
    }
)
tree_app_id = SpanningTree.id

Packager.add_application(SpanningTree)
