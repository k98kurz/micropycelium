try:
    from Packager import (
        Packager,
        Address,
        Application,
        Interface,
        Event,
        Cache,
        InterAppInterface,
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
        Cache,
        InterAppInterface,
        MODEM_INTERSECT_INTERVAL,
        MODEM_INTERSECT_RTX_TIMES,
    )
from binascii import crc32
from collections import deque, namedtuple
from hashlib import sha256
from random import randint
from time import time


def enum(**enums):
    """Enum workaround for micropython. CC BY-SA 4.0
        https://stackoverflow.com/a/1695250
    """
    return type('Enum', (), enums)

GossipOp = enum(
    REQUEST = 0,
    REQUEST_IDS = 1,
    NOTIFY = 15,
    PUBLISH = 240,
    MESSAGE = 241,
    MESSAGE_IDS = 242,
)
GossipMessage = namedtuple("GossipMessage", ['op', 'topic_id', 'data'])
# map of topic_id to list of application_ids
subscriptions: dict[bytes, list[bytes]] = {}
# buffer of seen message ids (half_sha256)
seen: deque[bytes] = deque([], 100)
# cache of GossipMessages
message_cache: Cache = Cache(limit=100)
# id of this gossip application
gossip_app_id: bytes = b''

def serialize_gm(gm: GossipMessage):
    return gm.op.to_bytes(1, 'big') + gm.topic_id + gm.data

def deserialize_gm(blob: bytes) -> GossipMessage:
    return GossipMessage(blob[0], blob[1:17], blob[17:])

def receive_gm(app: Application, blob: bytes, intrfc: Interface, mac: bytes):
    gm = deserialize_gm(blob)
    peer_id = Packager.inverse_peers.get((mac, intrfc.id), None)
    if gm.op == GossipOp.REQUEST:
        respond_gossip_request(peer_id or gm.data, gm.topic_id)
    elif gm.op == GossipOp.REQUEST_IDS:
        respond_gossip_ids(peer_id or gm.data, gm.topic_id)
    elif gm.op == GossipOp.NOTIFY:
        if message_cache.get(gm.data) is None and peer_id is not None:
            request_gossip_message(gm.data, peer_id)
    elif gm.op in (GossipOp.PUBLISH, GossipOp.MESSAGE):
        deliver_gossip(gm)
    elif gm.op == GossipOp.MESSAGE_IDS:
        if len(gm.data) % 16 or peer_id is None:
            # malformed or cannot contact originating node
            return
        ids = []
        for i in range(0, len(gm.data), 16):
            ids.append(gm.data[i:i+16])
        for id in ids:
            if message_cache.get(id) is None:
                request_gossip_message(id, peer_id)

def publish_gossip(topic_id: bytes, data: bytes):
    gm = GossipMessage(GossipOp.PUBLISH, topic_id, data)
    deliver_gossip(gm)

def deliver_gossip(gm: GossipMessage):
    gm_id = sha256(serialize_gm(gm)).digest()[:16]
    if gm_id in seen:
        return
    # add to cache if it is a PUBLISH
    if gm.op == GossipOp.PUBLISH:
        seen.append(gm_id)
        message_cache.add(gm_id, gm, ttl=1000)
    # deliver to subscribed applications
    for app_id in subscriptions.get(gm.topic_id, []):
        app = Packager.apps.get(app_id, None)
        if app is None:
            continue
        app.receive(gm.data, InterAppInterface, gossip_app_id)
    # skip forward if it was a MESSAGE and not a PUBLISH
    if gm.op == GossipOp.MESSAGE:
        return
    # forward or notify
    if len(gm.data) > 235 - 17 - 32:
        notify_gossip(gm.topic_id, gm_id)
    else:
        broadcast_gossip(gm)

def broadcast_gossip(gm: GossipMessage):
    Packager.broadcast(gossip_app_id, serialize_gm(gm))

def notify_gossip(topic_id: bytes, gm_id: bytes):
    gm = GossipMessage(GossipOp.NOTIFY, topic_id, gm_id)
    Packager.broadcast(gossip_app_id, serialize_gm(gm))

def request_gossip_message(message_id: bytes, peer_id: bytes):
    gm = GossipMessage(GossipOp.REQUEST, message_id, Packager.node_id)
    Packager.send(gossip_app_id, serialize_gm(gm), peer_id)

def respond_gossip_request(peer_id: bytes, gm_id: bytes):
    gm: GossipMessage|None = message_cache.get(gm_id)
    if gm is None:
        return
    if len(gm.data) > 235 - 17 - 32:
        # was a request from a notification; do not modify the op
        Packager.send(gossip_app_id, serialize_gm(gm), peer_id)
    else:
        # was a request following message ids; modify the op so it is not forwarded
        new_gm = GossipMessage(GossipOp.MESSAGE, gm.topic_id, gm.data)
        Packager.send(gossip_app_id, serialize_gm(new_gm), peer_id)

def request_gossip_ids(topic_id: bytes, peer_id: bytes):
    gm = GossipMessage(GossipOp.REQUEST_IDS, topic_id, Packager.node_id)
    Packager.send(gossip_app_id, serialize_gm(gm), peer_id)

def respond_gossip_ids(peer_id: bytes, topic_id: bytes):
    ids = list(message_cache.items.keys())
    gm = GossipMessage(GossipOp.MESSAGE_IDS, topic_id, b''.join(ids))
    Packager.send(gossip_app_id, serialize_gm(gm), peer_id)

def subscribe_gossip(topic_id: bytes, app_id: bytes):
    if topic_id not in subscriptions:
        subscriptions[topic_id] = []
    subscriptions[topic_id].append(app_id)

def unsubscribe_gossip(topic_id: bytes, app_id: bytes):
    if topic_id in subscriptions and app_id in subscriptions[topic_id]:
        subscriptions[topic_id].remove(app_id)
    if topic_id in subscriptions and len(subscriptions[topic_id]) == 0:
        del subscriptions[topic_id]

Gossip = Application(
    name='Gossip',
    description='Dev Gossip App',
    version=0,
    receive_func=receive_gm,
    callbacks={
        'publish': lambda _, topic_id, data: publish_gossip(topic_id, data),
        'notify': lambda _, topic_id, data: notify_gossip(topic_id, data),
        'respond': lambda _, topic_id, data: respond_gossip_request(topic_id, data),
        'request': lambda _, topic_id, data: request_gossip_message(topic_id, data),
        'subscribe': lambda _, topic_id, app_id: subscribe_gossip(topic_id, app_id),
        'unsubscribe': lambda _, topic_id, app_id: unsubscribe_gossip(topic_id, app_id),
        'deliver_gossip': lambda _, gm: deliver_gossip(gm),
        'get_seen': lambda _: seen,
        'get_subscriptions': lambda _: subscriptions,
        'get_message_cache': lambda _: message_cache,
        'serialize_gm': lambda _, gm: serialize_gm(gm),
        'deserialize_gm': lambda _, blob: deserialize_gm(blob),
    }
)
gossip_app_id = Gossip.id

Packager.add_application(Gossip)
