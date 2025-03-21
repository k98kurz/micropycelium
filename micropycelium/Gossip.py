try:
    from Packager import (
        enum,
        Packager,
        # Address,
        Application,
        Interface,
        Event,
        Cache,
        InterAppInterface,
        # MODEM_INTERSECT_INTERVAL,
        # MODEM_INTERSECT_RTX_TIMES,
        time_ms,
    )
except ImportError:
    from .Packager import (
        enum,
        Packager,
        # Address,
        Application,
        Interface,
        Event,
        Cache,
        InterAppInterface,
        # MODEM_INTERSECT_INTERVAL,
        # MODEM_INTERSECT_RTX_TIMES,
        time_ms,
    )
from collections import deque, namedtuple
from hashlib import sha256


GossipOp = enum(
    REQUEST = 0,
    REQUEST_IDS = 1,
    NOTIFY = 15,
    PUBLISH = 240,
    RESPOND = 254,
    RESPOND_IDS = 255,
)
GossipMessage = namedtuple("GossipMessage", ['op', 'topic_id', 'data'])
# map of topic_id to list of application_ids
subscriptions: dict[bytes, list[bytes]] = {}
# buffer of seen message ids (half_sha256)
seen_gm: deque[bytes] = deque([], 100)
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
    elif gm.op in (GossipOp.PUBLISH, GossipOp.RESPOND):
        deliver_gossip(gm)
    elif gm.op == GossipOp.RESPOND_IDS:
        if len(gm.data) % 16 or peer_id is None:
            # malformed or cannot contact originating node
            return
        ids = []
        for i in range(0, len(gm.data), 16):
            ids.append(gm.data[i:i+16])
        for id in ids:
            if id not in seen_gm:
                request_gossip_message(id, peer_id)

def publish_gossip(topic_id: bytes, data: bytes):
    gm = GossipMessage(GossipOp.PUBLISH, topic_id, data)
    deliver_gossip(gm)

def deliver_gossip(gm: GossipMessage):
    gm_id = sha256(serialize_gm(gm)).digest()[:16]
    if gm_id in seen_gm:
        return
    # add to cache if it is a PUBLISH or RESPOND
    if gm.op in (GossipOp.PUBLISH, GossipOp.RESPOND):
        seen_gm.append(gm_id)
        message_cache.add(gm_id, gm, ttl=300)
    # deliver to subscribed applications
    for app_id in subscriptions.get(gm.topic_id, []):
        app = Packager.apps.get(app_id, None)
        if app is None:
            continue
        app.receive(gm.data, InterAppInterface, gossip_app_id)
    # skip forward/notify if it was a RESPOND and the size is not too large for simple PUBLISH
    if gm.op == GossipOp.RESPOND and len(gm.data) <= 235 - 17 - 32:
        # i.e. it is not a new message; it is a response to a sync request
        return
    # forward or notify
    if len(gm.data) > 235 - 17 - 32:
        notify_gossip(gm.topic_id, gm_id)
    else:
        broadcast_gossip(gm)

def broadcast_gossip(gm: GossipMessage, count: int = 1):
    Packager.broadcast(gossip_app_id, serialize_gm(gm))
    if count <= 0:
        return
    Packager.new_events.append(Event(
        time_ms() + Gossip.params['echo_delay_ms'],
        b'b' + sha256(serialize_gm(gm)).digest()[:16],
        broadcast_gossip,
        gm,
        count - 1,
    ))

def notify_gossip(topic_id: bytes, gm_id: bytes, count: int = 1):
    gm = GossipMessage(GossipOp.NOTIFY, topic_id, gm_id)
    Packager.broadcast(gossip_app_id, serialize_gm(gm))
    if count <= 0:
        return
    Packager.new_events.append(Event(
        time_ms() + Gossip.params['echo_delay_ms'],
        b'n' + sha256(serialize_gm(gm)).digest()[:16],
        notify_gossip,
        topic_id,
        gm_id,
        count - 1,
    ))

def request_gossip_message(message_id: bytes, peer_id: bytes, count: int = 1):
    gm = GossipMessage(GossipOp.REQUEST, message_id, Packager.node_id)
    Packager.send(gossip_app_id, serialize_gm(gm), peer_id)
    if count <= 0:
        return
    Packager.new_events.append(Event(
        time_ms() + Gossip.params['echo_delay_ms'],
        b'q' + sha256(serialize_gm(gm)).digest()[:16],
        request_gossip_message,
        message_id,
        peer_id,
        count - 1,
    ))

def respond_gossip_request(peer_id: bytes, gm_id: bytes, count: int = 1):
    gm: GossipMessage|None = message_cache.get(gm_id)
    if gm is None:
        return
    if len(gm.data) > 235 - 17 - 32:
        # was a request from a notification; do not modify the op
        Packager.send(gossip_app_id, serialize_gm(gm), peer_id)
    else:
        # was a request following message ids; modify the op so it is not forwarded
        new_gm = GossipMessage(GossipOp.RESPOND, gm.topic_id, gm.data)
        Packager.send(gossip_app_id, serialize_gm(new_gm), peer_id)
    if count <= 0:
        return
    Packager.new_events.append(Event(
        time_ms() + Gossip.params['echo_delay_ms'],
        b'r' + sha256(serialize_gm(gm)).digest()[:16],
        respond_gossip_request,
        peer_id, gm_id, count - 1,
    ))

def request_gossip_ids(topic_id: bytes, peer_id: bytes):
    gm = GossipMessage(GossipOp.REQUEST_IDS, topic_id, Packager.node_id)
    Packager.send(gossip_app_id, serialize_gm(gm), peer_id)

def schedule_request_gossip_ids(topic_id: bytes, peer_id: bytes):
    Packager.new_events.append(Event(
        0,
        sha256(gossip_app_id + topic_id + peer_id).digest()[:16],
        request_gossip_ids,
        topic_id, peer_id,
    ))

def respond_gossip_ids(peer_id: bytes, topic_id: bytes):
    ids = []
    for gm_id, (_, gm) in message_cache.items.items():
        if gm.topic_id == topic_id:
            ids.append(gm_id)
    gm = GossipMessage(GossipOp.RESPOND_IDS, topic_id, b''.join(ids))
    Packager.send(gossip_app_id, serialize_gm(gm), peer_id)

def subscribe_gossip(topic_id: bytes, app_id: bytes):
    if topic_id not in subscriptions:
        subscriptions[topic_id] = []
    if app_id not in subscriptions[topic_id]:
        subscriptions[topic_id].append(app_id)

def unsubscribe_gossip(topic_id: bytes, app_id: bytes):
    if topic_id in subscriptions and app_id in subscriptions[topic_id]:
        subscriptions[topic_id].remove(app_id)
    if topic_id in subscriptions and len(subscriptions[topic_id]) == 0:
        del subscriptions[topic_id]

def add_peer_callback(_, pid: bytes, intrfcs: list[tuple[bytes, Interface]]):
    if pid not in Packager.peers:
        for topic_id in subscriptions:
            schedule_request_gossip_ids(topic_id, pid)

def sync_all_peers():
    for pid in Packager.peers:
        for topic_id in subscriptions:
            Gossip.invoke('request_ids', topic_id, pid)

    Packager.new_events.append(Event(
        time_ms() + Gossip.params['schedule_delay']*1000,
        Gossip.id,
        sync_all_peers,
    ))

def start():
    Packager.add_hook('add_peer', add_peer_callback)
    if Gossip.id in Packager.schedule:
        return
    Packager.new_events.append(Event(
        time_ms() + Gossip.params['start_delay']*1000,
        Gossip.id,
        sync_all_peers,
    ))

def stop():
    Packager.remove_hook('add_peer', add_peer_callback)

def get_messages(topic_id: bytes):
    res = []
    for _, val in message_cache.items.items():
        if val[1].topic_id == topic_id:
            res.append(val[1])
    return res


Gossip = Application(
    name='Gossip',
    description='Dev Gossip App',
    version=0,
    receive_func=receive_gm,
    callbacks={
        'publish': lambda _, topic_id, data: publish_gossip(topic_id, data),
        'notify': lambda _, topic_id, data: notify_gossip(topic_id, data),
        'respond': lambda _, topic_id, data: respond_gossip_request(topic_id, data),
        'respond_ids': lambda _, peer_id, topic_id: respond_gossip_ids(peer_id, topic_id),
        'request': lambda _, topic_id, peer_id: request_gossip_message(topic_id, peer_id),
        'request_ids': lambda _, topic_id, peer_id: request_gossip_ids(topic_id, peer_id),
        'subscribe': lambda _, topic_id, app_id: subscribe_gossip(topic_id, app_id),
        'unsubscribe': lambda _, topic_id, app_id: unsubscribe_gossip(topic_id, app_id),
        'deliver_gossip': lambda _, gm: deliver_gossip(gm),
        'sync': lambda _: sync_all_peers(),
        'start': lambda _: start(),
        'stop': lambda _: stop(),
        'get_seen': lambda _: seen_gm,
        'get_subscriptions': lambda _: subscriptions,
        'get_cache': lambda _: message_cache,
        'get_messages': lambda _, topic_id: get_messages(topic_id),
        'serialize_gm': lambda _, gm: serialize_gm(gm),
        'deserialize_gm': lambda _, blob: deserialize_gm(blob),
    },
    params={
        'start_delay': 10,
        'schedule_delay': 20,
        'echo_delay_ms': 20,
    }
)
gossip_app_id = Gossip.id

Packager.add_application(Gossip)
