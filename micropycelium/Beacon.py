try:
    from Packager import (
        Packager,
        Application,
        Interface,
        Event,
        MODEM_INTERSECT_INTERVAL,
        # MODEM_INTERSECT_RTX_TIMES,
        time_ms,
    )
except ImportError:
    from .Packager import (
        Packager,
        Application,
        Interface,
        Event,
        MODEM_INTERSECT_INTERVAL,
        # MODEM_INTERSECT_RTX_TIMES,
        time_ms,
    )
from collections import deque, namedtuple
from time import time


BeaconMessage = namedtuple("BeaconMessage", ['op', 'peer_id', 'apps'])
seen_bm: deque[BeaconMessage] = deque([], 4)
sent_bm: deque[BeaconMessage] = deque([], 4)
beacon_app_id = b''


def serialize_bm(bmsg: BeaconMessage):
    apps = b''.join([aid for aid in bmsg.apps])
    return bmsg.op + bmsg.peer_id + apps

def deserialize_bm(blob: bytes) -> BeaconMessage:
    op = blob[:1]
    pid = blob[1:33]
    apps = []
    if len(blob) > 33:
        app_ids = blob[33:]
        while len(app_ids) >= 16:
            apps.append(app_ids[:16])
            app_ids = app_ids[16:]
    return BeaconMessage(op, pid, apps)

def receive_bm(app: Application, blob: bytes, intrfc: Interface, mac: bytes):
    bmsg = deserialize_bm(blob)
    seen_bm.append(bmsg)
    node_id = Packager.node_id
    if bmsg.peer_id != node_id:
        Packager.add_peer(bmsg.peer_id, [(mac, intrfc)])

        if bmsg.op == b'\x00':
            # respond
            Beacon.invoke('respond', bmsg.peer_id)

def get_bmsgs(op: bytes):
    # cache values in local scope
    node_id = Packager.node_id
    apps = tuple(Packager.apps.keys())
    index = 0
    bmsgs = []
    while index < len(apps):
        if len(apps[index:]) > 10:
            app_ids = apps[index:index+10]
            index += 10
        else:
            app_ids = apps[index:]
            index = len(apps)
        bmsgs.append(BeaconMessage(
            op,
            node_id,
            app_ids
        ))
    return bmsgs

def send_beacon(pid: bytes):
    bmsgs = get_bmsgs(b'\x00')
    for bm in bmsgs:
        # send the BeaconMessage in a Package
        Packager.send(beacon_app_id, serialize_bm(bm), pid)

def respond_beacon(pid: bytes):
    bmsgs = get_bmsgs(b'\x01')
    for bm in bmsgs:
        # send the BeaconMessage in a Package
        Packager.send(beacon_app_id, serialize_bm(bm), pid)
    sent_bm.extend(bmsgs)

def broadcast_beacon():
    bmsgs = get_bmsgs(b'\x00')
    for bm in bmsgs:
        # broadcast the BeaconMessage in a Package
        Packager.broadcast(beacon_app_id, serialize_bm(bm))
    sent_bm.extend(bmsgs)

def timeout_peers():
    tdc = []
    for pid, peer in Packager.peers.items():
        peer.timeout -= 1
        if peer.timeout <= 0:
            tdc.append(pid)
    for pid in tdc:
        Packager.remove_peer(pid)

def periodic_beacon(count: int):
    """Broadcasts count times with a 30ms delay between."""
    if count <= 0:
        timeout_peers()
        return schedule_beacon()
    Beacon.invoke('broadcast')
    Packager.new_events.append(Event(
        time_ms() + Beacon.params['beacon_period'],
        beacon_app_id,
        periodic_beacon,
        count - 1
    ))

def schedule_beacon():
    """Schedules the periodic_beacon event to begin broadcasting after
        60s.
    """
    if beacon_app_id+b's' in Packager.schedule:
        return
    Packager.new_events.append(Event(
        time_ms() + Beacon.params['beacon_interval'],
        beacon_app_id+b's',
        periodic_beacon,
        Beacon.params['beacon_count']
    ))

def stop_beacon():
    Packager.cancel_events.append(beacon_app_id)
    Packager.cancel_events.append(beacon_app_id+b's')

Beacon = Application(
    name='Beacon',
    description='Dev Beacon App',
    version=0,
    receive_func=receive_bm,
    callbacks={
        'broadcast': lambda _: broadcast_beacon(),
        'send': lambda _, pid: send_beacon(pid),
        'respond': lambda _, pid: respond_beacon(pid),
        'get_bmsgs': lambda _, op: get_bmsgs(op),
        'serialize': lambda _, bm: serialize_bm(bm),
        'deserialize': lambda _, blob: deserialize_bm(blob),
        # 'start': lambda _: periodic_beacon(MODEM_INTERSECT_RTX_TIMES),
        'start': lambda _: periodic_beacon(2),
        'stop': lambda _: stop_beacon(),
        'get_seen': lambda _: seen_bm,
        'get_sent': lambda _: sent_bm,
    },
    params={
        'beacon_interval': 60_000,
        'beacon_period': MODEM_INTERSECT_INTERVAL,
        # 'beacon_count': MODEM_INTERSECT_RTX_TIMES,
        'beacon_count': 1,
    }
)
beacon_app_id = Beacon.id

Packager.add_application(Beacon)
