try:
    from Packager import Packager, Application, Interface
except ImportError:
    from .Packager import Packager, Application, Interface
from collections import deque, namedtuple
from hashlib import sha256
from machine import unique_id


Packager.node_id = sha256(sha256(unique_id()).digest()).digest()
BeaconMessage = namedtuple("BeaconMessage", ['op', 'peer_id', 'apps'])
seen: deque[BeaconMessage] = deque([], 10)
sent: deque[BeaconMessage] = deque([], 10)
app_id = b''



def serialize(bmsg: BeaconMessage):
    apps = b''.join([aid for aid in bmsg.apps])
    return bmsg.op + bmsg.peer_id + apps

def deserialize(blob: bytes) -> BeaconMessage:
    op = blob[:1]
    pid = blob[1:33]
    apps = []
    if len(blob) > 33:
        app_ids = blob[33:]
        while len(app_ids) >= 16:
            apps.append(app_ids[:16])
            app_ids = app_ids[16:]
    return BeaconMessage(op, pid, apps)

def receive(app: Application, blob: bytes, intrfc: Interface, mac: bytes):
    bmsg = deserialize(blob)
    seen.append(bmsg)
    node_id = Packager.node_id
    if bmsg.peer_id != node_id:
        Packager.add_peer(bmsg.peer_id, [(mac, intrfc)])

        if bmsg.op == b'\x00':
            # respond
            send(bmsg.peer_id)

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


def send(pid: bytes):
    bmsgs = get_bmsgs(b'\x01')
    for bm in bmsgs:
        # send the BeaconMessage in a Package
        Packager.send(app_id, serialize(bm), pid)

def broadcast():
    bmsgs = get_bmsgs(b'\x00')
    for bm in bmsgs:
        # broadcast the BeaconMessage in a Package
        Packager.broadcast(app_id, serialize(bm))

Beacon = Application(
    name='Beacon',
    description='Dev Beacon App',
    version=0,
    receive_func=receive,
    callbacks={
        'broadcast': lambda _: broadcast(),
        'send': lambda _, pid: send(pid),
        'get_bmsgs': lambda _, op: get_bmsgs(op),
        'serialize': lambda _, bm: serialize(bm),
        'deserialize': lambda _, blob: deserialize(blob),
    }
)
app_id = Beacon.id

Packager.add_application(Beacon)
