from collections import deque
from time import time, sleep, time_ns
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import micropycelium
from micropycelium import (
    Datagram,
    Field,
    Flags,
    Schema,
    SCHEMA_IDS,
    SCHEMA_IDS_SUPPORT_CHECKSUM,
    SCHEMA_IDS_SUPPORT_ROUTING,
    SCHEMA_IDS_SUPPORT_SEQUENCE,
    MODEM_INTERSECT_INTERVAL,
    MODEM_INTERSECT_RTX_TIMES,
    MODEM_SLEEP_MS,
    MODEM_WAKE_MS,
    dCPL,
    dTree,
    get_schema,
    get_schemas,
    schema_has,
    schema_lacks,
    Packet,
    Peer,
    Node,
    Package,
    Sequence,
    InSequence,
    Address,
    Event,
    Interface,
    Application,
    Cache,
    Packager,
    InterAppInterface,
    iai_box,
    ESPNowInterface,
    Beacon,
    BeaconMessage,
    SpanningTree,
    TreeMessage,
    TreeOp,
    tree_state,
    Gossip,
    GossipMessage,
    GossipOp,
    Ping,
    PingMessage,
    PingOp,
)


def xor(b1: bytes, b2: bytes) -> bytes:
    while len(b2) > len(b1):
        b1 += b'\x00'
    b3 = bytearray(len(b1))
    for i in range(len(b2)):
        b3[i] = b1[i] ^ b2[i]
    return bytes(b3)

def xor_diff(b1: bytes, b2: bytes) -> tuple[str, str]:
    b3 = xor(b1, b2)
    b4 = xor(b1, b2)
    for i in range(len(b3)):
        if b3[i] != 0:
            b3[i] = b1[i] if i < len(b1) else 255
            b4[i] = b2[i] if i < len(b2) else 255
    return (b3.hex(), b4.hex())

now = lambda: int(time_ns() / 1_000_000_000)


outbox: deque[Datagram] = deque()
inbox: deque[Datagram] = deque()
castbox: deque[Datagram] = deque()
config = {
    'awake': True,
}

def configure(_: Interface, data: dict):
    for key, value in data.items():
        config[key] = value

def wake(i: Interface):
    configure(i, {'awake': True})

def receive1(intrfc: Interface):
    return inbox.popleft() if len(inbox) else None

def receive12(intrfc: Interface):
    return inbox.popleft() if len(inbox) else castbox.popleft() if len(castbox) else None

def receive2(intrfc: Interface):
    return outbox.popleft() if len(outbox) else None

def receive22(intrfc: Interface):
    return outbox.popleft() if len(outbox) else castbox.popleft() if len(castbox) else None

def send1(datagram: Datagram):
    outbox.append(datagram)

def send2(datagram: Datagram):
    inbox.append(datagram)

def broadcast(datagram: Datagram):
    castbox.append(datagram)

mock_interface1 = Interface(
    'mock1',
    1200,
    configure,
    SCHEMA_IDS,
    receive1,
    send1,
    broadcast,
    wake_func=wake,
)

mock_interface2 = Interface(
    'mock2',
    1200,
    configure,
    SCHEMA_IDS,
    receive2,
    send2,
    broadcast
)

app_blobs = []

test_app = Application(
    'test',
    'test',
    0,
    lambda _P, blob, _i, _m: app_blobs.append(blob),
    {
        'hello': lambda _: 'world',
    }
)
