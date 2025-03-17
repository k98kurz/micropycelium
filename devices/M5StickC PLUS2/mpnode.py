from asyncio import run, sleep_ms, gather
from collections import deque
from machine import Pin, reset
from micropycelium import (
    Packager, debug, ESPNowInterface, Beacon, Gossip, SpanningTree, Ping,
    DebugApp, DebugOp,
)

def write_file(fname: str, data: str):
    with open(f'/{fname}', 'w') as f:
        f.write(data)

def read_file(fname: str) -> str:
    with open(f'/{fname}', 'r') as f:
        return f.read()

# set G4 to 1 to stay on
Pin(4, Pin.OUT).value(1)
# Button A: G37
btnA = Pin(37, Pin.IN)
btnAq = deque([], 5)
# Button B: G39
btnB = Pin(39, Pin.IN)
btnBq = deque([], 5)
btnC = Pin(35, Pin.IN)
btnCq = deque([], 5)
# LED: G19 (internal)
led19 = Pin(19, Pin.OUT)
led19q = deque([], 10)
# LED: G26 (hat pin)
led26 = Pin(26, Pin.OUT)
led26q = deque([], 10)

async def blink(p: Pin, ms: int):
    v = p.value()
    p.value(not v)
    await sleep_ms(ms)
    p.value(v)
async def bloop(q: deque, p: Pin):
    while True:
        while len(q):
            q.popleft()
            await blink(p, 100)
        await sleep_ms(1)
async def monitor_btn(p: Pin, q: deque, debounce_ms: int):
    while True:
        if not p.value():
            q.append(1)
            await sleep_ms(debounce_ms)
        await sleep_ms(1)
async def btnAloop():
    while True:
        if len(btnAq):
            btnAq.popleft()
            Beacon.invoke('start')
        await sleep_ms(1)
async def btnBloop():
    while True:
        if len(btnBq):
            btnBq.popleft()
            SpanningTree.invoke('broadcast')
        await sleep_ms(1)
async def btnCloop():
    while True:
        if len(btnCq):
            btnCq.popleft()
            SpanningTree.invoke('maintain_tree')
        await sleep_ms(1)

def hexify(thing):
    if type(thing) is list:
        return [hexify(i) for i in thing]
    elif type(thing) is tuple:
        return tuple(hexify(i) for i in thing)
    elif type(thing) is bytes:
        return thing.hex()
    elif type(thing) is dict:
        return {hexify(k): hexify(v) for k, v in thing.items()}
    else:
        return thing if type(thing) is str else repr(thing)

def debug_name(name: str):
    def inner(*args):
        args = [hexify(a) for a in args]
        debug(name, *args)
    return inner

def action_hook(name: str, q: deque):
    def inner(*args):
        debug(name)
        q.append(1)
    return inner

# add some hooks
Beacon.add_hook('receive', action_hook('Beacon.receive', led19q))
Beacon.add_hook('broadcast', debug_name('Beacon.broadcast'))
Beacon.add_hook('respond', debug_name('Beacon.respond'))
Beacon.add_hook('send', debug_name('Beacon.send'))

Gossip.add_hook('receive', action_hook('Gossip.receive', led26q))
Gossip.add_hook('publish', debug_name('Gossip.publish'))
Gossip.add_hook('respond', debug_name('Gossip.respond'))

SpanningTree.add_hook('receive', debug_name('SpanningTree.receive'))
SpanningTree.add_hook('broadcast', debug_name('SpanningTree.broadcast'))
SpanningTree.add_hook('send', debug_name('SpanningTree.send'))
SpanningTree.add_hook('respond', debug_name('SpanningTree.respond'))
SpanningTree.add_hook(
    'assign_address', action_hook('SpanningTree.assign_address', led26q)
)
SpanningTree.add_hook(
    'request_address_assignment',
    action_hook('SpanningTree.request_address_assignment', led26q)
)

def ping_report_cb(report):
    print('Ping report:')
    report = hexify(report)
    for k, v in report.items():
        print(f'  {k}: {v}')

Ping.add_hook('request', debug_name('Ping.request'))
Ping.add_hook('respond', debug_name('Ping.respond'))
Ping.add_hook('response_received', debug_name('Ping.response_received'))
Ping.add_hook('gossip_request', debug_name('Ping.gossip_request'))
Ping.add_hook('gossip_respond', debug_name('Ping.gossip_respond'))
Ping.add_hook('gossip_response_received', debug_name('Ping.gossip_response_received'))

DebugApp.add_hook('output', lambda _, info: print(info))

hooks_added = False
def add_hooks():
    global hooks_added
    if hooks_added:
        return
    hooks_added = True
    ESPNowInterface.add_hook('process:receive', debug_name(f'Interface({ESPNowInterface.name}).process:receive'))
    ESPNowInterface.add_hook('process:send', debug_name(f'Interface({ESPNowInterface.name}).process:send'))
    ESPNowInterface.add_hook('process:broadcast', debug_name(f'Interface({ESPNowInterface.name}).process:broadcast'))
    Packager.add_hook('send', debug_name('Packager.send'))
    Packager.add_hook('broadcast', debug_name('Packager.broadcast'))
    Packager.add_hook('receive', debug_name('Packager.receive'))
    Packager.add_hook('receive:rns', debug_name('Packager.receive:rns'))
    Packager.add_hook('receive:nia', debug_name('Packager.receive:nia'))
    Packager.add_hook('rns', debug_name('Packager.rns'))
    Packager.add_hook('send_packet', debug_name('Packager.send_packet'))
    Packager.add_hook('_send_datagram', debug_name('Packager._send_datagram'))
    Packager.add_hook('deliver', debug_name('Packager.deliver'))
    Packager.add_hook('add_peer', debug_name('Packager.add_peer'))
    Packager.add_hook('set_addr', debug_name('Packager.set_addr'))
    Packager.add_hook('remove_peer', debug_name('Packager.remove_peer'))
    Packager.add_hook('modemsleep', debug_name('modemsleep'))
    Packager.add_hook('sleepskip', debug_name('sleepskip'))

def start():
    try:
        run(gather(
            Packager.work(use_modem_sleep=True),
            bloop(led19q, led19),
            bloop(led26q, led26),
            monitor_btn(btnA, btnAq, 800),
            monitor_btn(btnB, btnBq, 200),
            monitor_btn(btnC, btnCq, 200),
            btnAloop(),
            btnBloop(),
            btnCloop(),
        ))
    except OSError:
        print('OSError encountered; resetting device')
        reset()

Beacon.invoke('start')
Gossip.invoke('start')
SpanningTree.invoke('start')
Ping.invoke('start')
DebugApp.invoke('start')
