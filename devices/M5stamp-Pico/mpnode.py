from asyncio import sleep_ms, run, gather
from collections import deque
from machine import Pin
from micropycelium import (
    Packager, debug, ESPNowInterface, Beacon, Gossip, SpanningTree, Ping
)
from neopixel import NeoPixel

def write_file(fname: str, data: str):
    with open(f'/{fname}', 'w') as f:
        f.write(data)

def read_file(fname: str) -> str:
    with open(f'/{fname}', 'r') as f:
        return f.read()

# RGB LED of the M5stamp-Pico
rgb = NeoPixel(Pin(27, Pin.OUT), 1)
rq = deque([], 10)
async def rloop():
    while True:
        r = rq.popleft() if len(rq) else (0, 0, 0)
        rgb.fill(r)
        rgb.write()
        await sleep_ms(100 if any(r) else 1)

btn = Pin(39, Pin.IN)
btnq = deque([], 5)
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
async def monitor_btn(p: Pin, q: deque, debounce_ms: int, inverse: bool = True):
    while True:
        if (inverse and not p.value()) or (not inverse and p.value()):
            q.append(1)
            Beacon.invoke('start')
            SpanningTree.invoke('broadcast')
            await sleep_ms(debounce_ms)
        await sleep_ms(1)

# colors
bcnrecv = (0, 0, 255)
bcnbrdcst = (255, 0, 0)
bcnrespond = (126, 126, 0)
gossiprecv = (0, 255, 0)
gossippblsh = (255, 255, 0)
gossiprspnd = (255, 165, 0)
treerecv = (255, 255, 255)
treebrdcst = (255, 126, 126)
treesend = (126, 126, 255)

# add some hooks
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
def bcn_recv_hook(*args, **kwargs):
    debug('Beacon.receive')
    rq.append(bcnrecv)
def bcn_brdcst_hook(*args, **kwargs):
    debug('Beacon.broadcast')
    rq.append(bcnbrdcst)
def bcn_respond_hook(*args, **kwargs):
    debug('Beacon.respond')
    rq.append(bcnrespond)

Beacon.add_hook('receive', bcn_recv_hook)
Beacon.add_hook('broadcast', bcn_brdcst_hook)
Beacon.add_hook('respond', bcn_respond_hook)
Beacon.add_hook('send', debug_name('Beacon.send'))

def gossip_recv_hook(*args, **kwargs):
    debug('Gossip.receive')
    rq.append(gossiprecv)
def gossip_pblsh_hook(*args, **kwargs):
    debug('Gossip.publish')
    rq.append(gossippblsh)
def gossip_rspnd_hook(*args, **kwargs):
    debug('Gossip.respond')
    rq.append(gossiprspnd)

Gossip.add_hook('receive', gossip_recv_hook)
Gossip.add_hook('publish', gossip_pblsh_hook)
Gossip.add_hook('respond', gossip_rspnd_hook)

def tree_recv_hook(*args, **kwargs):
    debug('SpanningTree.receive')
    rq.append(treerecv)
def tree_brdcst_hook(*args, **kwargs):
    debug('SpanningTree.broadcast')
    rq.append(treebrdcst)
def tree_send_hook(*args, **kwargs):
    debug('SpanningTree.send')
    rq.append(treesend)

SpanningTree.add_hook('receive', tree_recv_hook)
SpanningTree.add_hook('broadcast', tree_brdcst_hook)
SpanningTree.add_hook('send', tree_send_hook)
SpanningTree.add_hook('respond', debug_name('SpanningTree.respond'))
SpanningTree.add_hook('assign_address', debug_name('SpanningTree.assign_address'))
SpanningTree.add_hook('request_address_assignment', debug_name('SpanningTree.request_address_assignment'))

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

# debug hooks
hooks_added = False
def add_hooks():
    global hooks_added
    if hooks_added:
        return
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
    Packager.add_hook('add_route', debug_name('Packager.add_route'))
    Packager.add_hook('set_addr', debug_name('Packager.set_addr'))
    Packager.add_hook('remove_peer', debug_name('Packager.remove_peer'))
    Packager.add_hook('modemsleep', debug_name('modemsleep'))
    Packager.add_hook('sleepskip', debug_name('sleepskip'))

def start():
    run(gather(
        Packager.work(use_modem_sleep=False),
        rloop(),
        monitor_btn(btn, btnq, 800),
    ))

Beacon.invoke('start')
Gossip.invoke('start')
SpanningTree.invoke('start')
Ping.invoke('start')
