from asyncio import sleep_ms, run, gather
from collections import deque
from machine import Pin, reset
from micropycelium import (
    Packager, debug, ESPNowInterface, Beacon, Gossip, SpanningTree, Ping,
    DebugApp, DebugOp,
)
import gc


# useful for blinking LEDs
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

# useful for monitoring button presses
async def monitor_btn(p: Pin, q: deque, debounce_ms: int):
    while True:
        if not p.value():
            q.append(1)
            Beacon.invoke('start')
            SpanningTree.invoke('broadcast')
            await sleep_ms(debounce_ms)
        await sleep_ms(1)

# add some hooks
def bcn_recv_hook(*args, **kwargs):
    debug('Beacon.receive')
def bcn_brdcst_hook(*args, **kwargs):
    debug('Beacon.broadcast')
def bcn_respond_hook(*args, **kwargs):
    debug('Beacon.respond')
def bcn_send_hook(*args, **kwargs):
    debug('Beacon.send')

Beacon.add_hook('receive', bcn_recv_hook)
Beacon.add_hook('broadcast', bcn_brdcst_hook)
Beacon.add_hook('respond', bcn_respond_hook)
Beacon.add_hook('send', bcn_send_hook)

def debug_name(name: str):
    def inner(*args):
        args = [a.hex() if isinstance(a, bytes) else repr(a) for a in args]
        debug(name, *args)
    return inner

Gossip.add_hook('receive', debug_name('Gossip.receive'))
Gossip.add_hook('publish', debug_name('Gossip.publish'))
Gossip.add_hook('respond', debug_name('Gossip.respond'))

SpanningTree.add_hook('receive', debug_name('SpanningTree.receive'))
SpanningTree.add_hook('broadcast', debug_name('SpanningTree.broadcast'))
SpanningTree.add_hook('send', debug_name('SpanningTree.send'))

def ping_report_callback(*args, **kwargs):
    print('Ping report:')
    for k, v in kwargs.items():
        if isinstance(v, dict):
            print(f'  {k}:')
            for k2, v2 in v.items():
                print(f'    {k2}: {v2}')
        else:
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
    Packager.add_hook('add_route', debug_name('Packager.add_route'))
    Packager.add_hook('set_addr', debug_name('Packager.set_addr'))
    Packager.add_hook('remove_peer', debug_name('Packager.remove_peer'))
    Packager.add_hook('modemsleep', debug_name('modemsleep'))
    Packager.add_hook('sleepskip', debug_name('sleepskip'))

async def memrloop():
    while True:
        await sleep_ms(10_000)
        gc.collect()
        fr = gc.mem_free()
        al = gc.mem_alloc()
        print('**Memory Report**')
        print(f'\t{fr} ({fr/(fr+al)*100:.2f}%) free')
        print(f'\t{al} ({al/(fr+al)*100:.2f}%) allocated')

# to use an LED, create a Pin and a deque, then use run(gather(Packager.work(), bloop(pin, queue)))
# to use a button, create a Pin and a deque, then use run(gather(Packager.work(), monitor_btn(pin, queue, 300)))

tasks = None

def start():
    global tasks
    try:
        if tasks:
            for task in tasks:
                try:
                    task.cancel()
                except:
                    pass
        tasks = [
            Packager.work(use_modem_sleep=True),
            memrloop(),
        ]
        run(gather(*tasks))
    except OSError:
        print('OSError encountered; resetting device')
        reset()

add_hooks()
Beacon.invoke('start')
Gossip.invoke('start')
SpanningTree.invoke('start')
Ping.invoke('start')
DebugApp.invoke('start')
