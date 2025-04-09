from mpnode import console, hexify, debug, debug_name, memrloop
from asyncio import sleep_ms
from collections import deque
from machine import Pin, reset
from micropycelium import Packager, Beacon, Gossip, SpanningTree, Ping, DebugApp, ESPNowInterface

# save_imports
from asyncio import run, gather, create_task
from neopixel import NeoPixel

# RGB LED of the M5StampS3
rgb = NeoPixel(Pin(21, Pin.OUT), 1)
rq = deque([], 10)
async def rloop():
    while True:
        r = rq.popleft() if len(rq) else (0, 0, 0)
        rgb.fill(r)
        rgb.write()
        await sleep_ms(100 if any(r) else 1)

btn = Pin(0, Pin.IN)
btnq = deque([], 5)

async def monitor_btn(p: Pin, q: deque, debounce_ms: int, inverse: bool = True):
    while True:
        if (inverse and not p.value()) or (not inverse and p.value()):
            q.append(1)
            Beacon.invoke('start')
            SpanningTree.invoke('broadcast')
            await sleep_ms(debounce_ms)
        await sleep_ms(1)

# colors
blue = (0, 0, 255)
red = (255, 0, 0)
green = (0, 255, 0)
yellow = (255, 255, 0)
orange = (255, 165, 0)
white = (255, 255, 255)
purple = (128, 0, 128)
pink = (255, 192, 203)

def action_hook(name: str, c: tuple, q: deque):
    def inner(*args):
        args = [hexify(a) for a in args]
        debug(name, *args)
        q.append(c)
    return inner

# add some hooks
Beacon.add_hook('receive', action_hook('Beacon.receive', blue, rq))
Beacon.add_hook('broadcast', action_hook('Beacon.broadcast', red, rq))
Beacon.add_hook('respond', action_hook('Beacon.respond', green, rq))
Beacon.add_hook('send', debug_name('Beacon.send'))

Gossip.add_hook('receive', action_hook('Gossip.receive', purple, rq))
Gossip.add_hook('publish', debug_name('Gossip.publish'))
Gossip.add_hook('respond', action_hook('Gossip.respond', purple, rq))

SpanningTree.add_hook('receive', action_hook('SpanningTree.receive', white, rq))
SpanningTree.add_hook('broadcast', action_hook('SpanningTree.broadcast', pink, rq))
SpanningTree.add_hook('send', action_hook('SpanningTree.send', orange, rq))
SpanningTree.add_hook('respond', debug_name('SpanningTree.respond'))
SpanningTree.add_hook('assign_address', debug_name('SpanningTree.assign_address'))
SpanningTree.add_hook(
    'request_address_assignment',
    debug_name('SpanningTree.request_address_assignment')
)

def ping_respond_hook(*args, **kwargs):
    debug('Ping.respond', *args)
    rq.append(red)
    rq.append(white)
    rq.append(blue)
    rq.append(red)
    rq.append(white)
    rq.append(blue)

Ping.add_hook('request', debug_name('Ping.request'))
Ping.add_hook('respond', ping_respond_hook)
Ping.add_hook('response_received', debug_name('Ping.response_received'))
Ping.add_hook('gossip_request', debug_name('Ping.gossip_request'))
Ping.add_hook('gossip_respond', debug_name('Ping.gossip_respond'))
Ping.add_hook('gossip_response_received', debug_name('Ping.gossip_response_received'))

DebugApp.add_hook('output', debug_name('DebugApp.output'))
DebugApp.add_hook('receive', debug_name('DebugApp.receive'))

tasks = None

async def _start(
        additional_tasks = [],
        add_debug_hooks = True, pub_routes = True, sub_routes = False,
        add_intrfc_debug_hooks = False,
    ):
    if add_intrfc_debug_hooks:
        ESPNowInterface.add_hook(
            'process:receive',
            debug_name(f'Interface({ESPNowInterface.name}).process:receive')
        )
        ESPNowInterface.add_hook(
            'process:send',
            debug_name(f'Interface({ESPNowInterface.name}).process:send')
        )
        ESPNowInterface.add_hook(
            'process:broadcast',
            debug_name(f'Interface({ESPNowInterface.name}).process:broadcast')
        )
    Beacon.invoke('start')
    Gossip.invoke('start')
    SpanningTree.invoke('start')
    Ping.invoke('start')
    DebugApp.invoke('start')
    global tasks
    try:
        if tasks:
            for task in tasks:
                try:
                    task.cancel()
                except:
                    pass
        tasks = [
            create_task(Packager.work(use_modem_sleep=False)),
            create_task(rloop()),
            create_task(monitor_btn(btn, btnq, 800)),
            create_task(memrloop()),
            create_task(console(add_debug_hooks, pub_routes, sub_routes)),
        ]
        for task in additional_tasks:
            tasks.append(task)
        while True:
            try:
                await gather(*tasks)
            except Exception as e:
                if str(e) == 'quit':
                    break
                raise e
    except OSError as e:
        print('OSError encountered; resetting device')
        reset()

def start(
        additional_tasks = [],
        add_debug_hooks = True, pub_routes = True, sub_routes = False,
        add_intrfc_debug_hooks = False,
    ):
    run(_start(
        additional_tasks, add_debug_hooks, pub_routes, sub_routes,
        add_intrfc_debug_hooks,
    ))
