from mpnode import console, hexify, debug, debug_name, memrloop, bloop
from asyncio import sleep_ms
from collections import deque
from machine import reset
from micropycelium import Packager, Beacon, Gossip, SpanningTree, Ping, DebugApp, ESPNowInterface

# save_imports
from asyncio import run, gather, create_task
from machine import Pin


# set G4 to 1 to stay on
Pin(4, Pin.OUT).value(1)
# Button A: G37
btnA = Pin(37, Pin.IN)
btnAq = deque([], 5)
# Button B: G39
btnB = Pin(39, Pin.IN)
btnBq = deque([], 5)
# Button C (pwr): G35
btnC = Pin(35, Pin.IN)
btnCq = deque([], 5)
# LED: G19 (internal)
led19 = Pin(19, Pin.OUT)
led19q = deque([], 10)
# LED: G26 (hat pin)
led26 = Pin(26, Pin.OUT)
led26q = deque([], 10)


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

def action_hook(name: str, q: deque):
    def inner(*args):
        args = [hexify(a) for a in args]
        debug(name, *args)
        q.append(1)
    return inner

# add some hooks
Beacon.add_hook('receive', action_hook('Beacon.receive', led19q))
Beacon.add_hook('broadcast', debug_name('Beacon.broadcast'))
Beacon.add_hook('respond', debug_name('Beacon.respond'))
Beacon.add_hook('send', debug_name('Beacon.send'))

Gossip.add_hook('receive', action_hook('Gossip.receive', led19q))
Gossip.add_hook('publish', debug_name('Gossip.publish'))
Gossip.add_hook('respond', debug_name('Gossip.respond'))

SpanningTree.add_hook('receive', debug_name('SpanningTree.receive'))
SpanningTree.add_hook('broadcast', debug_name('SpanningTree.broadcast'))
SpanningTree.add_hook('send', debug_name('SpanningTree.send'))
SpanningTree.add_hook('respond', debug_name('SpanningTree.respond'))
SpanningTree.add_hook(
    'assign_address', action_hook('SpanningTree.assign_address', led19q)
)
SpanningTree.add_hook(
    'request_address_assignment',
    action_hook('SpanningTree.request_address_assignment', led19q)
)

def ping_respond_hook(*args, **kwargs):
    debug('Ping.respond', *args)
    led26q.append(1)
    led26q.append(1)
    led26q.append(1)

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
            create_task(bloop(led19q, led19)),
            create_task(bloop(led26q, led26)),
            create_task(monitor_btn(btnA, btnAq, 800)),
            create_task(monitor_btn(btnB, btnBq, 200)),
            create_task(monitor_btn(btnC, btnCq, 200)),
            create_task(btnAloop()),
            create_task(btnBloop()),
            create_task(btnCloop()),
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
    except OSError:
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
