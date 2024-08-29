from asyncio import run, sleep_ms, gather
from collections import deque
from machine import Pin
from micropycelium import Packager, Beacon, ESPNowInterface, debug

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
            if len(list(Packager.peers.keys())):
                Beacon.invoke('send', list(Packager.peers.keys())[0])
            else:
                Beacon.invoke('start')
            await sleep_ms(debounce_ms)
        await sleep_ms(1)

# add some hooks
def debug_name(name: str):
    def inner(*args):
        debug(name)
    return inner

def beacon_action_hook(name: str):
    def inner(*args):
        debug(name)
        led26q.append(1)
    return inner

hooks_added = False
def add_hooks():
    global hooks_added
    if hooks_added:
        return
    hooks_added = True
    Beacon.add_hook('receive', beacon_action_hook('Beacon.receive'))
    Beacon.add_hook('broadcast', debug_name('Beacon.broadcast'))
    Beacon.add_hook('send', debug_name('Beacon.send'))
    ESPNowInterface.add_hook('process:receive', debug_name(f'Interface({ESPNowInterface.name}).process:receive'))
    ESPNowInterface.add_hook('process:send', debug_name(f'Interface({ESPNowInterface.name}).process:send'))
    ESPNowInterface.add_hook('process:broadcast', debug_name(f'Interface({ESPNowInterface.name}).process:broadcast'))
    Packager.add_hook('send', debug_name('Packager.send'))
    Packager.add_hook('broadcast', debug_name('Packager.broadcast'))
    Packager.add_hook('receive', debug_name('Packager.receive'))
    Packager.add_hook('rns', debug_name('Packager.rns'))
    Packager.add_hook('send_packet', debug_name('Packager.send_packet'))
    Packager.add_hook('_send_datagram', debug_name('Packager._send_datagram'))
    Packager.add_hook('deliver', debug_name('Packager.deliver'))
    Packager.add_hook('add_peer', debug_name('Packager.add_peer'))
    Packager.add_hook('remove_peer', debug_name('Packager.remove_peer'))
    Packager.add_hook('modemsleep', debug_name('modemsleep'))
    Packager.add_hook('sleepskip', debug_name('sleepskip'))

def start():
    run(gather(
        Packager.work(use_modem_sleep=True),
        bloop(led26q, led26),
        monitor_btn(btnA, btnAq, 800),
        monitor_btn(btnB, btnBq, 200)
    ))

add_hooks()
Beacon.invoke('start')
start()
