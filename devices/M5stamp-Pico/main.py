from asyncio import sleep_ms, run, gather
from collections import deque
from machine import Pin
from micropycelium import Packager, debug, ESPNowInterface, Beacon
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
            await sleep_ms(debounce_ms)
        await sleep_ms(1)

# add some hooks
def debug_name(name: str):
    def inner(*args):
        debug(name)
    return inner
def recv_hook(*args, **kwargs):
    debug('Beacon.receive')
    rq.append((0, 0, 255))
def brdcst_hook(*args, **kwargs):
    debug('Beacon.broadcast')
    rq.append((255, 0, 0))
def respond_hook(*args, **kwargs):
    debug('Beacon.respond')
    rq.append((126, 126, 0))

Beacon.add_hook('receive', recv_hook)
Beacon.add_hook('broadcast', brdcst_hook)
Beacon.add_hook('respond', respond_hook)
Beacon.add_hook('send', debug_name('Beacon.send'))

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
    Packager.add_hook('remove_peer', debug_name('Packager.remove_peer'))
    Packager.add_hook('modemsleep', debug_name('modemsleep'))
    Packager.add_hook('sleepskip', debug_name('sleepskip'))

def start():
    run(gather(
        Packager.work(use_modem_sleep=True),
        monitor_btn(btn, btnq, 800),
    ))

add_hooks()
Beacon.invoke('start')
start()
