from asyncio import sleep_ms, run, gather
from collections import deque
from machine import Pin
from micropycelium import Packager, debug, ESPNowInterface, Beacon

def write_file(fname: str, data: str):
    with open(f'/{fname}', 'w') as f:
        f.write(data)

def read_file(fname: str) -> str:
    with open(f'/{fname}', 'r') as f:
        return f.read()

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
            await sleep_ms(debounce_ms)
        await sleep_ms(1)

# add some hooks
def recv_hook(*args, **kwargs):
    debug('Beacon.receive')
def brdcst_hook(*args, **kwargs):
    debug('Beacon.broadcast')
def send_hook(*args, **kwargs):
    debug('Beacon.send')

Beacon.add_hook('receive', recv_hook)
Beacon.add_hook('broadcast', brdcst_hook)
Beacon.add_hook('send', send_hook)

def debug_name(name: str):
    def inner(*args):
        debug(name)
    return inner

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
    Packager.add_hook('remove_peer', debug_name('Packager.remove_peer'))
    Packager.add_hook('modemsleep', debug_name('modemsleep'))
    Packager.add_hook('sleepskip', debug_name('sleepskip'))

# to use an LED, create a Pin and a deque, then use run(gather(Packager.work(), bloop(pin, queue)))
# to use a button, create a Pin and a deque, then use run(gather(Packager.work(), monitor_btn(pin, queue, 300)))

def start():
    run(Packager.work(use_modem_sleep=True))

Beacon.invoke('start')
add_hooks()
start()
