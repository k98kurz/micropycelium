from asyncio import sleep_ms, run, gather
from collections import deque
from machine import Pin
from micropycelium import Packager, ESPNowInterface, Beacon

def write_file(fname: str, data: str):
    with open(f'/{fname}', 'w') as f:
        f.write(data)

def read_file(fname: str):
    with open(f'/{fname}', 'r') as f:
        print(f.read())

try:
    # LEDs specific to my breadboard
    p18 = Pin(18, Pin.OUT)
    p19 = Pin(19, Pin.OUT)
    p26 = Pin(26, Pin.OUT)
    bq18 = deque([], 10)
    bq19 = deque([], 10)
    bq26 = deque([], 10)
    async def blink(p: Pin, ms: int):
        v = p.value()
        p.value(not v)
        await sleep_ms(ms)
        p.value(v)
    async def bloop(bq: deque, p: Pin):
        while True:
            while len(bq):
                bq.popleft()
                await blink(p, 100)
            await sleep_ms(1)
    def recv_hook(*args, **kwargs):
        bq19.append(1)
    def brdcst_hook(*args, **kwargs):
        bq18.append(1)
    def send_hook(*args, **kwargs):
        bq26.append(1)
    Beacon.add_hook('receive', recv_hook)
    Beacon.add_hook('broadcast', brdcst_hook)
    Beacon.add_hook('send', send_hook)
    hooked = True
except BaseException:
    hooked = False

Packager.add_application(Beacon)
Packager.add_interface(ESPNowInterface)
Beacon.invoke('start')
if hooked:
    run(gather(Packager.work(), bloop(bq18, p18), bloop(bq19, p19), bloop(bq26, p26)))
else:
    run(Packager.work())
