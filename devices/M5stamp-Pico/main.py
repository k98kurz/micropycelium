from asyncio import sleep_ms, run, gather
from collections import deque
from machine import Pin
from micropycelium import Packager, ESPNowInterface, Beacon
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
    rq.append((0, 0, 255))
def brdcst_hook(*args, **kwargs):
    rq.append((255, 0, 0))
def send_hook(*args, **kwargs):
    rq.append((126, 126, 126))
Beacon.add_hook('receive', recv_hook)
Beacon.add_hook('broadcast', brdcst_hook)
Beacon.add_hook('send', send_hook)

Packager.add_application(Beacon)
Packager.add_interface(ESPNowInterface)
Beacon.invoke('start')
# run(gather(Packager.work(), bloop(bq18, p18), bloop(bq19, p19), bloop(bq26, p26)))
run(gather(Packager.work(), rloop()))
