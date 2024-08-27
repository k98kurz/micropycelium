from machine import Pin
from asyncio import run
from micropycelium import Packager, ESPNowInterface, Beacon

def write_file(fname: str, data: str):
    with open(f'/{fname}', 'w') as f:
        f.write(data)

def read_file(fname: str) -> str:
    with open(f'/{fname}', 'r') as f:
        return f.read()

# set G4 to 1 to stay on
Pin(4, Pin.OUT).value(1)

Packager.add_application(Beacon)
Packager.add_interface(ESPNowInterface)
Beacon.invoke('start')
run(Packager.work())
