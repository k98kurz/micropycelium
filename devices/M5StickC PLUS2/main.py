from machine import Pin
from asyncio import run
from micropycelium import Packager, Beacon, ESPNowInterface, debug

def write_file(fname: str, data: str):
    with open(f'/{fname}', 'w') as f:
        f.write(data)

def read_file(fname: str) -> str:
    with open(f'/{fname}', 'r') as f:
        return f.read()

# set G4 to 1 to stay on
Pin(4, Pin.OUT).value(1)

# add some hooks
def debug_name(name: str):
    def inner(*args):
        debug(name)
    return inner

Beacon.add_hook('receive', debug_name('Beacon.receive'))
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

Beacon.invoke('start')

def start():
    run(Packager.work())

start()
