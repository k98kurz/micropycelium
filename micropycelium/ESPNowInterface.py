from .Packager import Interface, Datagram, Packager
import network
import espnow


_config = {}
sta_if = network.WLAN(network.STA_IF)
# sta_if.disconnect()
sta_if.active(True)
sta_if.config(channel=14)
e = espnow.ESPNow()
e.active(True)
e.add_peer(b'\xff\xff\xff\xff\xff\xff')

def wake_espnwintrfc(*args, **kwargs):
    sta_if.active(True)
    sta_if.config(channel=14)

def config_espnwintrfc(intrfc: Interface, data: dict):
    for k,v in data.items():
        _config[k] = v

def recv_espnwintrfc(intrfc: Interface) -> bytes|None:
    res = e.recv(0)
    if res and res[0]:
        return Datagram(res[1], intrfc.id, res[0])

def send_espnwintrfc(datagram: Datagram):
    if datagram.addr not in [p[0] for p in e.get_peers()]:
        e.add_peer(datagram.addr)
    e.send(datagram.addr, datagram.data, False)

def broadcast_espnwintrfc(datagram: Datagram):
    e.send(b'\xff\xff\xff\xff\xff\xff', datagram.data, False)


ESPNowInterface = Interface(
    name='espnow',
    bitrate=12_000_000,
    configure=config_espnwintrfc,
    supported_schemas=[i for i in range(0, 11)],
    receive_func=recv_espnwintrfc,
    send_func=send_espnwintrfc,
    broadcast_func=broadcast_espnwintrfc,
    wake_func=wake_espnwintrfc,
)

Packager.add_interface(ESPNowInterface)
