"""Mock for micropython espnow module."""
from enum import Enum

class wifi_phy_rate_t(Enum):
    # https://docs.espressif.com/projects/esp-idf/en/v4.4.1/esp32/api-reference/network/esp_wifi.html#_CPPv415wifi_phy_rate_t
    WIFI_PHY_RATE_1M_L = 0x00
    WIFI_PHY_RATE_2M_L = 0x01
    WIFI_PHY_RATE_5M_L = 0x02
    WIFI_PHY_RATE_11M_L = 0x03
    WIFI_PHY_RATE_2M_S = 0x05
    WIFI_PHY_RATE_5M_S = 0x06
    WIFI_PHY_RATE_11M_S = 0x07
    WIFI_PHY_RATE_48M = 0x08
    WIFI_PHY_RATE_24M = 0x09
    WIFI_PHY_RATE_12M = 0x0a
    WIFI_PHY_RATE_6M = 0x0b
    WIFI_PHY_RATE_54M = 0x0c
    WIFI_PHY_RATE_36M = 0x0d
    WIFI_PHY_RATE_18M = 0x0e
    WIFI_PHY_RATE_9M = 0x0f
    WIFI_PHY_RATE_MCS0_LGI = 0x10
    WIFI_PHY_RATE_MCS1_LGI = 0x11
    WIFI_PHY_RATE_MCS2_LGI = 0x12
    WIFI_PHY_RATE_MCS3_LGI = 0x13
    WIFI_PHY_RATE_MCS4_LGI = 0x14
    WIFI_PHY_RATE_MCS5_LGI = 0x15
    WIFI_PHY_RATE_MCS6_LGI = 0x16
    WIFI_PHY_RATE_MCS7_LGI = 0x17
    WIFI_PHY_RATE_MCS0_SGI = 0x18
    WIFI_PHY_RATE_MCS1_SGI = 0x19
    WIFI_PHY_RATE_MCS2_SGI = 0x1A
    WIFI_PHY_RATE_MCS3_SGI = 0x1B
    WIFI_PHY_RATE_MCS4_SGI = 0x1C
    WIFI_PHY_RATE_MCS5_SGI = 0x1D
    WIFI_PHY_RATE_MCS6_SGI = 0x1E
    WIFI_PHY_RATE_MCS7_SGI = 0x1F
    WIFI_PHY_RATE_LORA_250K = 0x29
    WIFI_PHY_RATE_LORA_500K = 0x2A
    WIFI_PHY_RATE_MAX = 0xff


class ESPNow:
    # https://docs.micropython.org/en/latest/library/espnow.html
    peers: dict[bytes, tuple]

    def __init__(self) -> None:
        self._status = False
        self.peers = {}
        self._conf = {
            'rxbuf': 526,
            'timeout_ms': 300_000,
            'rate': wifi_phy_rate_t.WIFI_PHY_RATE_1M_L,
        }
        self._statistics = [0, 0, 0, 0, 0]

    def active(self, status: bool|None = None) -> bool:
        """Initialise or de-initialise the ESP-NOW communication
            protocol depending on the value of the flag optional
            argument.
        """
        if status is not None:
            self._status = bool(status)
        return self._status

    def config(self, param: str, val = None) -> int|str|bytes|bool|None:
        """Set or get configuration values of the ESPNow interface. To
            set values, use the keyword syntax, and one or more
            parameters can be set at a time. To get a value the
            parameter name should be quoted as a string, and just one
            parameter is queried at a time.
        """
        if not self._status:
            raise OSError(1, "ESP_ERR_ESPNOW_NOT_INIT")
        if param in self._conf:
            if val is not None:
                self._conf[param] = val
            return self._conf[param]
        raise ValueError("invalid config param name")

    def send(self, mac: bytes, msg: bytes, sync: bool = True) -> bool:
        """Send the data contained in msg to the peer with given network
            mac address. In the second form, mac=None and sync=True. The
            peer must be registered with ESPNow.add_peer() before the
            message can be sent.
        """
        self._statistics[0] += 1
        self._statistics[1] += 1
        return True

    def recv(self, timeout_ms: int|None = None) -> tuple[None, None]|tuple[bytes, bytes]:
        """Wait for an incoming message and return the mac address of
            the peer and the message. Note: It is not necessary to
            register a peer (using add_peer()) to receive a message from
            that peer.
        """
        self._statistics[3] += 1
        return (b'mac0', b'msg')

    def irecv(self, timeout_ms: int|None = None) -> tuple[None, None]|tuple[bytearray, bytearray]:
        """Works like ESPNow.recv() but will reuse internal bytearrays
            to store the return values: [mac, msg], so that no new
            memory is allocated on each call.
        """
        self._statistics[3] += 1
        return (bytearray(b'mac0'), bytearray(b'msg'))

    def recvinto(self, data: list[bytearray, bytearray], timeout_ms: int|None = None) -> int:
        """Wait for an incoming message and return the length of the
            message in bytes. This is the low-level method used by both
            recv() and irecv() to read messages.
        """
        self._statistics[3] += 1
        data[0][:4] = b'mac0'
        data[1][:3] = b'msg'
        return 3

    def any(self) -> bool:
        """Check if data is available to be read with ESPNow.recv()."""
        return True

    def stats(self) -> tuple[int, int, int, int, int]:
        """A 5-tuple containing the number of packets sent/received/lost:
            (tx_pkts, tx_responses, tx_failures, rx_packets,
            rx_dropped_packets). Incoming packets are dropped when the
            recv buffers are full. To reduce packet loss, increase the
            rxbuf config parameters and ensure you are reading messages
            as quickly as possible. Note: Dropped packets will still be
            acknowledged to the sender as received.
        """
        return tuple(self._statistics)

    def set_pmk(self, pmk: bytes):
        """Set the Primary Master Key (PMK) which is used to encrypt the
            Local Master Keys (LMK) for encrypting messages. If this is
            not set, a default PMK is used by the underlying Espressif
            ESP-NOW software stack. Note: messages will only be
            encrypted if lmk is also set in ESPNow.add_peer() (see
            Security in the Espressif API docs).
        """
        return

    def add_peer(self, mac: bytes, lmk: bytes = None, channel: int = 0,
                 ifidx: int = 0, encrypt: bool = None):
        """Add/register the provided mac address as a peer. Additional
            parameters may also be specified as positional or keyword
            arguments (any parameter set to None will be set to it's
            default value).
        """
        self.peers[mac] = [mac, lmk, channel, ifidx, encrypt]

    def del_peer(self, mac: bytes):
        """Deregister the peer associated with the provided mac address."""
        self.peers.pop(mac)

    def peer_count(self) -> tuple[int, int]:
        """Return the number of registered peers: (peer_num,
            encrypt_num): where `peer_num` is the number of peers which
            are registered, and encrypt_num is the number of encrypted
            peers.
        """
        return (len(self.peers.keys()), len([1 for p in self.peers if p[-1]]))

    def get_peers(self) -> tuple[tuple]:
        """Return the “peer info” parameters for all the registered
            peers (as a tuple of tuples).
        """
        return tuple([tuple(p) for p in self.peers])

    def mod_peer(self, mac, lmk, channel: int = None, ifidx: int = None,
                 encrypt: bool = None):
        """Modify the parameters of the peer associated with the
            provided mac address. Parameters may be provided as
            positional or keyword arguments (see ESPNow.add_peer()). Any
            parameter that is not set (or set to None) will retain the
            existing value for that parameter.
        """
        peer = self.peers[mac]
        peer[1] = lmk
        if channel is not None:
            peer[2] = channel
        if ifidx is not None:
            peer[3] = ifidx
        if encrypt is not None:
            peer[4] = encrypt
