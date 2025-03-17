from micropycelium import Packager, Address
from mpnode import (
    start, debug_name, Gossip, SpanningTree, Ping,
    DebugApp, DebugOp, ping_report_cb
)
import machine

Packager.add_hook('add_peer', debug_name('Packager.add_peer'))
Packager.add_hook('add_route', debug_name('Packager.add_route'))
Packager.add_hook('set_addr', debug_name('Packager.set_addr'))
start()
