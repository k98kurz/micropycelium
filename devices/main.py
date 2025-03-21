from micropycelium import Packager, Address
from mpnode import (
    start, debug_name, Gossip, SpanningTree, Ping, DebugApp, DebugOp,
    ping_cb, monitor_btn, bloop, blink, memrloop,
)
import machine

Packager.add_hook('add_peer', debug_name('Packager.add_peer'))
Packager.add_hook('add_route', debug_name('Packager.add_route'))
Packager.add_hook('set_addr', debug_name('Packager.set_addr'))
Packager.add_hook('deliver:checksum_failed', debug_name('Packager.deliver:checksum_failed'))
Packager.add_hook('deliver:receive_failed', debug_name('Packager.deliver:receive_failed'))

# default start
start()

# custom start with additional tasks
# start([
#     # additional custom tasks here
# ])
