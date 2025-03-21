from micropycelium import Packager, Address
from mpnode import (
    start, debug_name, Gossip, SpanningTree, Ping, DebugApp, DebugOp,
    ping_cb, monitor_btn, bloop, blink, memrloop,
)
import machine

# default start
start()

# custom start with additional tasks
# start([
#     # additional custom tasks here
# ])
