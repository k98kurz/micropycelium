from micropycelium import Packager, Address
from mpnode import (
    start, debug_name, Gossip, SpanningTree, Ping, DebugApp, DebugOp,
    monitor_btn, bloop, blink, memrloop, add_command, add_cmd_alias,
)
import machine

try:
    from editor import edit # type: ignore
    def _edit(cmd):
        if len(cmd) < 1:
            print('edit - missing required arg')
            return
        edit(cmd[0])
    add_command(
        'edit',
        _edit,
        'edit [path] - open a file in the file editor'
    )
except:
    pass

# default start
start()

# custom start with additional tasks
# start([
#     # additional custom tasks here
# ])
