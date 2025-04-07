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
        args = []
        if len(cmd) > 1:
            args.append(int(cmd[1]))
        edit(cmd[0], *args)
    add_command(
        'edit',
        _edit,
        'edit [path] [page_size=42] - open a file in the file editor'
    )
except:
    pass

# default start
start()

# custom start with additional tasks
# start([
#     # additional custom tasks here
# ])
