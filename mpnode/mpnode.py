from asyncio import sleep_ms
from collections import deque
from machine import reset
from micropycelium import (
    Packager, debug, ESPNowInterface, Beacon, Gossip, SpanningTree, Ping,
    DebugApp, DebugOp, Address, dCPL, dTree, ainput,
    PROTOCOL_VERSION,
)
from micropython import const
from struct import pack
import gc


MPNODE_VERSION = const('0.1.0-dev')


def hexify(thing):
    if type(thing) is list:
        return [hexify(i) for i in thing]
    elif type(thing) is tuple:
        return tuple(hexify(i) for i in thing)
    elif type(thing) is bytes:
        return thing.hex()
    elif type(thing) is dict:
        return {hexify(k): hexify(v) for k, v in thing.items()}
    elif type(thing) in (int, float):
        return thing
    else:
        return thing if type(thing) is str else repr(thing)

debug_q = deque([], 25)
def debug(*args):
    debug_q.append(args)

def debug_name(name: str):
    def inner(*args):
        args = [hexify(a) for a in args]
        debug(name, *args)
    return inner

def ping_cb(report):
    if type(report) is str:
        output(report)
        return
    report = hexify(report)
    r = 'Ping report:\n'
    for k, v in report.items():
        r += f'  {k}: {v}\n'
    output(r)

hooks_added = False
def add_hooks():
    global hooks_added
    if hooks_added:
        return
    hooks_added = True
    ESPNowInterface.add_hook('process:receive', debug_name(f'Interface({ESPNowInterface.name}).process:receive'))
    ESPNowInterface.add_hook('process:send', debug_name(f'Interface({ESPNowInterface.name}).process:send'))
    ESPNowInterface.add_hook('process:broadcast', debug_name(f'Interface({ESPNowInterface.name}).process:broadcast'))
    Packager.add_hook('send', debug_name('Packager.send'))
    Packager.add_hook('broadcast', debug_name('Packager.broadcast'))
    Packager.add_hook('receive', debug_name('Packager.receive'))
    Packager.add_hook('receive:rns', debug_name('Packager.receive:rns'))
    Packager.add_hook('receive:nia', debug_name('Packager.receive:nia'))
    Packager.add_hook('rns', debug_name('Packager.rns'))
    Packager.add_hook('send_packet', debug_name('Packager.send_packet'))
    Packager.add_hook('_send_datagram', debug_name('Packager._send_datagram'))
    Packager.add_hook('deliver', debug_name('Packager.deliver'))
    Packager.add_hook('add_peer', debug_name('Packager.add_peer'))
    Packager.add_hook('set_addr', debug_name('Packager.set_addr'))
    Packager.add_hook('remove_peer', debug_name('Packager.remove_peer'))
    Packager.add_hook('modemsleep', debug_name('modemsleep'))
    Packager.add_hook('sleepskip', debug_name('sleepskip'))

async def memrloop():
    while True:
        await sleep_ms(10_000)
        gc.collect()
        fr = gc.mem_free()
        al = gc.mem_alloc()
        debug(
            '**Memory Report**\n' +
            f'\t{fr} ({fr/(fr+al)*100:.2f}%) free\n' +
            f'\t{al} ({al/(fr+al)*100:.2f}%) allocated'
        )

def _help():
    print('Commands:')
    print('\tm|monitor - monitors debug messages')
    print('\tget [node_id|addrs|peers|routes|next_hop addr metric] - get info from the local node')
    print('\tping [node_id|addr] [count] [timeout] - ping the node_id/address')
    print('\t\tcount default value is 4')
    print('\t\ttimeout default value is 5 (seconds)')
    print('\t\tIf node_id is provided, the address will be found from the known routes')
    print('\tgossip ping [node_id] [count] [timeout] - ping the node via gossip')
    print('\t\tcount default value is 4')
    print('\t\ttimeout default value is 5 (seconds)')
    print('\tdebug [node_id] [info|peers|routes|next_hop addr metric] - get debug info from a node')
    print('\tadmin [node_id] [password] [reset] - restart a remote node')
    print('\tversion - show version information')
    print('\tq|quit - quit the program')
    print('\treset - reset the device')
    print('\twait [count] - wait for [count=1] output messages')
    # print('\t - ')

outq = deque([], 2)
output = lambda res: outq.append(res)
async def wait(c = 1):
    print("Waiting for output. Hit Enter to stop waiting (command will run in background)...")
    i = 0
    while i < c:
        if len(outq):
            print(outq.popleft())
            i += 1
        if await ainput('', True) is not None:
            break

async def monitor():
    print("Hit Enter to stop monitoring")
    while True:
        if len(debug_q):
            print(*debug_q.popleft())
        if len(outq):
            print(outq.popleft())
        else:
            if await ainput('', True) is not None:
                break

async def console(add_debug_hooks = False, pub_routes = True, sub_routes = False):
    if add_debug_hooks:
        add_hooks()
    SpanningTree.params['pub'] = pub_routes
    SpanningTree.params['sub'] = sub_routes
    await monitor()
    while True:
        cmd = (await ainput("μpycelium> ")).split()
        if len(cmd) == 0:
            continue
        cmd[0] = cmd[0].lower()
        try:
            if cmd[0] in ('?', 'h', 'help'):
                _help()
            elif cmd[0] in ('monitor', 'm'):
                await monitor()
            elif cmd[0] == 'get':
                if len(cmd) < 2:
                    print('get - missing a required arg')
                    continue
                if cmd[1].lower() == 'node_id':
                    print(f'Node ID: {Packager.node_id.hex()}')
                elif cmd[1].lower() == 'addrs':
                    addrs = [a for a in Packager.node_addrs]
                    print(f'Addresses: {addrs}')
                elif cmd[1].lower() == 'peers':
                    peers = [pid.hex() for pid in Packager.peers]
                    print(f'Peers:')
                    for peer in peers:
                        print(f'  {peer}')
                elif cmd[1].lower() == 'routes':
                    print(f'Routes:')
                    for addr, pid in Packager.routes.items():
                        print(f'  {addr} -> {pid.hex()}')
                elif cmd[1].lower() == 'next_hop':
                    if len(cmd) < 4:
                        print('get next_hop - missing a required arg')
                        continue
                    nh_addr = Address.from_str(cmd[2])
                    metric = dCPL if 'cpl' in cmd[3].lower() else dTree
                    nh = Packager.next_hop(nh_addr, metric)
                    if nh is None:
                        print(f'No next hop found for {nh_addr}')
                    else:
                        print(f'Next Hop: {nh[0].id.hex()} {nh[1]}')
            elif cmd[0] == 'version':
                print(f'MPNode version: {MPNODE_VERSION}')
                print(f'Packager version: {Packager.version}')
                print(f'Protocol version: {PROTOCOL_VERSION}')
            elif cmd[0] in ('quit', 'q'):
                raise Exception('quit')
            elif cmd[0] == 'reset':
                reset()
            elif cmd[0] == 'ping':
                if len(cmd) < 2:
                    print('ping - missing required node_id|addr')
                    continue
                try:
                    nid = bytes.fromhex(cmd[1])
                    addr = None
                except:
                    nid = None
                    addr = Address.from_str(cmd[1])
                kwargs = {
                    'node_id': nid,
                    'addr': addr,
                    'callback': ping_cb,
                }
                if len(cmd) > 2:
                    kwargs['count'] = int(cmd[2])
                if len(cmd) > 3:
                    kwargs['timeout'] = int(cmd[3])
                Ping.invoke('ping', **kwargs)
                c = kwargs.get('count', 4)
                await wait(c + 2)
            elif cmd[0] == 'gossip':
                if len(cmd) < 2:
                    print('gossip - missing required subcommand')
                    continue
                if cmd[1].lower() == 'ping':
                    if len(cmd) < 3:
                        print('gossip ping - missing required addr')
                        continue
                    nid = bytes.fromhex(cmd[2])
                    kwargs = {
                        'node_id': nid,
                        'callback': output,
                    }
                    if len(cmd) > 3:
                        kwargs['count'] = int(cmd[3])
                    if len(cmd) > 4:
                        kwargs['timeout'] = int(cmd[4])
                    Ping.invoke('gossip_ping', **kwargs)
                    await wait(kwargs.get('count', 4) + 2)
                else:
                    print('unknown subcommand')
                    continue
            elif cmd[0] == 'debug':
                if len(cmd) < 3:
                    print('debug - missing a required arg')
                    continue
                nid = bytes.fromhex(cmd[1])
                cmd[2] = cmd[2].lower()
                nh_addr = b''
                if cmd[2] not in ('info', 'peers', 'routes', 'next_hop'):
                    print(f'debug - unknown mode {cmd[2]}')
                    continue
                if cmd[2] == 'info':
                    op = DebugOp.REQUEST_NODE_INFO
                elif cmd[2] == 'peers':
                    op = DebugOp.REQUEST_PEER_LIST
                elif cmd[2] == 'routes':
                    op = DebugOp.REQUEST_ROUTES
                elif cmd[2] == 'next_hop':
                    if len(cmd) < 5:
                        print('debug next_hop - missing a required arg')
                        continue
                    nh_addr = Address.from_str(cmd[3])
                    metric = dCPL if 'cpl' in cmd[4].lower() else dTree
                    nh_addr = pack('!BB16s', metric, nh_addr.tree_state, nh_addr.address)
                    op = DebugOp.REQUEST_NEXT_HOP
                DebugApp.add_hook('output', lambda *args: output(args[1]))
                DebugApp.add_hook(
                    'request',
                    lambda *args: output(f'DebugApp.request sent: {hexify(args[1:])}')
                )
                DebugApp.invoke('request', op, nid, nh_addr)
                await wait(2)
            elif cmd[0] == 'admin':
                if len(cmd) < 4:
                    print('admin - missing a required arg')
                    continue
                nid = bytes.fromhex(cmd[1])
                cmd[3] = cmd[3].lower()
                if cmd[3] == 'reset':
                    op = DebugOp.REQUIRE_RESET
                    DebugApp.invoke('require', op, nid, cmd[2].encode())
                    await wait(1)
                else:
                    print(f'admin - unknown subcommand {cmd[3]}')
                    continue
            elif cmd[0] == 'wait':
                if len(cmd) < 2:
                    await wait(1)
                else:
                    await wait(int(cmd[1]))
            else:
                print(f'Unknown command: {cmd[0]}')
                _help()
        except Exception as e:
            if str(e) == 'quit':
                raise e
            print(f'Error: {e}')
