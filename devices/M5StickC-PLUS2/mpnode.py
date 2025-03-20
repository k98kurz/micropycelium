from asyncio import sleep_ms, run, gather, create_task
from collections import deque
from machine import Pin, reset
from micropycelium import (
    Packager, debug, ESPNowInterface, Beacon, Gossip, SpanningTree, Ping,
    DebugApp, DebugOp, Address, dCPL, dTree, ainput,
    PROTOCOL_VERSION,
)
from micropython import const
from struct import pack
import gc


MPNODE_VERSION = const('0.1.0-dev')


# set G4 to 1 to stay on
Pin(4, Pin.OUT).value(1)
# Button A: G37
btnA = Pin(37, Pin.IN)
btnAq = deque([], 5)
# Button B: G39
btnB = Pin(39, Pin.IN)
btnBq = deque([], 5)
# Button C (pwr): G35
btnC = Pin(35, Pin.IN)
btnCq = deque([], 5)
# LED: G19 (internal)
led19 = Pin(19, Pin.OUT)
led19q = deque([], 10)
# LED: G26 (hat pin)
led26 = Pin(26, Pin.OUT)
led26q = deque([], 10)

async def blink(p: Pin, ms: int):
    p.value(1)
    await sleep_ms(ms)
    p.value(0)
async def bloop(q: deque, p: Pin):
    while True:
        while len(q):
            q.popleft()
            await blink(p, 100)
        await sleep_ms(1)
async def monitor_btn(p: Pin, q: deque, debounce_ms: int):
    while True:
        if not p.value():
            q.append(1)
            await sleep_ms(debounce_ms)
        await sleep_ms(1)
async def btnAloop():
    while True:
        if len(btnAq):
            btnAq.popleft()
            Beacon.invoke('start')
        await sleep_ms(1)
async def btnBloop():
    while True:
        if len(btnBq):
            btnBq.popleft()
            SpanningTree.invoke('broadcast')
        await sleep_ms(1)
async def btnCloop():
    while True:
        if len(btnCq):
            btnCq.popleft()
            SpanningTree.invoke('maintain_tree')
        await sleep_ms(1)

debug_q = deque([], 25)
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
def debug(*args):
    debug_q.append(args)
def debug_name(name: str):
    def inner(*args):
        args = [hexify(a) for a in args]
        debug(name, *args)
    return inner

def action_hook(name: str, q: deque):
    def inner(*args):
        debug(name)
        q.append(1)
    return inner

# add some hooks
Beacon.add_hook('receive', action_hook('Beacon.receive', led19q))
Beacon.add_hook('broadcast', debug_name('Beacon.broadcast'))
Beacon.add_hook('respond', debug_name('Beacon.respond'))
Beacon.add_hook('send', debug_name('Beacon.send'))

Gossip.add_hook('receive', action_hook('Gossip.receive', led26q))
Gossip.add_hook('publish', debug_name('Gossip.publish'))
Gossip.add_hook('respond', debug_name('Gossip.respond'))

SpanningTree.add_hook('receive', debug_name('SpanningTree.receive'))
SpanningTree.add_hook('broadcast', debug_name('SpanningTree.broadcast'))
SpanningTree.add_hook('send', debug_name('SpanningTree.send'))
SpanningTree.add_hook('respond', debug_name('SpanningTree.respond'))
SpanningTree.add_hook(
    'assign_address', action_hook('SpanningTree.assign_address', led26q)
)
SpanningTree.add_hook(
    'request_address_assignment',
    action_hook('SpanningTree.request_address_assignment', led26q)
)

def ping_report_cb(report):
    print('Ping report:')
    report = hexify(report)
    for k, v in report.items():
        print(f'  {k}: {v}')

Ping.add_hook('request', debug_name('Ping.request'))
Ping.add_hook('respond', debug_name('Ping.respond'))
Ping.add_hook('response_received', debug_name('Ping.response_received'))
Ping.add_hook('gossip_request', debug_name('Ping.gossip_request'))
Ping.add_hook('gossip_respond', debug_name('Ping.gossip_respond'))
Ping.add_hook('gossip_response_received', debug_name('Ping.gossip_response_received'))

DebugApp.add_hook('output', debug_name('DebugApp.output'))
DebugApp.add_hook('receive', debug_name('DebugApp.receive'))

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
    print("Hit Enter to stop")
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
                    'callback': output,
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

tasks = None

async def _start(add_debug_hooks = False, pub_routes = True, sub_routes = False):
    Beacon.invoke('start')
    Gossip.invoke('start')
    SpanningTree.invoke('start')
    Ping.invoke('start')
    DebugApp.invoke('start')
    global tasks
    try:
        if tasks:
            for task in tasks:
                try:
                    task.cancel()
                except:
                    pass
        tasks = [
            create_task(Packager.work(use_modem_sleep=False)),
            create_task(bloop(led19q, led19)),
            create_task(bloop(led26q, led26)),
            create_task(monitor_btn(btnA, btnAq, 800)),
            create_task(monitor_btn(btnB, btnBq, 200)),
            create_task(monitor_btn(btnC, btnCq, 200)),
            create_task(btnAloop()),
            create_task(btnBloop()),
            create_task(btnCloop()),
            create_task(memrloop()),
            create_task(console(add_debug_hooks, pub_routes, sub_routes)),
        ]
        while True:
            try:
                await gather(*tasks)
            except Exception as e:
                if str(e) == 'quit':
                    break
    except OSError:
        print('OSError encountered; resetting device')
        reset()

def start(add_debug_hooks = False, pub_routes = True, sub_routes = False):
    run(_start(add_debug_hooks, pub_routes, sub_routes))
