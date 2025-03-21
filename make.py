from sys import argv


def get_src(filename: str) -> list[str]:
    with open(filename, 'r') as f:
        return f.readlines()

def remove_imports(src: list[str]) -> list[str]:
    last_import = 0
    for i in range(len(src)):
        line = src[i]
        if 'import' in line:
            last_import = i
        if 'save_imports' in line:
            last_import -= 1
            break
    return src[last_import+1:]

def get_beacon_src() -> list[str]:
    beacon_src = get_src('micropycelium/Beacon.py')
    return remove_imports(beacon_src)

def get_gossip_src() -> list[str]:
    gossip_src = get_src('micropycelium/Gossip.py')
    return remove_imports(gossip_src)

def get_spanning_tree_src() -> list[str]:
    spanning_tree_src = get_src('micropycelium/SpanningTree.py')
    return remove_imports(spanning_tree_src)

def get_ping_src() -> list[str]:
    ping_src = get_src('micropycelium/Ping.py')
    return remove_imports(ping_src)

def get_debug_src() -> list[str]:
    debug_src = get_src('micropycelium/DebugApp.py')
    return remove_imports(debug_src)

def get_espnowintrfc_src() -> list[str]:
    espnowintrfc_src = get_src('micropycelium/ESPNowInterface.py')
    return remove_imports(espnowintrfc_src)

def main_mpnode(options: dict[str, list[str]]):
    parts = []
    mpnode_src = get_src('mpnode/mpnode.py')
    parts.append(''.join(mpnode_src))

    device = options.get('mpnode')[0]
    device_src = get_src(f'devices/{device}/mpnode.py')
    device_src = remove_imports(device_src)
    parts.append(''.join(device_src))

    print(''.join(parts))

def main(options: dict[str, list[str]]):
    if options.get('mpnode'):
        return main_mpnode(options)

    parts = []

    packager_src = get_src('micropycelium/Packager.py')
    # turn on debug
    if options.get('debug', True):
        for i in range(len(packager_src)):
            if packager_src[i][:5] == 'DEBUG':
                packager_src[i] = packager_src[i].replace('False', 'True')
                break
    parts.append(''.join(packager_src))

    exclude = [e.lower() for e in options.get('exclude', [])]
    if 'beacon' not in exclude:
        parts.append(''.join(get_beacon_src()))
    if 'gossip' not in exclude:
        parts.append(''.join(get_gossip_src()))
    if 'spanningtree' not in exclude:
        parts.append(''.join(get_spanning_tree_src()))
    if 'ping' not in exclude:
        parts.append(''.join(get_ping_src()))
    if 'debug' not in exclude:
        parts.append(''.join(get_debug_src()))
    if 'espnow' not in exclude and 'espnowinterface' not in exclude:
        parts.append(''.join(get_espnowintrfc_src()))

    ainput_src = get_src('micropycelium/ainput.py')
    parts.append(''.join(ainput_src))

    print(''.join(parts))


if __name__ == '__main__':
    options = {}
    for i in range(1, len(argv), 2):
        if len(argv) > i+1:
            options[argv[i]] = argv[i+1].split(',')
    main(options)
