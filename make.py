from sys import argv


def get_src(filename: str) -> list[str]:
    with open(filename, 'r') as f:
        return f.readlines()

def get_beacon_src() -> list[str]:
    beacon_src = get_src('micropycelium/Beacon.py')
    last_import = 0
    for i in range(len(beacon_src)):
        line = beacon_src[i]
        if 'import' in line:
            last_import = i
    return beacon_src[last_import+1:]

def get_gossip_src() -> list[str]:
    gossip_src = get_src('micropycelium/Gossip.py')
    last_import = 0
    for i in range(len(gossip_src)):
        line = gossip_src[i]
        if 'import' in line:
            last_import = i
    return gossip_src[last_import+1:]

def get_spanning_tree_src() -> list[str]:
    spanning_tree_src = get_src('micropycelium/SpanningTree.py')
    last_import = 0
    for i in range(len(spanning_tree_src)):
        line = spanning_tree_src[i]
        if 'import' in line:
            last_import = i
    return spanning_tree_src[last_import+1:]

def get_ping_src() -> list[str]:
    ping_src = get_src('micropycelium/Ping.py')
    last_import = 0
    for i in range(len(ping_src)):
        line = ping_src[i]
        if 'import' in line:
            last_import = i
    return ping_src[last_import+1:]

def get_espnowintrfc_src() -> list[str]:
    espnowintrfc_src = get_src('micropycelium/ESPNowInterface.py')
    last_import = 0
    for i in range(len(espnowintrfc_src)):
        line = espnowintrfc_src[i]
        if 'import' in line:
            last_import = i
    return espnowintrfc_src[last_import+1:]


def main(options: dict[str, list[str]]):
    parts = []

    packager_src = get_src('micropycelium/Packager.py')
    # turn on debug
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
    if 'espnow' not in exclude and 'espnowinterface' not in exclude:
        parts.append(''.join(get_espnowintrfc_src()))

    print(''.join(parts))


if __name__ == '__main__':
    options = {}
    for i in range(1, len(argv), 2):
        if len(argv) > i+1:
            options[argv[i]] = argv[i+1].split(',')
    main(options)
