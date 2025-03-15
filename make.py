with open('micropycelium/Packager.py', 'r') as f:
    packager_src = f.readlines()

with open('micropycelium/Beacon.py', 'r') as f:
    beacon_src = f.readlines()

with open('micropycelium/Gossip.py', 'r') as f:
    gossip_src = f.readlines()

with open('micropycelium/SpanningTree.py', 'r') as f:
    spanning_tree_src = f.readlines()

with open('micropycelium/ESPNowInterface.py', 'r') as f:
    espnowintrfc_src = f.readlines()


# discard all import lines from Beacon, Gossip, SpanningTree, and ESPNowInterface
last_import = 0
for i in range(len(beacon_src)):
    line = beacon_src[i]
    if 'import' in line:
        last_import = i
beacon_src = beacon_src[last_import+1:]

last_import = 0
for i in range(len(gossip_src)):
    line = gossip_src[i]
    if 'import' in line:
        last_import = i
gossip_src = gossip_src[last_import+1:]

last_import = 0
for i in range(len(spanning_tree_src)):
    line = spanning_tree_src[i]
    if 'import' in line:
        last_import = i
spanning_tree_src = spanning_tree_src[last_import+1:]

last_import = 0
for i in range(len(espnowintrfc_src)):
    line = espnowintrfc_src[i]
    if 'import' in line:
        last_import = i
espnowintrfc_src = espnowintrfc_src[last_import+1:]

# turn on debug
for i in range(len(packager_src)):
    if packager_src[i][:5] == 'DEBUG':
        packager_src[i] = packager_src[i].replace('False', 'True')
        break

print(''.join([*packager_src, *beacon_src, *gossip_src, *spanning_tree_src, *espnowintrfc_src]))