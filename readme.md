# Micropycelium

This repo is designed to implement a wireless mesh network and a few services
that run over it using micropython-compatible code. A goal is to minimize memory
use and provide an asynchronous control flow. It will include the following:

- Packet formats to fit into ESP-NOW and RYLR-998 LoRa datagrams
- A packet sequencer to break blobs into smaller packets with reliable tx
mechanism
- A Packager system to automatically send and receive Packages
- Interface plugins for the Packager to enable ESP-NOW, RYLR-998, UDP/IP, BTLE,
and custom WLAN similar to ESP-NOW for non-ESP devices (e.g. Raspberry Pi)
- An Application plugin system to generate and ingest Packages
- A connectionless gossip system for promulgating network information
- A VOUTE-based spanning tree system for greedy routing
- A service announcement system for nodes running the same Application(s) to
discover each other

## Status/Roadmap

- [-] Specification (mostly done)
- [x] Packet schemas and serialization code
- [x] Packet sequencer system
- [ ] Packager system
- [ ] ESP-NOW plugin
- [ ] VOUTE-based routing: tree state construction and updating
- [ ] VOUTE-based routing: tree distance routing (flags.mode=0)
- [ ] VOUTE-based routing: common prefix length routing (flags.mode=1)
- [ ] RYLR-998 plugin
- [ ] UDP/IP
- [ ] Bluetooth plugin
- [ ] VOUTE-based routing: leased addresses (fill bits after first null nibble)
- [ ] VOUTE-based routing: trace route discovery
- [ ] VOUTE-based routing: beacon routing or proxying (leased addresses)
- [ ] Custom WLAN plugin (reverse engineer ESP-NOW or equivalent)
