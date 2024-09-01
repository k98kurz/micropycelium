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

- [x] Specification
- [x] Packet schemas and serialization code
- [x] Packet sequencer system
- [x] Packager system
- [x] ESP-NOW Interface
- [x] Modem sleep mode for power saving: Request Node Status/Node Is Active before tx
- [ ] Eliptic curve cryptography
- [ ] VOUTE-based routing: tree state construction and updating
- [ ] VOUTE-based routing: tree distance routing (flags.mode=0)
- [ ] VOUTE-based routing: common prefix length routing (flags.mode=1)
- [ ] Cache management
- [ ] Refactor: Store class to save RAM with Sequence handling
- [ ] Error propagation
- [ ] Peer throttling/congestion control
- [ ] Gossip Application
- [ ] Cryptography encapsulation Application(s)
- [ ] RYLR-998 Interface
- [ ] UDP/IP
- [ ] Bluetooth Interface
- [ ] VOUTE-based routing: leased addresses (fill bits after first null nibble)
- [ ] VOUTE-based routing: trace route discovery
- [ ] VOUTE-based routing: beacon routing or proxying (leased addresses)
- [ ] Custom WLAN Interface (reverse engineer ESP-NOW or equivalent)
- [ ] Local and remote node management Application with semi-sandboxed REPL


# License

ISC License

Copyleft (c) 2024 Jonathan Voss (k98kurz)

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyleft notice and this permission notice appear in
all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
