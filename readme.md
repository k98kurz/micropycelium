# Micropycelium

This repo is designed to implement a wireless mesh network and a few services
that run over it using micropython-compatible code. A goal is to minimize memory
use and provide an asynchronous control flow. It will include the following:

- Packet formats to fit into ESP-NOW and RYLR-998 LoRa datagrams
- A packet sequencer to break blobs into smaller packets with reliable tx
mechanism
- A Packager system to automatically send and receive Packages
- Interface plugins for the Packager to enable ESP-NOW and RYLR-998; possibly
UDP/IP, BTLE, and a custom WLAN similar to ESP-NOW for non-ESP devices (e.g.
Raspberry Pi, Linux laptop, etc)
- An Application plugin system to generate and ingest Packages
- A connectionless gossip system for promulgating network information
- A PIE/VOUTE-based spanning tree system for greedy routing
- A service announcement system for nodes running the same Application(s) to
discover each other

This project is the result of a fairly lengthy process of discovery: first, I
tried using gradient descent to determine 2d/3d/4d spcial coordinates using
latency as an analog for distance (linear relationship over radio waves); then,
when I determined that would not work, I began to create and search for
alternatives, which resulted in an incomplete spec for the Mycelium network
system; then, I got some ESP32 devices and decided to start experimenting, and I
realized that it had to be paired down and more focused to have a chance of
actually working. Since the main goal of the Pycelium/Mycelium concept has been
inexpensive routers automagically creating a mesh network, it made sense to
start with some actual hardware running micropython, hence micropycelium as the
home of the first serious attempt at implementation.

## Status/Roadmap

For a functional v0.1 release:

- [x] Specification
- [x] Packet schemas and serialization code
- [x] Packet sequencer system
- [x] Packager system
- [x] ESP-NOW Interface
- [x] Modem sleep mode for power saving: Request Node Status/Node Is Active before tx
- [ ] Eliptic curve cryptography
- [ ] Greedy routing: tree state construction and updating
- [ ] Greedy routing: tree distance routing (flags.mode=0)
- [ ] Greedy routing: common prefix length routing (flags.mode=1)

Everything else can be tracked in the [issues](https://github.com/k98kurz/micropycelium/issues).
There are 6 milestones from v0.1 to v0.6, and issues planned for resolution have
been categorized into those milestones.

Once the v0.1 release is complete, these status items will be moved into a new
changelog file.


# License

ISC License

Copyleft (c) 2025 Jonathan Voss (k98kurz)

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
