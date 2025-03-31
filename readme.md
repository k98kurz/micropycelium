# Micropycelium

This repo is designed to implement a wireless mesh network and a few services
that run over it using micropython-compatible code. The goals include to
minimizing memory use, and providing an asynchronous control flow. It includes
the following:

- Packet formats to fit into ESP-NOW and RYLR-998 LoRa datagrams
- A packet sequencer to break blobs into smaller packets with reliable tx
mechanism
- A Packager system to automatically send and receive Packages
- Interface plugin for ESP-NOW; in the future, RYLR-998 (LoRa), UDP/IP, BTLE,
and a custom WLAN similar to ESP-NOW for non-ESP devices (e.g. Raspberry Pi,
Linux laptop, etc)
- An Application plugin system to generate and ingest Packages
- A connectionless gossip system for promulgating network information
- A PIE/VOUTE-based spanning tree system for greedy routing
- An mpnode console to monitor, configure, debug, and experiment
- 2 mpnode device-specific implementations: M5stamp and M5StickC-PLUS2
- 1 mpnode generic esp32 implementation

This project is the result of a fairly lengthy process of discovery: first, I
tried using gradient descent to determine 2d/3d/4d spcial coordinates using
latency as an analog for distance (linear relationship over radio waves); then,
when I determined that would not work, I began to create and search for
alternatives, which resulted in an incomplete spec for the Mycelium network
system; then, I got some ESP32 devices and decided to start experimenting, and I
realized that it had to be paired down and more focused to have a chance of
actually working. Since the main goal of the Pycelium/Mycelium concept has been
inexpensive routers automagically creating a routed mesh network, it made sense
to start with some actual hardware running micropython, hence micropycelium as
the home of the first serious attempt at implementation.

## Status/Roadmap

For a functional v0.1 release:

- [x] Specification
- [x] Packet schemas and serialization code
- [x] Packet sequencer system
- [x] Packager system
- [x] ESP-NOW Interface
- [x] Modem sleep mode for power saving: Request Node Status/Node Is Active before tx
- [x] Greedy routing: tree state construction and updating
- [x] Greedy routing: tree distance routing (flags.mode=0)
- [x] Greedy routing: common prefix length routing (flags.mode=1)
- [x] A few utility apps for debugging

Everything can be tracked in the [issues](https://github.com/k98kurz/micropycelium/issues).

Once the v0.1 release is complete, these status items will be moved into a new
changelog file.

## Usage

This is a highly experimental project. To use this, the following steps need to
be completed:

1. Follow the instructions from [notes/build.md](https://github.com/k98kurz/micropycelium/blob/master/notes/build.md)
2. Connect via tty serial to your device to get to a REPL or file management
3. Copy the main.py file from the devices directory to your device
4. Reset device, then hit "Enter" to get to the console prompt

This has not been tested on non-ESP32 devices, though expansion of support to
more hardware platforms is an eventual goal of this project.

For maximum flexibility in development, I also include my
[micropython file editor](https://github.com/k98kurz/micropython-file-editor) in
my test devices.
It can be added after flashing the firmware or built into the firmware as a
module in the same way as micropycelium (much better experience imo).

## Notes

- The system design spec is in
[Packager_spec.md](https://github.com/k98kurz/micropycelium/blob/master/Packager_spec.md).
- The PKI has not been implemented because micropython currently does not
include support for elliptic curve or ed25519.
- Due to the lack of security primitives and incomplete state of several
important planned features, many implementation details have not been evaluated
for security. I expect DoS attacks can be performed without much difficulty.
- This is highly experimental, and the system is not yet tuned for performance.

## Testing

There are currently 101 unit tests that rely on a bunch of mocks: 60 tests for
the core components and 41 for bundled apps (Beacon, Gossip, Ping, SpanningTree,
DebugApp). E2e testing is done with hardware and is a bit more involved.

To run the unit tests, clone the repo and then run the following:

```bash
find tests/ -name "test_*.py" -print -exec python {} \;
```

To do e2e testing with hardware, build and deploy the firmware as described in
the Usage section above, altering the main.py file as you like (e.g. add LED
blinks or something similar to a generic ESP32 node the way I have to the
M5stamp and M5StickC). Then turn on the devices, connect to the serial, and
monitor debug messages, use the command console, or just watch blinking lights.

In manual e2e testing, the Beacon app running through the ESPNOW network
interface adapter was able to properly transmit and receive between devices at
up to ~200 feet with direct line of sight on a windless night. Message routing
has been experimentally tested in a very small network size (3 nodes) with
success; scaling up for more thorough testing is a near-future task.

## Contributing / More Resources

Check out the [Pycelium discord server](https://discord.gg/b2QFEJDX69). If you
experience a problem, please discuss it on the Discord server. All suggestions
for improvement are also welcome, and the best place for that is also Discord.
If you experience a bug and do not use Discord, open an issue or discussion on
Github.

## License

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
