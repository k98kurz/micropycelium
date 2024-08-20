# Packager Overview

The packager will take blobs of arbitrary but bounded size and package them into
packets that fit within the transmission medium specifications. For ESP-NOW,
the data size is 250 bytes. For RYLR-998 LoRa module, the data size is 240 bytes.
Packet schemas with these two sizes will be included to support at least these
two modules. If necessary, additional schemas will be made to support modules
with even smaller data size.

## Encapsulation Model

The primary encapsulation model is application message blobs within Packages
within Packet(s). Additionally, applications will be able to encapsulate each
other's Packages, e.g. to add a layer of encryption or use gossip for pub/sub.

|-- Packet/sequence of packets --------|
|  |-- Package ---------------------|  |
|  |      app_id: 16                |  |
|  |      half_sha256: 16           |  |
|  |  |-- blob: variable --------|  |  |
|  |  |   Application Message    |  |  |
|  |  |--------------------------|  |  |
|  |------------------------------- |  |
|--------------------------------------|


# Packager Operations

## Broadcast

Takes an app ID and a blob, makes a Package, and then transmits it. Unless an
interface is specified, the Package will be transmitted on all available network
interfaces. If the Package is too large to fit in a single packet for a given
interface, it will be broken into a sequence of packets. Unless an interface
was specified, it will use a schema that works for all interfaces, which reduces
performance of ESP-NOW for the benefit of reduced caching requirements and
RYLR-998 compatibility.

## Send

Takes an app ID, blob, node ID, and optionally a schema ID. If the node is in
the peer list, the Send method puts the blob into a Package and then transmits
it to the peer using the interface with the highest bit rate. If the node is not
a peer but the node's address is known, the Send method puts the blob into a
Package and then attempts to route it. Transmission will attempt to use the
specified schema if its ID was supplied, otherwise it will use a schema that can
accommodate the Package size and is supported by all interfaces (to prevent
resequencing in case of transmission failure via one interface).

## Receive

Receives a Packet and the interface and MAC it came from, and determines what to
do with it. If the Packet is routable, it will attempt to forward the packet.

When a node receives a Package in a single packet, it will check the Application
ID and drop the Package if the Application has not registered to accept Packages.
If the Application was registered, the Package will be delivered to the
Application.

When a node receives a sequence, it will request retransmission of the first
packet in the sequence (`packet_id=0`) if it did not receive it, but it will not
request retransmission of other missing packets until it receives the first
packet (which contains the Application ID) and verifies that the Package will be
deliverable. If the Package is deliverable, the node will attempt to collect the
whole Package sequence and deliver the Package to the appropriate application.

This will be called by an asynchronous task that monitors network interfaces.

## Deliver

Takes a Package and attempts to deliver it to the Application. Invoked by the
Receive operation, but can also be invoked through the Packager API directly.
Directly invoking the Deliver operation may be useful for bootstrapping an
Application or for inter-Application communication.

## Add Application

Registers an Application to receive Packages.

## Remove Application

Deregestiers an Application so it will not receive Packages.

## Process

Asynchronous method that creates a task for each interface to let them process
their pending actions, then process pending Packager actions.

## Work

Asynchronous method that loops indefinitely, running the Process operation and
then sleeping for a short timeout.


# Application

An Application consists of a callback for accepting Package delivery and a set
of callbacks to expose functions to other Applications. The Application class
must be initialized with a name, a description, a verison number, a callback for
receiving Packages, and a dict with any functions that should be exposed to
other Applications. If callbacks are async, the results of invoking them will be
a coroutine.

## Receive

This method takes in a blob of bytes representing an application message and
invokes the callback, passing self and blob.

## Available

Returns a list[str] of the names of available callbacks. If a str name is
passed, it instead returns True if there is a callback with that name and False
otherwise.

## Invoke

Takes a str name, args, and kwargs, and attempts to invoke the callback with the
name, passing self, args, and kwargs. If the callback is async, a coroutine will
be returned.


# Package Format

Each package will have the following format:

- 16 `app_id`
- 16 `half_sha256`
- 0+ `blob`

The `app_id` is a 16 byte unique identifier for the application that created the
package. The `half_sha256` is the first half of the sha256 digest of the blob.
The maximum size for a package will be 12.9375 MiB or 12.3125 MiB, corresponding
to `blob` sizes of 13,565,952 and 12,910,592 bytes, depending on whether it is
packaged for ESP-NOW or RYLR-998 LoRa (determined by passing an array of
acceptable schema IDs to the packager API).


# Packet Fields

## version

The `version` field will be a u8 protocol version number.

## reserved

The `reserved` field will be 8 bits reserved for future protocol development.

## schema

The `schema` field will be a u8 packet schema identifier. The schema determines
which fields are used in the packet.

## flags

The `flags` field will be 8 bits (bits 0-7):
- Bit 0: error - set in response as a generic error notification
- Bit 1: throttle - set when a responding node is experiencing congestion
- Bits 2-3: encoded, mutually exclusive flags
- Bits 4: reserved0
- Bits 5: reserved1
- Bits 6: reserved2
- Bit 7: mode - set to switch the mode of a schema-specific feature

Bits 2 and 3 are used to encode mutually-exclusive flags, which the `Flags`
class exposes as attributes:

- 0b01 - ask: set when a transmitting node wants an ack for the packet
- 0b10 - ack: set when the transmitting node is responding to an ask
- 0b11 - rtx: set when requesting a packet retransmission

The mutually exclusive flag 0b00 is a no-op value. Bits 4-6 can be added to the
encoded flags field to increase the number of mutually exclusive flags if
necessary for future developments.

## packet_id

The `packet_id` field will be a u8 or u16 ID for the packet, depending on schema.
This value is used for parsing acks and to sequence parts within a package. In
schemas without `seq_id` and `seq_size`, the `packet_id` will increment mod 256
on each packet sent or received for every non-sequenced schema. In schemas with
sequencing, the `packet_id` is the packet index within the sequence.

## seq_id

The `seq_id` field will be a u8 sequence id. This is used to sequence a package
into packets, allowing for retransmission requests of any missed/dropped packets
within a sequence. This value is incremented mod 256 for each sequence sent or
received.

## seq_size

The `seq_size` field will be a u8 or u16 sequence size, depending on the schema.
This is used to inform a receiver the size of the sequence of packets needed to
reconstruct the package from its parts. This value will always be exactly 1 less
than the actual value; in other words, it will show the maximum `packet_id` for
the sequence.

## ttl

The `ttl` field will be a u8 and will contain the hop limit for the packet.
Each relay will decrement this counter before retransmission; if it reaches 0,
the relay will instead set the error flag and send the packet back toward the
originating node. If a relay receives a packet with the error flag active, it
will increment the ttl field before retransmitting back toward the originating
node; if it hits 255, the packet will be dropped.

packet schemas that do not use the `ttl` field will be ineligible for packet
switching beyond a single hop: if the relay cannot immediately deliver the
packet to the intended recipient, it will respond by returning the packet to
the originator with the error flag set.

## checksum

The `checksum` field will be 4 bytes and will contain the CRC32 checksum for the
body.

## tree_state

The `tree_state` field will be 1 byte and will contain the first byte of a CRC32
checksum for the state of the spanning tree configuration.

## to_addr

The `to_addr` field will be 16 bytes representing the spanning tree address of
the intended recipient node. Relays will retransmit by decrementing the TTL and
forwarding to the next nearest node using a greedy algorithm (MAC address of the
peer for ESP-NOW and network ID + address for LoRa).

## from_addr

The `from_addr` field will be 16 bytes representing the spanning tree address of
the packet origination node. Transmission errors will propagate back to this
node.


# Packet Format (Schemas)

All packets will start with the following fields:

- 1 `version`
- 1 `reserved`
- 1 `schema`
- 1 `flags`

Packets are formatted for either the ESP-NOW or RYLR-998 modulators, which
support maximum payload sizes of 250 bytes and 240 bytes, respectively.

Schemas 0-19 are reserved for ESP-NOW compatibility. Schemas 20-29 are reserved
for RYLR-998 compatibility.

## (version, schema) == (0, 0)

ESP-NOW; 245 B max Package size.

- 1 `packet_id`
- 245 `body`

## (version, schema) == (0, 1)

ESP-NOW; 241 B max Package size.

- 1 `packet_id`
- 4 `checksum`
- 241 `body`

## (version, schema) == (0, 2)

ESP-NOW; 256 max sequence size; 60.75 KiB max Package size.

- 1 `packet_id`
- 1 `seq_id`
- 1 `seq_size`
- 243 `body`

## (version, schema) == (0, 3)

ESP-NOW; 256 max sequence size; 59.75 KiB max Package size.

- 1 `packet_id`
- 1 `seq_id`
- 1 `seq_size`
- 4 `checksum`
- 239 `body`

## (version, schema) == (0, 4)

ESP-NOW; 65536 max sequence size; 14.8125 MiB max Package size.

- 2 `packet_id`
- 1 `seq_id`
- 2 `seq_size`
- 4 `checksum`
- 237 `body`

## (verison, schema) == (0, 5)

ESP-NOW; 211 B max Package size.

- 1 `packet_id`
- 1 `ttl`
- 1 `tree_state`
- 16 `to_addr`
- 16 `from_addr`
- 211 `body`

## (verison, schema) == (0, 6)

ESP-NOW; 207 B max Package size.

- 1 `packet_id`
- 1 `ttl`
- 4 `checksum`
- 1 `tree_state`
- 16 `to_addr`
- 16 `from_addr`
- 207 `body`

## (verison, schema) == (0, 7)

ESP-NOW; 256 max sequence size; 52.75 KiB max Package size.

- 1 `packet_id`
- 1 `seq_id`
- 1 `seq_size`
- 1 `ttl`
- 1 `tree_state`
- 16 `to_addr`
- 16 `from_addr`
- 209 `body`

## (verison, schema) == (0, 8)

ESP-NOW; 256 max sequence size; 51.25 KiB max Package size.

- 1 `packet_id`
- 1 `seq_id`
- 1 `seq_size`
- 1 `ttl`
- 4 `checksum`
- 1 `tree_state`
- 16 `to_addr`
- 16 `from_addr`
- 205 `body`

## (verison, schema) == (0, 9)

ESP-NOW; 65536 max sequence size; 12.9375 MiB max Package size.

- 2 `packet_id`
- 1 `seq_id`
- 2 `seq_size`
- 1 `ttl`
- 1 `tree_state`
- 16 `to_addr`
- 16 `from_addr`
- 207 `body`

## (verison, schema) == (0, 10)

ESP-NOW; 65536 max sequence size; 12.6875 MiB max Package size.

- 2 `packet_id`
- 1 `seq_id`
- 2 `seq_size`
- 1 `ttl`
- 4 `checksum`
- 1 `tree_state`
- 16 `to_addr`
- 16 `from_addr`
- 203 `body`

## (version, schema) == (0, 20)

RYLR-998; 235 B max Package size.

- 1 `packet_id`
- 235 `body`

## (version, schema) == (0, 21)

RYLR-998; 231 B max Package size.

- 1 `packet_id`
- 4 `checksum`
- 231 `body`

## (version, schema) == (0, 22)

RYLR-998; 256 max sequence size; 53.25 KiB max Package size.

- 1 `packet_id`
- 1 `seq_id`
- 1 `seq_size`
- 233 `body`

## (version, schema) == (0, 23)

RYLR-998; 256 max sequence size; 57.25 KiB max Package size.

- 1 `packet_id`
- 1 `seq_id`
- 1 `seq_size`
- 4 `checksum`
- 229 `body`

## (version, schema) == (0, 24)

RYLR-998; 65536 max sequence size; 14.1875 MiB max Package size.

- 2 `packet_id`
- 1 `seq_id`
- 2 `seq_size`
- 4 `checksum`
- 227 `body`

## (verison, schema) == (0, 25)

RYLR-998; 201 B max Package size.

- 1 `packet_id`
- 1 `ttl`
- 1 `tree_state`
- 16 `to_addr`
- 16 `from_addr`
- 201 `body`

## (verison, schema) == (0, 26)

RYLR-998; 197 B max Package size.

- 1 `packet_id`
- 1 `ttl`
- 4 `checksum`
- 1 `tree_state`
- 16 `to_addr`
- 16 `from_addr`
- 197 `body`

## (verison, schema) == (0, 27)

RYLR-998; 256 max sequence size; 49.75 KiB max Package size.

- 1 `packet_id`
- 1 `seq_id`
- 1 `seq_size`
- 1 `ttl`
- 1 `tree_state`
- 16 `to_addr`
- 16 `from_addr`
- 199 `body`

## (verison, schema) == (0, 28)

RYLR-998; 256 max sequence size; 48.75 KiB max Package size.

- 1 `packet_id`
- 1 `seq_id`
- 1 `seq_size`
- 1 `ttl`
- 4 `checksum`
- 1 `tree_state`
- 16 `to_addr`
- 16 `from_addr`
- 195 `body`

## (verison, schema) == (0, 29)

RYLR-998; 65536 max sequence size; 12.3125 MiB max Package size.

- 2 `packet_id`
- 1 `seq_id`
- 2 `seq_size`
- 1 `ttl`
- 1 `tree_state`
- 16 `to_addr`
- 16 `from_addr`
- 197 `body`

## (verison, schema) == (0, 30)

RYLR-998; 65536 max sequence size; 12.0625 MiB max Package size.

- 2 `packet_id`
- 1 `seq_id`
- 2 `seq_size`
- 1 `ttl`
- 4 `checksum`
- 1 `tree_state`
- 16 `to_addr`
- 16 `from_addr`
- 193 `body`


# Interface

An Interface provides an API to an underlying transmission module that handles
frame encapsulation and datagrams. It includes the following methods:

- configure: takes a dict of configuration values and configures the interface
- receive: returns a received datagram if there is one or None
- send: takes a datagram (with data and address) and transmits it
- broadcast: takes a datagram (without address) and broadcasts it
- process: processes the queued datagrams to be sent/broadcast and queues
datagrams in the inbox; async method that calls callbacks passed to `__init__`

The send and broadcast methods queue the data for asynchronous processing, and
the receive method reads from a queue that is populated by an async task.

An Interface also has the following attributes:

- supported_schemas: list of schema IDs supported by the interface

The `Interface` class provides a logical framework for this. Initializing it
requires passing `name: str`, `configure: function`,
`supported_schemas: list[int]`, and several synchronous and/or async callbacks.
Must provide one of each pair: (`send_func`, `send_func_async`); (`receive_func`,
`receive_func_async`); (`broadcast_func`, `broadcast_func_async`). When the
async `process` method is called, it first tries to send a datagram queued for
sending using one of the `send_` callbacks; it then tries to broadcast a
datagram queued for broadcast using one of the `broadcast_` callbacks; it then
tries to queue a datagram from calling one of the `receive_` callbacks.


# Packet Protocol

## Send

Takes a Packet and a retry counter (default=1).

Most applications will want to send data to specific node. This is supported
for all schemas. Packets can set `flags.ask=1` to ensure packet delivery.
However, for multi-part packages, packets in the sequence will have
`flags.ask=0` and rely upon the receiving node to request retransmission
for any dropped packets. Packets in this category will always have
`flags.rtx=0`.

For any packet sent with `flags.ask=1`, if a corresponding ack was not received
after a short timeout, retransmission will occur and a transmission attempt
counter will decrement.

All sequences should be cached when sent to enable retransmissions. All
sequences sent should include `flags.ask=1` on a sample of packets. After all
requested acks have been received, the sequence can be

## Broadcast

For applications that require broadcast, schemas that do not include the `ttl`,
`to_addr`, and `from_addr` fields (i.e. non-routed packets) can be broadcast on
configured interfaces. Broadcast packets may set `flags.ask` to 1;
however, only packets that do not use the `seq_size` and `seq_id` fields (i.e.
Packages that can be contained in the body of a single packet) can be broadcast
with `flags.ask = 1` to avoid congestion. Additionally, only schemas
with a 1-byte `packet_id` field can be broadcast.

## Ack

When a receiving node receives and processes a packet with `flags.ask=1`,
it will queue up a response packet using the same schema that has `flags.ack=1`,
an empty `body`, and the same `packet_id` as the received packet. If the
received packet was part of a sequence, the `seq_size` and `seq_id` fields will
be copied from the received packet. If the packet was routed, the `to_addr` will
be set to the `from_addr` of the original packet; the `from_addr` will be set to
the `to_addr` of the original packet; and the `tree_state` field will be copied.

## Request Retransmission

When a receiving node receives an incomplete sequence, after a delay, it will
reques retransmission of missing packets in the sequence by using the simplest
appropriate schema with the `seq_id` and `seq_size` of the sequence and an empty
`body` field. It will send one packet with `flags.rtx=1` for each
missing `packet_id`. Each retransmitted packet received will be added to the
sequence in the Packager.

After another delay, if no retransmissions were received, the node will count it
as a failure and try again; if some retransmissions were received, the node will
request retransmissions of remaining missing packets, but it will not count as a
failure.

After two failures, the node will drop the package and remove the sequence from
its memory/storage.

## Retransmit

A retransmission is a Send of the original packet. For this feature, sequences
will need to be cached in memory/storage for some time after the original
for receipt of the packets at the destination and receipt of retransmission
sequence transmission. The cache expiration should be twice the expected time
requests by the originating node. The cache should also support item priority
so that lower priority items can be preferentially removed from the cache when
it is full and new space is needed.

# Spanning Tree Embedding (Greedy Routing)

Routing will be accomplished using a simplified adaptation of Practical
Isometric Embedding (PIE) protocol and Virtual Overlays Using Tree Embeddings
(VOUTE). It will embed a spanning tree into the graph of nodes; assign addresses
to encode the spanning tree structure; and provide 2 routing metrics for
forwarding packets. The routing metric to use will be determined by setting
`flags.mode`: 0 for tree distance and 1 for common prefix length distance.

The spanning tree system will be maintained by an application, and its Package
format will start with a 1-byte `type` field, which will be 0x00 for a root
election claim, 0x0f for address assignment notification, 0xf0 for address
assignment request, and 0xff for address assignment response.

There are three separate aspects to consider: spanning tree creation/maintenance,
coordinates, and routing.

## Spanning Tree Creation and Maintenance

The first step in spanning tree creation is root election: a score is calculated
by XORing the sha256 of the node's public key with the sha256 of the protocol
name; if the result is lower than the score of the current root, the node is
elected. At the start of the protocol, a node broadcasts its own claim as root,
including the public key, sha256 of the protocol name, and a Unix epoch
timestamp, and any peer that has a current root with a lower score will respond
with it.

The second step is for peers of the root to request an address from the root.
The root will then assign an address to each peer, and those peers will then
drop any old tree data, mark their current tree data as old, allocate new tree
data, and update their tree state to the first byte of the CRC32 of the root
public key, the sha256 of the protocol name, and the Unix epoch timestamp. This
then generalizes for peers of peers of the root, etc.

Address assignments take the form of a chain of simple certificates stemming
from the root: the root signs an address assignment for a peer consisting of
the tree state, that peer's public key, and the assigned address. That peer can
then assign addresses to its children in the tree by signing address assignments
with the same format and bundling with it the cert from the root. Every peer's
address assignment then consists of its signed certificate from its parent and
the chain of signed address assignment certificates leading back to the root.

The election of new roots will cause tree recalculation. To ensure that the tree
is maintained, the root will periodically broadcast a new election claim with a
new timestamp, which then creates a new tree state. If a root fails to broadcast
after three consecutive periods, its term as root ends, and a new root is
elected.

New elections after a term expiration are done by each node calculating the
difference between its score and the previous root's score and waiting an
amount of time proportional to the log of that difference before broadcasting
its root election claim. This delay should give tree recalculations originating
from election of nodes with lower scores time to propagate across the network
and thus avoid unnecessary traffic and the creation of phantom tree states.

If a node drops its parent in the tree from the peer list, it will broadcast its
own root election claim, restarting the process of acquiring an address from the
peer that is closest to the root from the peers that respond to the broadcast.

## Coordinates

Addresses will encode up to 32 coordinates, each representing the index of a
child at the parent. This will allow for a network of between 16 tree levels at
up to 7+128 children per parent and 32 tree levels at up to 7 children per
parent. This allows for tree membership in the range between 1.1x10^27 and
1.2x10^34 nodes.

A zero value represents a lack of that coordinate. The root will have no
coordinates, i.e. an address of all zeros. Each child will take its parent's
coordinates as a prefix for its own; e.g. child 3 of the node with coordinates
(12, 1) will have coordinates (12, 1, 3).

Coordinates are encoded as follows: if the coordinate is <8, it is encoded in a
nibble with the high bit set to 0; if the coordinate is >7, it is encoded by
subtracting 8, converted to an octet, and setting the high bit to 1. Coordinates
can thus have a value between 1 and 135.

Coordinates are decoded as follows: split the address into nibbles; for each
nibble, if the high bit is not set, then the next 3 bits (the rest of the nibble)
encode the coordinate; if the high bit is set, then the next 7 bits (the rest of
the nibble and then the next) encode the coordinate, and we add the integer 8 to
that value.

Examples:

- (3, 1) => 0b0011 0b0001
- (8, 3) => 0b1000000 0b0011
- (4, 12) => 0b0100 0b10000100

The only exception is that the final nibble, if it is not part of the preceding
coordinate, can have values with the high bit set, i.e. integer values 1-15.

## Routing

Routing is done by calculating the selected distance metric for each peer and
forwarding to the peer closest (i.e. with the shortest distance) to the
destination. The distance metrics are defined as follows. For these definitions,
cpl(x1, x2) is the "common prefix length" and means the number of consecutive
coordinates starting at the beginning that are shared between addresses x1 and
x2; i.e. the length of the beginning shared address bytes. Also, |x1| means the
number of coordinates in address x1, and L = 17.

### Tree Distance

Tree distance, or dTree, is defined as follows:

dTree(x1, x2) = |x1| + |x2| - 2 * cpl(x1, x2)

Greedy routing with this metric tends to favor shorter paths but may congest
nodes closer to the root.

### CPL Distance

CPL Distance, or dCPL, is defined as follows:

For x1 != x2:

dCPL(x1, x2) = L - cpl(x1, x2) - 1 / (|x1| + |x2| + 1)

For x1 == x2:

dCPL(x1, x2) = 0

Greedy routing with this metric tends to favor routing further away from the
nodes closer to the root, but sometimes takes longer paths.

# Peer Discovery and Management

The Packager system will include peer discovery and management logic. This will
maintain a list of peers (i.e. directly connected nodes reachable without packet
routing) and nodes (reachable with or without routing) and the applications they
support, and it will expose this data to other applications.

## Peer list

Each node will maintain a peer list containing the following information:

- id: the public key of the peer
- interfaces: a list of tuples each containing (mac, interface_id)
- timeout: an int used for automatic peer disconnects
- throttle: an int used to throttle bandwidth for a peer
- last_tx: an int used to track transmissions for throttling

When a node adds a peer or receives a Beacon from that peer, it sets the timeout
value to 4. After a node sends its own Beacon, it decrements every peer timeout
counter, then drops all peers with a timeout counter of 0.

When a node receives a packet from a peer that includes `flags.throttle=1`, it
will increment the throttle count for that peer; when it receives a packet from
a peer that includes `flags.throttle=0`, it will decrement the throttle count
for that peer unless it is already 0. When a node tries to send a packet to a
peer with a throttle value greater than 0, it first checks the last_tx value; if
it is more than `throttle * 1000` ms in the past, transmit the packet, otherwise
schedule the transmission for `last_tx + throttle * 1000`.

## Node list

Each node will maintain a node list containing the following information:

- id: the public key of the node
- apps: list of IDs for apps the node supports
- ts: int timestamp of last update

See the Beacon and Gossip (Application Discovery) sections for details on how
this is populated and updated. Nodes will be dropped from the list after 30
minutes of the last update.

## Beacon

At initialization and periodically thereafter, each node will broadcast a beacon
Package introducing the node. The body of this beacon will be the byte 0x00, the
node's ed25519 public key and up to 10 app IDs it supports, and it will use the
simplest possible schema and all `flags` set to 0. This message format will be
compatible with both ESP-NOW and RYLR-998 using Packet Schemas 0 and 20,
respectively. If a node supports more than 10 apps, it will broadcast several
beacons.

## Beacon Response

Upon receiving a beacon from an unknown peer, a node will add this peer to its
peer list and then respond by sending a beacon response to that peer. The beacon
response Package body will contain the byte 0x01, the node's public key, and up
to 10 app IDs it supports. If the responding node supports mode than 10 apps, it
will send additional beacon responses.

When a node receives a beacon response Package, it will add that peer to its
peer list.

## Disconnect

Before disabling its radios, a node should send a disconnect Package with a body
that is the byte 0xff and the node's public key.

## Automatic peer disconnect

When a node receives a Beacon from a peer, it sets the peer timeout value to 4.
After a node sends out its periodic Beacon, it will decrement the timeout for
each peer in its peer list; if the timeout for a peer reaches 0, the peer is
removed from the peer list.


# Gossip (Application Discovery)

To enable additional functionality, primarily to allow nodes that run a shared
application to find each other across the network, a gossip application will be
included. This application will use broadcasts and sends to transmit Packages to
to peers and thus disseminate them across the network.

There are three types of gossip Packages: a Message, a Notification, and a
Request. Each Package body will start with a 1-byte `type` field which will be
0xf0 for a Message, 0x0f for a Notification, and 0x00 for a Request.

A Message Package contains the following:

- 1 type: 0xf0
- 16 topic_id: half_sha256 of the topic data
- 0+ data: the data for the topic subscribers to injest

A Notification Package contains the following:

- 1 type: 0x0f
- 16 message_id: the half_sha256 of the serialized Message

A Request Package contains the following:

- 1 type: 0x00
- 16 message_id: the half_sha256 of the serialized Message received in a
Notification

## Publish

Makes a Message out of a topic_id and data, then delivers the Message locally.

## Deliver

When a Message is delivered locally, the node broadcasts either the Message if
it can fit in a single packet or a Notification for the Message. If it
broadcasts a Notification, then it awaits Requests from its peers and responds
by sending the Message. The Message is also put into a cache to mark it as seen
so that future deliveries of the same Message are rejected and future
Notifications for the Message ID are ignored.

## Notify

When a Notification is received, if the Message ID is not in the cache, the node
will send a Request to the peer that sent the Notification.

## Respond

When a Request is received, if a Message with the requested ID is in the cache,
the node will send the Message to the peer that sent the Request.

## Subscribe

Associates an application with a topic ID. All new Messages delivered will be
forwarded to the subscribed application.


# References and Notes

## ESP-NOW

```python
import network
import espnow

# A WLAN interface must be active to send()/recv()
network.WLAN(network.STA_IF).active(True) # Or network.AP_IF
e = espnow.ESPNow()
e.active(True)

# or for async
import aioespnow
```

- https://docs.micropython.org/en/latest/library/espnow.html
- Cycle through channels broadcasting beacons until a response is received
- `ESPNow.config(rxbuf=1052)` optionally to double the receive buffer
- `ESPNow.config(channel=int)` optionally to set the WiFi channel
- `ESPNow.any() -> bool` to check if data is ready to be received
- `ESPNow.recv() -> list[bytes, bytes]` to receieve `[from_mac, data]`
- `ESPNow.send(mac: bytes, msg: bytes, sync=False)` to send a message
- https://docs.espressif.com/projects/esp-idf/en/latest/esp32c3/api-reference/network/esp_now.html
- https://github.com/espressif/esp-now
- https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/wifi.html

## RYLR-998

- https://reyax.com/products/rylr998/
- https://reyax.com//upload/products_download/download_file/RYLR998_EN.pdf
- https://reyax.com//upload/products_download/download_file/LoRa_AT_Command_RYLR998_RYLR498_EN.pdf
- https://docs.micropython.org/en/latest/library/machine.UART.html

## WLAN

- https://docs.micropython.org/en/latest/library/network.WLAN.html
- https://hackaday.io/project/161896-linux-espnow
- https://docs.espressif.com/projects/esp-idf/en/latest/esp32c3/api-reference/network/esp_now.html
- https://github.com/espressif/esp-now

## Bluetooth LE

- https://docs.micropython.org/en/latest/library/bluetooth.html
- https://docs.micropython.org/en/latest/library/bluetooth.html#l2cap-connection-oriented-channels

## collections.deque

- deque (doule-ended queue) has two thread safe operations: append and popleft
