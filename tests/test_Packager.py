import asyncio
from binascii import crc32
from collections import deque
from context import Packager
from hashlib import sha256
from time import time, sleep
import unittest


class TestFlags(unittest.TestCase):
    def test_byte_values(self):
        flags = Packager.Flags(0)
        assert not flags.error
        assert not flags.throttle
        assert not flags.ask
        assert not flags.ack
        assert not flags.rtx
        assert not flags.rns
        assert not flags.nia
        assert not flags.encoded6
        assert not flags.reserved1
        assert not flags.reserved2
        assert not flags.mode

        flags.ask = True
        assert flags.ask
        assert not flags.ack
        assert not flags.rtx
        assert not flags.rns
        assert not flags.nia
        assert not flags.encoded6
        assert int(flags) == 0b00001000

        flags.ack = True
        assert flags.ack
        assert not flags.ask
        assert not flags.rtx
        assert not flags.rns
        assert not flags.nia
        assert not flags.encoded6
        assert int(flags) == 0b00010000

        flags.rtx = True
        assert flags.rtx
        assert not flags.ask
        assert not flags.ack
        assert not flags.rns
        assert not flags.nia
        assert not flags.encoded6
        assert int(flags) == 0b00011000

        flags.rns = True
        assert flags.rns
        assert not flags.ask
        assert not flags.ack
        assert not flags.rtx
        assert not flags.nia
        assert not flags.encoded6
        assert int(flags) == 0b00100000

        flags.nia = True
        assert flags.nia
        assert not flags.ask
        assert not flags.ack
        assert not flags.rtx
        assert not flags.rns
        assert not flags.encoded6
        assert int(flags) == 0b00101000

        flags.encoded6 = True
        assert flags.encoded6
        assert not flags.ask
        assert not flags.ack
        assert not flags.rtx
        assert not flags.rns
        assert not flags.nia
        assert int(flags) == 0b00111000

        flags.error = True
        flags.throttle = True
        flags.reserved0 = True
        flags.reserved1 = True
        flags.reserved2 = True
        flags.mode = True

        assert int(flags) == 255


class TestSchema(unittest.TestCase):
    def test_SCHEMA_IDS(self):
        all_schemas = Packager.SCHEMA_IDS
        assert type(all_schemas) is list
        assert all([type(s) is int for s in all_schemas])
        sequence_schemas = Packager.SCHEMA_IDS_SUPPORT_SEQUENCE
        assert type(sequence_schemas) is list
        assert all([type(s) is int for s in sequence_schemas])
        routing_schemas = Packager.SCHEMA_IDS_SUPPORT_ROUTING
        assert type(routing_schemas) is list
        assert all([type(s) is int for s in routing_schemas])

        assert len(sequence_schemas) < len(all_schemas)
        assert len(routing_schemas) < len(all_schemas)
        assert all([i in all_schemas for i in sequence_schemas])
        assert all([i in all_schemas for i in routing_schemas])

    def test_get_schema(self):
        schema = Packager.get_schema(0)
        assert isinstance(schema, Packager.Schema)

    def test_get_schemas(self):
        ids = Packager.SCHEMA_IDS
        schemas = Packager.get_schemas(ids)
        assert type(schemas) is list
        for s in schemas:
            assert type(s) is Packager.Schema, s

    def test_pack_and_unpack_schema0(self):
        schema = Packager.get_schema(0)
        body = b'hello world'
        data = schema.pack(Packager.Flags(0), {
            'packet_id': b'\x00',
            'body': body,
        })
        assert type(data) is bytes
        packet = schema.unpack(data)
        assert type(packet) is dict
        assert packet['body'] == body


class TestPacket(unittest.TestCase):
    def test_setting_properties_then_pack_unpack_e2e(self):
        schema = Packager.get_schema(0)
        packet = Packager.Packet(
            schema,
            Packager.Flags(0),
            {
                'packet_id': 0,
                'body': b'hello world',
            }
        )
        packet.body = b'hulloo'
        packet.id = 1

        packed = packet.pack()
        assert type(packed) is bytes
        unpacked = Packager.Packet.unpack(packed)
        assert isinstance(unpacked, Packager.Packet)
        assert unpacked.body == packet.body
        assert unpacked.schema.id == packet.schema.id
        assert unpacked.flags == packet.flags, (unpacked.flags, packet.flags)

    def test_set_checksum(self):
        schema = Packager.get_schema(Packager.SCHEMA_IDS_SUPPORT_CHECKSUM[0])
        data = b'doo doodoo bitcoin something doodoo doo'
        packet = Packager.Packet(
            schema,
            Packager.Flags(0),
            {
                'packet_id': 0,
                'body': data
            }
        )
        assert 'checksum' not in packet.fields
        packet.set_checksum()
        assert 'checksum' in packet.fields
        assert packet.fields['checksum'] == crc32(packet.body).to_bytes(4, 'big')


def xor(b1: bytes, b2: bytes) -> bytes:
    while len(b2) > len(b1):
        b1 += b'\x00'
    b3 = bytearray(len(b1))
    for i in range(len(b2)):
        b3[i] = b1[i] ^ b2[i]
    return b3

def xor_diff(b1: bytes, b2: bytes) -> tuple[str, str]:
    b3 = xor(b1, b2)
    b4 = xor(b1, b2)
    for i in range(len(b3)):
        if b3[i] != 0:
            b3[i] = b1[i] if i < len(b1) else 255
            b4[i] = b2[i] if i < len(b2) else 255
    return (b3.hex(), b4.hex())


class TestSequence(unittest.TestCase):
    def test_set_data_and_get_packet(self):
        with self.assertRaises(AssertionError) as e:
            Packager.Sequence(Packager.get_schema(0), 1)
        assert 'schema must include' in str(e.exception)

        schema = Packager.get_schema(Packager.SCHEMA_IDS_SUPPORT_SEQUENCE[0])
        data = b''.join([(i%256).to_bytes(1, 'big') for i in range(1200)])
        flags = Packager.Flags(0)
        sequence = Packager.Sequence(schema, 0, len(data))
        sequence.set_data(data)
        assert sequence.data == data
        assert len(sequence.get_missing()) == 0, sequence.get_missing()
        assert data == b''.join([
            sequence.get_packet(i, flags, {}).body
            for i in range(sequence.seq_size)
        ])

    def test_e2e(self):
        with self.assertRaises(AssertionError) as e:
            Packager.Sequence(Packager.get_schema(0), 1)
        assert 'schema must include' in str(e.exception)

        schema = Packager.get_schema(Packager.SCHEMA_IDS_SUPPORT_SEQUENCE[0])
        data = b''.join([(i%256).to_bytes(1, 'big') for i in range(1221)])
        flags = Packager.Flags(0)
        sequence = Packager.Sequence(schema, 0, len(data))
        sequence.set_data(data)
        seq2 = Packager.Sequence(schema, 0, seq_size=sequence.seq_size)
        assert len(sequence.get_missing()) == 0, sequence.get_missing()
        assert len(seq2.get_missing()) > 0

        for i in range(sequence.seq_size):
            packet = sequence.get_packet(i, flags, {})
            assert isinstance(packet, Packager.Packet)
            if i % 5:
                assert not seq2.add_packet(packet)

        assert len(seq2.get_missing()) > 0
        for id in seq2.get_missing():
            seq2.add_packet(sequence.get_packet(id, flags, {}))

        assert len(seq2.get_missing()) == 0
        assert seq2.data == data, \
            (len(seq2.data), len(data), sequence.seq_size, seq2.seq_size,
             xor_diff(seq2.data, data))


outbox: deque[Packager.Datagram] = deque()
inbox: deque[Packager.Datagram] = deque()
castbox: deque[Packager.Datagram] = deque()
config = {}

def configure(_: Packager.Interface, data: dict):
    for key, value in data.items():
        config[key] = value

def receive1(intrfc: Packager.Interface):
    return inbox.popleft() if len(inbox) else None

def receive12(intrfc: Packager.Interface):
    return inbox.popleft() if len(inbox) else castbox.popleft() if len(castbox) else None

def receive2(intrfc: Packager.Interface):
    return outbox.popleft() if len(outbox) else None

def receive22(intrfc: Packager.Interface):
    return outbox.popleft() if len(outbox) else castbox.popleft() if len(castbox) else None

def send1(datagram: Packager.Datagram):
    outbox.append(datagram)

def send2(datagram: Packager.Datagram):
    inbox.append(datagram)

def broadcast(datagram: Packager.Datagram):
    castbox.append(datagram)

mock_interface1 = Packager.Interface(
    'mock1',
    1200,
    configure,
    Packager.SCHEMA_IDS,
    receive1,
    send1,
    broadcast
)

mock_interface2 = Packager.Interface(
    'mock1',
    1200,
    configure,
    Packager.SCHEMA_IDS,
    receive2,
    send2,
    broadcast
)

class TestInterface(unittest.TestCase):
    def tearDown(self) -> None:
        inbox.clear()
        outbox.clear()
        castbox.clear()
        mock_interface1.inbox.clear()
        mock_interface1.outbox.clear()
        mock_interface1.castbox.clear()
        return super().tearDown()

    def test_validate(self):
        assert mock_interface1.validate()

    def test_configure(self):
        assert 'thing' not in config
        mock_interface1.configure({'thing': 123})
        assert 'thing' in config

    def test_receive_process(self):
        assert len(inbox) == 0
        dgram = Packager.Datagram(b'hello', mock_interface1.id, b'mac address')
        inbox.append(dgram)
        assert len(mock_interface1.inbox) == 0
        asyncio.run(mock_interface1.process())
        assert len(mock_interface1.inbox) == 1
        assert mock_interface1.receive() == dgram
        assert len(mock_interface1.inbox) == 0
        assert len(inbox) == 0

    def test_send_process(self):
        assert len(outbox) == 0
        dgram = Packager.Datagram(b'hello', mock_interface1.id, b'mac address')
        assert len(mock_interface1.outbox) == 0
        mock_interface1.send(dgram)
        assert len(mock_interface1.outbox) == 1
        assert len(outbox) == 0
        asyncio.run(mock_interface1.process())
        assert len(mock_interface1.outbox) == 0
        assert len(outbox) == 1
        outbox.pop()

    def test_broadcast_process(self):
        assert len(castbox) == 0
        dgram = Packager.Datagram(b'hello', mock_interface1.id, b'mac address')
        assert len(mock_interface1.castbox) == 0
        mock_interface1.broadcast(dgram)
        assert len(mock_interface1.castbox) == 1
        assert len(castbox) == 0
        asyncio.run(mock_interface1.process())
        assert len(mock_interface1.castbox) == 0
        assert len(castbox) == 1
        castbox.pop()


class TestPeer(unittest.TestCase):
    def test_e2e(self):
        peer = Packager.Peer(b'123', {b'mac': mock_interface1})
        assert len(peer.addrs) == 0
        peer.set_addr(Packager.Address(b'\x00', b'\x00\x00\x00'))
        assert len(peer.addrs) == 1
        peer.set_addr(Packager.Address(b'\x01', b'\x01\x00\x00'))
        assert len(peer.addrs) == 2
        peer.set_addr(Packager.Address(b'\x02', b'\x02\x00\x00'))
        assert len(peer.addrs) == 2
        assert peer.addrs[0].tree_state == b'\x01'
        assert peer.addrs[1].tree_state == b'\x02'


app_blobs = []

test_app = Packager.Application(
    'test',
    'test',
    0,
    lambda _, blob: app_blobs.append(blob),
    {
        'hello': lambda _: 'world',
    }
)

class TestApplication(unittest.TestCase):
    def setUp(self) -> None:
        app_blobs.clear()
        return super().setUp()

    def tearDown(self) -> None:
        app_blobs.clear()
        return super().tearDown()

    def test_has_id(self):
        assert type(test_app.id) is bytes
        assert len(test_app.id) == 16

    def test_receive(self):
        assert len(app_blobs) == 0
        test_app.receive(b'hello world')
        assert len(app_blobs) == 1
        assert app_blobs[0] == b'hello world'

    def test_available(self):
        a1 = test_app.available()
        assert type(a1) is list
        assert all([type(a) is str for a in a1])

        a2 = test_app.available('nope')
        assert type(a2) is bool
        assert not a2
        assert test_app.available('hello')

    def test_invoke(self):
        assert test_app.invoke('hello') == 'world'


class TestPackager(unittest.TestCase):
    def setUp(self) -> None:
        inbox.clear()
        outbox.clear()
        castbox.clear()
        app_blobs.clear()
        mock_interface1.inbox.clear()
        mock_interface1.outbox.clear()
        mock_interface1.castbox.clear()
        Packager.Packager.interfaces.clear()
        Packager.Packager.node_addrs.clear()
        Packager.Packager.peers.clear()
        Packager.Packager.routes.clear()
        Packager.Packager.apps.clear()
        Packager.Packager.in_seqs.clear()
        Packager.Packager.schedule.clear()
        Packager.Packager.new_events.clear()
        Packager.Packager.cancel_events.clear()
        Packager.Packager.sleepskip.clear()
        return super().setUp()

    def tearDown(self) -> None:
        inbox.clear()
        outbox.clear()
        castbox.clear()
        app_blobs.clear()
        mock_interface1.inbox.clear()
        mock_interface1.outbox.clear()
        mock_interface1.castbox.clear()
        Packager.Packager.interfaces.clear()
        Packager.Packager.node_addrs.clear()
        Packager.Packager.peers.clear()
        Packager.Packager.routes.clear()
        Packager.Packager.apps.clear()
        Packager.Packager.in_seqs.clear()
        Packager.Packager.schedule.clear()
        Packager.Packager.new_events.clear()
        Packager.Packager.cancel_events.clear()
        Packager.Packager.sleepskip.clear()
        return super().tearDown()

    def test_add_interface_remove_interface_e2e(self):
        assert len(Packager.Packager.interfaces) == 0
        Packager.Packager.add_interface(mock_interface1)
        assert len(Packager.Packager.interfaces) == 1
        Packager.Packager.remove_interface(mock_interface1)
        assert len(Packager.Packager.interfaces) == 0

    def test_add_peer_remove_peer(self):
        assert len(Packager.Packager.peers.keys()) == 0
        Packager.Packager.add_peer(b'peer0', [(b'macpeer0', mock_interface1)])
        assert len(Packager.Packager.peers.keys()) == 1
        Packager.Packager.remove_peer(b'peer0')
        assert len(Packager.Packager.peers.keys()) == 0

    def test_add_route_remove_route(self):
        assert len(Packager.Packager.routes.keys()) == 0
        addr = Packager.Address(b'\x00', b'12345')
        Packager.Packager.add_peer(b'peer0', [(b'macpeer0', mock_interface1)])
        Packager.Packager.add_route(b'peer0', addr)
        assert len(Packager.Packager.routes.keys()) == 1
        Packager.Packager.remove_route(addr)
        assert len(Packager.Packager.routes.keys()) == 0

    def test_set_addr(self):
        assert len(Packager.Packager.node_addrs) == 0
        Packager.Packager.set_addr(Packager.Address(b'\x00', b'local node addr 0'))
        assert len(Packager.Packager.node_addrs) == 1
        Packager.Packager.set_addr(Packager.Address(b'\x01', b'local node addr 1'))
        assert len(Packager.Packager.node_addrs) == 2
        Packager.Packager.set_addr(Packager.Address(b'\x02', b'local node addr 2'))
        assert len(Packager.Packager.node_addrs) == 2
        assert Packager.Packager.node_addrs[0].tree_state == b'\x01'
        assert Packager.Packager.node_addrs[1].tree_state == b'\x02'

    def test_broadcast_small(self):
        Packager.Packager.add_interface(mock_interface1)
        assert len(Packager.Packager.interfaces) == 1
        assert len(castbox) == 0
        Packager.Packager.broadcast(b'app 9659b56ae1d8', b'test')
        asyncio.run(Packager.Packager.process())
        assert len(castbox) == 1, castbox

    def test_broadcast_large(self):
        Packager.Packager.add_interface(mock_interface1)
        assert len(castbox) == 0
        app_id = b'app 9659b56ae1d8'
        blob = b''.join([(i%256).to_bytes(1, 'big') for i in range(300)])
        Packager.Packager.broadcast(app_id, blob)
        asyncio.run(Packager.Packager.process())
        asyncio.run(Packager.Packager.process())
        asyncio.run(Packager.Packager.process())
        assert len(castbox) == 2, (len(castbox), len(castbox[0].data))
        packet = Packager.Packet.unpack(castbox.popleft().data)
        sequence = Packager.Sequence(
            packet.schema,
            packet.fields['seq_id'],
            seq_size=packet.fields['seq_size']+1
        )
        sequence.add_packet(packet)
        while len(castbox):
            packet = Packager.Packet.unpack(castbox.popleft().data)
            sequence.add_packet(packet)
        assert len(sequence.get_missing()) == 0, sequence.get_missing()
        package = Packager.Package.from_sequence(sequence)
        assert package.app_id == app_id, (app_id, package.app_id)
        assert package.blob == blob

    def test_send_local_small(self):
        Packager.Packager.add_interface(mock_interface1)
        assert len(Packager.Packager.interfaces) == 1
        assert len(outbox) == 0
        Packager.Packager.add_peer(b'123', [(b'macpeer0', mock_interface1)])
        assert Packager.Packager.send(b'app 9659b56ae1d8', b'test', b'123')
        asyncio.run(Packager.Packager.process())
        assert len(outbox) == 1, outbox

    def test_send_local_large(self):
        Packager.Packager.add_interface(mock_interface1)
        assert len(Packager.Packager.interfaces) == 1
        assert len(outbox) == 0
        app_id = b'app 9659b56ae1d8'
        blob = b''.join([(i%256).to_bytes(1, 'big') for i in range(300)])
        node_id = b'123'
        Packager.Packager.add_peer(node_id, [(b'macpeer0', mock_interface1)])
        assert Packager.Packager.send(app_id, blob, node_id)
        asyncio.run(Packager.Packager.process())
        asyncio.run(Packager.Packager.process())
        asyncio.run(Packager.Packager.process())
        assert len(outbox) == 2, (len(outbox), len(outbox[0].data))
        packet = Packager.Packet.unpack(outbox.popleft().data)
        sequence = Packager.Sequence(
            packet.schema,
            packet.fields['seq_id'],
            seq_size=packet.fields['seq_size']+1
        )
        sequence.add_packet(packet)
        while len(outbox):
            packet = Packager.Packet.unpack(outbox.popleft().data)
            sequence.add_packet(packet)
        assert len(sequence.get_missing()) == 0, sequence.get_missing()
        package = Packager.Package.from_sequence(sequence)
        assert package.app_id == app_id, (app_id, package.app_id)
        assert package.blob == blob

    def test_send_route_small(self):
        Packager.Packager.add_interface(mock_interface1)
        assert len(Packager.Packager.interfaces) == 1
        assert len(outbox) == 0
        app_id = b'app 9659b56ae1d8'
        blob = b'test'
        peer_id = b'123'
        peer_addr = Packager.Address(b'\x00', b'123')
        node_id = b'321'
        node_addr = Packager.Address(b'\x00', b'321')
        Packager.Packager.set_addr(Packager.Address(b'\x00', b'node0'))
        Packager.Packager.add_peer(peer_id, [(b'macpeer0', mock_interface1)])
        Packager.Packager.add_route(peer_id, peer_addr)
        Packager.Packager.add_route(node_id, node_addr)
        assert Packager.Packager.send(app_id, blob, node_id)
        asyncio.run(Packager.Packager.process())
        assert len(outbox) == 1, outbox

    def test_send_route_large(self):
        Packager.Packager.add_interface(mock_interface1)
        assert len(Packager.Packager.interfaces) == 1
        assert len(outbox) == 0
        app_id = b'app 9659b56ae1d8'
        blob = b''.join([(i%256).to_bytes(1, 'big') for i in range(300)])
        peer_id = b'123'
        peer_addr = Packager.Address(b'\x00', b'123')
        node_id = b'321'
        node_addr = Packager.Address(b'\x00', b'321')
        Packager.Packager.set_addr(Packager.Address(b'\x00', b'node0'))
        Packager.Packager.add_peer(peer_id, [(b'macpeer0', mock_interface1)])
        Packager.Packager.add_route(peer_id, peer_addr)
        Packager.Packager.add_route(node_id, node_addr)
        assert Packager.Packager.send(app_id, blob, node_id)
        asyncio.run(Packager.Packager.process())
        asyncio.run(Packager.Packager.process())
        asyncio.run(Packager.Packager.process())
        assert len(outbox) == 2, (len(outbox), len(outbox[0].data))
        packet = Packager.Packet.unpack(outbox.popleft().data)
        sequence = Packager.Sequence(
            packet.schema,
            packet.fields['seq_id'],
            seq_size=packet.fields['seq_size']+1
        )
        sequence.add_packet(packet)
        while len(outbox):
            packet = Packager.Packet.unpack(outbox.popleft().data)
            sequence.add_packet(packet)
        assert len(sequence.get_missing()) == 0, sequence.get_missing()
        package = Packager.Package.from_sequence(sequence)
        assert package.app_id == app_id, (app_id, package.app_id)
        assert package.blob == blob

    def test_get_interface_and_send_packet(self):
        Packager.Packager.add_interface(mock_interface1)
        Packager.Packager.add_interface(mock_interface2)
        assert len(Packager.Packager.interfaces) == 2
        Packager.Packager.add_peer(b'123', [(b'macpeer0', mock_interface1)])
        intrfc = Packager.Packager.get_interface(b'123')
        assert type(intrfc) is tuple
        assert len(intrfc) == 3
        assert intrfc[0] == b'macpeer0'
        assert intrfc[1] == mock_interface1
        assert type(intrfc[2]) is Packager.Peer

        packet = Packager.Packet(
            Packager.get_schema(Packager.SCHEMA_IDS[0]),
            Packager.Flags(0),
            {
                'body': b'test',
                'packet_id': 0,
            }
        )
        assert len(outbox) == 0
        # prevent mock_interface2 from receiving the datagram
        Packager.Packager.remove_interface(mock_interface2)
        assert Packager.Packager.send_packet(packet, b'123')
        asyncio.run(Packager.Packager.process())
        assert len(outbox) == 1, outbox

    def test_send_when_not_Peer_can_tx_queues_datagram(self):
        # add application, network interface, and peer
        Packager.Packager.add_application(test_app)
        Packager.Packager.add_interface(mock_interface1)
        Packager.Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])
        peer = list(Packager.Packager.peers.items())[0][1]
        # disable direct transmission
        peer.last_rx = int(time()-1) * 1000

        # try to send a Package, but it should queue the packet and send RNS
        assert len(peer.queue) == 0
        assert len(mock_interface1.outbox) == 0
        assert Packager.Packager.send(test_app.id, b'test', b'peer0')
        assert len(mock_interface1.outbox) == 1
        dgram = mock_interface1.outbox.popleft()
        packet = Packager.Packet.unpack(dgram.data)
        assert packet.flags.rns, (packet.flags, packet.body)
        assert len(peer.queue) == 1

        # event to resend RNS should be queued with a retry of 9
        assert len(Packager.Packager.new_events) == 1
        asyncio.run(Packager.Packager.process())
        assert len(Packager.Packager.new_events) == 0
        eid = b'rnspeer0' + mock_interface1.id
        assert eid in Packager.Packager.schedule
        event = Packager.Packager.schedule[eid]
        assert event.kwargs['retries'] == 9, event

        # wait 30 ms and process again; it should resend the RNS
        sleep(0.03)
        asyncio.run(Packager.Packager.process())
        assert len(mock_interface1.outbox) == 1
        dgram = mock_interface1.outbox.popleft()
        packet = Packager.Packet.unpack(dgram.data)
        assert packet.flags.rns, (packet.flags, packet.body)

        # event to resend RNS should be queued with a retry of 8
        assert len(Packager.Packager.new_events) == 1
        asyncio.run(Packager.Packager.process())
        assert len(Packager.Packager.new_events) == 0
        eid = b'rnspeer0' + mock_interface1.id
        assert eid in Packager.Packager.schedule
        event = Packager.Packager.schedule[eid]
        assert event.kwargs['retries'] == 8, event

        # simulate sending NIA
        flags = Packager.Flags(0)
        flags.nia = True
        dgram = Packager.Datagram(
            Packager.Packet(
                mock_interface1.default_schema,
                flags,
                {
                    'packet_id': 0,
                    'body': b'',
                }
            ).pack(),
            mock_interface1.id,
            b'mac0'
        )
        inbox.append(dgram)
        # receiving via process should set can_tx to True and send the packet
        asyncio.run(Packager.Packager.process())
        assert peer.can_tx
        assert len(mock_interface1.outbox) == 1
        asyncio.run(Packager.Packager.process())
        assert len(mock_interface1.outbox) == 0
        assert len(outbox) == 1

    def test_receive_RNS_sends_NIA(self):
        # add application, network interface, and peer
        Packager.Packager.add_application(test_app)
        Packager.Packager.add_interface(mock_interface1)
        Packager.Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])

        # simulate sending RNS from the peer
        flags = Packager.Flags(0)
        flags.rns = True
        inbox.append(Packager.Datagram(
            Packager.Packet(
                mock_interface1.default_schema,
                flags,
                {
                    'packet_id': 0,
                    'body': b'',
                }
            ).pack(),
            mock_interface1.id,
            b'mac0'
        ))
        assert len(mock_interface1.outbox) == 0
        asyncio.run(Packager.Packager.process())
        assert len(mock_interface1.outbox) == 1
        assert len(outbox) == 0
        asyncio.run(Packager.Packager.process())
        assert len(mock_interface1.outbox) == 0
        assert len(outbox) == 1
        dgram = outbox.popleft()
        assert dgram.intrfc_id == mock_interface1.id
        assert dgram.addr == b'mac0'
        p = Packager.Packet.unpack(dgram.data)
        assert p.flags.nia

    def test_modem_sleep_basic(self):
        # set up a logging event that shuts down after collecting 6 timestamps
        log = []
        now = lambda: int(time()*1000)
        def callback():
            log.append(now())
            if len(log) > 5:
                return Packager.Packager.stop()
            Packager.Packager.new_events.append(Packager.Event(
                now() + 10,
                b'log',
                callback
            ))

        Packager.Packager.new_events.append(Packager.Event(
            now() + 10,
            b'log',
            callback
        ))
        asyncio.run(Packager.Packager.work(use_modem_sleep=True))
        logdiff = []
        for i in range(1, len(log)):
            logdiff.append(log[i] - log[i-1])
        sub20s = [i for i in logdiff if i < 20]
        over90s = [i for i in logdiff if i >= 90]
        assert len(sub20s) == len(logdiff) - 1
        assert len(over90s) == 1

    def test_modem_sleep_skips_after_rx_or_tx(self):
        # set up a logging event that shuts down after collecting 6 timestamps
        log = []
        now = lambda: int(time()*1000)
        peer_id = b'peer0'
        peer_mac = b'mac0'
        def callback():
            log.append(now())
            if len(log) > 5:
                return Packager.Packager.stop()
            Packager.Packager.new_events.append(Packager.Event(
                now() + 10,
                b'log',
                callback
            ))
            Packager.Packager.send(test_app.id, b'hello world', peer_id)

        Packager.Packager.add_interface(mock_interface1)
        Packager.Packager.add_peer(peer_id, [(peer_mac, mock_interface1)])
        Packager.Packager.add_application(test_app)
        Packager.Packager.new_events.append(Packager.Event(
            now() + 10,
            b'log',
            callback
        ))
        asyncio.run(Packager.Packager.work(use_modem_sleep=True))
        logdiff = []
        for i in range(1, len(log)):
            logdiff.append(log[i] - log[i-1])
        sub20s = [i for i in logdiff if i < 20]
        over90s = [i for i in logdiff if i >= 90]
        assert len(sub20s) == len(logdiff)
        assert len(over90s) == 0
        assert len(Packager.Packager.sleepskip) > 0

    def test_event_handling_in_work(self):
        now = int(time())
        log = []
        def logcallback(count: int):
            log.append(int(time()*1000))
            if count > 1:
                return
            event = Packager.Event(
                (now-1)*1000,
                b'log',
                logcallback,
                count+1
            )
            Packager.Packager.queue_event(event)

        Packager.Packager.queue_event(Packager.Event(
            (now+1)*1000,
            b'test',
            Packager.Packager.stop,
        ))
        Packager.Packager.queue_event(Packager.Event(
            (now-1)*1000,
            b'log',
            logcallback,
            0
        ))
        assert len(log) == 0
        assert not Packager.Packager.running
        asyncio.run(Packager.Packager.work())
        assert not Packager.Packager.running
        assert now < int(time()) <= now + 2
        assert len(log) >= 2, len(log) # async is somewhat random
        assert len(Packager.Packager.schedule.keys()) == 0

        # test event cancellation
        def cancelcallback(eid: bytes):
            Packager.Packager.cancel_events.append(eid)

        def logcallback2(count: int):
            logcallback(count)
            cancelcallback(b'log')

        log.clear()
        now = int(time())
        Packager.Packager.queue_event(Packager.Event(
            (now+1)*1000,
            b'test',
            Packager.Packager.stop,
        ))
        Packager.Packager.queue_event(Packager.Event(
            (now-1)*1000,
            b'log',
            logcallback2,
            0
        ))
        asyncio.run(Packager.Packager.work())
        assert now < int(time()) <= now + 2
        assert len(log) == 1, log # the recurring event should have been canceled
        assert len(Packager.Packager.schedule.keys()) == 0

    def test_deliver(self):
        package = Packager.Package.from_blob(test_app.id, b'hello world')
        Packager.Packager.add_application(test_app)
        assert len(app_blobs) == 0
        Packager.Packager.deliver(package)
        assert len(app_blobs) == 1

    def test_sequence_synchronization_e2e_success(self):
        # prepare the sequence
        blob = b''.join([(i%256).to_bytes(1, 'big') for i in range(400)])
        package = Packager.Package.from_blob(test_app.id, blob).pack()
        schema_ids = list(set(Packager.SCHEMA_IDS_SUPPORT_SEQUENCE).difference(
            Packager.SCHEMA_IDS_SUPPORT_ROUTING
        ).difference(Packager.SCHEMA_IDS_SUPPORT_CHECKSUM))
        schemas = Packager.get_schemas(schema_ids)
        schemas.sort(key=lambda s: s.max_body, reverse=True)
        schema = schemas[0]
        seq = Packager.Sequence(schema, 0, data_size=len(package))
        seq.set_data(package)
        assert seq.seq_size == 2

        # add application, network interface, and peer
        Packager.Packager.add_application(test_app)
        Packager.Packager.add_interface(mock_interface1)
        Packager.Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])

        # start sequence transmission with first packet
        flags = Packager.Flags(0)
        inbox.append(Packager.Datagram(
            seq.get_packet(0, flags, {}).pack(),
            mock_interface1.id,
            b'mac0',
        ))

        assert len(Packager.Packager.new_events) == 0
        assert len(Packager.Packager.schedule.keys()) == 0
        assert len(Packager.Packager.in_seqs.keys()) == 0
        assert len(mock_interface1.outbox) == 0

        # should queue the sync_sequence event and send an ack
        asyncio.run(Packager.Packager.process())
        assert len(Packager.Packager.new_events) == 1
        assert len(Packager.Packager.schedule.keys()) == 0
        assert len(Packager.Packager.in_seqs.keys()) == 1
        assert len(mock_interface1.outbox) == 1
        assert len(outbox) == 0

        # mock_interface1 should send the ack datagram, and the event should be scheduled
        asyncio.run(Packager.Packager.process())
        assert len(mock_interface1.outbox) == 0
        assert len(outbox) == 1
        assert len(Packager.Packager.new_events) == 0
        assert len(Packager.Packager.schedule.keys()) == 1
        outbox.clear()

        # spoof timestamp to advance the event
        eid = list(Packager.Packager.schedule.keys())[0]
        event = Packager.Packager.schedule[eid]
        event.ts = int(time()-1)*1000
        assert event.handler == Packager.Packager.sync_sequence, event.handler

        # should now execute cls.sync_sequence
        assert Packager.Packager.in_seqs[0].retry == 3, Packager.Packager.in_seqs[0].retry
        assert len(mock_interface1.outbox) == 0
        assert len(outbox) == 0
        asyncio.run(Packager.Packager.process())
        # rtx should be queued for sending in the interface
        assert len(mock_interface1.outbox) == 1
        assert len(outbox) == 0
        assert mock_interface1.outbox[0].addr == b'mac0'
        assert Packager.Packager.in_seqs[0].retry == 2, Packager.Packager.in_seqs[0].retry

        # mock_interface1 should now send the rtx datagram
        asyncio.run(Packager.Packager.process())
        assert len(mock_interface1.outbox) == 0
        assert len(outbox) == 1
        packet = Packager.Packet.unpack(outbox.popleft().data)
        assert packet.flags.rtx
        assert packet.id == 1
        assert packet.fields['seq_id'] == 0
        assert packet.fields['seq_size'] == 1

        # retransmitting missing Packet should finish the Sequence and deliver the Package
        inbox.append(Packager.Datagram(
            seq.get_packet(packet.id, flags, {}).pack(),
            mock_interface1.id,
            b'mac0',
        ))
        assert len(app_blobs) == 0
        assert len(Packager.Packager.in_seqs.keys()) == 1
        asyncio.run(Packager.Packager.process())
        assert len(app_blobs) == 1
        assert app_blobs[0] == blob
        assert len(Packager.Packager.in_seqs.keys()) == 0

    def test_sequence_synchronization_e2e_failure(self):
        # sequence construction attempt should be dropped if the origin is unresponsive
        # prepare the sequence
        blob = b''.join([(i%256).to_bytes(1, 'big') for i in range(400)])
        package = Packager.Package.from_blob(test_app.id, blob).pack()
        schema_ids = list(set(Packager.SCHEMA_IDS_SUPPORT_SEQUENCE).difference(
            Packager.SCHEMA_IDS_SUPPORT_ROUTING
        ).difference(Packager.SCHEMA_IDS_SUPPORT_CHECKSUM))
        schemas = Packager.get_schemas(schema_ids)
        schemas.sort(key=lambda s: s.max_body, reverse=True)
        schema = schemas[0]
        seq = Packager.Sequence(schema, 0, data_size=len(package))
        seq.set_data(package)
        assert seq.seq_size == 2

        # add application, network interface, and peer
        Packager.Packager.add_application(test_app)
        Packager.Packager.add_interface(mock_interface1)
        Packager.Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])

        # start sequence transmission with first packet
        flags = Packager.Flags(0)
        inbox.append(Packager.Datagram(
            seq.get_packet(0, flags, {}).pack(),
            mock_interface1.id,
            b'mac0',
        ))

        # should queue the sync_sequence event and send an ack
        asyncio.run(Packager.Packager.process())
        assert len(Packager.Packager.new_events) == 1
        assert len(Packager.Packager.in_seqs.keys()) == 1
        assert len(mock_interface1.outbox) == 1

        # mock_interface1 should send the ack datagram, and the event should be scheduled
        asyncio.run(Packager.Packager.process())
        assert len(outbox) == 1
        assert len(Packager.Packager.schedule.keys()) == 1
        outbox.clear()

        # spoof timestamp to advance the event
        eid = list(Packager.Packager.schedule.keys())[0]
        event = Packager.Packager.schedule[eid]
        event.ts = int(time()-1)*1000
        assert event.handler == Packager.Packager.sync_sequence, event.handler

        # should now execute cls.sync_sequence
        assert Packager.Packager.in_seqs[0].retry == 3, Packager.Packager.in_seqs[0].retry
        asyncio.run(Packager.Packager.process())
        # rtx should be queued for sending in the interface
        assert len(mock_interface1.outbox) == 1
        assert Packager.Packager.in_seqs[0].retry == 2, Packager.Packager.in_seqs[0].retry
        assert len(Packager.Packager.new_events) == 1

        # mock_interface1 should now send the rtx datagram
        asyncio.run(Packager.Packager.process())
        assert len(Packager.Packager.new_events) == 0
        assert len(outbox) == 1
        packet = Packager.Packet.unpack(outbox.popleft().data)
        assert packet.flags.rtx

        # simulate unresponsive node by spoofing timestamp
        eid = list(Packager.Packager.schedule.keys())[0]
        event = Packager.Packager.schedule[eid]
        event.ts = int(time()-1)*1000
        assert event.handler == Packager.Packager.sync_sequence, event.handler

        # should execute cls.sync_sequence again
        assert Packager.Packager.in_seqs[0].retry == 2, Packager.Packager.in_seqs[0].retry
        asyncio.run(Packager.Packager.process())
        asyncio.run(Packager.Packager.process())
        assert Packager.Packager.in_seqs[0].retry == 1, Packager.Packager.in_seqs[0].retry
        # rtx datagram should be sent
        assert len(outbox) == 1
        outbox.clear()

        # simulate unresponsive node by spoofing timestamp
        eid = list(Packager.Packager.schedule.keys())[0]
        event = Packager.Packager.schedule[eid]
        event.ts = int(time()-1)*1000
        assert event.handler == Packager.Packager.sync_sequence, event.handler

        # should execute cls.sync_sequence again
        assert Packager.Packager.in_seqs[0].retry == 1, Packager.Packager.in_seqs[0].retry
        asyncio.run(Packager.Packager.process())
        asyncio.run(Packager.Packager.process())
        assert Packager.Packager.in_seqs[0].retry == 0, Packager.Packager.in_seqs[0].retry
        # rtx datagram should be sent
        assert len(outbox) == 1
        outbox.clear()

        # simulate unresponsive node by spoofing timestamp
        eid = list(Packager.Packager.schedule.keys())[0]
        event = Packager.Packager.schedule[eid]
        event.ts = int(time()-1)*1000
        assert event.handler == Packager.Packager.sync_sequence, event.handler

        # InSequence should be dropped
        assert len(Packager.Packager.in_seqs.keys()) == 1
        asyncio.run(Packager.Packager.process())
        assert len(Packager.Packager.in_seqs.keys()) == 0


if __name__ == '__main__':
    unittest.main()
