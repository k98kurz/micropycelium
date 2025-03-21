import asyncio
from binascii import crc32
from collections import deque
from context import *
from hashlib import sha256
from os import urandom
from random import randint
from time import time, sleep, time_ns
import unittest


class TestFlags(unittest.TestCase):
    def test_byte_values(self):
        flags = Flags(0)
        assert not flags.error
        assert not flags.throttle
        assert not flags.ask
        assert not flags.ack
        assert not flags.rtx
        assert not flags.rns
        assert not flags.nia
        assert not flags.encoded6
        assert not flags.encoded7
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
        assert not flags.encoded7
        assert int(flags) == 0b00001000

        flags.ack = True
        assert flags.ack
        assert not flags.ask
        assert not flags.rtx
        assert not flags.rns
        assert not flags.nia
        assert not flags.encoded6
        assert not flags.encoded7
        assert int(flags) == 0b00010000

        flags.rtx = True
        assert flags.rtx
        assert not flags.ask
        assert not flags.ack
        assert not flags.rns
        assert not flags.nia
        assert not flags.encoded6
        assert not flags.encoded7
        assert int(flags) == 0b00011000

        flags.rns = True
        assert flags.rns
        assert not flags.ask
        assert not flags.ack
        assert not flags.rtx
        assert not flags.nia
        assert not flags.encoded6
        assert not flags.encoded7
        assert int(flags) == 0b00100000

        flags.nia = True
        assert flags.nia
        assert not flags.ask
        assert not flags.ack
        assert not flags.rtx
        assert not flags.rns
        assert not flags.encoded6
        assert not flags.encoded7
        assert int(flags) == 0b00101000

        flags.encoded6 = True
        assert flags.encoded6
        assert not flags.ask
        assert not flags.ack
        assert not flags.rtx
        assert not flags.rns
        assert not flags.nia
        assert not flags.encoded7
        assert int(flags) == 0b00110000

        flags.encoded7 = True
        assert flags.encoded7
        assert not flags.ask
        assert not flags.ack
        assert not flags.rtx
        assert not flags.rns
        assert not flags.nia
        assert not flags.encoded6
        assert int(flags) == 0b00111000

        flags.error = True
        flags.throttle = True
        flags.reserved1 = True
        flags.reserved2 = True
        flags.mode = True

        assert int(flags) == 255


class TestSchema(unittest.TestCase):
    def test_SCHEMA_IDS(self):
        all_schemas = SCHEMA_IDS
        assert type(all_schemas) is list
        assert all([type(s) is int for s in all_schemas])
        sequence_schemas = SCHEMA_IDS_SUPPORT_SEQUENCE
        assert type(sequence_schemas) is list
        assert all([type(s) is int for s in sequence_schemas])
        routing_schemas = SCHEMA_IDS_SUPPORT_ROUTING
        assert type(routing_schemas) is list
        assert all([type(s) is int for s in routing_schemas])

        assert len(sequence_schemas) < len(all_schemas)
        assert len(routing_schemas) < len(all_schemas)
        assert all([i in all_schemas for i in sequence_schemas])
        assert all([i in all_schemas for i in routing_schemas])

    def test_get_schema(self):
        schema = get_schema(0)
        assert isinstance(schema, Schema)

    def test_get_schemas(self):
        ids = SCHEMA_IDS
        schemas = get_schemas(ids)
        assert type(schemas) is list
        for s in schemas:
            assert type(s) is Schema, s

    def test_pack_and_unpack_schema0(self):
        schema = get_schema(0)
        body = b'hello world'
        data = schema.pack(Flags(0), {
            'packet_id': b'\x00',
            'body': body,
        })
        assert type(data) is bytes
        packet = schema.unpack(data)
        assert type(packet) is dict
        assert packet['body'] == body


class TestPacket(unittest.TestCase):
    def test_setting_properties_then_pack_unpack_e2e(self):
        schema = get_schema(0)
        packet = Packet(
            schema,
            Flags(0),
            {
                'packet_id': 0,
                'body': b'hello world',
            }
        )
        packet.body = b'hulloo'
        packet.id = 1

        packed = packet.pack()
        assert type(packed) is bytes
        unpacked = Packet.unpack(packed)
        assert isinstance(unpacked, Packet)
        assert unpacked.body == packet.body
        assert unpacked.schema.id == packet.schema.id
        assert unpacked.flags == packet.flags, (unpacked.flags, packet.flags)

    def test_set_checksum(self):
        schema = get_schema(SCHEMA_IDS_SUPPORT_CHECKSUM[0])
        data = b'doo doodoo bitcoin something doodoo doo'
        packet = Packet(
            schema,
            Flags(0),
            {
                'packet_id': 0,
                'body': data
            }
        )
        assert 'checksum' not in packet.fields
        packet.set_checksum()
        assert 'checksum' in packet.fields
        assert packet.fields['checksum'] == crc32(packet.body).to_bytes(4, 'big')


class TestSequence(unittest.TestCase):
    def test_set_data_and_get_packet(self):
        with self.assertRaises(AssertionError) as e:
            Sequence(get_schema(0), 1)
        assert 'schema must include' in str(e.exception)

        schema = get_schema(SCHEMA_IDS_SUPPORT_SEQUENCE[0])
        data = b''.join([(i%256).to_bytes(1, 'big') for i in range(1200)])
        flags = Flags(0)
        sequence = Sequence(schema, 0, len(data))
        sequence.set_data(data)
        assert sequence.data == data
        assert len(sequence.get_missing()) == 0, sequence.get_missing()
        assert data == b''.join([
            sequence.get_packet(i, flags, {}).body
            for i in range(sequence.seq_size)
        ])

    def test_e2e(self):
        with self.assertRaises(AssertionError) as e:
            Sequence(get_schema(0), 1)
        assert 'schema must include' in str(e.exception)

        schema = get_schema(SCHEMA_IDS_SUPPORT_SEQUENCE[0])
        data = b''.join([(i%256).to_bytes(1, 'big') for i in range(1221)])
        flags = Flags(0)
        sequence = Sequence(schema, 0, len(data))
        sequence.set_data(data)
        seq2 = Sequence(schema, 0, seq_size=sequence.seq_size)
        assert len(sequence.get_missing()) == 0, sequence.get_missing()
        assert len(seq2.get_missing()) > 0

        for i in range(sequence.seq_size):
            packet = sequence.get_packet(i, flags, {})
            assert isinstance(packet, Packet)
            if i % 5:
                assert not seq2.add_packet(packet)

        assert len(seq2.get_missing()) > 0
        for id in seq2.get_missing():
            seq2.add_packet(sequence.get_packet(id, flags, {}))

        assert len(seq2.get_missing()) == 0
        assert seq2.data == data, \
            (len(seq2.data), len(data), sequence.seq_size, seq2.seq_size,
             xor_diff(seq2.data, data))


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
        dgram = Datagram(b'hello', mock_interface1.id, b'mac address')
        inbox.append(dgram)
        assert len(mock_interface1.inbox) == 0
        asyncio.run(mock_interface1.process())
        assert len(mock_interface1.inbox) == 1
        assert mock_interface1.receive() == dgram
        assert len(mock_interface1.inbox) == 0
        assert len(inbox) == 0

    def test_send_process(self):
        assert len(outbox) == 0
        dgram = Datagram(b'hello', mock_interface1.id, b'mac address')
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
        dgram = Datagram(b'hello', mock_interface1.id, b'mac address')
        assert len(mock_interface1.castbox) == 0
        mock_interface1.broadcast(dgram)
        assert len(mock_interface1.castbox) == 1
        assert len(castbox) == 0
        asyncio.run(mock_interface1.process())
        assert len(mock_interface1.castbox) == 0
        assert len(castbox) == 1
        castbox.pop()


class TestAddress(unittest.TestCase):
    def test_to_str_and_from_str(self):
        addr = Address(12, coords=[])
        adstr = str(addr)
        assert adstr == '12-::', adstr
        assert repr(addr) == 'Address(12-::)', repr(addr)
        assert addr == Address.from_str(adstr)
        addr = Address(35, coords=[2,4] + [0] * 29 + [1])
        adstr = str(addr)
        assert adstr == '35-24::01', adstr
        assert repr(addr) == 'Address(35-24::01)', repr(addr)
        assert addr == Address.from_str(adstr)
        addr = Address(176, coords=[2,4,1] + [0] * 27 + [13])
        adstr = str(addr)
        assert adstr == '176-2410::85', adstr
        assert repr(addr) == 'Address(176-2410::85)', repr(addr)
        assert addr == Address.from_str(adstr)
        assert addr == Address.from_str(repr(addr))
        addr = Address(176, coords=[2,1,0,0,4] + [0] * 27)
        adstr = str(addr)
        assert adstr == '176-210040::', adstr
        assert repr(addr) == 'Address(176-210040::)', repr(addr)
        assert addr == Address.from_str(adstr)
        assert len(addr.coords) == 32
        addr = Address.from_str(adstr)
        assert len(addr.coords) == 5

    def test_encode(self):
        coords = [1, 3, 7, 8, 129]
        address = Address.encode(coords)
        assert type(address) is bytearray
        assert len(address) == 16
        # coords 1 and 3
        assert address[0] == (0b0001 << 4) | 0b0011
        # coords 7 and first half of 8
        assert address[1] == (0b0111 << 4) | 0b1000
        # second half of 8 and first half of 129
        assert address[2] == (0b0000 << 4) | 0b1111
        # second half of 129 and the rest is padding
        assert address[3] == (0b1001 << 4) | 0b0000
        for i in range(4, len(address)):
            assert address[i] == 0

    def test_decode(self):
        address = bytes.fromhex('13780f90') + (b'\x00' * 12)
        assert len(address) == 16
        coords = Address.decode(address)
        assert type(coords) is list
        assert all([type(c) is int for c in coords])

    def test_encode_decode_e2e_fuzz(self):
        # first test max address with all 4-bit coords
        for _ in range(10_000):
            coords = [randint(0, 7) for _ in range(32)]
            # trim terminal empty coords
            while coords[-1] == 0:
                coords.pop()
            address = Address.encode(coords)
            assert Address.decode(address) == coords, \
                (coords, address.hex(), Address.decode(address))

        # second test max address with all 8-bit coords
        for _ in range(10_000):
            coords = [randint(8, 135) for _ in range(16)]
            address = Address.encode(coords)
            assert Address.decode(address) == coords, \
                (coords, address.hex(), Address.decode(address))

        # third test addresses with mix of 4-bit and 8-bit coords
        for _ in range(10_000):
            coords = [randint(0, 135) for _ in range(16)]
            # trim terminal empty coords
            while coords[-1] == 0:
                coords.pop()
            address = Address.encode(coords)
            assert Address.decode(address) == coords, \
                (coords, address.hex(), Address.decode(address))

        # finally test an overflow
        coords = [randint(0, 135) for _ in range(33)]
        address = Address.encode(coords)
        assert len(address) == 16
        assert Address.decode(address) != coords

    def test_initialization(self):
        with self.assertRaises(TypeError) as e:
            Address(b'0', coords=[])
        with self.assertRaises(ValueError) as e:
            Address(0)
        assert 'must provide at least one' in str(e.exception)
        with self.assertRaises(TypeError) as e:
            Address(0, '00sdsd')
        assert 'bytes|bytearray' in str(e.exception)
        with self.assertRaises(TypeError) as e:
            Address(0, coords=['a', 'b', 'c'])
        assert 'int' in str(e.exception)

        addr1 = Address(48, address=b'\x00' * 16)
        addr2 = Address(48, coords=[])
        assert addr1.address == addr2.address
        assert addr1.coords == addr2.coords

    def test_dTree(self):
        # with CPL of 2 and lengths of 3, the distance will be 2
        x1 = Address(48, coords=[1,2,1])
        x2 = Address(48, coords=[1,2,2])
        assert Address.dTree(x1, x2) == 2
        assert Address.dTree(x2, x1) == 2

        # with CPL of 1 and lengths of 3, the distance will be 4
        x1 = Address(48, coords=[1,2,1])
        x2 = Address(48, coords=[1,3,2])
        assert Address.dTree(x1, x2) == 4
        assert Address.dTree(x2, x1) == 4

        # with CPL of 1 and lengths of 2 and 3, the distance will be 3
        x1 = Address(48, coords=[1,2,1])
        x2 = Address(48, coords=[1,3])
        assert Address.dTree(x1, x2) == 3
        assert Address.dTree(x2, x1) == 3

        # with CPL of 31 and lengths of 32, the distance will be 1
        x1 = Address(48, coords=[1] * 31 + [1])
        x2 = Address(48, coords=[1] * 31 + [2])
        assert Address.dTree(x1, x2) == 2, Address.dTree(x1, x2)
        assert Address.dTree(x2, x1) == 2, Address.dTree(x2, x1)

    def test_dCPL(self):
        # with a CPL of 31, the distance will be between 1 and 2
        x1 = Address(48, coords=[1] * 31 + [1])
        x2 = Address(48, coords=[1] * 31 + [2])
        assert Address.dCPL(x1, x1) == 0
        assert Address.dCPL(x1, x2) > 1
        assert Address.dCPL(x1, x2) < 2
        assert Address.dCPL(x1, x2) == Address.dCPL(x2, x1)

        # with CPL of 2, the distance will be between 30 and 31
        x1 = Address(48, coords=[1,2,3])
        x2 = Address(48, coords=[1,2,4])
        assert Address.dCPL(x1, x2) < 31
        assert Address.dCPL(x1, x2) > 30
        assert Address.dCPL(x1, x2) == Address.dCPL(x2, x1)


class TestPeer(unittest.TestCase):
    def test_e2e(self):
        peer = Peer(b'123', {b'mac': mock_interface1})
        assert len(peer.addrs) == 0
        peer.set_addr(Address(0, b'\x00' * 16))
        assert len(peer.addrs) == 1
        peer.set_addr(Address(1, b'\x01' * 16))
        assert len(peer.addrs) == 2
        peer.set_addr(Address(2, b'\x02' * 16))
        assert len(peer.addrs) == 2
        assert peer.addrs[0].tree_state == 1
        assert peer.addrs[1].tree_state == 2


class TestCache(unittest.TestCase):
    def test_evict_on_get(self):
        cache = Cache(limit=10)
        cache.add(b'key', b'value', ttl=1)
        assert cache.get(b'key') == b'value'
        cache.add(b'key', b'value', ttl=-1)
        assert cache.get(b'key') is None

    def test_evict_on_add(self):
        cache = Cache(limit=2)
        cache.add(b'key1', b'value1', ttl=1)
        assert cache.get(b'key1') == b'value1'
        cache.add(b'key2', b'value2', ttl=2)
        assert cache.get(b'key1') == b'value1'
        assert cache.get(b'key2') == b'value2'
        cache.add(b'key3', b'value3', ttl=2)
        assert cache.get(b'key1') is None
        assert cache.get(b'key2') == b'value2'
        assert cache.get(b'key3') == b'value3'

    def test_clear(self):
        cache = Cache(limit=10)
        cache.add(b'key1', b'value1', ttl=1)
        cache.add(b'key2', b'value2', ttl=2)
        assert cache.get(b'key1') == b'value1'
        assert cache.get(b'key2') == b'value2'
        cache.clear()
        assert cache.get(b'key1') is None
        assert cache.get(b'key2') is None


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
        test_app.receive(b'hello world', mock_interface1, b'mac0')
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


if __name__ == '__main__':
    unittest.main()
