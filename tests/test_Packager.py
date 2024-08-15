from context import Packager
import unittest


class TestFlags(unittest.TestCase):
    def test_byte_values(self):
        flags = Packager.Flags(0)
        assert not flags.error
        assert not flags.throttle
        assert not flags.ask
        assert not flags.ack
        assert not flags.rtx
        assert not flags.reserved1
        assert not flags.reserved2
        assert not flags.mode

        flags.error = True
        flags.throttle = True
        flags.ask = True
        flags.ack = True
        flags.rtx = True
        flags.reserved1 = True
        flags.reserved2 = True
        flags.mode = True

        assert int(flags) == 255


class TestSchema(unittest.TestCase):
    def test_get_all_schema_ids(self):
        schemas = Packager.get_all_schema_ids()
        assert type(schemas) is list
        assert all([type(s) is int for s in schemas])

    def test_get_schema(self):
        schema = Packager.get_schema(0)
        assert isinstance(schema, Packager.Schema)

    def test_get_schemas(self):
        ids = Packager.get_all_schema_ids()
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
        unpacked = Packager.Packet.unpack(schema, packed)
        assert isinstance(unpacked, Packager.Packet)
        assert unpacked.body == packet.body
        assert unpacked.schema == packet.schema
        assert unpacked.flags == packet.flags, (unpacked.flags, packet.flags)


if __name__ == '__main__':
    unittest.main()
