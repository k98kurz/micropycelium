from __future__ import annotations
from binascii import crc32
from collections import namedtuple
from hashlib import sha256
from math import ceil
from struct import pack, unpack


Field = namedtuple("Field", ["name", "length", "type", "max_length"], defaults=(0,))


class Flags:
    error: bool
    throttle: bool
    ask: bool
    ack: bool
    rtx: bool
    reserved1: bool
    reserved2: bool
    mode: bool

    def __init__(self, state: int|bytes) -> None:
        self.state = state if type(state) is int else int.from_bytes(state, 'big')

    @property
    def error(self) -> bool:
        return bool(self.state & 0b10000000)

    @error.setter
    def error(self, val: bool):
        if val:
            self.state |= 0b10000000
        else:
            self.state &= 0b01111111

    @property
    def throttle(self) -> bool:
        return bool(self.state & 0b01000000)

    @throttle.setter
    def throttle(self, val: bool):
        if val:
            self.state |= 0b01000000
        else:
            self.state &= 0b10111111

    @property
    def ask(self) -> bool:
        return bool(self.state & 0b00100000)

    @ask.setter
    def ask(self, val: bool):
        if val:
            self.state |= 0b00100000
        else:
            self.state &= 0b11011111

    @property
    def ack(self) -> bool:
        return bool(self.state & 0b00010000)

    @ack.setter
    def ack(self, val: bool):
        if val:
            self.state |= 0b00010000
        else:
            self.state &= 0b11101111

    @property
    def rtx(self) -> bool:
        return bool(self.state & 0b00001000)

    @rtx.setter
    def rtx(self, val: bool):
        if val:
            self.state |= 0b00001000
        else:
            self.state &= 0b11110111

    @property
    def reserved1(self) -> bool:
        return bool(self.state & 0b00000100)

    @reserved1.setter
    def reserved1(self, val: bool):
        if val:
            self.state |= 0b00000100
        else:
            self.state &= 0b11111011

    @property
    def reserved2(self) -> bool:
        return bool(self.state & 0b00000010)

    @reserved2.setter
    def reserved2(self, val: bool):
        if val:
            self.state |= 0b00000010
        else:
            self.state &= 0b11111101

    @property
    def mode(self) -> bool:
        return bool(self.state & 0b00000001)

    @mode.setter
    def mode(self, val: bool):
        if val:
            self.state |= 0b00000001
        else:
            self.state &= 0b11111110

    def __int__(self) -> int:
        return self.state

    def __repr__(self) -> str:
        return f'Flags(error={self.error}, throttle={self.throttle}, ' +\
            f'ask={self.ask}, ack={self.ack}, rtx={self.rtx}, ' +\
            f'reserved1={self.reserved1}, reserved2={self.reserved2}, mode={self.mode})'

    def __eq__(self, other: Flags) -> bool:
        return self.state == other.state


class Schema:
    """Describes a packet schema."""
    version: int
    reserved: int = 0
    id: int
    fields: list[Field]

    def __init__(self, version: int, id: int, fields: list[Field]) -> None:
        self.version = version
        self.id = id
        # variable length field can only be last
        assert all([field.length > 0 for field in fields[:-1]])
        self.fields = fields

    def unpack(self, packet: bytes) -> dict[str, int|bytes|Flags]:
        """Parses the packet into its fields."""
        # uniform header elements
        version, reserved, id, flags, packet = unpack(f'!BBBB{len(packet)-4}s', packet)
        flags = Flags(flags)

        # varying header elements and body
        format_str = '!'
        size = 0
        for field in self.fields:
            if field.type is int:
                format_str += 'B' if field.length == 1 else ('H' if field.length == 2 else 'I')
            elif field.type is bytes:
                format_str += f'{field.length}s' if field.length else f'{len(packet)-size}s'
            size += field.length
        parts = unpack(format_str, packet)
        names = [field.name for field in self.fields]
        result = {
            'version': version,
            'reserved': reserved,
            'id': id,
            'flags': flags,
        }
        for name, value in zip(names, parts):
            result[name] = value
        return result

    def pack(self, flags: Flags, fields: dict[str, int|bytes,]) -> bytes:
        """Packs the packet fields into bytes."""
        # uniform header elements
        format_str = '!BBBB'
        parts = [self.version, self.reserved, self.id, int(flags)]

        # varying header elements and body
        for field in self.fields:
            val = fields[field.name]
            if type(val) is bytes:
                if field.max_length:
                    assert len(val) <= field.max_length
                else:
                    assert len(val) == field.length
            if type(val) is int:
                val = val.to_bytes(field.length, 'big')
            parts.append(val)

            if field.length == 1:
                format_str += 'c'
            else:
                if field.max_length:
                    format_str += f'{len(val)}s'
                else:
                    format_str += f'{field.length}s'
        return pack(format_str, *parts)


def get_schema(id: int) -> Schema:
    """Get the Schema definition with the given id."""
    match id:
        case 0:
            # ESP-NOW; 245 B max Package size
            return Schema(0, 0, [
                Field('packet_id', 1, int),
                Field('body', 0, bytes, 245),
            ])
        case 1:
            # ESP-NOW; 241 B max Package size
            return Schema(0, 1, [
                Field('packet_id', 1, int),
                Field('checksum', 4, bytes),
                Field('body', 0, bytes, 241),
            ])
        case 2:
            # ESP-NOW; 256 max sequence size; 60.75 KiB max Package size
            return Schema(0, 2, [
                Field('packet_id', 1, int),
                Field('seq_id', 1, int),
                Field('seq_size', 1, int),
                Field('body', 0, bytes, 243),
            ])
        case 3:
            # ESP-NOW; 256 max sequence size; 59.75 KiB max Package size
            return Schema(0, 3, [
                Field('packet_id', 1, int),
                Field('seq_id', 1, int),
                Field('seq_size', 1, int),
                Field('checksum', 4, bytes),
                Field('body', 0, bytes, 239),
            ])
        case 4:
            # ESP-NOW; 65536 max sequence size; 14.8125 MiB max Package size
            return Schema(0, 4, [
                Field('packet_id', 2, int),
                Field('seq_id', 1, int),
                Field('seq_size', 2, int),
                Field('checksum', 4, bytes),
                Field('body', 0, bytes, 237),
            ])
        case 5:
            # ESP-NOW; 211 B max Package size
            return Schema(0, 5, [
                Field('packet_id', 1, int),
                Field('ttl', 1, int),
                Field('tree_state', 1, int),
                Field('to_addr', 16, bytes),
                Field('from_addr', 16, bytes),
                Field('body', 0, bytes, 211),
            ])
        case 6:
            # ESP-NOW; 207 B max Package size
            return Schema(0, 6, [
                Field('packet_id', 1, int),
                Field('ttl', 1, int),
                Field('checksum', 4, bytes),
                Field('tree_state', 1, int),
                Field('to_addr', 16, bytes),
                Field('from_addr', 16, bytes),
                Field('body', 0, bytes, 207),
            ])
        case 7:
            # ESP-NOW; 256 max sequence size; 52.75 KiB max Package size
            return Schema(0, 7, [
                Field('packet_id', 1, int),
                Field('seq_id', 1, int),
                Field('seq_size', 1, int),
                Field('ttl', 1, int),
                Field('tree_state', 1, int),
                Field('to_addr', 16, bytes),
                Field('from_addr', 16, bytes),
                Field('body', 0, bytes, 209),
            ])
        case 8:
            # ESP-NOW; 256 max sequence size; 51.25 KiB max Package size
            return Schema(0, 8, [
                Field('packet_id', 1, int),
                Field('seq_id', 1, int),
                Field('seq_size', 1, int),
                Field('ttl', 1, int),
                Field('checksum', 4, bytes),
                Field('tree_state', 1, int),
                Field('to_addr', 16, bytes),
                Field('from_addr', 16, bytes),
                Field('body', 0, bytes, 205),
            ])
        case 9:
            # ESP-NOW; 65536 max sequence size; 12.9375 MiB max Package size
            return Schema(0, 9, [
                Field('packet_id', 2, int),
                Field('seq_id', 1, int),
                Field('seq_size', 2, int),
                Field('ttl', 1, int),
                Field('tree_state', 1, int),
                Field('to_addr', 16, bytes),
                Field('from_addr', 16, bytes),
                Field('body', 0, bytes, 207),
            ])
        case 10:
            # ESP-NOW; 65536 max sequence size; 12.6875 MiB max Package size
            return Schema(0, 10, [
                Field('packet_id', 2, int),
                Field('seq_id', 1, int),
                Field('seq_size', 2, int),
                Field('ttl', 1, int),
                Field('checksum', 4, bytes),
                Field('tree_state', 1, int),
                Field('to_addr', 16, bytes),
                Field('from_addr', 16, bytes),
                Field('body', 0, bytes, 203),
            ])
        case 20:
            # RYLR-998; 235 B max Package size
            return Schema(0, 20, [
                Field('packet_id', 1, int),
                Field('body', 0, bytes, 235),
            ])
        case 21:
            # RYLR-998; 231 B max Package size
            return Schema(0, 21, [
                Field('packet_id', 1, int),
                Field('checksum', 4, bytes),
                Field('body', 0, bytes, 231),
            ])
        case 22:
            # RYLR-998; 256 max sequence size; 53.25 KiB max Package size
            return Schema(0, 22, [
                Field('packet_id', 1, int),
                Field('seq_id', 1, int),
                Field('seq_size', 1, int),
                Field('body', 0, bytes, 233),
            ])
        case 23:
            # RYLR-998; 256 max sequence size; 57.25 KiB max Package size
            return Schema(0, 23, [
                Field('packet_id', 1, int),
                Field('seq_id', 1, int),
                Field('seq_size', 1, int),
                Field('checksum', 4, bytes),
                Field('body', 0, bytes, 229),
            ])
        case 24:
            # RYLR-998; 65536 max sequence size; 14.1875 MiB max Package size
            return Schema(0, 24, [
                Field('packet_id', 2, int),
                Field('seq_id', 1, int),
                Field('seq_size', 2, int),
                Field('checksum', 4, bytes),
                Field('body', 0, bytes, 227),
            ])
        case 25:
            # RYLR-998; 201 B max Package size
            return Schema(0, 25, [
                Field('packet_id', 1, int),
                Field('ttl', 1, int),
                Field('tree_state', 1, int),
                Field('to_addr', 16, bytes),
                Field('from_addr', 16, bytes),
                Field('body', 0, bytes, 201),
            ])
        case 26:
            # RYLR-998; 197 B max Package size
            return Schema(0, 26, [
                Field('packet_id', 1, int),
                Field('ttl', 1, int),
                Field('checksum', 4, bytes),
                Field('tree_state', 1, int),
                Field('to_addr', 16, bytes),
                Field('from_addr', 16, bytes),
                Field('body', 0, bytes, 197),
            ])
        case 27:
            # RYLR-998; 256 max sequence size; 49.75 KiB max Package size
            return Schema(0, 27, [
                Field('packet_id', 1, int),
                Field('seq_id', 1, int),
                Field('seq_size', 1, int),
                Field('ttl', 1, int),
                Field('tree_state', 1, int),
                Field('to_addr', 16, bytes),
                Field('from_addr', 16, bytes),
                Field('body', 0, bytes, 199),
            ])
        case 28:
            # RYLR-998; 256 max sequence size; 48.75 KiB max Package size
            return Schema(0, 28, [
                Field('packet_id', 1, int),
                Field('seq_id', 1, int),
                Field('seq_size', 1, int),
                Field('ttl', 1, int),
                Field('checksum', 4, bytes),
                Field('tree_state', 1, int),
                Field('to_addr', 16, bytes),
                Field('from_addr', 16, bytes),
                Field('body', 0, bytes, 195),
            ])
        case 29:
            # RYLR-998; 65536 max sequence size; 12.3125 MiB max Package size
            return Schema(0, 29, [
                Field('packet_id', 2, int),
                Field('seq_id', 1, int),
                Field('seq_size', 2, int),
                Field('ttl', 1, int),
                Field('tree_state', 1, int),
                Field('to_addr', 16, bytes),
                Field('from_addr', 16, bytes),
                Field('body', 0, bytes, 197),
            ])
        case 30:
            # RYLR-998; 65536 max sequence size; 12.0625 MiB max Package size
            return Schema(0, 30, [
                Field('packet_id', 2, int),
                Field('seq_id', 1, int),
                Field('seq_size', 2, int),
                Field('ttl', 1, int),
                Field('checksum', 4, bytes),
                Field('tree_state', 1, int),
                Field('to_addr', 16, bytes),
                Field('from_addr', 16, bytes),
                Field('body', 0, bytes, 193),
            ])

def get_schemas(ids: list[int]) -> list[Schema]:
    """Get a list of Schema definitions with the given ids."""
    return [get_schema(i) for i in ids]

def schema_supports_sequence(schema: Schema) -> bool:
    """Determine if a Schema supports sequencing."""
    return len([True for field in schema.fields if field.name == 'packet_id']) == 1 \
        and len([True for field in schema.fields if field.name == 'seq_id'])  == 1 \
        and len([True for field in schema.fields if field.name == 'seq_size'])  == 1 \
        and len([True for field in schema.fields if field.name == 'body'])  == 1

def schema_supports_routing(schema: Schema) -> bool:
    """Determine if a Schema supports routing."""
    return len([True for f in schema.fields if f.name == 'ttl']) == 1


SCHEMA_IDS: list[int] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
SCHEMA_IDS_SUPPORT_SEQUENCE: list[int] = [
    i for i in SCHEMA_IDS
    if len([True for f in get_schema(i).fields if f.name == 'seq_size'])
]
SCHEMA_IDS_SUPPORT_ROUTING: list[int] = [
    i for i in SCHEMA_IDS
    if len([True for f in get_schema(i).fields if f.name == 'ttl'])
]
SCHEMA_IDS_SUPPORT_CHECKSUM: list[int] = [
    i for i in SCHEMA_IDS
    if len([True for f in get_schema(i).fields if f.name == 'checksum'])
]


class Packet:
    schema: Schema
    id: int
    flags: Flags
    body: bytes|bytearray
    fields: dict[str, int|bytes|bytearray]

    def __init__(self, schema: Schema, flags: Flags,
                 fields: dict[str, int|bytes|bytearray]) -> None:
        self.schema = schema
        self.flags = flags
        self.fields = fields

    @classmethod
    def unpack(cls, schema: Schema, data: bytes|bytearray) -> Packet:
        fields = schema.unpack(data)
        return cls(schema, fields['flags'], fields)

    def pack(self) -> bytes|bytearray:
        return self.schema.pack(self.flags, self.fields)

    @property
    def id(self) -> int:
        return self.fields['packet_id']

    @id.setter
    def id(self, data: int):
        self.fields['packet_id'] = data

    @property
    def body(self) -> bytes|bytearray:
        return self.fields.get('body', b'')

    @body.setter
    def body(self, data: bytes|bytearray):
        self.fields['body'] = data

    def set_checksum(self):
        """Set the checksum field to the crc32 of the body. Raises
            AssertionError if the Schema supports checksums.
        """
        assert len([True for f in self.schema.fields if f.name == 'checksum']), \
            f'Schema(id={self.schema.id}) does not support setting the checksum'
        self.fields['checksum'] = crc32(self.body).to_bytes(4, 'big')

    def __repr__(self) -> str:
        return f'Packet(schema.id={self.schema.id}, id={self.id}, ' + \
            f'flags={self.flags}, body={self.body.hex()})'


class Sequence:
    schema: Schema
    id: int
    data: bytearray|memoryview
    data_size: int|None
    seq_size: int # equal to actual seq_size-1; i.e. seq_size=0 means 1 packet
    max_body: int
    fields: dict[str, int|bytes|bytearray|memoryview|Flags]
    packets: set[int]

    def __init__(self, schema: Schema, id: int, data_size: int = None,
                 seq_size: int = None) -> None:
        """Initialize the Sequence. Raises AssertionError for data_size
            or seq_size that cannot be supported by the Schema, or if
            the Schema does not support sequencing.
        """
        assert schema_supports_sequence(schema), \
            'schema must include packet_id, seq_id, seq_size, and body to make a Sequence'
        assert 0 <= id < 256, 'sequence id must be between 0 and 255'
        assert data_size is None or 0 <= data_size, 'data_size cannot be negative'
        self.max_body = [f for f in schema.fields if f.name == 'body'][0].max_length
        assert data_size is None or data_size < 2**([
            field for field in schema.fields
            if field.name == 'seq_size'
        ][0].length*8)*self.max_body, f'data_size {data_size} too large for schema(id={schema.id})'
        assert seq_size is None or seq_size < 2**([
            field for field in schema.fields
            if field.name == 'seq_size'
        ][0].length*8), f'seq_size too large for schema(id={schema.id})'
        self.schema = schema
        self.id = id
        self.data_size = data_size
        self.data = bytearray(data_size) if data_size else bytearray(seq_size * self.max_body)
        self.packets = set()
        self.seq_size = ceil(data_size/self.max_body) if data_size else seq_size or 0
        self.fields = {}

    def set_data(self, data: bytes) -> None:
        """Sets the data for the sequence. Raises AssertionError if it
            is too large to be supported by the Schema.
        """
        size = len(data)
        max_seq_size = 2**([
            f for f in self.schema.fields
            if f.name == 'seq_size'
        ][0].length*8)
        assert size <= max_seq_size * self.max_body, \
            f'data is too large to fit into sequence of schema(id={self.schema.id})'
        if size != len(self.data):
            # copy the data into a fresh buffer
            self.data = bytearray(data)
        else:
            # overwrite current buffer
            self.data[:] = data[:]
        self.seq_size = ceil(size/self.max_body)
        self.packets = set([i for i in range(self.seq_size)])

    def get_packet(self, id: int, flags: Flags, fields: dict[str, int|bytes|Flags]) -> Packet|None:
        """Get the packet with the id (index within the sequence). Uses
            and modifies the fields dict memory in-place. If the packet
            has not been seen, return None. If the packet has been seen,
            return the Packet.
        """
        if id not in self.packets:
            return None

        offset = id * self.max_body
        size = len(self.data)
        bs = self.max_body if offset + self.max_body <= len(self.data) else size - offset
        fields['body'] = self.data[offset:offset+bs]
        fields['packet_id'] = id
        fields['seq_id'] = self.id
        fields['seq_size'] = self.seq_size - 1
        if id in (0, self.seq_size-1, self.seq_size/2):
            flags.ask = True
        return Packet(self.schema, flags, fields)

    def add_packet(self, packet: Packet) -> bool:
        """Adds a packet, writing its body into the data buffer. Returns
            True if all packets in the sequence have been merged in and
            False otherwise.
        """
        self.packets.add(packet.id)
        offset = packet.id * self.max_body
        bs = len(packet.body)
        self.data[offset:offset+bs] = packet.body
        if packet.id == self.seq_size - 1:
            trim = self.max_body - len(packet.body)
            self.data = self.data[:-trim]
        return len(self.packets) == self.seq_size

    def get_missing(self) -> set[int]:
        """Returns a set of IDs of missing packets. Sequence size must
            be set for this to work.
        """
        return set() if self.seq_size is None else set([i for i in range(self.seq_size)]).difference(self.packets)


class Package:
    app_id: bytes|bytearray|memoryview
    half_sha256: bytes|bytearray|memoryview
    blob: bytes|bytearray|memoryview|None

    def __init__(self, app_id: bytes|bytearray|memoryview, half_sha256: bytes|bytearray,
                 blob: bytes|bytearray|None) -> None:
        assert type(app_id) in (bytes, bytearray, memoryview) and len(app_id) == 16
        assert type(half_sha256) in (bytes, bytearray, memoryview) and len(half_sha256) == 16
        assert type(blob) in (bytes, bytearray, memoryview) or blob is None
        self.app_id = app_id
        self.half_sha256 = half_sha256
        self.blob = blob

    def verify(self) -> bool:
        return sha256(self.blob).digest()[:16] == self.half_sha256

    @classmethod
    def from_blob(cls, app_id: bytes|bytearray, blob: bytes|bytearray) -> Package:
        half_sha256 = sha256(blob).digest()[:16]
        return cls(app_id, half_sha256, blob)

    @classmethod
    def from_sequence(cls, seq: Sequence) -> Package:
        assert len(seq.get_missing()) == 0
        app_id = seq.data[:16]
        half_sha256 = seq.data[16:32]
        blob = seq.data[32:]
        return cls(app_id, half_sha256, blob)


class Packager:
    def broadcast(self, blob: bytes):
        ...
