from binascii import crc32
from collections import namedtuple, deque
from hashlib import sha256
from math import ceil
from random import randint
from struct import pack, unpack
from time import time
import asyncio
import micropython

try:
    from typing import Callable
except ImportError:
    ...

try:
    from types import GeneratorType
except ImportError:
    GeneratorType = type((lambda: (yield))())

try:
    from machine import lightsleep # type: ignore
except ImportError:
    from time import sleep
    def lightsleep(ms):
        sleep(ms/1000)

if hasattr(asyncio, 'coroutines'):
    def iscoroutine(c):
        return asyncio.coroutines.iscoroutine(c)
else:
    def iscoroutine(c):
        return isinstance(c, GeneratorType)


VERSION = micropython._const(0)


Field = namedtuple("Field", ["name", "length", "type", "max_length"], defaults=(0,))


@micropython.native
class Flags:
    error: bool
    throttle: bool
    ask: bool
    ack: bool
    rtx: bool
    rns: bool
    nia: bool
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
    def _bit2(self) -> bool:
        return bool(self.state & 0b00100000)
    @_bit2.setter
    def _bit2(self, val):
        if val:
            self.state |= 0b00100000
        else:
            self.state &= 0b11011111

    @property
    def _bit3(self) -> bool:
        return bool(self.state & 0b00010000)
    @_bit3.setter
    def _bit3(self, val):
        if val:
            self.state |= 0b00010000
        else:
            self.state &= 0b11101111

    @property
    def _bit4(self) -> bool:
        return bool(self.state & 0b00001000)
    @_bit4.setter
    def _bit4(self, val):
        if val:
            self.state |= 0b00001000
        else:
            self.state &= 0b11110111

    @property
    def ask(self) -> bool:
        return not self._bit2 and not self._bit3 and self._bit4
    @ask.setter
    def ask(self, val: bool):
        self._bit2 = False
        self._bit3 = False
        self._bit4 = val

    @property
    def ack(self) -> bool:
        return not self._bit2 and self._bit3 and not self._bit4
    @ack.setter
    def ack(self, val: bool):
        self._bit2 = False
        self._bit3 = val
        self._bit4 = False

    @property
    def rtx(self) -> bool:
        return not self._bit2 and self._bit3 and self._bit4
    @rtx.setter
    def rtx(self, val: bool):
        self._bit2 = False
        self._bit3 = val
        self._bit4 = val

    @property
    def rns(self) -> bool:
        return self._bit2 and not self._bit3 and not self._bit4
    @rns.setter
    def rns(self, val: bool):
        self._bit2 = val
        self._bit3 = False
        self._bit4 = False

    @property
    def nia(self) -> bool:
        return self._bit2 and not self._bit3 and self._bit4
    @nia.setter
    def nia(self, val: bool):
        self._bit2 = val
        self._bit3 = False
        self._bit4 = val

    @property
    def encoded6(self) -> bool:
        return self._bit2 and self._bit3 and self._bit4
    @encoded6.setter
    def encoded6(self, val: bool):
        self._bit2 = val
        self._bit3 = val
        self._bit4 = val

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
            f'rns={self.rns}, nia={self.nia}, encoded6={self.encoded6}, ' +\
            f'reserved1={self.reserved1}, reserved2={self.reserved2}, mode={self.mode})'

    def __eq__(self, other: 'Flags') -> bool:
        return self.state == other.state


@micropython.native
class Schema:
    """Describes a packet schema."""
    version: int
    reserved: int = 0
    id: int
    fields: list[Field]
    max_body: int
    max_seq: int

    def __init__(self, version: int, id: int, fields: list[Field]) -> None:
        self.version = version
        self.id = id
        # variable length field can only be last
        assert all([field.length > 0 for field in fields[:-1]])
        self.fields = fields
        self.max_body = [f.max_length for f in self.fields if f.name == 'body'][0]
        max_seq = [f.length for f in self.fields if f.name == 'seq_size']
        self.max_seq = 2**(max_seq[0]*8) if max_seq else 1

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
                    assert len(val) <= field.max_length, f'{field.name}: {val} too large'
                else:
                    assert len(val) == field.length, f'{field.name}: {val} invalid length'
            if type(val) is int:
                val = val.to_bytes(field.length, 'big')
            parts.append(bytes(val))

            if field.length == 1:
                format_str += 'c'
            else:
                if field.max_length:
                    format_str += f'{len(val)}s'
                else:
                    format_str += f'{field.length}s'
        return pack(format_str, *parts)

    @property
    def max_blob(self) -> int:
        """Returns the max blob size the Schema can support transmitting."""
        return self.max_seq * self.max_body

@micropython.native
def get_schema(id: int) -> Schema:
    """Get the Schema definition with the given id."""
    if id == 0:
        # ESP-NOW; 245 B max Package size
        return Schema(0, 0, [
            Field('packet_id', 1, int),
            Field('body', 0, bytes, 245),
        ])
    if id == 1:
        # ESP-NOW; 241 B max Package size
        return Schema(0, 1, [
            Field('packet_id', 1, int),
            Field('checksum', 4, bytes),
            Field('body', 0, bytes, 241),
        ])
    if id == 2:
        # ESP-NOW; 256 max sequence size; 60.75 KiB max Package size
        return Schema(0, 2, [
            Field('packet_id', 1, int),
            Field('seq_id', 1, int),
            Field('seq_size', 1, int),
            Field('body', 0, bytes, 243),
        ])
    if id == 3:
        # ESP-NOW; 256 max sequence size; 59.75 KiB max Package size
        return Schema(0, 3, [
            Field('packet_id', 1, int),
            Field('seq_id', 1, int),
            Field('seq_size', 1, int),
            Field('checksum', 4, bytes),
            Field('body', 0, bytes, 239),
        ])
    if id == 4:
        # ESP-NOW; 65536 max sequence size; 14.8125 MiB max Package size
        return Schema(0, 4, [
            Field('packet_id', 2, int),
            Field('seq_id', 1, int),
            Field('seq_size', 2, int),
            Field('checksum', 4, bytes),
            Field('body', 0, bytes, 237),
        ])
    if id == 5:
        # ESP-NOW; 211 B max Package size
        return Schema(0, 5, [
            Field('packet_id', 1, int),
            Field('ttl', 1, int),
            Field('tree_state', 1, int),
            Field('to_addr', 16, bytes),
            Field('from_addr', 16, bytes),
            Field('body', 0, bytes, 211),
        ])
    if id == 6:
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
    if id == 7:
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
    if id == 8:
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
    if id == 9:
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
    if id == 10:
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
    if id == 20:
        # RYLR-998; 235 B max Package size
        return Schema(0, 20, [
            Field('packet_id', 1, int),
            Field('body', 0, bytes, 235),
        ])
    if id == 21:
        # RYLR-998; 231 B max Package size
        return Schema(0, 21, [
            Field('packet_id', 1, int),
            Field('checksum', 4, bytes),
            Field('body', 0, bytes, 231),
        ])
    if id == 22:
        # RYLR-998; 256 max sequence size; 53.25 KiB max Package size
        return Schema(0, 22, [
            Field('packet_id', 1, int),
            Field('seq_id', 1, int),
            Field('seq_size', 1, int),
            Field('body', 0, bytes, 233),
        ])
    if id == 23:
        # RYLR-998; 256 max sequence size; 57.25 KiB max Package size
        return Schema(0, 23, [
            Field('packet_id', 1, int),
            Field('seq_id', 1, int),
            Field('seq_size', 1, int),
            Field('checksum', 4, bytes),
            Field('body', 0, bytes, 229),
        ])
    if id == 24:
        # RYLR-998; 65536 max sequence size; 14.1875 MiB max Package size
        return Schema(0, 24, [
            Field('packet_id', 2, int),
            Field('seq_id', 1, int),
            Field('seq_size', 2, int),
            Field('checksum', 4, bytes),
            Field('body', 0, bytes, 227),
        ])
    if id == 25:
        # RYLR-998; 201 B max Package size
        return Schema(0, 25, [
            Field('packet_id', 1, int),
            Field('ttl', 1, int),
            Field('tree_state', 1, int),
            Field('to_addr', 16, bytes),
            Field('from_addr', 16, bytes),
            Field('body', 0, bytes, 201),
        ])
    if id == 26:
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
    if id == 27:
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
    if id == 28:
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
    if id == 29:
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
    if id == 30:
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

@micropython.native
def get_schemas(ids: list[int]) -> list[Schema]:
    """Get a list of Schema definitions with the given ids."""
    return [get_schema(i) for i in ids]

@micropython.native
def schema_supports_sequence(schema: Schema) -> bool:
    """Determine if a Schema supports sequencing."""
    return len([True for field in schema.fields if field.name == 'packet_id']) == 1 \
        and len([True for field in schema.fields if field.name == 'seq_id'])  == 1 \
        and len([True for field in schema.fields if field.name == 'seq_size'])  == 1 \
        and len([True for field in schema.fields if field.name == 'body'])  == 1

@micropython.native
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


@micropython.native
class Packet:
    schema: Schema
    id: int
    flags: Flags
    body: bytes|bytearray|memoryview
    fields: dict[str, int|bytes|bytearray]

    def __init__(self, schema: Schema, flags: Flags,
                 fields: dict[str, int|bytes|bytearray]) -> None:
        self.schema = schema
        self.flags = flags
        self.fields = fields

    @classmethod
    def unpack(cls, data: bytes|bytearray) -> 'Packet':
        version, reserved, schema_id, flags, _ = unpack(f'!BBBB{len(data)-4}s', data)
        assert version <= VERSION, 'unsupported version encountered'
        schema = get_schema(schema_id)
        fields = schema.unpack(data)
        return cls(schema, Flags(flags), fields)

    def pack(self) -> bytes|bytearray:
        return self.schema.pack(self.flags, self.fields)

    @property
    def id(self) -> int:
        return self.fields['packet_id']

    @id.setter
    def id(self, data: int):
        self.fields['packet_id'] = data

    @property
    def body(self) -> bytes|bytearray|memoryview:
        return self.fields.get('body', b'')

    @body.setter
    def body(self, data: bytes|bytearray|memoryview):
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


@micropython.native
class Sequence:
    schema: Schema
    id: int
    data: bytearray|memoryview
    data_size: int|None
    seq_size: int # equal to actual seq_size-1; i.e. seq_size=0 means 1 packet
    max_body: int
    fields: dict[str, int|bytes|bytearray|memoryview|Flags]
    packets: set[int]
    tx_intrfcs_tried: set[str]

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
        self.tx_intrfcs_tried = set()

    def set_data(self, data: bytes|bytearray|memoryview) -> None:
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
        """Get the packet with the id (index within the sequence).
            Copies the field dict before modifying. If the packet has
            not been seen, return None. If the packet has been seen,
            return the Packet. Packet body will be a memoryview to
            conserve memory, but it is not readonly because micropython
            does not yet support readonly memoryview.
        """
        if id not in self.packets:
            return None

        offset = id * self.max_body
        size = len(self.data)
        bs = self.max_body if offset + self.max_body <= len(self.data) else size - offset
        fields = {
            k:v for k,v in fields.items()
        }
        fields['body'] = memoryview(self.data)[offset:offset+bs]
        fields['packet_id'] = id
        fields['seq_id'] = self.id
        fields['seq_size'] = self.seq_size - 1
        if id in (0, self.seq_size-1, self.seq_size//2):
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


@micropython.native
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
    def from_blob(cls, app_id: bytes|bytearray, blob: bytes|bytearray) -> 'Package':
        """Generate a Package using an app_id and a blob."""
        half_sha256 = sha256(blob).digest()[:16]
        return cls(app_id, half_sha256, blob)

    @classmethod
    def from_sequence(cls, seq: Sequence) -> 'Package':
        """Generate a Package using a completed sequence. Raises
            AssertionError if the sequence is missing packets.
        """
        assert len(seq.get_missing()) == 0
        return cls.unpack(seq.data)

    def pack(self) -> bytes:
        """Serialize a Package into bytes."""
        return pack(f'!16s16s{len(self.blob)}s', self.app_id, self.half_sha256, self.blob)

    @classmethod
    def unpack(cls, data: bytes) -> 'Package':
        """Deserialize a Package from bytes."""
        app_id, half_sha256, blob = unpack(f'!16s16s{len(data)-32}s', data)
        return cls(app_id, half_sha256, blob)


@micropython.native
class Datagram:
    data: bytes
    intrfc_id: bytes|None
    addr: bytes|None
    def __init__(self, data: bytes, intrfc_id: bytes|None = None, addr: bytes|None = None) -> None:
        self.data = data
        self.intrfc_id = intrfc_id
        self.addr = addr


@micropython.native
class Interface:
    name: str
    supported_schemas: list[int]
    default_schema: Schema
    bitrate: int
    id: bytes
    inbox: deque[Datagram]
    outbox: deque[Datagram]
    castbox: deque[Datagram]
    receive_func: Callable|None
    receive_func_async: Callable|None
    send_func: Callable|None
    send_func_async: Callable|None
    broadcast_func: Callable|None
    broadcast_func_async: Callable|None

    def __init__(self, name: str, bitrate: int, configure: Callable,
                 supported_schemas: list[int], receive_func: Callable = None,
                 send_func: Callable = None, broadcast_func: Callable = None,
                 receive_func_async: Callable = None,
                 send_func_async: Callable = None,
                 broadcast_func_async: Callable = None) -> None:
        """Initialize an Interface. Note that the 0th item in the
            supported_schemas argument is used as the default Schema ID.
        """
        self.inbox = deque()
        self.outbox = deque()
        self.castbox = deque()
        self.name = name
        self._configure = configure
        self.bitrate = bitrate
        self.supported_schemas = supported_schemas
        self.default_schema = get_schema(supported_schemas[0])
        self.id = sha256(
            name.encode() + bitrate.to_bytes(4, 'big') +
            b''.join([i.to_bytes(1, 'big') for i in supported_schemas])
        ).digest()[:4]
        self.receive_func = receive_func
        self.send_func = send_func
        self.broadcast_func = broadcast_func
        self.receive_func_async = receive_func_async
        self.send_func_async = send_func_async
        self.broadcast_func_async = broadcast_func_async

    def configure(self, data: dict) -> None:
        """Call the configure callback, passing self and data."""
        self._configure(self, data)

    def receive(self) -> Datagram|None:
        """Returns a datagram if there is one or None."""
        return self.inbox.popleft() if len(self.inbox) else None

    def send(self, datagram: Datagram) -> None:
        """Puts a datagram into the outbox."""
        self.outbox.append(datagram)

    def broadcast(self, datagram: Datagram) -> None:
        """Puts a datagram into the castbox."""
        self.castbox.append(datagram)

    async def process(self):
        """Process Interface actions."""
        if self.receive_func:
            datagram = self.receive_func(self)
            if datagram:
                self.inbox.append(datagram)
        elif self.receive_func_async:
            datagram = await self.receive_func_async(self)
            if datagram:
                self.inbox.append(datagram)

        if len(self.outbox):
            if self.send_func:
                self.send_func(self.outbox.popleft())
            elif self.send_func_async:
                await self.send_func_async(self.outbox.popleft())

        if len(self.castbox):
            if self.broadcast_func:
                self.broadcast_func(self.castbox.popleft())
            elif self.broadcast_func_async:
                await self.broadcast_func_async(self.castbox.popleft())

    def validate(self) -> bool:
        """Returns False if the interface does not have all required methods
            and attributes, or if they are not the proper types. Otherwise
            returns True.
        """
        if not hasattr(self, 'supported_schemas') or \
            type(self.supported_schemas) is not list or \
            not all([type(i) is int for i in self.supported_schemas]):
            return False
        if not callable(self._configure):
            return False
        if not callable(self.send_func) and not callable(self.send_func_async):
            return False
        if not callable(self.receive_func) and not callable(self.receive_func_async):
            return False
        if not callable(self.broadcast_func) and not callable(self.broadcast_func_async):
            return False
        return True


@micropython.native
class Address:
    tree_state: bytes
    address: bytes

    def __init__(self, tree_state: bytes, address: bytes) -> None:
        self.tree_state = tree_state
        self.address = address


@micropython.native
class Peer:
    """Class for tracking local peer connectivity info. Peer id should
        be a public key, and interfaces must be a dict mapping MAC
        address bytes to associated Interface.
    """
    id: bytes
    interfaces: list[tuple[bytes, Interface],]
    addrs: deque[Address]
    timeout: int # drop peers that turn off
    throttle: int # congestion control
    last_rx: int # timestamp of last received transmission
    can_tx: bool
    queue: deque[Datagram] # queue of Packets or seq_id to send

    def __init__(self, id: bytes, interfaces: list[tuple[bytes, Interface],]) -> None:
        self.id = id
        self.interfaces = interfaces
        self.addrs = deque()
        self.timeout = 4
        self.throttle = 0
        self.last_rx = int(time() * 1000)
        self.queue = deque([], 10)

    def set_addr(self, addr: Address):
        self.addrs.append(addr)
        while len(self.addrs) > 2:
            self.addrs.popleft()

    @property
    def can_tx(self) -> bool:
        return self.last_rx + 800 > int(time() * 1000)


@micropython.native
class Node:
    """Class for tracking nodes and the apps they support."""
    id: bytes
    apps: list[bytes]

    def __init__(self, id: bytes, apps: list[bytes] = []) -> None:
        self.id = id
        self.apps = apps


@micropython.native
class Application:
    name: str
    description: str
    version: int
    id: bytes
    receive_func: Callable
    callbacks: dict[str, Callable]

    def __init__(self, name: str, description: str, version: int,
                 receive_func: Callable, callbacks: dict = {}) -> None:
        self.name = name
        self.description = description
        self.version = version
        name = name.encode()
        description = description.encode()
        self.id = sha256(pack(
            f'!{len(name)}s{len(description)}sI',
            name,
            description,
            version
        )).digest()[:16]
        self.receive_func = receive_func
        self.callbacks = callbacks

    def receive(self, blob: bytes, intrfc: Interface, mac: bytes):
        """Passes self, blob, and intrfc to the receive_func callback."""
        self.receive_func(self, blob, intrfc, mac)

    def available(self, name: str|None = None) -> list[str]|bool:
        """If name is passed, returns True if there is a callback with
            that name and False if there is not. Otherwise, return a
            list[str] of callback names.
        """
        return name in self.callbacks if name else [n for n in self.callbacks]

    def invoke(self, name: str, *args, **kwargs):
        """Tries to invoke the named callback, passing self, args, and
            kwargs. Returns None if the callback does not exist or the
            result of the function call. If the callback is async, a
            coroutine will be returned.
        """
        return (self.callbacks[name](self, *args, **kwargs)) if name in self.callbacks else None


@micropython.native
class Event:
    ts: int # in milliseconds
    id: bytes
    handler: Callable
    args: tuple
    kwargs: dict
    def __init__(self, ts: int, id: bytes, handler: Callable,
                 *args, **kwargs) -> None:
        self.ts = ts
        self.id = id
        self.handler = handler
        self.args = args
        self.kwargs = kwargs
    def __repr__(self) -> str:
        return f'Event(ts={self.ts}, id=0x{self.id.hex()}, ' + \
            f'handler={self.handler}, args={self.args}, kwargs={self.kwargs})'


@micropython.native
class InSequence:
    seq: Sequence
    src: bytes|Address
    retry: int
    intrfc: Interface
    def __init__(self, seq: Sequence, src: bytes|Address, intrfc: Interface) -> None:
        self.seq = seq
        self.src = src
        self.intrfc = intrfc
        self.retry = 2


@micropython.native
class Packager:
    interfaces: list[Interface] = []
    seq_id: int = 0
    packet_id: int = 0
    seq_cache: dict[int, Sequence] = {} # to-do
    apps: dict[bytes, object] = {}
    in_seqs: dict[int, InSequence] = {}
    peers: dict[bytes, Peer] = {}
    routes: dict[Address, bytes] = {}
    node_id: bytes = b''
    node_addrs: deque[Address] = deque()
    apps: dict[bytes, Application] = {}
    schedule: dict[bytes, Event] = {}
    new_events: deque[Event] = deque([], 64)
    cancel_events: deque[bytes] = deque([], 64)
    running: bool = False
    sleepskip: deque[bool] = deque([], 20)

    @classmethod
    def add_interface(cls, interface: Interface):
        """Adds an interface. Raises AssertionError if it does not meet
            the requirements for a network interface.
        """
        assert interface.validate()
        cls.interfaces.append(interface)

    @classmethod
    def remove_interface(cls, interface: Interface):
        """Removes a network interface."""
        cls.interfaces.remove(interface)

    @classmethod
    def add_peer(cls, peer_id: bytes, interfaces: list[tuple[bytes, Interface],]):
        """Adds a peer to the local peer list. Packager will be able to
            send Packages to all such peers.
        """
        if peer_id not in cls.peers:
            cls.peers[peer_id] = Peer(peer_id, interfaces)
        for mac, intrfc in interfaces:
            if mac not in (i[0] for i in cls.peers[peer_id].interfaces):
                cls.peers[peer_id].interfaces[mac] = intrfc

    @classmethod
    def remove_peer(cls, peer_id: bytes):
        """Removes a peer from the local peer list. Packager will be
            unable to send Packages to this peer.
        """
        if peer_id in cls.peers:
            peer = cls.peers.pop(peer_id)
            for addr in peer.addrs:
                if addr in cls.routes:
                    cls.routes.pop(addr)

    @classmethod
    def add_route(cls, node_id: bytes, address: Address):
        """Adds an address for a peer. Will also store the previous
            Address for the peer to maintain routability during tree
            state transitions.
        """
        if node_id in cls.peers:
            addrs = cls.peers[node_id].addrs
            if len(addrs) > 1 and address not in addrs:
                cls.routes.pop(addrs[0])
            if address not in addrs:
                cls.peers[node_id].set_addr(address)
        cls.routes[address] = node_id

    @classmethod
    def remove_route(cls, address: Address):
        """Removes the route to the peer with the given address."""
        if address in cls.routes:
            cls.routes.pop(address)

    @classmethod
    def set_addr(cls, addr: Address):
        """Sets the current tree embedding address for this node,
            preserving the previous address to maintain routability
            between tree state transitions.
        """
        cls.node_addrs.append(addr)
        while len(cls.node_addrs) > 2:
            cls.node_addrs.popleft()

    @classmethod
    def broadcast(cls, app_id: bytes, blob: bytes, interface: Interface|None = None) -> bool:
        """Create a Package from the blob and broadcast it on all
            interfaces that support broadcast. Uses the schema supported
            by all interfaces. Returns False if no schemas could be
            found that are supported by all interfaces.
        """
        schema: Schema
        chosen_intrfcs: list[Interface]
        if interface:
            schemas = [
                s for s in get_schemas(interface.supported_schemas)
                if s.max_blob >= len(blob) + 32
            ]
            schema = schemas.sort(key=lambda s: s.max_body, reverse=True)[0]
            chosen_intrfcs = [interface]
        else:
            # use only a schema supported by all interfaces
            schemas = set(cls.interfaces[0].supported_schemas)
            for interface in cls.interfaces:
                schemas.intersection_update(set(interface.supported_schemas))
            schemas = [s for s in get_schemas(list(schemas)) if s.max_blob >= len(blob) + 32]
            if len(schemas) == 0:
                return False
            # choose the schema with the largest body size
            schemas.sort(key=lambda s: s.max_body, reverse=True)
            schema = schemas[0]
            chosen_intrfcs = cls.interfaces

        p = Package.from_blob(app_id, blob).pack()
        fl = Flags(0)
        fields = {'body':p, 'packet_id': cls.packet_id, 'seq_id': cls.seq_id, 'seq_size': 1}
        p1 = Packet(schema, fl, fields)
        # try to send as a single packet if possible
        try:
            if len(p1.pack()) <= schema.max_body:
                packets = [p1]
            else:
                raise ValueError()
        except:
            s = Sequence(schema, cls.seq_id, len(p))
            s.set_data(p)
            packets = [s.get_packet(i, fl, fields) for i in range(s.seq_size)]
            cls.seq_cache[cls.seq_id] = s
            cls.seq_id = (cls.seq_id + 1) % 256

        for intrfc in chosen_intrfcs:
            br = intrfc.broadcast
            for p in packets:
                br(Datagram(p.pack()))
        return True

    @classmethod
    def send(cls, app_id: bytes, blob: bytes, node_id: bytes, schema: int = None) -> bool:
        """Attempts to send a Package containing the app_id and blob to
            the specified node. Returns True if it can be sent and False
            if it cannot (i.e. if it is not a known peer and there is
            not a known route to the node).
        """
        islocal = node_id in cls.peers
        if not islocal and node_id not in [r for a, r in cls.routes.items()]:
            return False

        p = Package.from_blob(app_id, blob).pack()
        schema: Schema = None
        if islocal:
            peer = cls.peers[node_id]
        else:
            # to-do: routing
            # for now, pick one at random
            addrs = [
                a for a, p in cls.routes.items()
                if p in cls.peers
            ]
            addrs.sort(key=lambda _: randint(0, 255))
            addr = addrs[-1]
            peer_id = cls.routes[addr]
            peer = cls.peers[peer_id]

        intrfcs = peer.interfaces
        sids = set(intrfcs[0][1].supported_schemas)
        for _, ntrfc in intrfcs:
            sids.intersection_update(set(ntrfc.supported_schemas))
        sids = get_schemas(list(sids))
        sids = [s for s in sids if s.max_blob >= len(p)]
        sids.sort(key=lambda s: s.max_body, reverse=True)
        schema = sids[0]
        intrfcs.sort(key=lambda mi: mi[1].bitrate, reverse=True)
        intrfc = intrfcs[0]
        fields = {'body':p, 'packet_id': cls.packet_id, 'seq_id': cls.seq_id, 'seq_size': 1}
        if not islocal:
            fields = {
                k:v for k,v in fields.items()
            }
            fields['to_addr'] = addr.address
            fields['from_addr'] = cls.node_addrs[-1].address
            fields['tree_state'] = addr.tree_state
        if schema.max_blob > schema.max_body:
            seq = Sequence(schema, cls.seq_id, len(p))
            seq.set_data(p)
            for i in range(seq.seq_size):
                cls._send_datagram(Datagram(
                    seq.get_packet(i, Flags(0), fields).pack(),
                    intrfc[1].id,
                    intrfc[0]
                ), peer)
        else:
            fields['body'] = p
            cls._send_datagram(Datagram(
                Packet(schema, Flags(0), fields).pack(),
                intrfc[1].id,
                intrfc[0]
            ), peer)
            cls.packet_id = (cls.packet_id + 1) % 256

        return True

    @classmethod
    def get_interface(cls, node_id: bytes|None = None,
                             to_addr: Address|None = None,
                             exclude: list[bytes,] = []
                             ) -> tuple[bytes|None, Interface|None, Peer|None]:
        """Get the proper Interface and MAC for direct transmission to
            the neighbor with the given node_id or for direct
            transmission to the best candidate for routing toward the
            given to_addr. Returns None if neither node_id nor to_addr
            are passed or if an Interface cannot be found. If exclude is
            passed, the Interfaces for those nodes with ids specified in
            the list will be excluded from consideration.
        """
        if node_id in cls.peers and node_id not in exclude:
            # direct neighbors
            intrfcs = cls.peers[node_id].interfaces
            intrfcs.sort(key=lambda mi: mi[1].bitrate, reverse=True)
            return (intrfcs[0][0], intrfcs[0][1], cls.peers[node_id])
        elif node_id in (nid for _, nid in cls.routes.items()):
            # known node reachable via routing; find next hop
            # set to_addr
            addrs = [addr for addr, pid in cls.routes.items() if pid == node_id]
            nowaddrs = [a for a in addrs if a.tree_state == cls.node_addrs[-1].tree_state]
            if len(nowaddrs):
                to_addr = nowaddrs[0]
            to_addr = addrs[0]
        if to_addr:
            # need to route
            # to-do: routing
            # for now, pick one at random
            addrs = [
                a for a, p in cls.routes.items()
                if p in cls.peers
            ]
            addrs.sort(key=lambda _: randint(0, 255))
            addr = addrs[-1]
            peer_id = cls.routes[addr]
            if peer_id in exclude:
                return (None, None, None)
            intrfcs = cls.peers[peer_id].interfaces
            intrfcs.sort(key=lambda mi: mi[1].bitrate, reverse=True)
            return (intrfcs[0][0], intrfcs[0][1], cls.peers[peer_id])
        else:
            return (None, None, None)

    @classmethod
    def rns(cls, peer_id: bytes, intrfc_id: bytes, retries: int = 10):
        """Send RNS if one has not been sent in the last 20 ms,
            otherwise update the event.
        """
        eid = b'rns'+peer_id+intrfc_id
        now = int(time()*1000)
        if eid in [e.id for e in cls.new_events]:
            return # do not add a duplicate event

        if retries < 1:
            # clear queue and drop the attempts
            cls.peers[peer_id].queue.clear()
            return

        # queue event and send RNS
        event = Event(now+20, eid, cls.rns, peer_id, intrfc_id, retries=retries-1)
        cls.new_events.append(event)
        flags = Flags(0)
        flags.rns = True
        intrfc = [i for i in cls.interfaces if i.id == intrfc_id][0]
        mac = [
            mac for mac, i in cls.peers[peer_id].interfaces
            if i.id == intrfc_id
        ][0]
        intrfc.send(Datagram(
            Packet(intrfc.default_schema, flags, {
                'packet_id': cls.packet_id,
                'body': b'',
            }).pack(),
            intrfc_id,
            mac
        ))
        cls.packet_id = (cls.packet_id + 1) % 256

    @classmethod
    def _send_datagram(cls, dgram: Datagram, peer: Peer):
        """Sends a Datagram on the appropriate interface. Raises
            AssertionError if the interface ID is invalid.
        """
        cls.sleepskip.extend([True, True, True, True, True, True, True, True, True, True])
        assert dgram.intrfc_id in [i.id for i in cls.interfaces]
        intrfc = [i for i in cls.interfaces if i.id == dgram.intrfc_id][0]
        if peer.can_tx:
            intrfc.send(dgram)
        else:
            # queue the datagram and try sending RNS on the interface instead
            peer.queue.append(dgram)
            cls.rns(peer.id, intrfc.id)

    @classmethod
    def send_packet(cls, packet: Packet, node_id: bytes = None) -> bool:
        """Attempts to send a Packet either to a specific node or toward
            the to_addr field (decrement ttl); if flags.error is set,
            send toward the from_addr field (no ttl decrement). Returns
            False if it cannot be sent.
        """
        if node_id in cls.peers:
            # direct neighbors
            mac, intrfc, peer = cls.get_interface(node_id)
        elif node_id in (nid for _, nid in cls.routes.items()):
            # known node reachable via routing
            mac, intrfc, peer = cls.get_interface(node_id)
        elif 'to_addr' in packet.fields and 'from_addr' in packet.fields:
            # this is an intermediate hop
            to_addr = Address(packet.fields['tree_state'], packet.fields['to_addr'])
            from_addr = packet.fields['from_addr']
            if packet.flags.error:
                exclude = [cls.routes[to_addr]] if from_addr in cls.routes else []
                mac, intrfc, peer = cls.get_interface(to_addr=from_addr, exclude=exclude)
            else:
                exclude = [cls.routes[from_addr]] if from_addr in cls.routes else []
                mac, intrfc, peer = cls.get_interface(to_addr=to_addr, exclude=exclude)
                packet.fields['ttl'] -= 1

            if packet.fields['ttl'] <= 0:
                # drop the packet
                return False
        else:
            return False

        if not mac:
            return False

        cls._send_datagram(Datagram(packet.pack(), intrfc.id, mac), peer)
        return True

    @classmethod
    def sync_sequence(cls, seq_id: int):
        """Requests retransmission of any missing packets."""
        seq = cls.in_seqs[seq_id]
        if seq.retry <= 0:
            # drop sequence because the originator is not responding to rtx
            cls.in_seqs.pop(seq_id)
            return

        flags = Flags(0)
        flags.rtx = True
        fields = {
            'body': b'',
            'seq_id': seq_id,
            'seq_size': seq.seq.seq_size - 1,
        }

        if isinstance(seq.src, Address):
            tree_state = seq.src.tree_state
            from_addr = [a for a in cls.node_addrs if a.tree_state == tree_state]
            if len(from_addr) == 0:
                # drop sequence because of tree state transition
                cls.in_seqs.pop(seq_id)
                return
            fields['to_addr'] = seq.src.address
            fields['tree_state'] = tree_state
            fields['from_addr'] = from_addr[0]
            seq.src = cls.routes[seq.src]

        for pid in seq.seq.get_missing():
            fields['packet_id'] = pid
            cls.send_packet(Packet(
                seq.seq.schema,
                flags,
                fields
            ), seq.src)

        # decrement retry counter and schedule event
        seq.retry -= 1
        eid = b'SS' + seq.seq.id.to_bytes(2, 'big')
        cls.queue_event(Event(
            int(time()+30)*1000,
            eid,
            cls.sync_sequence,
            seq_id
        ))

    @classmethod
    def receive(cls, p: Packet, intrfc: Interface, mac: bytes) -> None:
        """Receives a Packet and determines what to do with it. If it is
            a routable packet, forward to the next hop using send_packet;
            if that fails, set the error flag and transmit backwards
            through the route.
        """
        cls.sleepskip.extend([True, True, True, True, True, True, True, True, True, True])
        src = b'' # source of Packet
        if 'to_addr' in p.fields:
            if p.fields['to_addr'] not in [a.address for a in cls.node_addrs]:
                # forward
                cls.send_packet(p)
                return
            else:
                # this is the intended delivery point
                if p.flags.ask:
                    # send ack
                    flags = Flags(p.flags.state)
                    flags.ask = False
                    flags.ack = True
                    fields = {
                        'packet_id': p.id,
                        'to_addr': p.fields['from_addr'],
                        'from_addr': p.fields['to_addr'],
                        'tree_state': p.fields['tree_state'],
                        'body': b'',
                    }
                    if 'seq_id' in p.fields:
                        fields['seq_size'] = p.fields['seq_size']
                        fields['seq_id'] = p.fields['seq_id']
                    cls.send_packet(Packet(
                        p.schema,
                        flags,
                        fields
                    ))
        else:
            for nid, peer in cls.peers.items():
                if mac in (i[0] for i in peer.interfaces if i[1] is intrfc):
                    src = nid
                    break

        if 'seq_id' in p.fields:
            # try to reconstitute the sequence
            # first cancel pending sequence synchronization event
            seq_id = p.fields['seq_id']
            eid = b'SS' + seq_id.to_bytes(2, 'big')
            if eid in cls.schedule:
                cls.cancel_events.append(eid)
            if seq_id not in cls.in_seqs:
                cls.in_seqs[seq_id] = InSequence(
                    Sequence(p.schema, seq_id, seq_size=p.fields['seq_size']+1),
                    src,
                    intrfc
                )
            seq = cls.in_seqs[seq_id]
            seq.retry = 3 # reset retries because the originator is reachable
            if seq.seq.add_packet(p):
                cls.deliver(Package.unpack(seq.seq.data), intrfc, mac)
                cls.in_seqs.pop(seq_id)
            else:
                # schedule sequence sync event
                cls.queue_event(Event(
                    int(time() + 30)*1000,
                    eid,
                    cls.sync_sequence,
                    seq_id
                ))
        elif p.flags.nia:
            # peer responded to RNS: cancel event, update peer.last_rx
            peer = cls.peers[src]
            eid = b'rns'+peer.id+intrfc.id
            cls.cancel_events.append(eid)
            peer.last_rx = int(time()*1000)
            return
        elif p.flags.rns:
            # peer sent RNS: send NIA
            peer = cls.peers[src]
            flags = Flags(0)
            flags.nia = True
            intrfc.send(Datagram(
                Packet(intrfc.default_schema, flags, {
                    'packet_id': cls.packet_id,
                    'body': b'',
                }).pack(),
                intrfc.id,
                mac
            ))
            cls.packet_id = (cls.packet_id + 1) % 256
            return
        else:
            # parse and deliver the Package
            cls.deliver(Package.unpack(p.body), intrfc, mac)

        if p.flags.ask:
            # send ack
            flags = Flags(p.flags.state)
            flags.ask = False
            flags.ack = True
            fields = {
                'packet_id': p.id,
                'body': b'',
            }
            if 'seq_id' in p.fields:
                fields['seq_size'] = p.fields['seq_size']
                fields['seq_id'] = p.fields['seq_id']
            cls.send_packet(Packet(
                p.schema,
                flags,
                fields
            ), src)

    @classmethod
    def deliver(cls, p: Package, i: Interface, m: bytes) -> bool:
        """Attempt to deliver a Package. Returns False if the Package
            half_sha256 is invalid for the blob, or if the Application
            was not registered, or if the Application's receive method
            errors. Otherwise returns True.
        """
        if p.half_sha256 != sha256(p.blob).digest()[:16] or p.app_id not in cls.apps:
            return False
        try:
            cls.apps[p.app_id].receive(p.blob, i, m)
            return True
        except:
            return False

    @classmethod
    def add_application(cls, app: Application):
        """Registers an Application to accept Package delivery."""
        cls.apps[app.id] = app

    @classmethod
    def remove_appliation(cls, app: Application|bytes):
        """Deregisters an Application to no longer accept Package delivery."""
        if isinstance(app, Application):
            app = app.id
        cls.apps.pop(app)

    @classmethod
    def queue_event(cls, event: Event):
        """Queues a new event. On the next call to cls.process(), it
            will be added to the schedule, overwriting any event with
            the same ID.
        """
        cls.new_events.append(event)

    @classmethod
    async def process(cls):
        """Process interface actions, then process Packager actions."""
        # schedule new events
        while len(cls.new_events):
            event = cls.new_events.popleft()
            cls.schedule[event.id] = event

        # remove all canceled events from the schedule
        while len(cls.cancel_events):
            eid = cls.cancel_events.popleft()
            cls.schedule.pop(eid)

        # process interface actions
        tasks = []
        for intrfc in cls.interfaces:
            tasks.append(intrfc.process())
        await asyncio.gather(*tasks)

        # read from interfaces
        for intrfc in cls.interfaces:
            while len(intrfc.inbox):
                dgram = intrfc.inbox.popleft()
                cls.receive(
                    Packet.unpack(dgram.data),
                    [i for i in cls.interfaces if i.id == dgram.intrfc_id][0],
                    dgram.addr
                )

        # handle scheduled events
        ce = []
        cos = []
        now = int(time()*1000)
        for eid, event in cls.schedule.items():
            if now >= event.ts:
                t = event.handler(*event.args, **event.kwargs)
                if iscoroutine(t):
                    cos.append(t)
                ce.append(eid)
        if len(cos):
            await asyncio.gather(cos)

        # remove all processed events from the schedule
        for eid in ce:
            cls.schedule.pop(eid)

        # send queued datagrams for reachable peers
        for _, peer in cls.peers.items():
            if peer.can_tx:
                while len(peer.queue):
                    dgram = peer.queue.popleft()
                    intrfc = [
                        i for _, i in peer.interfaces
                        if i.id == dgram.intrfc_id
                    ][0]
                    intrfc.send(dgram)

    @classmethod
    async def work(cls, interval_ms: int = 1, use_modem_sleep: bool = False,
                   modem_sleep_ms: int = 90, modem_active_ms: int = 40):
        """Runs the process method in a loop. If use_modem_sleep is True,
            lightsleep(modem_sleep_ms) will be called periodically to
            save battery, then the method will continue for at least
            modem_active_ms. If the sleepskip queue is not empty and the
            process is eligible for a sleep cycle, an item will be
            popped off the queue and the cycle will be skipped.
        """
        cls.running = True
        modem_cycle = 0
        ts = int(time()*1000)
        while cls.running:
            await cls.process()
            await asyncio.sleep(interval_ms / 1000)
            if use_modem_sleep:
                if len(cls.sleepskip):
                    cls.sleepskip.popleft()
                    continue
                modem_cycle = int(time()*1000) - ts
                if modem_cycle > modem_active_ms:
                    modem_cycle = 0
                    lightsleep(modem_sleep_ms)
                    ts = int(time()*1000)

    @classmethod
    def stop(cls):
        """Sets cls.running to False for graceful shutdown of worker."""
        cls.running = False


# Interface for inter-Application communication.
_iai_box: deque[Datagram] = deque([], 10)
_iai_config = {}

InterAppInterface = Interface(
    name='InterAppInterface',
    bitrate=1_000_000_000,
    configure=lambda _, d: _iai_config.update(d),
    supported_schemas=SCHEMA_IDS,
    receive_func=lambda _: _iai_box.popleft() if len(_iai_box) else None,
    send_func=lambda d: _iai_box.append(d),
    broadcast_func=lambda d: _iai_box.append(d),
)
