import hashlib

from witnet.util.transformations import concat
sha256 = lambda x: hashlib.sha256(x).digest()

TAG_TYPE_BITS = 3
TAG_TYPE_MASK = (1 << TAG_TYPE_BITS) - 1
VAR_INT = 0
FIXED64 = 1
LENGTH_DELIMITED = 2
START_GROUP = 3
END_GROUP = 4
FIXED32 = 5


def var_int(value: int):
    """
    Write unsigned `VarInt` to a file-like object.
    """
    if isinstance(value, str):
        value = int(value)
    tmp = []
    while value > 0x7F:
        tmp.append(bytes((value & 0x7F | 0x80,)))
        value >>= 7
    tmp.append(bytes((value,)))
    return concat(tmp)


def var_int_serializer(value: int):
    return var_int(value)


def bytes_serializer(value: bytes):
        return concat([var_int(len(value)), value])



def get_tag_field_number(tag: int):
    return tag >> TAG_TYPE_BITS


def get_tag_wire_type(tag: int):
    return tag & TAG_TYPE_MASK


def make_tag(field_number: int, tag: int):
    return (field_number << TAG_TYPE_BITS) | tag


def make_tag_bytes(field_number: int, tag: int):
    return var_int_serializer(make_tag(field_number, tag))


def pb_field(field_number: int, tag: int, value):
    _data = []
    if tag == VAR_INT:
        _data = concat([var_int_serializer(value=value)])
    elif tag == LENGTH_DELIMITED:
        _data = bytes_serializer(value=value)
    else:
        ...
    return concat([make_tag_bytes(field_number=field_number, tag=tag), _data])
