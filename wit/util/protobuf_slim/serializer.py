from .types import uint, uint32, uint64
from wit.util.transformations import concat
from typing import Union


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


def var_int_serializer(value: Union[uint, uint32, uint64]):
    return var_int(value)


def bytes_serializer(value: bytes):
    return concat([var_int(uint(len(value))), value])
