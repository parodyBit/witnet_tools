import hashlib
import unicodedata
from typing import List, AnyStr, Union
sha256 = lambda x: hashlib.sha256(x).digest()
sha512 = lambda x: hashlib.sha512(x).digest()
ripemd160 = lambda x: hashlib.new('ripemd160', x).digest()
hash160 = lambda x: ripemd160(sha256(x))


Bytes = List[int]


def bin_to_bytes(b: bin) -> bytes:
    return int(b, 2).to_bytes(max((len(b) + 7) // 8, 1), byteorder='big')


def bin_to_int(b: bin) -> int:
    return int(b, 2)


def bytes_to_bin(b: bytes) -> bin:
    return ''.join((int_to_bin(i).zfill(8) for i in b))


def bytes_to_int(bts: bytes) -> int:
    return int.from_bytes(bts, 'big')


def bytes_to_hex(b: bytes):
    return b.hex()


def bytes_to_str(b: bytes) -> str:
    return b.decode('utf-8')


def int_to_bin(i: int) -> bin:
    return format(i, 'b')


def int_to_bytes(i: int) -> bytes:
    length = max(1, (i.bit_length() + 7) // 8)
    return i.to_bytes(length, 'big')


def int_to_hex(i: int) -> str:
    return format(i, 'x')


def int_to_str(i: int) -> str:
    return bytes_to_str(int_to_bytes(i))


def hex_to_bytes(h: str):
    return bytes.fromhex(h)


def hex_to_int(h: str):
    return int(h, 16)


def hex_to_str(h: str) -> str:
    return bytes_to_str(hex_to_bytes(h))


def str_to_bytes(s: str) -> bytes:
    return str.encode(s, 'utf-8')


def str_to_hex(s: str) -> str:
    return bytes_to_hex(str_to_bytes(s))


def str_to_int(s: str) -> int:
    return bytes_to_int(str_to_bytes(s))

def str_to_bool(s: str) -> bool:
    return s.lower() in ['true', '1', 'yes']

def wit_to_nano_wit(value: float) -> int:
    value = float(value * 10 ** 9)
    assert value.is_integer(), 'The smallest denomination is 1 nanoWIT or 10^-9 WIT'
    return int(value)


def nano_wit_to_wit(value: int) -> float:
    value = float(value / 10 ** 9)
    return float(value)


class BaseConversionError(Exception):
    pass


def convert_bits(data: Bytes, from_bits: int, to_bits: int, pad=True) -> Bytes:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    max_v = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or (value >> from_bits):
            raise BaseConversionError
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & max_v)
    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & max_v)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & max_v):

        raise BaseConversionError
    return ret


def normalize_string(txt: AnyStr) -> str:
    if isinstance(txt, bytes):
        utxt = txt.decode('utf8')
    elif isinstance(txt, str):
        utxt = txt
    else:
        raise TypeError('String value expected')

    return unicodedata.normalize('NFKD', utxt)


def concat(values: Union[List[str], List[bytes]]) -> Union[str, bytes]:
    if isinstance(values[0], str):
        return concat_string(values)
    elif isinstance(values[0], bytes):
        return concat_bytes(values)


def concat_string(values: List[str]) -> str:
    return ''.join(values)


def concat_bytes(values: List[bytes]) -> bytes:
    return b''.join(values)
