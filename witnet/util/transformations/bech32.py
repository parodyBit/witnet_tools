from enum import Enum
from typing import List

from witnet.util.transformations.transformations import convert_bits, normalize_string


class Bech32Encoding(Enum):
    """Enumeration type to list the various supported encodings."""
    BECH32 = 1
    BECH32M = 2


class Bech32DecodeError(Exception):
    pass


CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def bech32_poly_mod(values) -> int:
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> List[int]:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp: str, data) -> bool:
    """Verify a checksum given HRP and converted data characters."""
    return bech32_poly_mod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp: str, data):
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_poly_mod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_decode_address(bech: str):
    #print(bech)
    bech, separator = bech.lower(), bech.find('1')
    hrp_ = bech[:separator]
    # print(hrp_, bech)
    data = [CHARSET.find(x) for x in bech[separator + 1:]]
    # print(bytes(data).hex())
    decoded = data[:-6]
    try:
        if any(ord(x) < 33 or ord(x) > 126 for x in bech):
            raise Bech32DecodeError('Character outside US-ASCII [33-126] range')
        if (bech.lower() != bech) and (bech.upper() != bech):
            raise Bech32DecodeError('Mixed upper and lower case')
        if separator == 0:
            raise Bech32DecodeError('Empty human readable part')
        elif separator == -1:
            raise Bech32DecodeError('No separator character')
        elif separator + 7 > len(bech):
            raise Bech32DecodeError('Checksum too short')
        if not all(x in CHARSET for x in bech[separator + 1:]):
            raise Bech32DecodeError('Character not in charset')
        if not bech32_verify_checksum(hrp_, data):
            raise Bech32DecodeError('Invalid checksum')
        if decoded is None or len(decoded) < 2:
            raise Bech32DecodeError('Witness program too short')

    except Bech32DecodeError as error:
        print(error)

    b256 = convert_bits(decoded, from_bits=5, to_bits=8, pad=True)

    return b256


def bech32_encode_master_key(hrp: str, data: str) -> str:
    hex_bytes = [b for b in bytes.fromhex(data)]
    data = convert_bits(data=hex_bytes, from_bits=8, to_bits=5, pad=False)
    checksum = bech32_create_checksum(hrp=hrp, data=data[:-1])
    combined = data[:-1] + checksum

    return normalize_string(hrp + '1' + ''.join([CHARSET[i] for i in combined]))


def bech32_encode_address(hrp: str, data: str) -> str:
    hex_bytes = [b for b in bytes.fromhex(data)]
    data = convert_bits(data=hex_bytes, from_bits=8, to_bits=5, pad=False)

    checksum = bech32_create_checksum(hrp=hrp, data=data)

    combined = data + checksum

    return normalize_string(hrp + '1' + ''.join([CHARSET[i] for i in combined]))


def decode(hrp: str, bech: str):
    bech, separator = bech.lower(), bech.find('1')
    hrp_ = bech[:separator]
    assert hrp == hrp_

    data = [CHARSET.find(x) for x in bech[separator + 1:]]
    decoded = data[:-6]
    witness_version = data[0]
    b32 = ''.join([bin(b)[2:].zfill(5) for b in decoded])

    b256 = [int(b32[i: i + 8], 2) for i in range(0, len(b32), 8)]
    witness_program = b256
    return witness_version, witness_program


def encode(hrp: str, witver: int, witprog) -> str:
    """Encode a segwit address."""
    spec = Bech32Encoding.BECH32 if witver == 0 else Bech32Encoding.BECH32M
    ret = bech32_encode_address(hrp, [witver] + convert_bits(witprog, 8, 5), spec)
    if decode(hrp, ret) == (None, None):
        return ''
    return ret
