from wit.crypto.ECDSA import PublicKey

from wit.util.transformations import hash160, sha256
from wit.util.transformations import int_to_bytes, bytes_to_hex
from wit.util.transformations import base58
from wit.util.transformations import bech32
from wit.witnet.address.address import Address
from wit.witnet.exceptions import ScriptValidationError, UpstreamError
from wit.witnet.network import network

from typing import Union


def witness_byte(witver: int) -> bytes:
    assert 0 <= witver <= 16, "Witness version must be between 0-16"
    return int_to_bytes(witver + 0x50 if witver > 0 else 0)


def is_witness_program(script):
    # op codes
    _0 = 0x00
    _1 = 0x51
    _16 = 0x60

    """https://github.com/bitcoin/bitcoin/blob/5961b23898ee7c0af2626c46d5d70e80136578d3/src/script/script.cpp#L221"""
    if len(script) < 4 or len(script) > 42:
        return False
    if script[0] != _0 and (script[0] < _1 or script[0] > _16):
        return False
    if script[1] < 0x02 or script[1] > 0x28:
        return False
    return True


def witness_program(script):
    if not is_witness_program(script):
        raise ScriptValidationError("Script is not a witness program")
    return script[2:]


def version_byte(script):
    if not is_witness_program(script):
        raise ScriptValidationError("Script is not a witness program")
    return script[0]


def legacy_address(pub_or_script: Union[bytes, PublicKey], version_bytes: bytes) -> str:
    """https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses"""
    bts = pub_or_script.encode(compressed=False) if isinstance(pub_or_script, PublicKey) else pub_or_script
    hashed = hash160(bts)
    payload = version_bytes + hashed
    return hashed_payload_to_address(payload)


def hashed_payload_to_address(payload):
    checksum = sha256(sha256(payload))[:4]
    address = payload + checksum
    return base58.encode(address)


def script_to_bech32(script: bytes, witver: int) -> str:
    """https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program"""
    witprog = sha256(script)
    return bech32.encode(network('hrp'), witver, witprog)


def pubkey_to_pkh(pub: PublicKey):
    return sha256(bytearray.fromhex(pub.hex(compressed=True)))[:20]


def pubkey_to_bech32(pub: PublicKey, witver: int) -> str:
    """https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program"""
    h1 = pubkey_to_pkh(pub)
    # print(f'hashlib.sha256(bytearray.fromhex({pub.hex(compressed=True)})).digest()[:20]')

    h2 = "".join([bin(nibble)[2:].zfill(8) for nibble in h1])
    h3 = [int(h2[i: i + 5], 2) for i in range(0, len(h2), 5)]

    checksum = bech32.bech32_create_checksum('wit', h3)

    h4 = h3 + checksum

    BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    address = 'wit' + "1" + "".join([BECH32_CHARSET[i] for i in h4])

    return address


def pubkey_to_address(pub: PublicKey) -> str:
    return pubkey_to_bech32(pub=pub, witver=0x00)
