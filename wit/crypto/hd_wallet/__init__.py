from dataclasses import dataclass, fields
from typing import Any
from wit.crypto.ECDSA import PrivateKey
from wit.crypto.hd_wallet.extended_key import Xprv
from wit.util.transformations import bytes_to_hex
from wit.util.transformations.bech32 import bech32_decode_address, bech32_encode_master_key

@dataclass
class Field:
    val: Any


@dataclass
class Base:
    def __post_init__(self):
        for field in fields(self):
            if isinstance(field.default, Field):
                field_value = getattr(self, field.name)
                if isinstance(field_value, Field) or field_value is None:
                    setattr(self, field.name, field.default.val)




def from_slip32(master_key: str, root_path=None) -> Xprv:
    bech = bech32_decode_address(master_key)
    idx = 0
    # byte lengths of the serialized byte data
    DEPTH = 1
    INDEX = 4 * bech[idx:idx + DEPTH][0]
    CHAIN = 32
    secret_prefix = b'\x00'
    KEYLN = 32

    depth = bech[idx:idx + DEPTH]
    idx += DEPTH
    index = None
    chain_code = bytes(bech[idx:idx + CHAIN])

    idx += CHAIN
    idx += len(secret_prefix)
    key_data = bytes(bech[idx:idx + KEYLN])
    private_key = PrivateKey(key_data)
    public_key = private_key.to_public()

    chain_code = bytes(bech[1:33])
    private_key = PrivateKey(bytes(bech[34:66]))


    return Xprv(key=private_key, code=chain_code, depth=depth[0], path=root_path)




def to_slip32(master_key: Xprv) -> str:
    depth = master_key.depth
    chain_code = master_key.code
    private_key = master_key.key.bytes()

    slip_32 = int(depth).to_bytes(length=1, byteorder='big')
    slip_32 += chain_code
    slip_32 += b'\x00'
    slip_32 += private_key
    slip_32 += b'\x00'
    bech = bech32_encode_master_key(hrp='xprv', data=bytes_to_hex(slip_32))

    return bech
