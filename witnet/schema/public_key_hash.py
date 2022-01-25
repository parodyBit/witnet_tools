from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED
from witnet.util.transformations import bytes_to_hex, sha256
from witnet.util.transformations.bech32 import bech32_decode_address, bech32_encode_address


@dataclass
class PublicKeyHash:
    hash: bytes

    @classmethod
    def from_address(cls, data: str):

        return PublicKeyHash(hash=bytes(bech32_decode_address(data)))

    def to_address(self):
        return bech32_encode_address(hrp='wit', data=bytes_to_hex(self.hash))

    def pb_bytes(self) -> bytes:
        return pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.hash)

    def hash(self):
        return sha256(self.pb_bytes())
