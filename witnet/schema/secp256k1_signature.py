from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED
from witnet.util.transformations import sha256, bytes_to_hex


@dataclass
class Secp256k1Signature:
    der: bytes

    @classmethod
    def from_json(cls, data: dict):
        return Secp256k1Signature(der=bytes(data['der']))

    def to_json(self, as_hex: bool = True):
        return {'der': list(self.der)} if not as_hex else {'der': bytes_to_hex(self.der)}

    def pb_bytes(self) -> bytes:
        return pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.der)

    def hash(self):
        return sha256(self.pb_bytes())
