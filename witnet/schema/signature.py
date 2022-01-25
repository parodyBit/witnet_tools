from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED
from witnet.util.transformations import sha256
from witnet.schema.secp256k1_signature import Secp256k1Signature


@dataclass
class Signature:
    secp256k1: Secp256k1Signature

    @classmethod
    def from_json(cls, data: dict):
        return Signature(secp256k1=Secp256k1Signature.from_json(data=data['Secp256k1']))

    def to_json(self):
        return {'Secp256k1': self.secp256k1.to_json()}

    def pb_bytes(self) -> bytes:
        return pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.secp256k1.pb_bytes())

    def hash(self):
        return sha256(self.pb_bytes())
