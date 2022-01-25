from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED
from witnet.util.transformations import concat, sha256, bytes_to_hex
from witnet.schema.public_key import PublicKey


@dataclass
class VrfProof:
    proof: bytes
    public_key: PublicKey

    @classmethod
    def from_json(cls, data: dict) -> 'VrfProof':
        return VrfProof(proof=bytes(data['proof']), public_key=PublicKey.from_json(data['public_key']))

    def to_json(self, as_hex: bool = True):
        return {
            'proof': list(self.proof),
            'public_key': self.public_key.to_json()
        } if not as_hex else {
            'proof': bytes_to_hex(self.proof),
            'public_key': self.public_key.to_json()
        }

    def pb_bytes(self):
        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=bytes(self.proof)),
            pb_field(field_number=2, tag=LENGTH_DELIMITED, value=self.public_key.pb_bytes()),
        ])

    def hash(self):
        return sha256(self.pb_bytes())
