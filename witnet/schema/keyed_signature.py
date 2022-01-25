from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, sha256
from witnet.util.transformations import concat
from witnet.schema.public_key import PublicKey
from witnet.schema.signature import Signature


@dataclass
class KeyedSignature:
    signature: Signature
    public_key: PublicKey

    @classmethod
    def from_json(cls, data: dict):
        return KeyedSignature(
            signature=Signature.from_json(data=data['signature']),
            public_key=PublicKey.from_json(data=data['public_key'])
        )

    def to_json(self):
        return {'signature': self.signature.to_json(), 'public_key': self.public_key.to_json()}

    def pb_bytes(self) -> bytes:
        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.signature.pb_bytes()),
            pb_field(field_number=2, tag=LENGTH_DELIMITED, value=self.public_key.pb_bytes())

        ])

    def hash(self):
        return sha256(self.pb_bytes())
