from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED
from witnet.util.transformations import concat, sha256
from witnet.schema.hash import Hash
from witnet.schema.public_key_hash import PublicKeyHash


@dataclass
class RevealTransactionBody:
    dr_pointer: Hash
    reveal: bytes
    pkh: PublicKeyHash

    @classmethod
    def from_json(cls, data: dict) -> 'RevealTransactionBody':
        return RevealTransactionBody(
            dr_pointer=Hash.from_string(data=data['dr_pointer']),
            reveal=bytes(data['reveal']),
            pkh=PublicKeyHash.from_address(data=data['pkh'])
        )

    def to_json(self):
        ...

    def pb_bytes(self):
        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.dr_pointer.pb_bytes()),
            pb_field(field_number=2, tag=LENGTH_DELIMITED, value=self.reveal),
            pb_field(field_number=3, tag=LENGTH_DELIMITED, value=self.pkh.pb_bytes())
        ])

    def hash(self):
        return sha256(self.pb_bytes())
