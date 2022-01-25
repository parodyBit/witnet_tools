from dataclasses import dataclass
from typing import List

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, sha256
from witnet.util.transformations import concat
from witnet.schema.dr_transaction_body import DRTransactionBody
from witnet.schema.keyed_signature import KeyedSignature


@dataclass
class DRTransaction:
    body: DRTransactionBody
    signatures: List[KeyedSignature]

    @classmethod
    def from_json(cls, data: dict):
        return DRTransaction(
            body=DRTransactionBody.from_json(data['body']),
            signatures=[KeyedSignature.from_json(x) for x in data['signatures']]
        )

    def to_json(self) -> dict:
        return {
            'body': self.body.to_json(),
            'signatures': [x.to_json() for x in self.signatures]
        }

    def pb_bytes(self) -> bytes:
        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.body.pb_bytes()),
            concat([pb_field(field_number=2, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.signatures])
        ])

    def hash(self):
        return sha256(self.pb_bytes())
