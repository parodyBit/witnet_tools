from dataclasses import dataclass
from typing import List

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED
from witnet.util.transformations import concat, sha256
from witnet.schema.keyed_signature import KeyedSignature
from witnet.schema.reveal_transaction_body import RevealTransactionBody


@dataclass
class RevealTransaction:
    body: RevealTransactionBody
    signatures: List[KeyedSignature]

    @classmethod
    def from_json(cls, data: dict) -> 'RevealTransaction':
        return RevealTransaction(
            body=RevealTransactionBody.from_json(data['body']),
            signatures=[KeyedSignature.from_json(x) for x in data['signatures']]
        )

    def to_json(self):
        return {
            'body': self.body.to_json(),
            'signatures': [KeyedSignature.to_json(x) for x in self.signatures]
        }

    def pb_bytes(self):
        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.body.pb_bytes()),
            concat([pb_field(field_number=2, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.signatures])
        ])

    def hash(self):
        return sha256(self.pb_bytes())
