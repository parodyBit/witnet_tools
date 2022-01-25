from dataclasses import dataclass
from typing import List

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, sha256
from witnet.util.transformations import concat
from witnet.schema.commit_transaction_body import CommitTransactionBody
from witnet.schema.keyed_signature import KeyedSignature


@dataclass
class CommitTransaction:
    body: CommitTransactionBody
    signatures: List[KeyedSignature]

    @classmethod
    def from_json(cls, data: dict) -> 'CommitTransaction':
        return CommitTransaction(
            body=CommitTransactionBody.from_json(data=data['body']),
            signatures=[KeyedSignature.from_json(x) for x in data['signatures']]
        )

    def to_json(self):
        return {
            'body': self.body.to_json(),
            'signatures': [x.to_json() for x in self.signatures]
        }

    def pb_bytes(self):
        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.body.to_json()),
            concat([pb_field(field_number=2, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.signatures])
        ])

    def hash(self):
        return sha256(self.pb_bytes())
