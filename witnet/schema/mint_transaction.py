from dataclasses import dataclass
from typing import List

from witnet.util.protobuf.wire_type import pb_field, VAR_INT, LENGTH_DELIMITED, sha256
from witnet.util.transformations import concat
from witnet.schema.value_transfer_output import ValueTransferOutput


@dataclass
class MintTransaction:
    epoch: int
    outputs: List[ValueTransferOutput]

    @classmethod
    def from_json(cls, data: dict) -> 'MintTransaction':
        return MintTransaction(
            epoch=data['epoch'],
            outputs=[ValueTransferOutput.from_json(x) for x in data['outputs']]
        )

    def to_json(self):
        return {
            'epoch': self.epoch,
            'outputs': [x.to_json() for x in self.outputs]
        }

    def pb_bytes(self):
        return concat([
            pb_field(field_number=1, tag=VAR_INT, value=self.epoch),
            concat([pb_field(field_number=2, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.outputs])
        ])

    def hash(self):
        return sha256(self.pb_bytes())
