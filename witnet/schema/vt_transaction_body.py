from dataclasses import dataclass
from typing import List

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED
from witnet.util.transformations import concat, sha256
from witnet.schema.input import Input
from witnet.schema.value_transfer_output import ValueTransferOutput


@dataclass
class VTTransactionBody:
    inputs: List[Input]
    outputs: List[ValueTransferOutput]

    @classmethod
    def from_json(cls, data: dict):
        return VTTransactionBody(
            inputs=[Input.from_json(x) for x in data['inputs']],
            outputs=[ValueTransferOutput.from_json(x) for x in data['outputs']]
        )

    def to_json(self):
        return {
            'inputs': [x.to_json() for x in self.inputs],
            'outputs': [x.to_json() for x in self.outputs]
        }

    def pb_bytes(self) -> bytes:
        return concat([
            concat([pb_field(field_number=1, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.inputs]),
            concat([pb_field(field_number=2, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.outputs])
        ])

    def hash(self):
        return sha256(self.pb_bytes())
