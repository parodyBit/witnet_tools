from dataclasses import dataclass
from typing import List

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, sha256
from witnet.util.transformations import concat
from witnet.schema.data_request_output import DataRequestOutput
from witnet.schema.input import Input
from witnet.schema.value_transfer_output import ValueTransferOutput


@dataclass
class DRTransactionBody:
    inputs: List[Input]
    outputs: List[ValueTransferOutput]
    dr_output: DataRequestOutput

    @classmethod
    def from_json(cls, data: dict):
        return DRTransactionBody(
            inputs=[Input.from_json(x) for x in data['inputs']],
            outputs=[ValueTransferOutput.from_json(x) for x in data['outputs']],
            dr_output=DataRequestOutput.from_json(data['dr_output'])
        )

    def to_json(self, as_hex: bool = False) -> dict:
        return {
            'inputs': [x.to_json() for x in self.inputs],
            'outputs': [x.to_json() for x in self.outputs],
            'dr_output': self.dr_output.to_json(as_hex)
        }

    def pb_bytes(self) -> bytes:
        return concat([
            concat([pb_field(field_number=1, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.inputs]),
            concat([pb_field(field_number=2, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.outputs]),
            pb_field(field_number=3, tag=LENGTH_DELIMITED, value=self.dr_output.pb_bytes())
        ])

    def data_poi_hash(self) -> bytes:
        # Specified data to be divided in a new level in the proof of inclusion
        return self.dr_output.hash()

    def rest_poi_hash(self) -> bytes:
        # Rest of the transaction to be divided in a new level in the proof of inclusion
        return sha256(self.pb_bytes())

    def hash(self):
        return sha256(concat([self.data_poi_hash(), self.rest_poi_hash()]))
