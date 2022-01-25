from dataclasses import dataclass
from typing import List

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED
from witnet.util.transformations import concat, sha256
from witnet.schema.hash import Hash
from witnet.schema.public_key_hash import PublicKeyHash
from witnet.schema.value_transfer_output import ValueTransferOutput


@dataclass
class TallyTransaction:
    dr_pointer: Hash
    tally: bytes
    outputs: List[ValueTransferOutput]
    out_of_consensus: List[PublicKeyHash]
    error_committers: List[PublicKeyHash]

    @classmethod
    def from_json(cls, data: dict) -> 'TallyTransaction':
        return TallyTransaction(
            dr_pointer=Hash.from_string(data['dr_pointer']),
            tally=bytes(data['tally']),
            outputs=[ValueTransferOutput.from_json(x) for x in data['outputs']],
            out_of_consensus=[PublicKeyHash.from_address(x) for x in data['out_of_consensus']],
            error_committers=[PublicKeyHash.from_address(x) for x in data['error_committers']]
        )

    def to_json(self):
        return {
            'dr_pointer': self.dr_pointer.to_string(),
            'tally:': list(self.tally),
            'outputs': [x.to_json() for x in self.outputs],
            'out_of_consensus': [x.to_address() for x in self.out_of_consensus],
            'error_committers': [x.to_address() for x in self.error_committers],
        }

    def pb_bytes(self):
        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.dr_pointer.pb_bytes()),
            pb_field(field_number=2, tag=LENGTH_DELIMITED, value=self.tally),
            concat([pb_field(field_number=3, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.outputs]),
            concat([pb_field(field_number=4, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.out_of_consensus]),
            concat([pb_field(field_number=5, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.error_committers]),
        ])

    def hash(self):
        return sha256(self.pb_bytes())
