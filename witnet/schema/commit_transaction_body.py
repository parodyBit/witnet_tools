from dataclasses import dataclass
from typing import List

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, sha256
from witnet.util.transformations import concat
from witnet.schema.bn256_public_key import Bn256PublicKey
from witnet.schema.data_request_eligibility_claim import DataRequestEligibilityClaim
from witnet.schema.hash import Hash
from witnet.schema.input import Input
from witnet.schema.value_transfer_output import ValueTransferOutput


@dataclass
class CommitTransactionBody:
    dr_pointer: Hash
    commitment: Hash
    proof: DataRequestEligibilityClaim
    collateral: List[Input]
    outputs: List[ValueTransferOutput]
    bn256_public_key: Bn256PublicKey

    @classmethod
    def from_json(cls, data: dict) -> 'CommitTransactionBody':
        return CommitTransactionBody(
            dr_pointer=Hash.from_string(data['dr_pointer']),
            commitment=Hash.from_string(data['dr_pointer']),
            proof=DataRequestEligibilityClaim.from_json(data['proof']),
            collateral=[Input.from_json(x) for x in data['collateral']],
            outputs=[ValueTransferOutput.from_json(x) for x in data['outputs']],
            bn256_public_key=Bn256PublicKey.from_json(data['bn256_public_key'])
        )

    def to_json(self):
        return {
            'dr_pointer': self.dr_pointer.to_string(),
            'commitment': self.commitment.to_string(),
            'proof': self.proof.to_json(),
            'collateral': [x.to_json() for x in self.collateral],
            'outputs': [x.to_json() for x in self.outputs],
            'bn256_public_key': self.bn256_public_key.to_json()
        }

    def pb_bytes(self):
        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.dr_pointer.pb_bytes()),
            pb_field(field_number=2, tag=LENGTH_DELIMITED, value=self.commitment.pb_bytes()),
            pb_field(field_number=3, tag=LENGTH_DELIMITED, value=self.proof.pb_bytes()),
            concat([pb_field(field_number=4, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.collateral]),
            concat([pb_field(field_number=5, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.outputs]),
            pb_field(field_number=6, tag=LENGTH_DELIMITED, value=self.bn256_public_key.pb_bytes()),
        ])

    def hash(self):
        return sha256(self.pb_bytes())
