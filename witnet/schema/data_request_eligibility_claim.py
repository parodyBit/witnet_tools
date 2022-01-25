from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, sha256
from witnet.util.transformations import concat
from witnet.schema.vrf_proof import VrfProof


@dataclass
class DataRequestEligibilityClaim:
    proof: VrfProof

    @classmethod
    def from_json(cls, data: dict) -> 'DataRequestEligibilityClaim':
        return DataRequestEligibilityClaim(proof=VrfProof.from_json(data['proof']))

    def to_json(self):
        return {'proof': self.proof.to_json()}

    def pb_bytes(self):
        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.proof.pb_bytes())
        ])

    def hash(self):
        return sha256(self.pb_bytes())
