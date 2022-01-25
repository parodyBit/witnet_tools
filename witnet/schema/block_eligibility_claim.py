from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED
from witnet.util.transformations import concat, sha256
from witnet.schema.vrf_proof import VrfProof


@dataclass
class BlockEligibilityClaim:
    proof: VrfProof

    @classmethod
    def from_json(cls, data: dict) -> 'BlockEligibilityClaim':
        return BlockEligibilityClaim(proof=VrfProof.from_json(data['proof']))

    def to_json(self, as_hex: bool = True) -> dict:
        return {'proof': self.proof.to_json(as_hex)}

    def pb_bytes(self) -> bytes:
        return concat([pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.proof.pb_bytes())])

    def hash(self) -> bytes:
        return sha256(self.pb_bytes())
