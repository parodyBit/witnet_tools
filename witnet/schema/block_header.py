from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, VAR_INT, LENGTH_DELIMITED, sha256
from witnet.util.transformations import concat
from witnet.schema.block_eligibility_claim import BlockEligibilityClaim
from witnet.schema.block_merkle_roots import BlockMerkleRoots
from witnet.schema.bn256_public_key import Bn256PublicKey
from witnet.schema.checkpoint_beacon import CheckpointBeacon


@dataclass
class BlockHeader:
    signals: int
    beacon: CheckpointBeacon
    merkle_roots: BlockMerkleRoots
    proof: BlockEligibilityClaim
    bn256_public_key: Bn256PublicKey

    @classmethod
    def from_json(cls, data: dict) -> 'BlockHeader':
        return BlockHeader(
            signals=data['signals'],
            beacon=CheckpointBeacon.from_json(data=data['beacon']),
            merkle_roots=BlockMerkleRoots.from_json(data=data['merkle_roots']),
            proof=BlockEligibilityClaim.from_json(data=data['proof']),
            bn256_public_key=Bn256PublicKey.from_json(data=data['bn256_public_key'])
        )

    def to_json(self, as_hex: bool = True):
        return {
            'beacon': self.beacon.to_json(),
            'bn256_public_key': self.bn256_public_key.to_json(as_hex),
            'merkle_roots': self.merkle_roots.to_json(),
            'proof': self.proof.to_json(as_hex),
            'signals': self.signals
        }

    def pb_bytes(self):
        return concat([
            pb_field(field_number=1, tag=VAR_INT, value=self.signals),
            pb_field(field_number=2, tag=LENGTH_DELIMITED, value=self.beacon.pb_bytes()),
            pb_field(field_number=3, tag=LENGTH_DELIMITED, value=self.merkle_roots.pb_bytes()),
            pb_field(field_number=4, tag=LENGTH_DELIMITED, value=self.proof.pb_bytes()),
            pb_field(field_number=5, tag=LENGTH_DELIMITED, value=self.bn256_public_key.pb_bytes()),
        ])

    def hash(self):
        return sha256(self.pb_bytes())
