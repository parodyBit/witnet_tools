from dataclasses import dataclass

from witnet.constants import COMMIT_WEIGHT, REVEAL_WEIGHT, BETA, OUTPUT_SIZE, TALLY_WEIGHT
from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, VAR_INT
from witnet.util.transformations import concat, sha256
from witnet.schema.rad_request import RADRequest


@dataclass
class DataRequestOutput:
    data_request: RADRequest
    witness_reward: int
    witnesses: int
    commit_and_reveal_fee: int
    min_consensus_percentage: int
    collateral: int

    @classmethod
    def from_json(cls, data: dict):
        return DataRequestOutput(
            collateral=data["collateral"],
            commit_and_reveal_fee=data["commit_and_reveal_fee"],
            data_request=RADRequest.from_json(data=data["data_request"]),
            min_consensus_percentage=data["min_consensus_percentage"],
            witness_reward=data["witness_reward"],
            witnesses=data["witnesses"],
        )

    def to_json(self, as_hex: bool = False):
        return {
            'collateral': self.collateral,
            'commit_and_reveal_fee': self.commit_and_reveal_fee,
            'data_request': self.data_request.to_json(as_hex),
            'min_consensus_percentage': self.min_consensus_percentage,
            'witness_reward': self.witness_reward,
            'witnesses': self.witnesses
        }

    def pb_bytes(self) -> bytes:
        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.data_request.pb_bytes()),
            pb_field(field_number=2, tag=VAR_INT, value=self.witness_reward),
            pb_field(field_number=3, tag=VAR_INT, value=self.witnesses),
            pb_field(field_number=4, tag=VAR_INT, value=self.commit_and_reveal_fee),
            pb_field(field_number=5, tag=VAR_INT, value=self.min_consensus_percentage),
            pb_field(field_number=6, tag=VAR_INT, value=self.collateral),
        ])

    def hash(self):
        return sha256(self.pb_bytes())

    def weight(self):
        """
        Witness reward: 8 bytes
        Witnesses: 2 bytes
        commit_and_reveal_fee: 8 bytes
        min_consensus_percentage: 4 bytes
        collateral: 8 bytes
        """
        return self.data_request.weight() + 8 + 2 + 8 + 4 + 8

    def extra_weight(self) -> int:
        commits_weight = self.witnesses * COMMIT_WEIGHT
        reveals_weight = self.witnesses * REVEAL_WEIGHT * BETA
        tally_outputs_weight = self.witnesses * OUTPUT_SIZE
        tally_weight = TALLY_WEIGHT * BETA + tally_outputs_weight
        return commits_weight + reveals_weight + tally_weight
