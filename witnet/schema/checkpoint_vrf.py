from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, VAR_INT, LENGTH_DELIMITED, sha256
from witnet.util.transformations import concat
from witnet.schema.hash import Hash


@dataclass
class CheckpointVRF:
    checkpoint: int
    hash_prev_vrf: Hash

    @classmethod
    def from_json(cls, data: dict) -> 'CheckpointVRF':
        return CheckpointVRF(checkpoint=data['checkpoint'], hash_prev_vrf=Hash.from_string(data['hash_prev_vrf']))

    def to_json(self):
        return {
            'checkpoint': self.checkpoint,
            'hash_prev_vrf': self.hash_prev_vrf.to_string()
        }

    def pb_bytes(self):
        return concat([
            pb_field(field_number=1, tag=VAR_INT, value=self.checkpoint),
            pb_field(field_number=2, tag=LENGTH_DELIMITED, value=self.hash_prev_vrf.pb_bytes())
        ])

    def hash(self):
        return sha256(self.pb_bytes())
