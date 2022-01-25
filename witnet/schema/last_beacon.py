from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, sha256
from witnet.util.transformations import concat
from witnet.schema.checkpoint_beacon import CheckpointBeacon


@dataclass
class LastBeacon:
    highest_block_checkpoint: CheckpointBeacon
    highest_superblock_checkpoint: CheckpointBeacon

    @classmethod
    def from_json(cls, data: dict) -> 'LastBeacon':
        return LastBeacon(
            highest_block_checkpoint=CheckpointBeacon.from_json(data['highest_block_checkpoint']),
            highest_superblock_checkpoint=CheckpointBeacon.from_json(data['highest_superblock_checkpoint'])
        )

    def to_json(self):
        return {
            'highest_block_checkpoint': self.highest_block_checkpoint.to_json(),
            'highest_superblock_checkpoint': self.highest_superblock_checkpoint.to_json(),
        }

    def pb_bytes(self):
        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.highest_block_checkpoint.pb_bytes()),
            pb_field(field_number=2, tag=LENGTH_DELIMITED, value=self.highest_superblock_checkpoint.pb_bytes()),
        ])

    def hash(self):
        return sha256(self.pb_bytes())

