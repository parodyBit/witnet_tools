from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, VAR_INT
from witnet.util.transformations import concat, sha256
from witnet.schema.hash import Hash


@dataclass
class SuperBlock:
    signing_committee_length: int
    ars_root: Hash
    data_request_root: Hash
    index: int
    last_block: Hash
    last_block_in_previous_superblock: Hash
    tally_root: Hash

    @classmethod
    def from_json(cls, data: dict) -> 'SuperBlock':
        return SuperBlock(
            signing_committee_length=int(data['signing_committee_length']),
            ars_root=Hash.from_string(data['ars_root']),
            data_request_root=Hash.from_string(data['data_request_root']),
            index=int(data['index']),
            last_block=Hash.from_string('last_block'),
            last_block_in_previous_superblock=Hash.from_string('last_block_in_previous_superblock'),
            tally_root=Hash.from_string(data['tally_root'])
        )

    def to_json(self):
        return {
            'signing_committee_length': self.signing_committee_length,
            'ars_root': self.ars_root.to_string(),
            'data_request_root': self.data_request_root.to_string(),
            'index': self.index,
            'last_block': self.last_block.to_string(),
            'last_block_in_previous_superblock': self.last_block_in_previous_superblock.to_string(),
            'tally_root': self.tally_root.to_string()
        }

    def pb_bytes(self):
        return concat([
            pb_field(field_number=1, tag=VAR_INT, value=self.signing_committee_length),
            pb_field(field_number=2, tag=LENGTH_DELIMITED, value=self.ars_root.pb_bytes()),
            pb_field(field_number=3, tag=LENGTH_DELIMITED, value=self.data_request_root.pb_bytes()),
            pb_field(field_number=4, tag=VAR_INT, value=self.index),
            pb_field(field_number=5, tag=LENGTH_DELIMITED, value=self.last_block.pb_bytes()),
            pb_field(field_number=6, tag=LENGTH_DELIMITED, value=self.last_block_in_previous_superblock.pb_bytes()),
            pb_field(field_number=7, tag=LENGTH_DELIMITED, value=self.tally_root.pb_bytes()),
        ])

    def hash(self):
        return sha256(self.pb_bytes())
