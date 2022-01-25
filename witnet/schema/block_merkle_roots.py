from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, sha256
from witnet.util.transformations import concat
from witnet.schema.hash import Hash


@dataclass
class BlockMerkleRoots:
    mint_hash: Hash
    vt_hash_merkle_root: Hash
    dr_hash_merkle_root: Hash
    commit_hash_merkle_root: Hash
    reveal_hash_merkle_root: Hash
    tally_hash_merkle_root: Hash

    @classmethod
    def from_json(cls, data: dict) -> 'BlockMerkleRoots':
        return BlockMerkleRoots(
            mint_hash=Hash.from_string(data['mint_hash']),
            vt_hash_merkle_root=Hash.from_string(data['vt_hash_merkle_root']),
            dr_hash_merkle_root=Hash.from_string(data['dr_hash_merkle_root']),
            commit_hash_merkle_root=Hash.from_string(data['commit_hash_merkle_root']),
            reveal_hash_merkle_root=Hash.from_string(data['reveal_hash_merkle_root']),
            tally_hash_merkle_root=Hash.from_string(data['tally_hash_merkle_root'])
        )

    def to_json(self):
        return {
            'commit_hash_merkle_root': self.commit_hash_merkle_root.to_string(),
            'dr_hash_merkle_root': self.dr_hash_merkle_root.to_string(),
            'mint_hash': self.mint_hash.to_string(),
            'reveal_hash_merkle_root': self.reveal_hash_merkle_root.to_string(),
            'tally_hash_merkle_root': self.tally_hash_merkle_root.to_string(),
            'vt_hash_merkle_root': self.vt_hash_merkle_root.to_string()
        }

    def pb_bytes(self):
        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.mint_hash.pb_bytes()),
            pb_field(field_number=2, tag=LENGTH_DELIMITED, value=self.vt_hash_merkle_root.pb_bytes()),
            pb_field(field_number=3, tag=LENGTH_DELIMITED, value=self.dr_hash_merkle_root.pb_bytes()),
            pb_field(field_number=4, tag=LENGTH_DELIMITED, value=self.commit_hash_merkle_root.pb_bytes()),
            pb_field(field_number=5, tag=LENGTH_DELIMITED, value=self.reveal_hash_merkle_root.pb_bytes()),
            pb_field(field_number=6, tag=LENGTH_DELIMITED, value=self.tally_hash_merkle_root.pb_bytes()),
        ])

    def hash(self):
        return sha256(self.pb_bytes())
