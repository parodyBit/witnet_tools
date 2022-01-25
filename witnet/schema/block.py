from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED
from witnet.util.transformations import concat, sha256
from witnet.schema.block_header import BlockHeader
from witnet.schema.block_transactions import BlockTransactions
from witnet.schema.keyed_signature import KeyedSignature
from witnet.schema.transaction_hashes import TransactionHashes


@dataclass
class Block:
    block_header: BlockHeader
    block_sig: KeyedSignature
    txns: BlockTransactions
    confirmed: bool
    txns_hashes: TransactionHashes

    @classmethod
    def from_json(cls, data: dict) -> 'Block':
        return Block(
            block_header=BlockHeader.from_json(data['block_header']),
            block_sig=KeyedSignature.from_json(data['block_sig']),
            txns=BlockTransactions.from_json(data['txns']),
            confirmed=data['confirmed'],
            txns_hashes=TransactionHashes.from_json(data['txns_hashes'])
        )

    def to_json(self, as_hex: bool = True) -> dict:
        return {
            'block_header': self.block_header.to_json(as_hex),
            'block_sig': self.block_sig.to_json(as_hex),
            'txns': self.txns.to_json(),
            'confirmed': self.confirmed,
            'txns_hashes': self.txns_hashes.to_json()
        }

    def pb_bytes(self) -> bytes:

        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.block_header.pb_bytes()),
            pb_field(field_number=2, tag=LENGTH_DELIMITED, value=self.block_sig.pb_bytes()),
            pb_field(field_number=3, tag=LENGTH_DELIMITED, value=self.txns.pb_bytes()),
        ])

    def hash(self) -> bytes:
        return sha256(self.pb_bytes())
