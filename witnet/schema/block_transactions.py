from dataclasses import dataclass
from typing import List

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED
from witnet.util.transformations import concat, sha256
from witnet.schema.commit_transaction import CommitTransaction
from witnet.schema.dr_transaction import DRTransaction
from witnet.schema.mint_transaction import MintTransaction
from witnet.schema.reveal_transaction import RevealTransaction
from witnet.schema.tally_transaction import TallyTransaction
from witnet.schema.vt_transaction import VTTransaction


@dataclass
class BlockTransactions:
    mint: MintTransaction
    value_transfer_txns: List[VTTransaction]
    data_request_txns: List[DRTransaction]
    commit_txns: List[CommitTransaction]
    reveal_txns: List[RevealTransaction]
    tally_txns: List[TallyTransaction]

    @classmethod
    def from_json(cls, data: dict) -> 'BlockTransactions':
        return BlockTransactions(
            mint=MintTransaction.from_json(data['mint']),
            value_transfer_txns=[VTTransaction.from_json(x) for x in data['value_transfer_txns']],
            data_request_txns=[DRTransaction.from_json(x) for x in data['data_request_txns']],
            commit_txns=[CommitTransaction.from_json(x) for x in data['commit_txns']],
            reveal_txns=[RevealTransaction.from_json(x) for x in data['reveal_txns']],
            tally_txns=[TallyTransaction.from_json(x) for x in data['tally_txns']]
        )

    def to_json(self):
        return {
            'mint': self.mint.to_json(),
            'reveal_txns': [x.to_json() for x in self.reveal_txns],
            'tally_txns': [x.to_json() for x in self.tally_txns],
            'value_transfer_txns': [x.to_json() for x in self.value_transfer_txns],
        }

    def pb_bytes(self):

        vt_txn_bytes = concat([
            pb_field(field_number=2, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.value_transfer_txns]) \
            if len(self.value_transfer_txns) > 0 else b''

        commit_txn_bytes = concat([
            pb_field(field_number=4, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.commit_txns]) \
            if len(self.commit_txns) > 0 else b''
        reveal_txn_bytes = concat([
            pb_field(field_number=5, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.reveal_txns])\
            if len(self.reveal_txns) > 0 else b''
        tally_txn_bytes = concat([
            pb_field(field_number=6, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.tally_txns]) \
            if len(self.tally_txns) > 0 else b''

        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.mint.pb_bytes()),
            vt_txn_bytes,
            commit_txn_bytes,
            reveal_txn_bytes,
            tally_txn_bytes,
        ])

    def hash(self):
        return sha256(self.pb_bytes())
