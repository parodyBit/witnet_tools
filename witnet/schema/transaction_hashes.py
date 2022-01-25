from dataclasses import dataclass
from typing import List

from witnet.schema.hash import Hash


@dataclass
class TransactionHashes:
    commit: List[Hash]
    data_request: List[Hash]
    mint: Hash
    reveal: List[Hash]
    tally: List[Hash]
    value_transfer: List[Hash]

    @classmethod
    def from_json(cls, data: dict) -> 'TransactionHashes':
        return TransactionHashes(
            commit=[Hash.from_string(x) for x in data['commit']],
            data_request=[Hash.from_string(x) for x in data['data_request']],
            mint=Hash.from_string(data['mint']),
            reveal=[Hash.from_string(x) for x in data['reveal']],
            tally=[Hash.from_string(x) for x in data['tally']],
            value_transfer=[Hash.from_string(x) for x in data['value_transfer']],
        )

    def to_json(self):
        return {
            'commit': [x.to_string() for x in self.commit],
            'data_request': [x.to_string() for x in self.data_request],
            'mint': self.mint.to_string(),
            'reveal': [x.to_string() for x in self.reveal],
            'tally': [x.to_string() for x in self.tally],
            'value_transfer': [x.to_string() for x in self.value_transfer],
        }
