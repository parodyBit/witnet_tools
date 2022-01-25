from dataclasses import dataclass
from typing import List

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, VAR_INT
from witnet.util.transformations import concat, sha256
from witnet.schema.rad_aggregate import RADAggregate
from witnet.schema.rad_retrieve import RADRetrieve
from witnet.schema.rad_tally import RADTally


@dataclass
class RADRequest:
    time_lock: int
    retrieve: List[RADRetrieve]
    aggregate: RADAggregate
    tally: RADTally

    @classmethod
    def from_json(cls, data: dict):
        return RADRequest(
            time_lock=data["time_lock"],
            retrieve=[RADRetrieve.from_json(x) for x in data['retrieve']],
            aggregate=RADAggregate.from_json(data=data["aggregate"]),
            tally=RADTally.from_json(data=data["tally"])
        )

    def to_json(self, as_hex: bool = False):
        return {
            'time_lock': self.time_lock,
            'retrieve': [x.to_json(as_hex) for x in self.retrieve],
            'aggregate': self.aggregate.to_json(as_hex),
            'tally': self.tally.to_json(as_hex)
        }

    def pb_bytes(self) -> bytes:
        timelock_bytes = pb_field(
            field_number=1,
            tag=VAR_INT,
            value=self.time_lock
        ) if (self.time_lock > 0) else b''
        retrieve_bytes = concat(
            [pb_field(field_number=2, tag=LENGTH_DELIMITED, value=x.pb_bytes()) for x in self.retrieve]
        )
        aggregate_bytes = pb_field(field_number=3, tag=LENGTH_DELIMITED, value=self.aggregate.pb_bytes())
        tally_bytes = pb_field(field_number=4, tag=LENGTH_DELIMITED, value=self.tally.pb_bytes())
        return concat([timelock_bytes, retrieve_bytes, aggregate_bytes, tally_bytes])

    def hash(self):
        return sha256(self.pb_bytes())

    def weight(self) -> int:
        # timelock: 8 bytes

        retrievals_weight = sum([x.weight() for x in self.retrieve])
        return retrievals_weight + self.aggregate.weight()
