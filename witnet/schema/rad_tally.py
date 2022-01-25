from dataclasses import dataclass
from typing import List

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, VAR_INT
from witnet.util.transformations import concat, sha256
from witnet.schema.rad_filter import RADFilter


@dataclass
class RADTally:
    filters: List[RADFilter]
    reducer: int

    @classmethod
    def from_json(cls, data: dict):
        return RADTally(
            filters=[RADFilter.from_json(data=x) for x in data["filters"]],
            reducer=data["reducer"]
        )

    def to_json(self, as_hex: bool = False):
        return {'filters': [x.to_json(as_hex) for x in self.filters], 'reducer': self.reducer}

    def pb_bytes(self) -> bytes:
        filter_bytes = pb_field(
            field_number=1,
            tag=LENGTH_DELIMITED,
            value=concat([x.pb_bytes() for x in self.filters])
        ) if (len(self.filters) > 0) else []
        reducer_bytes = pb_field(field_number=2, tag=VAR_INT, value=self.reducer)
        return concat([filter_bytes, reducer_bytes])

    def hash(self):
        return sha256(self.pb_bytes())
