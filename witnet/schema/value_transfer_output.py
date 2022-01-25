from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, VAR_INT, LENGTH_DELIMITED
from witnet.util.transformations import concat, sha256
from witnet.schema.public_key_hash import PublicKeyHash


@dataclass
class ValueTransferOutput:
    pkh: PublicKeyHash
    value: int
    time_lock: int

    @classmethod
    def from_json(cls, data: dict):
        return ValueTransferOutput(
            pkh=PublicKeyHash.from_address(data=data['pkh']),
            time_lock=int(data['time_lock']),
            value=int(data['value'])
        )

    def to_json(self):
        return {
            'pkh': self.pkh.to_address(),
            'time_lock': self.time_lock,
            'value': self.value
        }

    def pb_bytes(self) -> bytes:
        time_lock_bytes = pb_field(
            field_number=3,
            tag=VAR_INT,
            value=self.time_lock
        ) if (self.time_lock > 0) else None
        if time_lock_bytes is None:
            return concat([
                pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.pkh.pb_bytes()),
                pb_field(field_number=2, tag=VAR_INT, value=self.value)
            ])
        else:
            return concat([
                pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.pkh.pb_bytes()),
                pb_field(field_number=2, tag=VAR_INT, value=self.value),
                time_lock_bytes
            ])

    def hash(self):
        return sha256(self.pb_bytes())
