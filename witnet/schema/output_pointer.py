from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, VAR_INT, LENGTH_DELIMITED
from witnet.util.transformations import concat, sha256, bytes_to_hex, hex_to_bytes
from witnet.schema.hash import Hash


@dataclass
class OutputPointer:
    transaction_id: Hash
    output_index: int

    @classmethod
    def from_string(cls, data: str):
        return OutputPointer(
            transaction_id=Hash.from_string(data.split(':')[0]),
            output_index=int(data.split(':')[1])
        )

    def to_string(self):
        return bytes_to_hex(self.transaction_id.SHA256) + ':' + str(self.output_index)

    def pb_bytes(self) -> bytes:
        output_index_bytes = pb_field(
            field_number=2,
            tag=VAR_INT,
            value=self.output_index
        ) if (self.output_index > 0) else b''

        return concat([
            pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.transaction_id.pb_bytes()),
            output_index_bytes
        ])

    def hash(self):
        return sha256(self.pb_bytes())
