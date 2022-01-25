from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, VAR_INT, LENGTH_DELIMITED
from witnet.util.transformations import concat, sha256, bytes_to_hex


@dataclass
class RADFilter:
    op: int
    args: bytes

    @classmethod
    def from_json(cls, data: dict):
        return RADFilter(op=data['op'], args=bytes(data['args']))

    def to_json(self, as_hex: bool = False):
        return {
            'op': self.op,
            'args': list(self.args) if not as_hex else bytes_to_hex(self.args)
        }

    def pb_bytes(self) -> bytes:
        op_bytes = pb_field(field_number=1, tag=VAR_INT, value=self.op)
        args_bytes = pb_field(field_number=2, tag=LENGTH_DELIMITED, value=self.args)
        return concat([op_bytes, args_bytes])

    def hash(self):
        return sha256(self.pb_bytes())

    def weight(self) -> int:
        # op: 4 bytes
        return len(list(self.args)) + 4
