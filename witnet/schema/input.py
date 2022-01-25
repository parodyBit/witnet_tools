from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, sha256
from witnet.schema.output_pointer import OutputPointer


@dataclass
class Input:
    output_pointer: OutputPointer

    @classmethod
    def from_json(cls, data: dict):
        return Input(output_pointer=OutputPointer.from_string(data=data['output_pointer']))

    def to_json(self):
        return {'output_pointer': self.output_pointer.to_string()}

    def pb_bytes(self) -> bytes:
        return pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.output_pointer.pb_bytes())

    def hash(self):
        return sha256(self.pb_bytes())
