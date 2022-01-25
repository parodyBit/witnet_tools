from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, sha256
from witnet.util.transformations import hex_to_bytes, bytes_to_hex


@dataclass
class Hash:
    SHA256: bytes

    @classmethod
    def from_string(cls, data: str):
        return Hash(SHA256=hex_to_bytes(data))

    def to_string(self):
        return bytes_to_hex(self.SHA256)

    def pb_bytes(self) -> bytes:
        return pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.SHA256)

    def hash(self):
        return sha256(self.pb_bytes())
