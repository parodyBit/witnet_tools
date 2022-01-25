from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED
from witnet.util.transformations import concat, int_to_bytes, sha256, bytes_to_hex


@dataclass
class PublicKey:
    _bytes: bytes
    compressed: int

    @classmethod
    def from_json(cls, data: dict):
        return PublicKey(_bytes=bytes(data['bytes']), compressed=data['compressed'])

    def to_json(self, as_hex: bool = True):
        return {
            'bytes': list(self._bytes),
            'compressed': self.compressed
        } if not as_hex else {
            'bytes': bytes_to_hex(self._bytes),
            'compressed': self.compressed
        }

    def pb_bytes(self) -> bytes:
        return pb_field(
            field_number=1,
            tag=LENGTH_DELIMITED,
            value=concat([int_to_bytes(self.compressed), self._bytes])
        )

    def hash(self):
        return sha256(self.pb_bytes())
