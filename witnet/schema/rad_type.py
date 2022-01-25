from dataclasses import dataclass
from enum import Enum

from witnet.rad.script import concat
from witnet.util.protobuf.wire_type import pb_field, VAR_INT
from witnet.util.transformations import sha256


@dataclass
class RADType:
    Unknown = 0
    HttpGet = 1
    Rng = 2
    value: int

    def __init__(self, value: int):
        self.value = value

    @classmethod
    def from_str(cls, data: str):

        if data == 'Unknown':
            return RADType(RADType.Unknown)
        elif data == 'HTTP-GET':
            return RADType(RADType.HttpGet)
        elif data == 'RNG':
            return RADType(RADType.Rng)

    def to_string(self):
        if self.value == RADType.Unknown:
            return 'Unknown'
        elif self.value == RADType.HttpGet:
            return 'HTTP-GET'
        elif self.value == RADType.Rng:
            return 'RNG'

    def pb_bytes(self):
        return pb_field(field_number=1, tag=VAR_INT, value=self.value) if self.value > 0 else b''

    def hash(self):
        return sha256(self.pb_bytes())

