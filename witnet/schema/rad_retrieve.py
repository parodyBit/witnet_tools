from dataclasses import dataclass

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, VAR_INT
from witnet.util.transformations import concat, str_to_bytes, sha256, bytes_to_hex
from witnet.schema.rad_type import RADType


@dataclass
class RADRetrieve:
    kind: RADType
    url: str
    script: bytes

    @classmethod
    def from_json(cls, data: dict):
        return RADRetrieve(kind=RADType.from_str(data['kind']), url=data['url'], script=bytes(data['script']))

    def to_json(self, as_hex: bool = False):
        return {
            'kind': self.kind.to_string(),
            'url': self.url,
            'script': list(self.script) if not as_hex else bytes_to_hex(self.script)
        }

    def pb_bytes(self) -> bytes:
        kind_bytes = pb_field(field_number=1, tag=VAR_INT, value=self.kind.value)
        url_bytes = pb_field(field_number=2, tag=LENGTH_DELIMITED, value=str_to_bytes(self.url))
        script_bytes = pb_field(field_number=3, tag=LENGTH_DELIMITED, value=self.script)
        if self.kind.value == 0:
            return concat([url_bytes, script_bytes])
        else:
            return concat([kind_bytes, url_bytes, script_bytes])

    def hash(self):
        return sha256(self.pb_bytes())

    def weight(self):
        # RadType: 1 byte
        return len(list(self.script)) + len(list(str_to_bytes(self.url))) + 1
