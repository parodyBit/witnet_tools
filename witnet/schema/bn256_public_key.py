from dataclasses import dataclass
from typing import Union

from witnet.util.protobuf.wire_type import pb_field, LENGTH_DELIMITED, sha256
from witnet.util.transformations import concat, bytes_to_hex


@dataclass
class Bn256PublicKey:
    # the genesis block has no key and is the only one.
    public_key: Union[bytes, None]

    @classmethod
    def from_json(cls, data: Union[dict, None]) -> 'Bn256PublicKey':

        if data is None:
            return Bn256PublicKey(public_key=None)
        return Bn256PublicKey(public_key=bytes(data['public_key']))

    def to_json(self, as_hex: bool = True):
        if self.public_key is None:
            return None
        return {'public_key': list(self.public_key)} if not as_hex else {'public_key': bytes_to_hex(self.public_key)}

    def pb_bytes(self):
        if self.public_key is None:
            return b''
        return concat([pb_field(field_number=1, tag=LENGTH_DELIMITED, value=self.public_key)])

    def hash(self):
        return sha256(self.pb_bytes())
