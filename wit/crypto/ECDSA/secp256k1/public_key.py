import wit.crypto.number_theory as nt
from wit.util.transformations import bytes_to_int, bytes_to_hex, int_to_bytes, hex_to_bytes
from wit.witnet.schema import witnet_proto as proto

from .secp256k1 import P, CURVE
from .point import Point


class PublicKey:

    def __init__(self, point: 'Point'):
        self.point = point

    def __eq__(self, other: 'PublicKey') -> bool:
        return self.point == other.point

    def __repr__(self) -> str:
        return f"PublicKey({self.encode().hex()})"

    @classmethod
    def decode(cls, key: bytes) -> 'PublicKey':
        if key.startswith(b'\x04'):  # uncompressed key
            assert len(key) == 65, 'An uncompressed public key must be 65 bytes long'
            x, y = bytes_to_int(key[1:33]), bytes_to_int(key[33:])
        else:  # compressed key
            assert len(key) == 33, 'A compressed public key must be 33 bytes long'
            x = bytes_to_int(key[1:])
            root = nt.modsqrt(CURVE.f(x), P)
            if key.startswith(b'\x03'):  # odd root
                y = root if root % 2 == 1 else -root % P
            elif key.startswith(b'\x02'):  # even root
                y = root if root % 2 == 0 else -root % P
            else:
                assert False, 'Wrong key format'
        return cls(Point(x, y, curve=CURVE))

    @classmethod
    def from_hex(cls, hexstring: str) -> 'PublicKey':
        return cls.decode(hex_to_bytes(hexstring))

    @property
    def x(self) -> int:
        """X coordinate of the (X, Y) point"""
        return self.point.x

    @property
    def y(self) -> int:
        """Y coordinate of the (X, Y) point"""
        return self.point.y

    def encode(self, compressed=True) -> bytes:
        if compressed:
            if self.y & 1:  # odd root
                return b'\x03' + int_to_bytes(self.x).rjust(32, b'\x00')
            else:  # even root
                return b'\x02' + int_to_bytes(self.x).rjust(32, b'\x00')
        return b'\x04' + int_to_bytes(self.x).rjust(32, b'\x00') + int_to_bytes(self.y).rjust(32, b'\x00')

    def to_json(self, compressed=True):
        enc = self.encode(compressed=compressed)
        return {'bytes': list(enc[1::]), 'compressed': enc[0]}

    @classmethod
    def from_json(cls, data: dict):
        _bytes, _compressed = data.values()
        return PublicKey.from_hex(bytes_to_hex((int_to_bytes(_compressed) + bytes(_bytes).rjust(32, b'\x00'))))

    @classmethod
    def from_schema(cls, public_key: proto.PublicKey):
        return PublicKey.from_json(public_key.to_json())

    def hex(self, compressed=True) -> str:
        return bytes_to_hex(self.encode(compressed=compressed))

    def to_address(self, address_type: str = 'P2WPKH', compressed=True) -> str:
        from wit.witnet.address import pubkey_to_address
        if compressed is True and address_type == 'P2PKH':
            return pubkey_to_address(self)
        return pubkey_to_address(self)

    def to_pkh(self):
        from wit.witnet.address import pubkey_to_pkh
        return pubkey_to_pkh(self)
