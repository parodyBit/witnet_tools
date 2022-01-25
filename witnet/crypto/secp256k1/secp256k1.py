from dataclasses import dataclass
from typing import Tuple, Union
import secrets

from witnet.crypto import number_theory as nt, message
from witnet.schema import KeyedSignature
from witnet.schema.secp256k1_signature import Secp256k1Signature
from witnet.schema.signature import Signature
from witnet.schema.vt_transaction import VTTransaction

from witnet.util.transformations import hex_to_int, sha256, int_to_hex

from witnet.schema.public_key import PublicKey
from witnet.util.transformations import bytes_to_int, bytes_to_hex, int_to_bytes, hex_to_bytes
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# Generator
G = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, \
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Elliptic curve parameters A and B of the curve : y² = x³ Ax + B
A: int = 0
B: int = 7



class Point:

    def __init__(self, x, y, curve=None):
        self.x = x
        self.y = y
        self.curve = curve
        assert self in curve, f"Point {x}, {y} not in curve"

    def __add__(self, other):
        assert self.curve == other.curve, 'Cannot add points on different curves'
        return self.curve.point_add(self, other)

    def __sub__(self, other):
        return self + (other * -1)

    def __mul__(self, other: int):
        assert isinstance(other, int), 'Multiplication is only defined between a point and an integer'
        return self.curve.point_mul(self, other)

    def __repr__(self):
        return f"Point({self.x}, {self.y}, {self.curve.name})"

    def __eq__(self, other):
        return self.x % self.curve.prime == other.x % self.curve.prime \
               and self.y % self.curve.prime == other.y % self.curve.prime


@dataclass
class Curve:
    prime: int  # P
    a: int
    b: int
    generator: Union[Tuple, Point]
    order: int  # N
    name: str

    def __post_init__(self):
        if type(self.generator).__name__ == 'tuple':
            print('-----')
            self.generator = Point(*self.generator, curve=self)

    def point_add(self, p, q):
        """https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition"""
        _p = self.prime
        if p == q:
            lam = (3 * p.x * p.x) * pow(2 * p.y % _p, _p - 2, _p)
        else:
            lam = pow(q.x - p.x, _p - 2, _p) * (q.y - p.y) % _p

        rx = lam ** 2 - p.x - q.x
        ry = lam * (p.x - rx) - p.y
        return Point(rx % _p, ry % _p, curve=self)

    def point_mul(self, p, d):
        d = d % self.order

        n = p
        q = None

        for i in reversed(format(d, 'b')):
            if i == '1':
                if q is None:
                    q = n
                else:
                    q = self.point_add(q, n)

            n = self.point_add(n, n)
        return q

    def __contains__(self, point):
        return point.y ** 2 % self.prime == (point.x ** 3 + self.a * point.x + self.b) % self.prime

    def f(self, x):
        """Compute y**2 = x^3 + ax + b in field FP"""
        return (x ** 3 + self.a * x + self.b) % self.prime


CURVE = Curve(P, 0, 7, G, N, name='secp256k1')


class WitPrivateKey(message.Message):

    def __init__(self, bts):
        assert bytes_to_int(bts) < N, 'Key larger than Curve Order'
        super().__init__(bts)

    @classmethod
    def random(cls):
        key = secrets.randbelow(N)
        return cls.from_int(key)

    def to_public(self) -> 'WitPublicKey':
        point = CURVE.generator * self.int()
        return WitPublicKey(point)

    def __repr__(self):
        return f"PrivateKey({self.msg.hex()})"

    def sign_hash(self, _hash) -> Signature:
        e = hex_to_int(_hash) if isinstance(_hash, str) else bytes_to_int(_hash)
        r, s = 0, 0
        while r == 0 or s == 0:
            k = secrets.randbelow(N)
            point = CURVE.generator * k
            r = point.x % N

            inv_k = nt.mulinv(k, N)
            s = (inv_k * (e + r * self.int())) % N

        return Signature(r=r, s=s)

    def sign_vtt(self, transaction) -> VTTransaction:
        vtt_body = transaction.body
        vtt_hash = sha256(vtt_body.to_pb_bytes())

        der_bytes = self.sign_hash(vtt_hash).encode(compact=False)

        signature = Signature(secp256k1=Secp256k1Signature(der=der_bytes))
        pubkey = self.to_public().pub_key()
        _sig = KeyedSignature(signature=signature, public_key=pubkey)

        transaction.signatures.append(_sig)
        return transaction


class WitPublicKey:

    def __init__(self, point: 'Point'):
        self.point = point

    def __eq__(self, other: 'WitPublicKey') -> bool:
        return self.point == other.point

    def __repr__(self) -> str:
        return f"PublicKey({self.encode().hex()})"

    @classmethod
    def decode(cls, key: bytes) -> 'WitPublicKey':
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
    def from_hex(cls, hexstring: str) -> 'WitPublicKey':
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

    def pub_key(self):
        if self.y & 1:  # odd root
            return PublicKey(_bytes=int_to_bytes(self.x).rjust(32, b'\x00'), compressed=3)
        else:  # even root
            return PublicKey(_bytes=int_to_bytes(self.x).rjust(32, b'\x00'), compressed=2)

    @classmethod
    def from_json(cls, data: dict):
        _bytes, _compressed = data.values()
        return WitPublicKey.from_hex(bytes_to_hex((int_to_bytes(_compressed) + bytes(_bytes).rjust(32, b'\x00'))))

    @classmethod
    def from_schema(cls, public_key: PublicKey):
        return WitPublicKey.from_json(public_key.to_json())

    def hex(self, compressed=True) -> str:
        return bytes_to_hex(self.encode(compressed=compressed))

    def to_address(self, address_type: str = 'P2WPKH', compressed=True) -> str:
        from witnet.witnet.address import pubkey_to_address
        if compressed is True and address_type == 'P2PKH':
            return pubkey_to_address(self)
        return pubkey_to_address(self)

    def to_pkh(self):
        from witnet.witnet.address import pubkey_to_pkh
        return pubkey_to_pkh(self)

class Signature:

    def __init__(self, r, s, force_low_s=True):
        self.r = r

        if force_low_s:
            # https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures
            self.s = s if s <= N // 2 else N - s
        else:
            self.s = s

    @classmethod
    def decode(cls, bts):
        from collections import deque
        data = deque(bts)
        lead = data.popleft() == 0x30
        assert lead, f'Invalid leading byte: 0x{lead:x}'  # ASN1 SEQUENCE
        sequence_length = data.popleft()
        assert sequence_length <= 70, f'Invalid Sequence length: {sequence_length}'
        lead = data.popleft()
        assert lead == 0x02, f'Invalid r leading byte: 0x{lead:x}'  # 0x02 byte before r
        len_r = data.popleft()
        assert len_r <= 33, f'Invalid r length: {len_r}'
        bts = bytes(data)

        r, data = bytes_to_int(bts[:len_r]), deque(bts[len_r:])

        lead = data.popleft()
        assert lead == 0x02, f'Invalid s leading byte: 0x{lead:x}'  # 0x02 byte before s
        len_s = data.popleft()
        assert len_s <= 33, f'Invalid s length: {len_s}'
        bts = bytes(data)
        s, rest = bytes_to_int(bts[:len_s]), bts[len_s:]
        assert len(rest) == 0, f'{len(rest)} leftover bytes'

        return cls(r, s)

    def encode(self, compact=False):
        """https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#der-encoding"""
        r = int_to_bytes(self.r)
        if r[0] > 0x7f:
            r = b'\x00' + r
        s = int_to_bytes(self.s)

        if s[0] > 0x7f:
            s = b'\x00' + s

        len_r = int_to_bytes(len(r))
        len_s = int_to_bytes(len(s))
        len_sig = int_to_bytes(len(r) + len(s) + 4)
        if compact:
            return r + s
        return b'\x30' + len_sig + b'\x02' + len_r + r + b'\x02' + len_s + s

    def verify_hash(self, _hash, public_key):
        from witnet.crypto.number_theory import mulinv

        public_key: WitPublicKey = public_key
        if not (1 <= self.r < N and 1 <= self.s < N):
            return False

        e = bytes_to_int(_hash)
        w = mulinv(self.s, N)
        u1 = (e * w) % N
        u2 = (self.r * w) % N
        point: Point = CURVE.generator * u1 + public_key.point * u2
        return self.r % N == point.x % N

    @classmethod
    def from_hex(cls, hex_string):
        return cls.decode(hex_to_bytes(hex_string))

    def __repr__(self):
        return f"{self.__class__.__name__}({int_to_hex(self.r)}, {int_to_hex(self.s)})"

    def __eq__(self, other):
        return self.r == other.r and self.s == other.s

    def hex(self):
        return bytes_to_hex(self.encode())


def is_signature(hex_string):
    try:
        if isinstance(hex_string, bytes):
            Signature.decode(hex_string)
        else:
            Signature.from_hex(hex_string)
    except (AssertionError, IndexError):
        return False
    return True


def verify_openssl(signature: Signature, signature_form: bytes, pub: 'WitPublicKey'):
    """Validate a signature using OpenSSL"""
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as directory_name:
        with open(directory_name + '/sig.raw', 'wb') as file:
            file.write(signature.encode())

        with open(directory_name + '/hash1.sha256', 'wb') as file:
            file.write(sha256(signature_form))

        with open(directory_name + '/key.hex', 'w') as file:
            file.write('3056301006072a8648ce3d020106052b8104000a034200\n' + pub.hex())

        os.system(f'xxd -r -p < {directory_name}/key.hex | openssl pkey -pubin -inform der > {directory_name}/key.pem')
        os.system(
            f'openssl sha256 < {directory_name}/hash1.sha256 -verify {directory_name}/key.pem -signature {directory_name}/sig.raw')
