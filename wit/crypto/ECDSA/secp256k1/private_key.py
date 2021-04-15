import secrets

from wit.crypto import number_theory as nt
from wit.crypto.ECDSA.secp256k1.public_key import PublicKey
from wit.crypto.message import message
from wit.crypto.message.signature import Signature
from wit.witnet.schema import witnet_proto as proto
from wit.util.transformations import bytes_to_int, hex_to_int, sha256

from wit.crypto.ECDSA.secp256k1 import N, CURVE

class PrivateKey(message.Message):

    def __init__(self, bts):
        assert bytes_to_int(bts) < N, 'Key larger than Curve Order'
        super().__init__(bts)

    @classmethod
    def random(cls):
        key = secrets.randbelow(N)
        return cls.from_int(key)

    def to_public(self) -> 'PublicKey':
        point = CURVE.generator * self.int()
        return PublicKey(point)

    def __repr__(self):
        return f"PrivateKey({self.msg.hex()})"

    def sign_hash(self, _hash) -> Signature:
        from wit.crypto.ECDSA.secp256k1 import N, CURVE
        e = hex_to_int(_hash) if isinstance(_hash, str) else bytes_to_int(_hash)
        r, s = 0, 0
        while r == 0 or s == 0:
            k = secrets.randbelow(N)
            point = CURVE.generator * k
            r = point.x % N

            inv_k = nt.mulinv(k, N)
            s = (inv_k * (e + r * self.int())) % N

        return Signature(r=r, s=s)

    def sign_vtt(self, transaction) -> proto.VTTransaction:
        vtt_body = transaction.body
        vtt_hash = sha256(vtt_body.to_pb_bytes())

        der_bytes = self.sign_hash(vtt_hash).encode(compact=False)

        signature = proto.Signature(Secp256k1=proto.Secp256k1Signature(der=der_bytes))
        pubkey = proto.PublicKey(public_key=self.to_public().encode())
        sig = proto.KeyedSignature(signature=signature, public_key=pubkey)

        transaction.signatures.append(sig)
        return transaction
