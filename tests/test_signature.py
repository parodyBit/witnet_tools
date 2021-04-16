from unittest import TestCase
from wit.crypto.message.signature import Signature
from wit.crypto.ECDSA.secp256k1 import PrivateKey, PublicKey
from wit.util.transformations import hex_to_bytes, int_to_hex, concat


class TestSignature(TestCase):

    def test_sign_and_verify(self):
        data = hex_to_bytes(concat(['ab' for _ in range(32)]))
        secret_key = PrivateKey.from_hex(concat(['cd' for _ in range(32)]))
        public_key = secret_key.to_public()
        local_signature = secret_key.sign_hash(data)
        expected_signature = '3044' \
                             '0220' \
                             '3dc4fa74655c21b7ffc0740e29bfd88647e8dfe2b68c507cf96264e4e7439c1f' \
                             '0220' \
                             '7aa61261b18eebdfdb704ca7bab4c7bcf7961ae0ade5309f6f1398e21aec0f9f'

        recovered_signature = Signature.from_hex(expected_signature)

        assert local_signature.verify_hash(data, public_key)
        assert recovered_signature.verify_hash(data, public_key)

        return True
