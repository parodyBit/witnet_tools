import hashlib
import hmac

from witnet.crypto.hd_wallet.extended_key import ExtendedKey
from witnet.crypto.secp256k1 import WitPrivateKey, WitPublicKey
from witnet.util.transformations import bytes_to_hex, int_to_bytes, hash160
from witnet.witnet.exceptions import KeyDerivationError


class Xpub(ExtendedKey):
    root_path = 'M'

    def child(self, i: int) -> 'Xpub':
        hardened = i >= 1 << 31

        if hardened:
            raise KeyDerivationError('Cannot derive a hardened key from an extended public key')

        I = hmac.new(key=self.code, msg=self.keydata() + int_to_bytes(i).rjust(4, b'\x00'),
                     digestmod=hashlib.sha512).digest()
        tmp = bytes_to_hex(self.keydata() + int_to_bytes(i).rjust(4, b'\x00'))

        I_L, I_R = I[:32], I[32:]

        key = WitPrivateKey(I_L).to_public().point + self.key.point
        ret_code = I_R
        path = self.path + f'/{i}'

        # TODO add point at infinity check
        return Xpub(WitPublicKey(key), ret_code, depth=self.depth + 1, i=i, parent=self.fingerprint(), path=path)

    def id(self):
        return hash160(self.key.encode(compressed=True))

    def keydata(self):
        return self.key.encode(compressed=True)

    def __repr__(self):
        return f"{self.__class__.__name__}(path={self.path}, key={self.key.hex(compressed=True)})"

    def address(self):
        return self.key.to_address(compressed=True)
