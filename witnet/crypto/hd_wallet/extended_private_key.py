import hashlib
import hmac
from typing import Union

from witnet.crypto.bip39.mnemonic import Mnemonic
from witnet.crypto.hd_wallet.extended_key import ExtendedKey
from witnet.crypto.hd_wallet.extended_public_key import Xpub
from witnet.crypto.secp256k1 import CURVE, WitPrivateKey
from witnet.util.transformations import int_to_bytes, bytes_to_int, hash160, hex_to_bytes, bytes_to_hex
from witnet.util.transformations.bech32 import bech32_encode_master_key, bech32_decode_address
from witnet.witnet.exceptions import KeyDerivationError


class Xprv(ExtendedKey):
    root_path = 'm'

    def child(self, i: int) -> 'Xprv':
        hardened = i >= 1 << 31
        if hardened:
            I = hmac.new(key=self.code, msg=self.keydata() + int_to_bytes(i).rjust(4, b'\x00'),
                         digestmod=hashlib.sha512).digest()
            tmp = int_to_bytes(i).rjust(4, b'\x00')

        else:
            I = hmac.new(key=self.code,
                         msg=self.key.to_public().encode(compressed=True) + int_to_bytes(i).rjust(4, b'\x00'),
                         digestmod=hashlib.sha512).digest()
            tmp = self.key.to_public().encode(compressed=True) + int_to_bytes(i).rjust(4, b'\x00')

        I_L, I_R = bytes_to_int(I[:32]), I[32:]
        key = (I_L + self.key.int()) % CURVE.order
        if I_L >= CURVE.order or key == 0:
            return self.child(i + 1)
        ret_code = I_R
        if hardened:
            path = self.path + f'/{i - 2 ** 31}h'
        else:
            path = self.path + f'/{i}'

        return Xprv(WitPrivateKey.from_int(key), ret_code, depth=self.depth + 1, i=i, parent=self.fingerprint(), path=path)

    def to_xpub(self) -> 'Xpub':
        return Xpub(self.key.to_public(), self.code, depth=self.depth, i=self.i, parent=self.parent,
                    path=self.path.replace('m', 'M'))

    def to_child_xpub(self, i: int) -> 'Xpub':
        # return self.child(i).to_xpub()  # works always
        return self.to_xpub().child(i)  # works only for non-hardened child keys

    def id(self):
        return hash160(self.key.to_public().encode(compressed=True))

    def keydata(self):
        return self.key.bytes().rjust(33, b'\x00')

    def serialize(self):
        pass

    @classmethod
    def from_seed(cls, seed: Union[bytes, str], network_key=b'Bitcoin seed') -> 'Xprv':
        """
        :param seed:
        :param network_key:
        :return:
        """
        if isinstance(seed, str):
            seed = hex_to_bytes(seed)
        assert 16 <= len(seed) <= 64, 'Seed should be between 128 and 512 bits'
        I = hmac.new(key=network_key, msg=seed, digestmod=hashlib.sha512).digest()
        I_L, I_R = I[:32], I[32:]
        if bytes_to_int(I_L) == 0 or bytes_to_int(I_L) > CURVE.order:
            raise KeyDerivationError
        key, code = WitPrivateKey(I_L), I_R
        # print(f'\tMaster Secret Key: {bytes_to_hex(I_L)}')
        # print(f'\tMaster Chain Code: {bytes_to_hex(I_R)}')
        return cls(key, code)

    def __repr__(self):
        return f"{self.__class__.__name__}(path={self.path}, key={self.key})"

    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase='') -> 'Xprv':
        seed = Mnemonic.to_seed(mnemonic=mnemonic, passphrase=passphrase)
        return cls.from_seed(seed)

    def address(self):
        return self.key.to_public().to_address(compressed=True)

    @classmethod
    def from_xprv(cls, xprv: str) -> 'Xprv':
        ...
        from witnet.util.transformations.bech32 import bech32_decode_address

        bech = bech32_decode_address(xprv)
        idx = 0
        # byte lengths of the serialized byte data
        DEPTH = 1
        INDEX = 4 * bech[idx:idx + DEPTH][0]
        CHAIN = 32
        secret_prefix = b'\x00'
        KEYLN = 32

        depth = bech[idx:idx + DEPTH]
        idx += DEPTH
        if INDEX == 0:
            print('MasterKey')
        index = None
        chain_code = bytes(bech[idx:idx + CHAIN])

        idx += CHAIN
        idx += len(secret_prefix)
        key_data = bytes(bech[idx:idx + KEYLN])
        private_key = WitPrivateKey(key_data)
        public_key = private_key.to_public()

        chain_code = bytes(bech[1:33])
        tmp_xprv = Xprv(key=private_key, code=chain_code, depth=depth[0])
        return bech



def from_slip32(master_key: str, root_path=None) -> Xprv:
    bech = bech32_decode_address(master_key)
    idx = 0
    # byte lengths of the serialized byte data
    DEPTH = 1
    INDEX = 4 * bech[idx:idx + DEPTH][0]
    CHAIN = 32
    secret_prefix = b'\x00'
    KEYLN = 32

    depth = bech[idx:idx + DEPTH]
    idx += DEPTH
    index = None
    chain_code = bytes(bech[idx:idx + CHAIN])

    idx += CHAIN
    idx += len(secret_prefix)
    key_data = bytes(bech[idx:idx + KEYLN])
    private_key = WitPrivateKey(key_data)
    public_key = private_key.to_public()

    chain_code = bytes(bech[1:33])
    private_key = WitPrivateKey(bytes(bech[34:66]))


    return Xprv(key=private_key, code=chain_code, depth=depth[0], path=root_path)




def to_slip32(master_key: Xprv) -> str:
    depth = master_key.depth
    chain_code = master_key.code
    private_key = master_key.key.bytes()

    slip_32 = int(depth).to_bytes(length=1, byteorder='big')
    slip_32 += chain_code
    slip_32 += b'\x00'
    slip_32 += private_key
    slip_32 += b'\x00'
    bech = bech32_encode_master_key(hrp='xprv', data=bytes_to_hex(slip_32))

    return bech
