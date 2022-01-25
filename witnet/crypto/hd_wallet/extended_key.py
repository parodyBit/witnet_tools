from typing import Union

from witnet.crypto.secp256k1 import WitPrivateKey, WitPublicKey
from witnet.util.transformations import bytes_to_int, bytes_to_hex, sha256, base58

from witnet.witnet.network import network

KEY = Union[WitPrivateKey, WitPublicKey]


class ExtendedKey:
    root_path = NotImplemented

    def __init__(self, key: KEY, code: bytes, depth=0, i=None, parent=b'\x00\x00\x00\x00', path=None):
        self.key = key
        self.code = code
        assert depth in range(256), 'Depth can only be 0-255'
        self.depth = depth
        if i is not None:
            assert 0 <= i < 1 << 32, f'Invalid i : {i}'
        self.i = i
        self.parent = parent
        self.path = path or self.root_path
        assert (self.depth == 0 and self.i is None and self.parent == b'\x00\x00\x00\x00' and self.path == self.root_path) or \
               (self.depth != 0 and self.i is not None and self.parent != b'\x00\x00\x00\x00' and self.path != self.root_path), \
            f"Unable to determine if root path (depth={self.depth}, i={self.i}, path={self.path}, parent={bytes_to_hex(self.parent)})"

    def child(self, i):
        raise NotImplementedError

    def is_master(self):
        return self.depth == 0 and self.i is None and self.parent == b'\x00\x00\x00\x00' and self.path == self.root_path

    def __truediv__(self, other):
        if isinstance(other, float):
            # hardened child derivation
            i = int(other) + 2 ** 31
        elif isinstance(other, int):
            # non-hardened child derivation
            i = other
        else:
            raise TypeError
        return self.child(i)

    def __floordiv__(self, other):
        if not isinstance(other, int):
            raise TypeError
        return self.child(other + 2 ** 31)

    def id(self):
        raise NotImplementedError

    def fingerprint(self):
        return self.id()[:4]

    def serialize(self):
        raise NotImplementedError

    def encode(self):
        data = self.serialize()
        assert len(data) == 78
        checksum = sha256(sha256(data))[:4]
        return base58.encode(data + checksum)

    @classmethod
    def deserialize(cls, bts: bytes) -> 'ExtendedKey':
        from witnet.crypto.hd_wallet.extended_private_key import Xprv
        from witnet.crypto.hd_wallet.extended_public_key import Xpub

        def read(n):
            nonlocal bts
            data, bts = bts[:n], bts[n:]
            return data

        net = read(4)
        is_private = net in network('Mainnet').values()
        is_public = net in network('Mainnet').values()
        assert is_public ^ is_private, f'Invalid network bytes : {bytes_to_hex(net)}'
        # address_lookup = {val: key for key, val in (network('Mainnet') if is_private else network('Mainnet')).items()}
        constructor = Xprv if is_private else Xpub
        depth = bytes_to_int(read(1))
        assert depth in range(256), f'Invalid depth : {depth}'
        fingerprint = read(4)
        i = bytes_to_int(read(4))
        if depth == 0:
            i = None
            path = None
        else:
            ih = f'{i}' if i < 2 ** 31 else f"{i - 2 ** 31}h"
            path = '/'.join([constructor.root_path] + ['x' for _ in range(depth - 1)] + [ih])

        code = read(32)
        key = read(33)
        key = WitPrivateKey(key) if is_private else WitPublicKey.decode(key)
        assert not bts, 'Leftover bytes'
        return constructor(key, code, depth=depth, i=i, parent=fingerprint, path=path)

    @classmethod
    def decode(cls, string: str) -> 'ExtendedKey':
        bts = base58.decode(string)
        assert len(bts) == 82, f'Invalid length {len(bts)})'
        data, checksum = bts[:78], bts[78:]
        assert sha256(sha256(data)).startswith(checksum), 'Invalid checksum'
        return cls.deserialize(data)

    def __eq__(self, other):
        return self.encode() == other.encode()
