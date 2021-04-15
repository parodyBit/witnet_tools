from wit.util.transformations import bytes_to_int, int_to_bytes, hex_to_bytes, int_to_hex, bytes_to_hex, sha256


class Signature:

    def __init__(self, r, s, force_low_s=True):
        self.r = r

        if force_low_s:
            # https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures
            from wit.crypto.ECDSA.secp256k1 import N
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
        from wit.crypto.ECDSA.secp256k1 import N, CURVE, Point
        from wit.crypto.number_theory import mulinv
        from wit.crypto.ECDSA.secp256k1.public_key import PublicKey
        public_key:PublicKey = public_key
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


def verify_openssl(signature: Signature, signature_form: bytes, pub: 'PublicKey'):
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
