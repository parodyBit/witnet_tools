import bisect
import hashlib
import hmac
import itertools
import os
from typing import AnyStr, List, Sequence, TypeVar, Union
import unicodedata

_T = TypeVar("_T")
PBKDF2_ROUNDS = 2048


class ConfigurationError(Exception):
    pass


# From <https://stackoverflow.com/questions/212358/binary-search-bisection-in-python/2233940#2233940>
def binary_search(
        a: Sequence[_T],
        x: _T,
        lo: int = 0,
        hi: int = None,  # can't use a to specify default for hi
) -> int:
    hi = hi if hi is not None else len(a)  # hi defaults to len(a)
    pos = bisect.bisect_left(a, x, lo, hi)  # find insertion position
    return pos if pos != hi and a[pos] == x else -1  # don't walk off the end


# Refactored code segments from <https://github.com/keis/base58>
def b58encode(v: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    p, acc = 1, 0
    for c in reversed(v):
        acc += p * c
        p = p << 8

    string = ""
    while acc:
        acc, idx = divmod(acc, 58)
        string = alphabet[idx: idx + 1] + string
    return string


class Mnemonic(object):
    def __init__(self, language: str):
        self.radix = 2048
        with open(f'{self._get_directory()}/{language}.txt', 'r', encoding='utf-8') as f:
            self.wordlist = [w.strip() for w in f.readlines()]
        if len(self.wordlist) != self.radix:
            raise ConfigurationError(
                f'Word list should contain {self.radix} words, but it contains {len(self.wordlist)} words.'
            )

    @staticmethod
    def _get_directory() -> str:
        return os.path.join(os.path.dirname(__file__), "wordlist")

    @classmethod
    def list_languages(cls) -> List[str]:
        return [f.split('.')[0] for f in os.listdir(cls._get_directory()) if f.endswith('.txt')]

    @staticmethod
    def normalize_string(txt: AnyStr) -> str:
        if isinstance(txt, bytes):
            utxt = txt.decode('utf8')
        elif isinstance(txt, str):
            utxt = txt
        else:
            raise TypeError('String value expected')

        return unicodedata.normalize('NFKD', utxt)

    @classmethod
    def detect_language(cls, code: str) -> str:
        code = cls.normalize_string(code)
        first = code.split(" ")[0]
        languages = cls.list_languages()

        for lang in languages:
            mnemo = cls(lang)
            if first in mnemo.wordlist:
                return lang

        raise ConfigurationError("Language not detected")

    def generate(self, word_count: int = 12) -> str:
        strength = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}
        if word_count not in strength.keys():
            raise ValueError(
                f'Number of words must be one of the following: [12, 15, 18, 21, 24], but it is not ({word_count}).'
            )
        return self.to_mnemonic(os.urandom(strength[word_count] // 8))

    # Adapted from <http://tinyurl.com/oxmn476>
    def to_entropy(self, words: Union[List[str], str]) -> bytearray:
        if not isinstance(words, list):
            words = words.split(" ")
        if len(words) not in [12, 15, 18, 21, 24]:
            raise ValueError(
                f'Number of words must be one of the following: [12, 15, 18, 21, 24], but it is not ({len(words)}).'
            )
        # Look up all the words in the list and construct the
        # concatenation of the original entropy and the checksum.
        concat_length_bits = len(words) * 11
        concat_bits = [False] * concat_length_bits
        wordindex = 0
        if self.detect_language(" ".join(words)) == "english":
            use_binary_search = True
        else:
            use_binary_search = False
        for word in words:
            # Find the words index in the wordlist
            ndx = (
                binary_search(self.wordlist, word)
                if use_binary_search
                else self.wordlist.index(word)
            )
            if ndx < 0:
                raise LookupError('Unable to find "%s" in word list.' % word)
            # Set the next 11 bits to the value of the index.
            for ii in range(11):
                concat_bits[(wordindex * 11) + ii] = (ndx & (1 << (10 - ii))) != 0
            wordindex += 1
        checksum_length_bits = concat_length_bits // 33
        entropy_length_bits = concat_length_bits - checksum_length_bits
        # Extract original entropy as bytes.
        entropy = bytearray(entropy_length_bits // 8)
        for ii in range(len(entropy)):
            for jj in range(8):
                if concat_bits[(ii * 8) + jj]:
                    entropy[ii] |= 1 << (7 - jj)
        # Take the digest of the entropy.
        hash_bytes = hashlib.sha256(entropy).digest()
        hash_bits = list(
            itertools.chain.from_iterable(
                [c & (1 << (7 - i)) != 0 for i in range(8)] for c in hash_bytes
            )
        )
        # Check all the checksum bits.
        for i in range(checksum_length_bits):
            if concat_bits[entropy_length_bits + i] != hash_bits[i]:
                raise ValueError("Failed checksum.")
        return entropy

    def to_mnemonic(self, data: bytes) -> str:
        if len(data) not in [16, 20, 24, 28, 32]:
            raise ValueError(
                f'Data length should be one of the following: [16, 20, 24, 28, 32], but it is not ({len(data)}).'
            )
        h = hashlib.sha256(data).hexdigest()
        b = (
                bin(int.from_bytes(data, byteorder='big'))[2:].zfill(len(data) * 8)
                + bin(int(h, 16))[2:].zfill(256)[: len(data) * 8 // 32]
        )
        result = []
        for i in range(len(b) // 11):
            idx = int(b[i * 11: (i + 1) * 11], 2)
            result.append(self.wordlist[idx])
        if (
                self.detect_language(' '.join(result)) == 'japanese'
        ):  # Japanese must be joined by ideographic space.
            result_phrase = u'\u3000'.join(result)
        else:
            result_phrase = " ".join(result)
        return result_phrase

    def check(self, mnemonic: str) -> bool:
        mnemonic_list = self.normalize_string(mnemonic).split(" ")
        # list of valid mnemonic lengths
        if len(mnemonic_list) not in [12, 15, 18, 21, 24]:
            return False
        try:
            idx = map(
                lambda x: bin(self.wordlist.index(x))[2:].zfill(11), mnemonic_list
            )
            b = "".join(idx)
        except ValueError:
            return False
        l = len(b)  # noqa: E741
        d = b[: l // 33 * 32]
        h = b[-l // 33:]
        nd = int(d, 2).to_bytes(l // 33 * 4, byteorder="big")
        nh = bin(int(hashlib.sha256(nd).hexdigest(), 16))[2:].zfill(256)[: l // 33]
        return h == nh

    def expand_word(self, prefix: str) -> str:
        if prefix in self.wordlist:
            return prefix
        else:
            matches = [word for word in self.wordlist if word.startswith(prefix)]
            if len(matches) == 1:  # matched exactly one word in the word list
                return matches[0]
            else:
                # exact match not found.
                # this is not a validation routine, just return the input
                return prefix

    def expand(self, mnemonic: str) -> str:
        return " ".join(map(self.expand_word, mnemonic.split(" ")))

    @classmethod
    def to_seed(cls, mnemonic: str, passphrase: str = "") -> bytes:
        mnemonic = cls.normalize_string(mnemonic)
        passphrase = cls.normalize_string(passphrase)
        passphrase = "mnemonic" + passphrase
        mnemonic_bytes = mnemonic.encode("utf-8")
        passphrase_bytes = passphrase.encode("utf-8")
        stretched = hashlib.pbkdf2_hmac(
            hash_name="sha512", password=mnemonic_bytes, salt=passphrase_bytes, iterations=PBKDF2_ROUNDS
        )
        return stretched[:64]

    @staticmethod
    def to_hd_master_key(seed: bytes, testnet: bool = False) -> str:
        if len(seed) != 64:
            raise ValueError(f'Provided seed should have length of 64, is {len(seed)}', )

        # Compute HMAC-SHA512 of seed
        seed = hmac.new(b"Bitcoin seed", seed, digestmod=hashlib.sha512).digest()

        # Serialization format can be found at:
        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format
        xprv = b'\x04\x88\xad\xe4'
        if testnet:
            xprv = b"\x04\x35\x83\x94"  # Version for private testnet
        xprv += b"\x00" * 9  # Depth, parent fingerprint, and child number
        xprv += seed[32:]  # Chain code
        xprv += b"\x00" + seed[:32]  # Master key

        # Double hash using SHA256
        hashed_xprv = hashlib.sha256(xprv).digest()
        hashed_xprv = hashlib.sha256(hashed_xprv).digest()

        # Append 4 bytes of checksum
        xprv += hashed_xprv[:4]

        # Return base58
        return b58encode(xprv)
