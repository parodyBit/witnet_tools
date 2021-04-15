from enum import Enum, unique
from wit.util.transformations import sha256, sha512


class WitnetMainnet:
    HRP = 'wit'
    PUBKEY_ADDRESS = 0x00
    SCRIPT_ADDRESS = 0x05
    SECRET_KEY = 0x80
    WIF = 0x80


class ExtendedPrivateKey:
    HRP = 'xprv'

@unique
class NETWORK(Enum):
    MAINNET = 'Mainnet'
    TESTNET = 'Testnet'
    DEVNET = 'Devnet'


def current_network():
    return NETWORK('Mainnet')


networks = {
    NETWORK.MAINNET: WitnetMainnet,
}


def network(attr):
    net = networks[current_network()]
    return vars(net)[attr]


class WitnetMasterKey:
    MASTER_KEY_SALT = b'Bitcoin Seed'
    PBKDF2_HASH_FUNCTION = sha512
    PBKDF2_HASH_ITERATIONS = 2048
    ENC_SALT_LENGTH = 64
