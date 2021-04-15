from wit.crypto.hd_wallet.extended_key import Xprv
from wit.crypto.hd_wallet.mnemonic import Mnemonic
from wit.crypto.hd_wallet import from_slip32, to_slip32
from wit.witnet.address.address import Address


def address_from_xprv(xprv:Xprv):
    return Address(address=xprv.address(),
                   public_key_hash=xprv.to_xpub().key.to_pkh(),
                   public_key=xprv.to_xpub().key)


def recover_master_xprv_from_str(xprv_str: str):
    xprv: Xprv = from_slip32(master_key=xprv_str)
    return address_from_xprv(xprv), xprv


def recover_master_xprv_from_mnemonic(mnemonic: str, password: str = ''):
    seed = Mnemonic.to_seed(mnemonic=mnemonic, passphrase=password)
    xprv = Xprv.from_seed(seed=seed)
    return address_from_xprv(xprv), xprv


def recover_node_xprv(xprv):
    return recover_master_xprv_from_str(xprv_str=xprv)


def recover_node_from_mnemonic(mnemonic: str, password: str = ''):
    return recover_master_xprv_from_mnemonic(mnemonic=mnemonic, password=password)


def recover_wallet_xprv_from_mnemonic(mnemonic: str, password: str = '') -> Xprv:
    seed = Mnemonic.to_seed(mnemonic=mnemonic, passphrase=password)
    return Xprv.from_seed(seed=seed) / 3. / 4919. / 0.
