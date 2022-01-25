import unittest

from witnet.crypto.hd_wallet.extended_private_key import Xprv


xprv_str = 'xprv1qpujxsyd4hfu0dtwa524vac84e09mjsgnh5h9crl8wrqg58z5wmsuqqcxlqmar3fjhkprndzkpnp2xlze76g4hu7g7c4r4r2m2e6y8xlvu566tn6'
mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'



class TestKeys(unittest.TestCase):

    def xprv_from_mnemonic(self):
        xprv = Xprv.from_xprv(xprv_str)
        print(xprv.address())


    def xprv_from_xprv_str(self):
        ...

    def node_key_from_xprv(self):
        ...

    def wallet_from_xprv(self):
        ...
