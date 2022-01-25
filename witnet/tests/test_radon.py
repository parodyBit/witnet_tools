import unittest

from witnet.rad.script import RadonString
from witnet.rad.util import cbor_to_radon, radon_to_cbor

cbor_script = [132, 24, 119, 130, 24, 102, 99, 98, 112, 105, 130, 24, 102, 99, 85, 83,
               68, 130, 24, 100, 106, 114, 97, 116, 101, 95, 102, 108, 111, 97, 116]

rad_script = [119, [102, 'bpi'], [102, 'USD'], [100, 'rate_float']]


class TestRadon(unittest.TestCase):

    def test_cbor_to_radon(self):
        assert cbor_to_radon(cbor_script) == rad_script

    def test_radon_to_cbor(self):
        assert radon_to_cbor(rad_script) == cbor_script

    def test_rad_request(self):
        test_script = RadonString\
            .parse_json_map()\
            .get_map('bpi')\
            .get_map('USD')\
            .get_float('rate_float')\
            .encode()

        assert test_script == cbor_script
