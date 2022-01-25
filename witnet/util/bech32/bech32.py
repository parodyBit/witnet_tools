from typing import List

CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]


def bech32_poly_mod(values) -> int:
    """Internal function that computes the Bech32 checksum."""
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> List[int]:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp: str, data) -> bool:
    """Verify a checksum given HRP and converted data characters."""
    return bech32_poly_mod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp: str, data):
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_poly_mod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
