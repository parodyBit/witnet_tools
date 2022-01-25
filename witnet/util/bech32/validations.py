
checksumLength = 6
seperator = '1'


def is_checksum_too_short(seperator_position: int, data: str) -> bool:
    return (len(data) - seperator_position - 1 - checksumLength) < 0


def is_hrp_too_short(seperator_position: int):
    return seperator_position == 0


def is_mixed_case(data: str):
    return data.lower() != data and data.upper() != data


def has_invalid_seperator(data: str) -> bool:
    return data.rfind(seperator) == -1
