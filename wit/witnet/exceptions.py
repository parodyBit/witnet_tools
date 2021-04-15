from urllib.error import HTTPError


class TransactionError(Exception):
    def __init__(self, message, transaction=None, data=None, transaction_hash=None):
        self.message = message
        self.transaction = transaction
        self.data = data
        self.transaction_hash = transaction_hash


class SerializationError(TransactionError):
    pass


class ValidationError(TransactionError):
    pass


class SigningError(TransactionError):
    pass


class UpstreamError(Exception):
    pass


class ScriptValidationError(Exception):
    pass


class Base58DecodeError(Exception):
    pass


class InvalidAddress(Exception):
    pass


class KeyDerivationError(Exception):
    pass


__all__ = [
    'SigningError',
    'TransactionError',
    'ValidationError',
    'ScriptValidationError',
    'Base58DecodeError',
    'HTTPError',
    'SerializationError',
    'UpstreamError',
    'InvalidAddress',
    'KeyDerivationError',
]
