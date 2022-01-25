from dataclasses import dataclass
from typing import Union, Tuple, List


@dataclass
class WalletError:
    code: int
    message: str


@dataclass
class AddressInfo:
    label: Union[None, str]
    received_payments: Union[None, list]
    received_amount: int
    first_payment_date: Union[None, int]
    last_payment_date: Union[None, int]


@dataclass
class Address:
    address: str
    index: int
    keychain: int
    account: int
    path: str
    info: AddressInfo


@dataclass
class ExtendedKeyedSignature:
    signature: str
    public_key: str
    chaincode: str





@dataclass
class WalletInfo:
    first_payment_date: Union[None, str]
    label: Union[None, str]
    last_payment_date: Union[None, str]
    received_amount: str
    received_payments: list


@dataclass
class WalletAddress:
    account: int
    address: str
    index: int
    info: Union[None, dict, WalletInfo]
    keychain: int
    path: str

    def __post_init__(self):
        self.info = WalletInfo(**self.info)


@dataclass
class WalletAccount:
    addresses: List[Address]


@dataclass
class Confirmed:
    available: int
    locked: int


@dataclass
class Unconfirmed:
    available: int
    locked: int


@dataclass
class AccountBalance:
    confirmed: Union[None, dict, Confirmed]
    local: str
    unconfirmed: Union[None, dict, Unconfirmed]

    def __post_init__(self):
        self.confirmed = Confirmed(**self.confirmed) if isinstance(self.confirmed, dict) else ...
        if type(self.unconfirmed) == dict:
            self.unconfirmed = Unconfirmed(**self.unconfirmed)


@dataclass
class WalletSession:
    account_balance: Union[None, dict, AccountBalance]
    available_accounts: list
    current_account: int
    description: Union[None, str]
    name: str
    session_expiration_secs: int
    session_id: str

    def __post_init__(self):
        print(type(self.account_balance))
        if type(self.account_balance) == dict:
            self.account_balance = AccountBalance(**self.account_balance)
