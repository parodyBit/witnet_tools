from examples.key_recovery import recover_wallet_xprv_from_mnemonic, recover_node_xprv, \
    recover_master_xprv_from_mnemonic
from examples.key_recovery import address_from_xprv
from wit.crypto.ECDSA.secp256k1 import PublicKey, PrivateKey
from wit.crypto.hd_wallet import to_slip32
from wit.crypto.hd_wallet.extended_key import Xprv
from wit.crypto.hd_wallet.mnemonic import Mnemonic
from wit.util.transformations import wit_to_nano_wit, hex_to_bytes, sha256
from wit.witnet.address import Address
from wit.witnet.node.node_client import NodeClient
from wit.witnet.schema import witnet_proto as proto
from wit.witnet.transactions import value_transfer

# Connect to the node json rpc server
node_client = NodeClient(ipv4='12.0.0.1', port=21338)

# All examples will use these test vectors

test_xprv_str = 'xprv1qpujxsyd4hfu0dtwa524vac84e09mjsgnh5h9crl8wrqg58z5wmsuqqcxlqmar3fjhkprndzkpnp2xlze76g4hu7g7c4r4r2m2e6y8xlvu566tn6'

test_mnemonic = 'abandon abandon abandon abandon abandon abandon ' \
                'abandon abandon abandon abandon abandon about'

inputs = [
    {'output_pointer': '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f:0'},
    {'output_pointer': '0000000000000000000000000000000000000000000000000000000000000000:1'},
]
# these addresses are the first two wallet addresses for the test vector
# value in nanoWit
outputs = [
    {'address': 'wit174la8pevl74hczcpfepgmt036zkmjen4hu8zzs', 'time_lock': 0, 'value': 1_000_000_000},
    {'address': 'wit1cetlhcpqc3jxqxap6egql5py4jrgwnfzfsm6l7', 'time_lock': 0, 'value': 1_000_000}
]


def basic_node_send_vtt_example():
    node_address, node_xprv = recover_node_xprv(xprv=test_xprv_str)
    # node_address, node_xprv = recover_master_xprv_from_mnemonic(mnemonic=mnemonic, password='')

    print(node_address.address)
    print('Balance:', node_address.balance, 'wit')
    # private key for signing transactions
    private_key = node_xprv.key
    # public_key = node_xprv.to_xpub().key

    # the create_vtt method calls the node to get utxos
    #    selects smallest utxo first
    #    the change is computed and automatically returned to the node
    transaction_id, transaction = node_address.create_vtt(to=outputs, private_key=private_key, fee=1)
    # since the test vector account should have zero balance
    #    > {"error": "Insufficient Funds"}
    #   the error is in creating the transaction. not an error from the node.

    print(transaction)

    # enable this if the transaction built is valid and you really want to send it..
    real_transaction = False
    if real_transaction:
        print(transaction.to_json())
        print('Sending Value Transfer Transaction:', transaction_id)
        response = node_client.inventory(inventory_item=transaction)
        print(response, transaction.transaction_id)


def basic_wallet_recovery(limit=10):
    # wallet from the mnemonic
    wallet_master_xprv = recover_wallet_xprv_from_mnemonic(mnemonic=test_mnemonic)
    ext_xprv_list, change_xprv_list = [], []
    ext_addr_list, change_addr_list = [], []

    for index in range(limit):
        ext_xprv: Xprv = wallet_master_xprv / 0 / index
        change_xprv: Xprv = wallet_master_xprv / 1 / index

        ext_xprv_list.append(ext_xprv)
        change_xprv_list.append(change_xprv)

        ext_addr_list.append(address_from_xprv(ext_xprv))
        change_addr_list.append(address_from_xprv(change_xprv))

        print(ext_xprv.path, ext_xprv.address())
        print(change_xprv.path, change_xprv.address())
    balance = 0
    for index in range(limit):
        balance += ext_addr_list[index].balance
        balance += change_addr_list[index].balance
    print('Wallet Balance:', balance)
    return ext_addr_list, ext_xprv_list


# Create and sign a transaction
def buid_vtt_example(inputs, outputs) -> proto.VTTransaction:
    # the build_transaction method returns a transaction without signatures
    transaction: proto.VTTransaction = value_transfer.build_transaction(inputs, outputs)
    print(transaction.to_json())
    print(transaction.transaction_id)
    return transaction


def sign_vtt_example(transaction: proto.VTTransaction, private_key: PrivateKey) -> proto.VTTransaction:
    # sign the transaction with the private key and return it
    return private_key.sign_vtt(transaction=transaction)



def mnemonic_example():
    # language is the filename of a file in
    # wit/crypto/hd_wallet/mnemonic/wordlist/
    mnemo = Mnemonic(language='english')
    mnemonic = mnemo.generate(word_count=12)
    seed = Mnemonic.to_seed(mnemonic=mnemonic)
    xprv = Xprv.from_seed(seed=seed)
    print(mnemonic)
    print(xprv.address())
    print(to_slip32(xprv))
