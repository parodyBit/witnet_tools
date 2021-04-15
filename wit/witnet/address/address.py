from wit.crypto.ECDSA import PublicKey, PrivateKey
from wit.util.transformations import wit_to_nano_wit, nano_wit_to_wit, sha256
from wit.util.transformations.bech32 import bech32_decode_address
import wit.witnet.schema.witnet_proto as proto
from wit.witnet.node import NodeClient
from datetime import datetime


class Address:
    def __init__(self, address, public_key_hash, public_key: PublicKey = None):
        self.address = address
        self.public_key_hash = public_key_hash
        self.public_key = public_key
        self._utxos = None

    def __repr__(self):
        return f'{self.address}'

    @property
    def utxos(self):
        if not self._utxos:
            node = NodeClient.manager()
            utxos = node.get_utxo_info(address=self.address)
            self._utxos = utxos
        return self._utxos

    @property
    def balance(self):
        if not self._utxos:
            self._utxos = self.utxos
        return nano_wit_to_wit(sum([out['value'] for out in self.utxos]))

    def decode_address(self):
        return bech32_decode_address(self.public_key_hash)

    @classmethod
    def from_hex(cls, hex_string) -> 'Address':

        key = PublicKey.from_hex(hex_string)
        return Address(address=key.to_address(), public_key_hash=key.to_pkh(), public_key=key)


    def send_vtt(self, transaction):
        node = NodeClient.manager()
        response = node.inventory(inventory_item=transaction.to_json())
        return response

    def create_vtt(self, to, private_key: PrivateKey, change_address=None, utxo_selection_strategy=None, fee: int = 0,
         fee_type='absolute'):

        node = NodeClient.manager()
        now = datetime.timestamp(datetime.now())
        to_sum = 0
        print(self.balance)
        print(to_sum + fee)
        for receiver in to:
            to_sum += receiver['value']
        to_sum += fee
        if self.balance < nano_wit_to_wit(to_sum):
            return '0', {"error": "Insufficient Funds"}


        available_utxos, selected_utxos = {}, []
        for x, utxo in enumerate(self.utxos):
            if utxo['timelock'] < now:
                available_utxos[utxo['output_pointer']] = utxo['value']

        sorted_x = sorted(available_utxos.items(), key=lambda kv: kv[1])
        value_owed = to_sum
        selected_utxo_total_value = 0

        for i, x in enumerate(sorted_x):
            if value_owed > 0:
                selected_utxos.append(x)
                selected_utxo_total_value += x[1]
                value_owed -= x[1]

        change = int(abs(value_owed))
        if change > 0:
            to.append({'address': self.address, 'time_lock': 0, 'value': change})
            change = 0

        inputs, outputs = [], []

        # Inputs
        for utxo in selected_utxos:
            output_pointer, value = utxo
            # print(output_pointer, value)
            _input = proto.Input.from_json({'output_pointer': output_pointer})
            inputs.append(_input)

        # Outputs
        for receiver in to:
            pkh = receiver['address']
            value = receiver['value']

            if 'time_lock' in receiver:
                time_lock = receiver['time_lock']
            else:
                time_lock = 0

            vto_dict = {
                'pkh': pkh,
                'time_lock': time_lock,
                'value': value
            }

            output: proto.ValueTransferOutput = proto.ValueTransferOutput.from_json(vto_dict)
            outputs.append(output)
        vtt_transaction_body = proto.VTTransactionBody(inputs=inputs, outputs=outputs)

        vtt_hash = sha256(vtt_transaction_body.to_pb_bytes())
        der_bytes = private_key.sign_hash(vtt_hash).encode(compact=False)

        signatures = []
        signature = proto.Signature(Secp256k1=proto.Secp256k1Signature(der=der_bytes))
        pubkey = proto.PublicKey(public_key=private_key.to_public().encode())
        sig = proto.KeyedSignature(signature=signature, public_key=pubkey)

        for _input in inputs:
            signatures.append(sig)

        vtt_transaction_body = proto.VTTransactionBody(inputs=inputs, outputs=outputs)
        transaction = proto.VTTransaction(body=vtt_transaction_body, signatures=signatures)
        return vtt_hash, transaction
