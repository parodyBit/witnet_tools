from witnet.schema.input import Input
from witnet.schema.value_transfer_output import ValueTransferOutput
from witnet.schema.vt_transaction import VTTransaction
from witnet.schema.vt_transaction_body import VTTransactionBody


def build_transaction(inputs, outputs):
    _inputs, _outputs = [], []
    # Inputs
    inputs = [Input.from_json(utxo) for utxo in inputs]

    # Outputs
    # Need to change the names a bit to conform to the protobuf naming convention
    # we input it using the same convention of the witnet wallet json rpc server
    # i.e. convert ['address','timelock','amount'] to ['pkh','time_lock','value']
    for receiver in outputs:
        pkh = receiver['address']
        value = receiver['value']

        if 'time_lock' in receiver:
            time_lock = receiver['time_lock']
        else:
            time_lock = 0

        vto_dict = {'pkh': pkh, 'time_lock': time_lock, 'value': value}

        output: ValueTransferOutput = ValueTransferOutput.from_json(vto_dict)
        _outputs.append(output)

    vtt_transaction_body = VTTransactionBody(inputs=inputs, outputs=_outputs)
    transaction = VTTransaction(body=vtt_transaction_body, signatures=[])
    return transaction
