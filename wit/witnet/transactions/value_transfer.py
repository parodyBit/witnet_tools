from wit.witnet.schema import witnet_proto as proto

# helper function
def build_transaction(inputs, outputs):
    _inputs, _outputs = [], []
    # Inputs
    inputs = [proto.Input.from_json(utxo) for utxo in inputs]

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
        print(vto_dict)
        output: proto.ValueTransferOutput = proto.ValueTransferOutput.from_json(vto_dict)
        _outputs.append(output)
    print(_outputs)
    #outputs = [proto.ValueTransferOutput.from_json(_output) for _output in _outputs]

    vtt_transaction_body = proto.VTTransactionBody(inputs=inputs, outputs=_outputs)
    transaction = proto.VTTransaction(body=vtt_transaction_body, signatures=[])
    return transaction
