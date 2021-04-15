from dataclasses import dataclass
from typing import List
from wit.util.protobuf_slim import field, field_hdr, idx_hdr, output_hdr
from wit.util.protobuf_slim.serializer import bytes_serializer, var_int
from wit.util.protobuf_slim.types import uint32
from wit.util.protobuf_slim.types import uint64, fixed32, fixed64, sfixed64, sfixed32, sint64, sint32, double, int32, \
    int64, uint
from enum import IntEnum, Enum, unique
from wit.util.transformations import snake_to_camel, camel_to_snake, hex_to_bytes, concat

from wit.util.transformations.bech32 import bech32_decode_address, bech32_encode_address


@unique
class var_case(Enum):
    snake = camel_to_snake
    camel = snake_to_camel


pb_types = {
    'double': double,
    'float': float,
    'int32': int32,
    'int64': int64,
    'uint32': uint32,
    'uint64': uint64,
    'sint32': sint32,
    'sint64': sint64,
    'fixed32': fixed32,
    'fixed64': fixed64,
    'sfixed32': sfixed32,
    'sfixed64': sfixed64,
    'bool': bool,
    'string': str,
    'bytes': bytes,
}


def from_json(class_, data):
    import inspect
    items = class_.__dict__['__annotations__'].keys()
    values = {}
    for x in items:
        if x in data:
            obj = class_.__dict__['__annotations__'][x]
            if str(type(obj)) == "<class 'typing._GenericAlias'>":
                obj_type = obj.__dict__['__args__'][0]
                if type(data[x] == list):
                    values[x]: List[obj_type] = []
                    for item in data[x]:
                        if obj_type.__name__ == 'NoneType':
                            values[x].append(None)
                        else:
                            values[x].append(obj_type.from_json(data=item))
            else:
                if inspect.isfunction(obj):
                    obj = obj(data[x]).__class__
                obj_type = obj.__base__
                if inspect.getmodule(obj).__name__ == 'builtins':
                    if obj.__name__ == 'bytes':
                        values[x] = bytes(data[x])
                if obj_type == PbBase:
                    values[x] = class_.__dict__['__annotations__'][x].from_json(data[x])
    return class_(**values)


class PbBase:
    @classmethod
    def from_json(cls, data, case=var_case.snake):
        return from_json(class_=cls, data=data, case=case)

    def to_pb_bytes(self):
        items = self.__dict__


@dataclass
class Address(PbBase):
    address: bytes = field(1)


@dataclass
class Hash(PbBase):
    SHA256: bytes = field(1)

    def __repr__(self):
        return f'{self.__class__.__name__}(SHA256={self.SHA256.hex()})'

    @classmethod
    def from_json(cls, data, case=var_case.snake):
        return cls(SHA256=hex_to_bytes(data))

    def to_pb_bytes(self):
        return concat([field_hdr, bytes_serializer(self.SHA256)])


@dataclass
class PublicKey(PbBase):
    public_key: bytes = field(1)

    def __repr__(self):
        return f'{self.__class__.__name__}(hash={self.public_key.hex()})'

    @classmethod
    def from_json(cls, data, case=None):
        return cls(public_key=bytes([data['compressed']] + data['bytes']))

    def to_pb_bytes(self):
        contents = concat([field_hdr, bytes_serializer(self.public_key)])
        contents = concat([var_int(18), bytes_serializer(contents)])
        return contents

    def to_json(self):
        return {
            'bytes': list(self.public_key)[1:],
            'compressed': list(self.public_key)[0]
        }


@dataclass
class PublicKeyHash(PbBase):
    hash: bytes = field(1)

    def __repr__(self):
        return f'{self.__class__.__name__}(hash={self.hash.hex()})'

    @classmethod
    def from_json(cls, data, case=var_case.snake):
        from wit.util.transformations.bech32 import bech32_decode_address
        return PublicKeyHash(hash=bytes(bech32_decode_address(data)))

    def to_json(self):
        from wit.witnet.address import Address
        address = Address.from_hex(self.hash.hex())
        return address.public_key_hash

    def to_pb_bytes(self):
        content = concat([field_hdr, bytes_serializer(self.hash)])
        return concat([field_hdr, bytes_serializer(content)])


@dataclass
class Secp256k1Signature(PbBase):
    der: bytes = field(1)

    def __repr__(self):
        return f'{self.__class__.__name__}(hash={self.der.hex()})'

    def to_json(self):
        return {
            'der': list(self.der)
        }

    def to_pb_bytes(self):
        contents = concat([field_hdr, bytes_serializer(self.der)])
        contents = concat([field_hdr, bytes_serializer(contents)])
        return contents


@dataclass
class Signature(PbBase):
    Secp256k1: Secp256k1Signature = field(1)

    def to_json(self):
        return {
            'Secp256k1': self.Secp256k1.to_json()
        }

    def to_pb_bytes(self):
        contents = concat([field_hdr, bytes_serializer(self.Secp256k1.to_pb_bytes())])
        return concat([var_int(18), var_int(43 + len(self.Secp256k1.der)), contents])


@dataclass
class KeyedSignature(PbBase):
    signature: Signature = field(1)
    public_key: PublicKey = field(2)

    def to_json(self):
        return {
            'public_key': self.public_key.to_json(),
            'signature': self.signature.to_json()
        }

    def to_pb_bytes(self):
        return concat([self.signature.to_pb_bytes(), self.public_key.to_pb_bytes()])


@dataclass
class OutputPointer(PbBase):
    transaction_id: Hash = field(1)
    output_index: uint32 = field(2)

    def __repr__(self):
        return f'{self.__class__.__name__}(transaction_id={self.transaction_id}, output_index={self.output_index})'

    def to_pb_bytes(self):
        output_index = b''
        if int(self.output_index) > 0:
            output_index = concat([idx_hdr, var_int(self.output_index)])
        contents = concat([field_hdr, bytes_serializer(hex_to_bytes(self.transaction_id.SHA256.hex()))])
        # need to refactor this
        _bytes = concat([field_hdr, bytes_serializer(contents), output_index])
        _bytes = concat([field_hdr, bytes_serializer(_bytes)])
        _bytes = concat([field_hdr, bytes_serializer(_bytes)])
        return _bytes

    def to_json(self):
        return {'output_pointer': f'{self.transaction_id.SHA256.hex()}:{self.output_index}'}


@dataclass
class Input(PbBase):
    output_pointer: OutputPointer = field(1)

    @classmethod
    def from_json(cls, data, case=var_case.snake):
        if 'output_pointer' in data:
            transaction_id, output_index = data['output_pointer'].split(':')
            return cls(output_pointer=OutputPointer(transaction_id=Hash(SHA256=hex_to_bytes(transaction_id)),
                                                    output_index=output_index))

    def to_pb_bytes(self):
        return self.output_pointer.to_pb_bytes()

    def to_json(self):
        return self.output_pointer.to_json()


@dataclass
class VrfProof(PbBase):
    proof: bytes = field(1)
    public_key: PublicKey = field(2)

    def __repr__(self):
        return f'{self.__class__.__name__}(proof={self.proof.hex()}, pubic_key={self.public_key})'


@dataclass
class DataRequestEligibilityClaim(PbBase):
    proof: VrfProof = field(1)


@dataclass
class CheckpointBeacon(PbBase):
    checkpoint: fixed32 = field(1)
    hash_prev_block: Hash = field(2)

    @classmethod
    def from_json(cls, data, case=var_case.snake):
        return cls(checkpoint=data['checkpoint'], hash_prev_block=Hash(SHA256=hex_to_bytes(data['hashPrevBlock'])))


@dataclass
class BlockMerkleRoots(PbBase):
    mint_hash: Hash = field(1)
    vt_hash_merkle_root: Hash = field(2)
    dr_hash_merkle_root: Hash = field(3)
    commit_hash_merkle_root: Hash = field(4)
    reveal_hash_merkle_root: Hash = field(5)
    tally_hash_merkle_root: Hash = field(6)


@dataclass
class BlockEligibilityClaim(PbBase):
    proof: VrfProof = field(1)


@dataclass
class ValueTransferOutput(PbBase):
    pkh: PublicKeyHash = field(1)
    value: uint64 = field(2)
    time_lock: uint64 = field(3)

    @classmethod
    def from_json(cls, data, case=None):
        data['pkh'] = PublicKeyHash(hash=bytes(bech32_decode_address(data['pkh'])))
        return cls(**data)

    def to_pb_bytes(self):
        time_lock = b''
        if int(self.time_lock) > 0:
            time_lock = concat([var_int(uint(24)), var_int(self.time_lock)])

        content = concat([self.pkh.to_pb_bytes(), idx_hdr, var_int(int(self.value)), time_lock])
        return concat([output_hdr, bytes_serializer(content)])

    def to_json(self):
        return {
            'pkh': bech32_encode_address('wit', self.pkh.hash.hex()),
            'time_lock': int(self.time_lock),
            'value': self.value
        }


@dataclass
class MintTransaction(PbBase):
    epoch: fixed32 = field(1)
    outputs: List[ValueTransferOutput] = field(2)


@dataclass
class VTTransactionBody(PbBase):
    inputs: List[Input] = field(1, default_factory=list)
    outputs: List[ValueTransferOutput] = field(2, default_factory=list)

    def to_pb_bytes(self):
        inputs = concat([_input.to_pb_bytes() for _input in self.inputs])
        outputs = concat([_output.to_pb_bytes() for _output in self.outputs])
        return concat([inputs, outputs])

    def to_json(self):
        return {
            'inputs': [_input.to_json() for _input in self.inputs],
            'outputs': [output.to_json() for output in self.outputs],
        }


@dataclass
class VTTransaction(PbBase):
    body: VTTransactionBody = field(1)
    signatures: List[KeyedSignature] = field(2, default_factory=list)

    def to_json(self):
        return {
            'transaction': {
                'ValueTransfer': {
                    'body': self.body.to_json(),
                    'signatures': [signature.to_json() for signature in self.signatures]
                }
            }
        }

    def to_pb_bytes(self):
        body = self.body.to_pb_bytes()
        signatures = concat([_signature.to_pb_bytes() for _signature in self.signatures])
        contents = bytes_serializer(concat([body, signatures]))
        contents = concat([field_hdr, bytes_serializer(contents)])
        return contents

    @property
    def transaction_id(self):
        from wit.util.transformations import sha256
        return sha256(self.body.to_pb_bytes()).hex()

@dataclass
class RADFilter(PbBase):
    op: uint32 = field(1)
    args: bytes = field(2)


class RADType(IntEnum):
    HttpGet = 0


@dataclass
class RADRetrieve(PbBase):
    kind: RADType = field(1)
    url: str = field(2)
    script: bytes = field(3)


@dataclass
class RADAggregate(PbBase):
    filters: List[RADFilter] = field(1)
    reducer: uint32 = field(2)


@dataclass
class RADTally(PbBase):
    filters: List[RADFilter] = field(1)
    reducer: uint32 = field(2)


@dataclass
class RADRequest(PbBase):
    time_lock: uint64 = field(1)
    retrieve: List[RADRetrieve] = field(2)
    aggregate: RADAggregate = field(3)
    tally: RADTally = field(4)


@dataclass
class DataRequestOutput(PbBase):
    data_request: RADRequest = field(1)
    witness_reward: uint64 = field(2)
    witnesses: uint32 = field(3)
    commit_and_reveal_fee: uint64 = field(4)
    min_consensus_percentage: uint32 = field(5)
    collateral: uint64 = field(6)


@dataclass
class DRTransactionBody(PbBase):
    inputs: List[Input] = field(1)
    outputs: List[ValueTransferOutput] = field(2)
    dr_output: DataRequestOutput = field(3)


@dataclass
class DRTransaction(PbBase):
    body: DRTransactionBody = field(1)
    signatures: List[KeyedSignature] = field(2)
