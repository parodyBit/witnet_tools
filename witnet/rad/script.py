from typing import List, Union

from witnet.rad.op_codes import OP
from witnet.rad.util import radon_to_cbor


def concat(script: List, op):
    _script = script.copy()
    _script.append(op)
    return _script


class RadonType:
    script: List[Union[list, int, str, float, bool, bytes]]

    def __init__(self, script: List):
        self.script = script

    def encode(self) -> List[int]:
        return radon_to_cbor(self.script.copy())


class RadonArray(RadonType):

    def count(self) -> 'RadonInteger':
        return RadonInteger(concat(self.script, OP.ARRAY_COUNT))

    def filter(self, i: int) -> 'RadonArray':
        return RadonArray(concat(self.script, [OP.ARRAY_FILTER, i]))

    def get_array(self, i: int) -> 'RadonArray':
        return RadonArray(concat(self.script, [OP.ARRAY_GET_ARRAY, i]))

    def get_boolean(self, i: int) -> 'RadonBoolean':
        return RadonBoolean(concat(self.script, [OP.ARRAY_GET_BOOLEAN, i]))

    def get_bytes(self, i: int) -> 'RadonBytes':
        return RadonBytes(concat(self.script, [OP.ARRAY_GET_BYTES, i]))

    def get_float(self, i: int) -> 'RadonFloat':
        return RadonFloat(concat(self.script, [OP.ARRAY_GET_FLOAT, i]))

    def get_integer(self, i: int) -> 'RadonInteger':
        return RadonInteger(concat(self.script, [OP.ARRAY_GET_INTEGER, i]))

    def get_map(self, i: int) -> 'RadonMap':
        return RadonMap(concat(self.script, [OP.ARRAY_GET_MAP, i]))

    def get_string(self, i: int) -> 'RadonString':
        return RadonString(concat(self.script, [OP.ARRAY_GET_STRING, i]))

    def map(self, i: int) -> 'RadonArray':
        return RadonArray(concat(self.script, [OP.ARRAY_MAP, i]))

    def reduce(self, i: int) -> 'RadonArray':
        return RadonArray(concat(self.script, [OP.ARRAY_REDUCE, i]))

    def sort(self, i: int) -> 'RadonArray':
        return RadonArray(concat(self.script, [OP.ARRAY_SORT, i]))


class RadonBoolean(RadonType):

    def as_string(self) -> 'RadonString':
        return RadonString(concat(self.script, OP.BOOLEAN_AS_STRING))

    def negate(self) -> 'RadonBoolean':
        return RadonBoolean(concat(self.script, OP.BOOLEAN_NEGATE))


class RadonBytes(RadonType):

    def as_string(self) -> 'RadonString':
        return RadonString(concat(self.script, OP.BYTES_AS_STRING))

    def hash(self) -> 'RadonString':
        return RadonString(concat(self.script, OP.BYTES_HASH))


class RadonFloat(RadonType):
    def absolute(self) -> 'RadonFloat':
        return RadonFloat(concat(self.script, OP.FLOAT_ABSOLUTE))

    def as_string(self) -> 'RadonString':
        return RadonString(concat(self.script, OP.FLOAT_AS_STRING))

    def ceiling(self) -> 'RadonInteger':
        return RadonInteger(concat(self.script, OP.FLOAT_CEILING))

    def floor(self) -> 'RadonInteger':
        return RadonInteger(concat(self.script, OP.FLOAT_FLOOR))

    def greater_than(self, i: float) -> 'RadonBoolean':
        return RadonBoolean(concat(self.script, [OP.FLOAT_GREATER_THAN, i]))

    def less_than(self, i: float) -> 'RadonBoolean':
        return RadonBoolean(concat(self.script, [OP.FLOAT_LESS_THAN, i]))

    def modulo(self, i: int) -> 'RadonInteger':
        return RadonInteger(concat(self.script, [OP.FLOAT_MODULO, i]))

    def multiply(self, i: float) -> 'RadonFloat':
        return RadonFloat(concat(self.script, [OP.FLOAT_MULTIPLY, i]))

    def negate(self) -> 'RadonFloat':
        return RadonFloat(concat(self.script, OP.FLOAT_NEGATE))

    def power(self, i: int) -> 'RadonFloat':
        return RadonFloat(concat(self.script, [OP.FLOAT_POWER, i]))

    def round(self) -> 'RadonInteger':
        return RadonInteger(concat(self.script, OP.FLOAT_ROUND))

    def truncate(self, i: int) -> 'RadonFloat':
        return RadonFloat(concat(self.script, [OP.FLOAT_TRUNCATE, i]))


class RadonInteger(RadonType):

    def absolute(self) -> 'RadonInteger':
        return RadonInteger(concat(self.script, OP.INTEGER_ASBOLUTE))

    def as_float(self) -> 'RadonFloat':
        return RadonFloat(concat(self.script, OP.INTEGER_AS_FLOAT))

    def as_string(self) -> 'RadonString':
        return RadonString(concat(self.script, OP.INTEGER_AS_STRING))

    def greater_than(self, i: int) -> 'RadonBoolean':
        return RadonBoolean(concat(self.script, [OP.INTEGER_GREATER_THAN, i]))

    def less_than(self, i: int) -> 'RadonBoolean':
        return RadonBoolean(concat(self.script, [OP.INTEGER_LESS_THAN, i]))

    def modulo(self, i: int) -> 'RadonInteger':
        return RadonInteger(concat(self.script, [OP.INTEGER_MODULO, i]))

    def multiply(self, i: int) -> 'RadonInteger':
        return RadonInteger(concat(self.script, [OP.INTEGER_MULTIPLY, i]))

    def negate(self) -> 'RadonInteger':
        return RadonInteger(concat(self.script, OP.INTEGER_NEGATE))
    
    def power(self, i: int) -> 'RadonInteger':
        return RadonInteger(concat(self.script, [OP.INTEGER_POWER, i]))


class RadonMap(RadonType):

    def get_array(self, key: str) -> 'RadonArray':
        return RadonArray(concat(self.script, [OP.MAP_GET_ARRAY, key]))
    
    def get_boolean(self, key: str) -> 'RadonBoolean':
        return RadonBoolean(concat(self.script, [OP.MAP_GET_BOOLEAN, key]))
    
    def get_bytes(self, key: str) -> 'RadonBytes':
        return RadonBytes(concat(self.script, [OP.MAP_GET_BYTES, key]))
    
    def get_float(self, key: str) -> 'RadonFloat':
        return RadonFloat(concat(self.script, [OP.MAP_GET_FLOAT, key]))
    
    def get_integer(self, key: str) -> 'RadonInteger':
        return RadonInteger(concat(self.script, [OP.MAP_GET_INTEGER, key]))
    
    def get_map(self, key: str) -> 'RadonMap':
        return RadonMap(concat(self.script, [OP.MAP_GET_MAP, key]))
    
    def get_string(self, key: str) -> 'RadonString':
        return RadonString(concat(self.script, [OP.MAP_GET_STRING, key]))
    
    def keys(self) -> 'RadonArray':
        return RadonArray(concat(self.script, OP.MAP_KEYS))
    
    def values_as_array(self) -> 'RadonArray':
        return RadonArray(concat(self.script, OP.MAP_VALUES_AS_ARRAY))


class RadonString(RadonType):

    def as_boolean(self) -> 'RadonBoolean': 
        return RadonBoolean(concat(self.script, OP.STRING_AS_BOOLEAN))
    
    def as_float(self) -> 'RadonFloat':
        return RadonFloat(concat(self.script, OP.STRING_AS_FLOAT))
    
    def as_integer(self) -> 'RadonInteger':
        return RadonInteger(concat(self.script, OP.STRING_AS_INTEGER))
    
    def length(self) -> 'RadonInteger':
        return RadonInteger(concat(self.script, OP.STRING_LENGTH))
    
    def match(self, key: str) -> 'RadonBoolean':
        return RadonBoolean(concat(self.script, [OP.STRING_MATCH, key]))
    
    def parse_json_array(self) -> 'RadonArray':
        return RadonArray(concat(self.script, OP.STRING_PARSE_JSON_ARRAY))

    @classmethod
    def parse_json_map(cls) -> 'RadonMap':
        return RadonMap(concat([], OP.STRING_PARSE_JSON_MAP))
    
    def to_upper_case(self) -> 'RadonString':
        return RadonString(concat(self.script, OP.STRING_TO_UPPER_CASE))
    
    def to_lower_case(self) -> 'RadonString':
        return RadonString(concat(self.script, OP.STRING_TO_LOWER_CASE))
