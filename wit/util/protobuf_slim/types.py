from typing import NewType
from enum import Enum, unique

double = NewType('double', float)
fixed32 = NewType('fixed32', int)
fixed64 = NewType('fixed64', int)
sfixed32 = NewType('sfixed32', int)
sfixed64 = NewType('sfixed64', int)
sint32 = NewType('sint32', int)
sint64 = NewType('sint64', int)
uint = NewType('uint', int)  # is not a part of the standard
uint32 = NewType('uint32', int)
uint64 = NewType('uint64', int)
int32 = uint32  # TODO: is it actually the same?
int64 = uint64  # TODO: is it actually the same?

# Not available in `typing`.
NoneType = type(None)


@unique
class PBTypes(Enum):
    double = NewType('double', float)
    float = NewType('pfloat', float)
    int32 = NewType('int32', int)
    int64 = NewType('int64', int)
    uint32 = NewType('uint32', int)
    uint64 = NewType('uint64', int)
    sint32 = NewType('sint32', int)
    sint64 = NewType('sint64', int)
    fixed32 = NewType('fixed32', int)
    fixed64 = NewType('fixed64', int)
    sfixed32 = NewType('sfixed32', int)
    sfixed64 = NewType('sfixed64', int)
    bool = NewType('pbool', bool)
    string = NewType('pstring', str)
    bytes = NewType('pbytes', str)