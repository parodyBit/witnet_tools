import dataclasses
from wit.util.protobuf_slim.serializer import bytes_serializer, var_int_serializer, var_int
from wit.util.protobuf_slim import types

field_hdr  = var_int(types.uint(10))  # 0x0a
idx_hdr    = var_int(types.uint(16))  # 0x10
output_hdr = var_int(types.uint(18))  # 0x12

def field(number: int, *args, **kwargs) -> dataclasses.Field:
    """
    Convenience function to assign field numbers.
    Calls the standard ``dataclasses.field`` function with the metadata assigned.
    """
    return dataclasses.field(*args, metadata={'number': number}, **kwargs)


def optional_field(number: int, *args, **kwargs) -> dataclasses.Field:
    """
    Convenience function to define a field which is assigned `None` by default.
    """
    return field(number, *args, default=None, **kwargs)