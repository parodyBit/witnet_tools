from dataclasses import dataclass, fields
from typing import Any


@dataclass
class Field:
    val: Any


@dataclass
class Base:
    def __post_init__(self):
        for field in fields(self):
            if isinstance(field.default, Field):
                field_value = getattr(self, field.name)
                if isinstance(field_value, Field) or field_value is None:
                    setattr(self, field.name, field.default.val)


