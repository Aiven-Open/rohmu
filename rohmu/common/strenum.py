"""
rohmu - StrEnum

Copyright (c) 2023 Aiven, Helsinki, Finland. https://aiven.io/
See LICENSE for details
"""
from __future__ import annotations

import enum


class StrEnum(str, enum.Enum):
    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def of(cls, value: str) -> StrEnum | None:
        try:
            return cls(value)
        except ValueError:
            return None
