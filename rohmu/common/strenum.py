# Copyright (c) 2023 Aiven, Helsinki, Finland. https://aiven.io/
# See LICENSE for details
"""rohmu - StrEnum"""

from __future__ import annotations

from typing import Optional
from typing_extensions import Self

import enum


class StrEnum(str, enum.Enum):
    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def of(cls, value: str) -> Optional[Self]:
        try:
            return cls(value)
        except ValueError:
            return None
