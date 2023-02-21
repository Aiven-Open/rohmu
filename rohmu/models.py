# Copyright (c) 2023 Aiven, Helsinki, Finland. https://aiven.io/


from rohmu.notifier.interface import Notifier
from typing import Optional

import enum
import pydantic


class ProxyType(enum.Enum):
    socks5 = "socks5"
    http = "http"

    def __str__(self) -> str:
        return str(self.value)


class ProxyInfo(pydantic.BaseModel):
    host: str
    port: int
    type: ProxyType
    user: Optional[str]
    password: Optional[str] = pydantic.Field(None, alias="pass")


class StorageModel(pydantic.BaseModel):
    notifier: Optional[Notifier] = None

    class Config:
        use_enum_values = True
        # Notifier Type does not have validation (yet)
        arbitrary_types_allowed = True
        # extra fields would not be accepted by corresponding __init__ methods anyways
        extra_forbid = True
