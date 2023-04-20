# Copyright (c) 2023 Aiven, Helsinki, Finland. https://aiven.io/


from rohmu.common.statsd import StatsdConfig
from rohmu.notifier.interface import Notifier
from typing import Optional

import enum
import pydantic


class StorageOperation(str, enum.Enum):
    iter_key = "iter_key"
    copy_file = "copy_file"
    delete_key = "delete_key"
    get_file = "get_file"
    get_file_size = "get_file_size"
    get_metadata_for_key = "get_metadata_for_key"
    list_path = "list_path"
    list_iter = "list_iter"
    store_file = "store_file"
    metadata_for_key = "metadata_for_key"
    head_request = "head_request"
    create_bucket = "create_bucket"

    # These are S3-only but their use (and especially failures) are interesting
    create_multipart_upload = "create_multipart_upload"
    multipart_aborted = "multipart_aborted"
    multipart_complete = "multipart_complete"

    def __str__(self):
        return str(self.value)


class ProxyType(str, enum.Enum):
    socks5 = "socks5"
    http = "http"


class RohmuModel(pydantic.BaseModel):
    class Config:
        # As we're keen to both export and decode json, just using
        # enum values for encode/decode is much saner than the default
        # enumname.value (it is also slightly less safe but oh well)
        use_enum_values = True

        # Extra values should be errors, as they are most likely typos
        # which lead to grief when not detected. However, if we ever
        # start deprecating some old fields and not wanting to parse
        # them, this might need to be revisited.
        extra = "forbid"

        # Validate field default values too
        validate_all = True

        # Validate also assignments
        # validate_assignment = True
        # TBD: Figure out why this doesn't work in some unit tests;
        # possibly the tests themselves are broken


class ProxyInfo(RohmuModel):
    host: str
    port: int
    type: ProxyType
    user: Optional[str]
    password: Optional[str] = pydantic.Field(None, alias="pass")


class StorageModel(pydantic.BaseModel):
    notifier: Optional[Notifier] = None
    statsd_info: Optional[StatsdConfig] = None

    class Config:
        use_enum_values = True
        # Notifier Type does not have validation (yet)
        arbitrary_types_allowed = True
        # extra fields would not be accepted by corresponding __init__ methods anyways
        extra_forbid = True
