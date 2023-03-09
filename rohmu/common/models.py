# Copyright (c) 2023 Aiven, Helsinki, Finland. https://aiven.io/
import pydantic


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
