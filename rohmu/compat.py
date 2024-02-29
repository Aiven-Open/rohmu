# rohmu - This module used to contain compatible implementations for older
# python version.
#
# Since we don't support those older versions anymore, this module could be removed,
# but as rohmu is used outside pghoard itself better keep the imports and throw
# a deprecation warning.

from contextlib import suppress  # # noqa: F401
from os import makedirs  # noqa: F401

import warnings

warnings.warn(
    "pghoard.rohmu.compat is deprecated, you should import from the standard library directly instead",
    DeprecationWarning,
    stacklevel=2,
)
