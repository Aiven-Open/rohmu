from rohmu.util import get_total_size_from_content_range
from typing import Optional

import pytest


@pytest.mark.parametrize(
    "content_range,result",
    [
        ("0-100/100", 100),
        ("50-55/100", 100),
        ("0-100/*", None),
        ("0-100/1", 1),
    ],
)
def test_get_total_size_from_content_range(content_range: str, result: Optional[int]) -> None:
    assert get_total_size_from_content_range(content_range) == result
