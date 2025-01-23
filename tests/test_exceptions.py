from __future__ import annotations

import pytest

from dissect.ntfs import exceptions


@pytest.mark.parametrize(
    ("exc", "std"),
    [
        (exceptions.FileNotFoundError, FileNotFoundError),
        (exceptions.IsADirectoryError, IsADirectoryError),
        (exceptions.NotADirectoryError, NotADirectoryError),
    ],
)
def test_filesystem_error_subclass(exc: exceptions.Error, std: Exception) -> None:
    assert issubclass(exc, std)
    assert isinstance(exc(), std)

    with pytest.raises(std):
        raise exc()
