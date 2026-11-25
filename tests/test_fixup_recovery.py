from __future__ import annotations

import io
from typing import BinaryIO

import pytest

from dissect.ntfs.exceptions import BrokenMftError
from dissect.ntfs.mft import Mft, MftRecord
from dissect.ntfs.ntfs import NTFS


@pytest.mark.parametrize("source", ["record", "mft", "ntfs"])
def test_fixup_recovery_is_explicit_and_preserves_diagnostics(mft_bin: BinaryIO, source: str) -> None:
    data = bytearray(mft_bin.read())
    offset = 33 * 1024
    data[offset + 510] ^= 1
    raw = data[offset : offset + 1024]

    with pytest.raises(BrokenMftError, match="Fixup mismatch"):
        MftRecord.from_bytes(raw)

    if source == "record":
        record = MftRecord.from_bytes(raw, recover=True)
    elif source == "mft":
        record = Mft(io.BytesIO(data), recover=True).get(33)
    else:
        fs = NTFS(mft=io.BytesIO(data), recover=True)
        record = fs.mft.get(33)
        with pytest.raises(BrokenMftError, match="Fixup mismatch"):
            MftRecord.from_bytes(raw, ntfs=fs, recover=False)

    assert record.recover
    assert record.filename == "Random.bin"
    assert record.errors == ["fixup: Fixup mismatch"]
    for operation in (record.open, record.size, record.dataruns):
        with pytest.raises(BrokenMftError, match="fixup"):
            operation()


@pytest.mark.parametrize("offset", [0, 49, 512])
def test_fixup_recovery_rejects_invalid_array_layout(mft_bin: BinaryIO, offset: int) -> None:
    data = bytearray(mft_bin.read()[33 * 1024 : 34 * 1024])
    data[4:6] = offset.to_bytes(2, "little")
    with pytest.raises(BrokenMftError, match="Fixup offset out of range"):
        MftRecord.from_bytes(data, recover=True)
