from __future__ import annotations

import io
import struct
from typing import BinaryIO

import pytest

from dissect.ntfs.c_ntfs import FILE_FILE_NAME_INDEX_PRESENT, FILE_RECORD_SEGMENT_IN_USE
from dissect.ntfs.mft import Mft, MftRecord
from dissect.ntfs.ntfs import NTFS


@pytest.mark.parametrize(
    (
        "recover",
        "child_deleted",
        "parent_deleted",
        "parent_is_directory",
        "parent_sequence",
        "reference_sequence",
        "recovered",
    ),
    [
        (True, True, True, True, 2, 1, True),
        (True, True, True, True, 0, 0xFFFF, True),
        (False, True, True, True, 2, 1, False),
        (True, False, True, True, 2, 1, False),
        (True, True, False, True, 2, 1, False),
        (True, True, True, False, 2, 1, False),
        (True, True, True, True, 3, 1, False),
        (True, True, True, True, 1, 0xFFFF, False),
        (True, True, True, True, 1, 0, False),
    ],
)
def test_deleted_parent_sequence_recovery(
    mft_bin: BinaryIO,
    recover: bool,
    child_deleted: bool,
    parent_deleted: bool,
    parent_is_directory: bool,
    parent_sequence: int,
    reference_sequence: int,
    recovered: bool,
) -> None:
    """Recover only the immediate deallocation sequence transition of deleted directories."""
    data = bytearray(mft_bin.read())
    parent_offset = 37 * 1024
    child_offset = 42 * 1024
    child = MftRecord.from_bytes(data[child_offset : child_offset + 1024])
    filename = child.attributes.FILE_NAME[0]
    reference_offset = child_offset + filename.header.offset + filename.header.header.Form.Resident.ValueOffset
    struct.pack_into("<H", data, reference_offset + 6, reference_sequence)
    struct.pack_into("<H", data, parent_offset + 16, parent_sequence)
    parent_flags = FILE_FILE_NAME_INDEX_PRESENT if parent_is_directory else 0
    parent_flags |= 0 if parent_deleted else FILE_RECORD_SEGMENT_IN_USE
    struct.pack_into("<H", data, parent_offset + 22, parent_flags)
    struct.pack_into("<H", data, child_offset + 22, 0 if child_deleted else FILE_RECORD_SEGMENT_IN_USE)

    fs = NTFS()
    fs.mft = Mft(io.BytesIO(data), ntfs=fs, recover=recover)
    record = fs.mft(42)
    expected = "Directory\\File 1.txt" if recovered else f"<broken_reference_0x25#{reference_sequence}>\\File 1.txt"
    assert record.full_path() == expected
    assert record.full_path() == expected
    assert len(record.errors) == int(recovered)
    if recovered:
        assert "parent 37" in record.errors[0]
        assert str(reference_sequence) in record.errors[0]
        assert str(parent_sequence) in record.errors[0]


def test_path_recovery_preserves_valid_references(mft_bin: BinaryIO) -> None:
    fs = NTFS()
    fs.mft = Mft(mft_bin, ntfs=fs, recover=True)
    record = fs.mft(42)

    assert record.full_path() == "Directory\\File 1.txt"
    assert record.errors == []
