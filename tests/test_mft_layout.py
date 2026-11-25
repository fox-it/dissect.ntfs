from __future__ import annotations

import io
import struct
from typing import BinaryIO

import pytest

from dissect.ntfs.exceptions import BrokenMftError
from dissect.ntfs.mft import MftRecord
from dissect.ntfs.util import apply_fixup


@pytest.fixture
def file_record(mft_bin: BinaryIO) -> bytearray:
    mft_bin.seek(41 * 1024)
    return bytearray(mft_bin.read(1024))


@pytest.mark.parametrize("recover", [False, True])
@pytest.mark.parametrize("length", [4, 5, 41, 42, 511, 512, 513, 1023])
def test_mft_rejects_truncated_records(file_record: bytearray, length: int, recover: bool) -> None:
    with pytest.raises(BrokenMftError):
        MftRecord.from_bytes(file_record[:length], recover=recover)
    with pytest.raises(BrokenMftError):
        MftRecord.from_fh(io.BytesIO(file_record[:length]), 0, recover=recover)


@pytest.mark.parametrize("recover", [False, True])
@pytest.mark.parametrize("size", [0, 512, 2048])
def test_mft_rejects_inconsistent_record_size(file_record: bytearray, size: int, recover: bool) -> None:
    struct.pack_into("<I", file_record, 28, size)
    with pytest.raises(BrokenMftError, match="record size"):
        MftRecord.from_bytes(file_record, recover=recover)


@pytest.mark.parametrize("recover", [False, True])
@pytest.mark.parametrize("count", [0, 1, 2, 4, 255])
def test_mft_rejects_inconsistent_fixup_count(file_record: bytearray, count: int, recover: bool) -> None:
    struct.pack_into("<H", file_record, 6, count)
    with pytest.raises(BrokenMftError, match="Fixup count"):
        MftRecord.from_bytes(file_record, recover=recover)


@pytest.mark.parametrize("recover", [False, True])
@pytest.mark.parametrize("offset", [8, 16, 40])
def test_mft_rejects_fixup_array_inside_header(file_record: bytearray, offset: int, recover: bool) -> None:
    struct.pack_into("<H", file_record, 4, offset)
    with pytest.raises(BrokenMftError, match="Fixup offset out of range"):
        MftRecord.from_bytes(file_record, recover=recover)


@pytest.mark.parametrize("recover", [False, True])
def test_mft_rejects_fixup_array_overlapping_attributes(file_record: bytearray, recover: bool) -> None:
    struct.pack_into("<H", file_record, 20, 52)
    with pytest.raises(BrokenMftError, match="Fixup offset out of range"):
        MftRecord.from_bytes(file_record, recover=recover)


@pytest.mark.parametrize("recover", [False, True])
def test_mft_rejects_fixup_array_overlapping_trailer(file_record: bytearray, recover: bool) -> None:
    struct.pack_into("<H", file_record, 4, 506)
    struct.pack_into("<H", file_record, 20, 520)
    file_record[506:512] = b"\xaa\xaa\x11\x11\xaa\xaa"
    file_record[1022:1024] = b"\xaa\xaa"
    with pytest.raises(BrokenMftError, match="Fixup offset out of range"):
        MftRecord.from_bytes(file_record, recover=recover)


@pytest.mark.parametrize(("size", "fixup_offset", "attribute_offset"), [(1024, 42, 48), (4096, 48, 72)])
def test_mft_accepts_legacy_header_and_large_record(
    file_record: bytearray, size: int, fixup_offset: int, attribute_offset: int
) -> None:
    original = MftRecord.from_bytes(file_record)
    attributes = original.data[original.header.FirstAttributeOffset : original.header.BytesInUse]
    data = bytearray(size)
    data[:42] = original.data[:42]
    data[attribute_offset : attribute_offset + len(attributes)] = attributes
    struct.pack_into("<HH", data, 4, fixup_offset, size // 512 + 1)
    struct.pack_into("<H", data, 20, attribute_offset)
    struct.pack_into("<II", data, 24, attribute_offset + len(attributes), size)
    data[fixup_offset : fixup_offset + 2] = b"\xaa\xaa"
    for sector in range(size // 512):
        trailer = (sector + 1) * 512 - 2
        replacement = fixup_offset + 2 * (sector + 1)
        data[replacement : replacement + 2] = data[trailer : trailer + 2]
        data[trailer : trailer + 2] = b"\xaa\xaa"

    record = MftRecord.from_bytes(data)

    assert record.filename == original.filename == "File.txt"
    assert record.open().read() == original.open().read() == b"Contents here"


@pytest.mark.parametrize("ignore_mismatch", [False, True])
@pytest.mark.parametrize("offset", [0, 2, 506])
def test_apply_fixup_rejects_array_overlapping_header_or_trailer(offset: int, ignore_mismatch: bool) -> None:
    data = bytearray(1024)
    if offset == 506:
        data[506:512] = b"\xaa\xaa\x11\x11\xaa\xaa"
        data[1022:1024] = b"\xaa\xaa"
    struct.pack_into("<H", data, 4, offset)
    with pytest.raises(ValueError, match="Fixup offset out of range"):
        apply_fixup(data, ignore_mismatch=ignore_mismatch)


def test_apply_fixup_accepts_array_ending_before_trailer() -> None:
    data = bytearray(1024)
    struct.pack_into("<H", data, 4, 504)
    data[504:512] = b"\xaa\xaa\x11\x11\x22\x22\xaa\xaa"
    data[1022:1024] = b"\xaa\xaa"
    original = bytes(data)

    fixed = apply_fixup(data)

    assert fixed[510:512] == b"\x11\x11"
    assert fixed[1022:1024] == b"\x22\x22"
    assert bytes(data) == original
