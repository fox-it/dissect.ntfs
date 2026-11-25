from __future__ import annotations

import io
import struct
from typing import BinaryIO
from unittest.mock import Mock

import pytest
from dissect.util.stream import RunlistStream

from dissect.ntfs.c_ntfs import FILE_RECORD_SEGMENT_IN_USE
from dissect.ntfs.mft import Mft, MftRecord


def shorten_mft(data: bytearray, records: int) -> None:
    """Change only the declared size of the MFT's nonresident data stream."""
    data_attribute = MftRecord.from_bytes(data[:1024]).attributes.DATA[0]
    struct.pack_into("<Q", data, data_attribute.header.offset + 48, records * 1024)


def test_segments_respects_declared_end(mft_bin: BinaryIO) -> None:
    data = bytearray(mft_bin.read())
    shorten_mft(data, 33)
    mft = Mft(io.BytesIO(data))

    forward = [record.segment for record in mft.segments()]
    assert forward[-1] == 32
    assert [record.segment for record in mft.segments(-1, 0)] == forward[::-1]


@pytest.mark.parametrize("damaged_zero", [False, True])
def test_physical_segments_recovers_records_after_declared_end(mft_bin: BinaryIO, damaged_zero: bool) -> None:
    data = bytearray(mft_bin.read())
    expected = {record.segment: record.filename for record in Mft(io.BytesIO(data)).segments()}
    shorten_mft(data, 33)
    data[33 * 1024 + 22] &= ~FILE_RECORD_SEGMENT_IN_USE
    data[34 * 1024 : 34 * 1024 + 4] = b"BAAD"
    del expected[34]
    if damaged_zero:
        data[:4] = b"BAAD"
        del expected[0]

    mft = Mft(io.BytesIO(data))
    records = {record.segment: record for record in mft.segments(physical=True)}

    assert {segment: record.filename for segment, record in records.items()} == expected
    assert records[33].filename == "Random.bin"
    assert not records[33].header.Flags & FILE_RECORD_SEGMENT_IN_USE
    assert records[44].filename == "Large.txt"


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        (40, 42, [40, 41, 42]),
        (-1, 40, [44, 43, 42, 41, 40]),
        (42, -1, [42, 43, 44]),
        (50, 40, [44, 43, 42, 41, 40]),
        (40, 50, [40, 41, 42, 43, 44]),
        (50, 60, []),
        (60, 50, []),
    ],
)
def test_physical_segments_bounds_and_partial_tail(
    mft_bin: BinaryIO, start: int, end: int, expected: list[int]
) -> None:
    data = mft_bin.read()[: 45 * 1024]
    # A partial FILE record after the last complete slot must not be parsed.
    mft = Mft(io.BytesIO(data + data[33 * 1024 : 33 * 1024 + 512]))
    mft.get = Mock(wraps=mft.get)

    assert [record.segment for record in mft.segments(start, end, physical=True)] == expected
    assert all(0 <= call.args[0] <= 44 for call in mft.get.call_args_list)


@pytest.mark.parametrize("data", [b"", b"FILE" + bytes(508)])
def test_physical_segments_without_complete_records(data: bytes) -> None:
    assert list(Mft(io.BytesIO(data)).segments(physical=True)) == []


def test_physical_segments_runlist_stream(mft_bin: BinaryIO) -> None:
    data = mft_bin.read()[: 45 * 1024]
    stream = RunlistStream(io.BytesIO(data), [(0, 45)], len(data), 1024)
    mft = Mft(stream)

    assert [record.segment for record in mft.segments(-1, 40, physical=True)] == [44, 43, 42, 41, 40]
