from __future__ import annotations

import datetime
import struct

import pytest

from dissect.ntfs.attr import Attribute, FileName, StandardInformation
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, IO_REPARSE_TAG
from dissect.ntfs.exceptions import VolumeNotAvailableError
from dissect.ntfs.mft import MftRecord


def resident_attribute(contents: bytes) -> bytes:
    length = (24 + len(contents) + 7) & ~7
    header = struct.pack("<IIBBHHHIHBB", 0x80, length, 0, 0, 0, 0, 0, len(contents), 24, 0, 0)
    return (header + contents).ljust(length, b"\x00")


@pytest.mark.parametrize("recover", [False, True])
def test_short_resident_attribute_at_end_of_record(recover: bool) -> None:
    # The 40-byte $DSC attribute at offset 0x3c0 of Server2022 APTSimulatorVM
    # record 4074. Its 24-byte resident header fits; the 72-byte union does not.
    short_attribute = bytes.fromhex("00010000280000000004180000000300080000002000000024004400530043000200000000000000")
    contents = b"x" * (0x3C0 - 56 - 24)
    payload = resident_attribute(contents) + short_attribute + b"\xff\xff\xff\xff\x00\x00\x00\x00"
    data = bytearray(1024)
    struct.pack_into("<4sHH", data, 0, b"FILE", 48, 3)
    struct.pack_into("<HHII", data, 20, 56, 1, 56 + len(payload), 1024)
    data[56 : 56 + len(payload)] = payload
    data[48:54] = b"\xaa\xaa" + data[510:512] + data[1022:1024]
    data[510:512] = data[1022:1024] = b"\xaa\xaa"

    record = MftRecord.from_bytes(data, recover=recover)

    attribute = record.attributes[ATTRIBUTE_TYPE_CODE.LOGGED_UTILITY_STREAM][0]
    assert attribute.name == "$DSC"
    assert attribute.data() == b"\x02" + bytes(7)
    assert record.open().read() == contents
    assert record.attributes_complete
    assert record.errors == []


@pytest.mark.parametrize("length", [0, 1, 8, 16, 40])
def test_standalone_short_resident_attribute(length: int) -> None:
    contents = bytes(range(length))
    attribute = Attribute.from_bytes(resident_attribute(contents))
    assert attribute.resident
    assert attribute.data() == contents


@pytest.mark.parametrize("length", [0, 8, 16, 23])
def test_truncated_resident_header_still_fails(length: int) -> None:
    with pytest.raises(EOFError):
        Attribute.from_bytes(resident_attribute(b"")[:length])


def test_nonresident_header_preserves_total_allocated() -> None:
    data = (
        struct.pack("<IIBBHHH", 0x80, 80, 1, 0, 0, 1, 0)
        + struct.pack("<QQHB5sQQQQ", 0, 15, 72, 4, bytes(5), 65536, 60000, 60000, 32768)
        + b"\x11\x08\x20\x01\x08\x00\x00\x00"
    )
    attribute = Attribute.from_bytes(data)
    assert not attribute.resident
    assert attribute.header.header.Form.Nonresident.TotalAllocated == 32768
    assert attribute.header.compression_unit == 4
    assert attribute.dataruns() == [(32, 8), (None, 8)]


def test_attributes() -> None:
    # Single $STANDARD_INFORMATION attribute
    data = bytes.fromhex(
        "100000006000000000001800000000004800000018000000d2145d665666d801"
        "d2145d665666d801d2145d665666d801d2145d665666d8010600000000000000"
        "0000000000000000000000000001000000000000000000000000000000000000"
    )
    attr = Attribute.from_bytes(data)
    assert attr.type == ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION

    assert isinstance(attr.attribute, StandardInformation)
    assert attr.creation_time == datetime.datetime(2022, 5, 12, 23, 17, 7, 802645, tzinfo=datetime.timezone.utc)
    assert attr.creation_time_ns == 1652397427802645000
    assert attr.last_modification_time == datetime.datetime(
        2022, 5, 12, 23, 17, 7, 802645, tzinfo=datetime.timezone.utc
    )
    assert attr.last_modification_time_ns == 1652397427802645000
    assert attr.last_change_time == datetime.datetime(2022, 5, 12, 23, 17, 7, 802645, tzinfo=datetime.timezone.utc)
    assert attr.last_change_time_ns == 1652397427802645000
    assert attr.last_access_time == datetime.datetime(2022, 5, 12, 23, 17, 7, 802645, tzinfo=datetime.timezone.utc)
    assert attr.last_access_time_ns == 1652397427802645000

    # Single $FILE_NAME attribute
    data = bytes.fromhex(
        "300000006800000000001800000003004a000000180001000500000000000500"
        "d2145d665666d801d2145d665666d801d2145d665666d801d2145d665666d801"
        "004000000000000000400000000000000600000000000000040324004d004600"
        "5400000000000000"
    )
    attr = Attribute.from_bytes(data)
    assert attr.type == ATTRIBUTE_TYPE_CODE.FILE_NAME

    assert isinstance(attr.attribute, FileName)
    assert attr.file_name == "$MFT"
    assert attr.creation_time == datetime.datetime(2022, 5, 12, 23, 17, 7, 802645, tzinfo=datetime.timezone.utc)
    assert attr.last_modification_time == datetime.datetime(
        2022, 5, 12, 23, 17, 7, 802645, tzinfo=datetime.timezone.utc
    )
    assert attr.last_change_time == datetime.datetime(2022, 5, 12, 23, 17, 7, 802645, tzinfo=datetime.timezone.utc)
    assert attr.last_access_time == datetime.datetime(2022, 5, 12, 23, 17, 7, 802645, tzinfo=datetime.timezone.utc)
    assert attr.file_size == 16384

    # Single $DATA attribute
    data = bytes.fromhex(
        "8000000048000000010040000000060000000000000000003f00000000000000"
        "4000000000000000000004000000000000000400000000000000040000000000"
        "2140550200000000"
    )
    attr = Attribute.from_bytes(data)
    assert attr.type == ATTRIBUTE_TYPE_CODE.DATA

    assert attr.dataruns() == [(597, 64)]

    with pytest.raises(VolumeNotAvailableError):
        attr.open()


def test_reparse_point_moint_point() -> None:
    data = bytes.fromhex(
        "c00000005800000000000000000004004000000018000000030000a038000000"
        "00001a001c0012005c003f003f005c0043003a005c0054006100720067006500"
        "7400000043003a005c00540061007200670065007400"
    )
    attr = Attribute.from_bytes(data)
    assert attr.type == ATTRIBUTE_TYPE_CODE.REPARSE_POINT

    assert attr.tag == IO_REPARSE_TAG.MOUNT_POINT
    assert attr.substitute_name == "\\??\\C:\\Target"
    assert attr.print_name == "C:\\Target"
    assert attr.absolute
    assert not attr.relative


def test_reparse_point_symlink() -> None:
    data = bytes.fromhex(
        "c000000058000000000000000000040040000000180000000c0000a038000000"
        "12001a00000012000000000043003a005c005400610072006700650074005c00"
        "3f003f005c0043003a005c00540061007200670065007400"
    )
    attr = Attribute.from_bytes(data)
    assert attr.type == ATTRIBUTE_TYPE_CODE.REPARSE_POINT

    assert attr.tag == IO_REPARSE_TAG.SYMLINK
    assert attr.substitute_name == "\\??\\C:\\Target"
    assert attr.print_name == "C:\\Target"
    assert attr.absolute
    assert not attr.relative

    data = bytes.fromhex(
        "c00000004800000000000000000004002c000000180000000c0000a024000000"
        "0c000c0000000c00010000005400610072006700650074005400610072006700"
        "6500740000000000"
    )
    attr = Attribute.from_bytes(data)
    assert attr.type == ATTRIBUTE_TYPE_CODE.REPARSE_POINT

    assert attr.tag == IO_REPARSE_TAG.SYMLINK
    assert attr.substitute_name == "Target"
    assert attr.print_name == "Target"
    assert not attr.absolute
    assert attr.relative
