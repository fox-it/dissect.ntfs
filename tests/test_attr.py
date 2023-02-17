import datetime

import pytest

from dissect.ntfs.attr import Attribute, FileName, StandardInformation
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, IO_REPARSE_TAG
from dissect.ntfs.exceptions import VolumeNotAvailableError


def test_attributes():
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


def test_reparse_point_moint_point():
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


def test_reparse_point_symlink():
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
