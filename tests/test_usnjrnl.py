from io import BytesIO

from dissect.ntfs.usnjrnl import UsnRecord


def test_usnjrnl_record_v4():
    data = bytes.fromhex(
        "5000000004000000c1000000000001000000000000000000bf00000000000100"
        "0000000000000000d00201000000000003810080000000000000000001001000"
        "00000000000000000040280000000000"
    )
    record = UsnRecord(None, BytesIO(data), 0)
    assert len(record.extents) == 1
    assert record.extents[0].Offset == 0
    assert record.extents[0].Length == 0x284000


def test_usnjrnl_record_v2():
    data = bytes.fromhex(
        "5800000002000000c100000000000100bf000000000001002003010000000000"
        "6252641a86a4d7010381008000000000000000002000000018003c0069007300"
        "2d00310035005000320036002e0074006d00700000000000"
    )
    record = UsnRecord(None, BytesIO(data), 0)
    assert record.filename == "is-15P26.tmp"
    assert str(record.timestamp) == "2021-09-08 07:49:50.607420+00:00"
