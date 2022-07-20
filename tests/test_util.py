from dissect.ntfs.attr import Attribute
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
from dissect.ntfs.util import AttributeMap, apply_fixup


def test_fixup():
    buf = bytearray(
        b"FILE\x30\x00"
        + (b"\x00" * 42)
        + b"\x02\x00\xFF\x00\xFE\x00"
        + (b"\x00" * 456)
        + b"\x02\x00"
        + (b"\x00" * 510)
        + b"\x02\x00"
    )
    fixed = apply_fixup(buf)

    assert fixed[510:512] == b"\xFF\x00"
    assert fixed[1022:1024] == b"\xFE\x00"

    buf = bytearray(
        b"FILE\x30\x00"
        + (b"\x00" * 42)
        + b"\x02\x00\xFF\x00\xFE\x00\xFD\x00\xFC\x00"
        + (b"\x00" * 452)
        + b"\x02\x00"
        + (b"\x00" * 510)
        + b"\x02\x00"
        + (b"\x00" * 510)
        + b"\x02\x00"
        + (b"\x00" * 510)
        + b"\x02\x00"
    )
    fixed = apply_fixup(buf)

    assert fixed[510:512] == b"\xFF\x00"
    assert fixed[1022:1024] == b"\xFE\x00"
    assert fixed[1534:1536] == b"\xFD\x00"
    assert fixed[2046:2048] == b"\xFC\x00"


def test_attribute_map():
    attr_map = AttributeMap()
    assert len(attr_map) == 0
    assert attr_map.STANDARD_INFORMATION == []
    assert attr_map[ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION] == []
    assert ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION not in attr_map

    data = bytes.fromhex(
        "100000006000000000001800000000004800000018000000d2145d665666d801"
        "d2145d665666d801d2145d665666d801d2145d665666d8010600000000000000"
        "0000000000000000000000000001000000000000000000000000000000000000"
    )
    attr = Attribute.from_bytes(data)
    attr_map.add(attr)

    assert len(attr_map) == 1
    assert len(attr_map.STANDARD_INFORMATION) == 1
    assert len(attr_map[ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION]) == 1
    assert attr_map[ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION] == attr_map.STANDARD_INFORMATION
    assert ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION in attr_map

    assert len(attr_map.find("", ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION)) == 1
