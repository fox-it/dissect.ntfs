from __future__ import annotations

import io
import struct

import pytest

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
from dissect.ntfs.exceptions import BrokenMftError
from dissect.ntfs.mft import Mft, MftRecord
from dissect.ntfs.ntfs import NTFS


def resident_attribute(kind: int, payload: bytes, instance: int = 0) -> bytes:
    length = (24 + len(payload) + 7) & ~7
    header = struct.pack("<IIBBHHHIHBB", kind, length, 0, 0, 0, 0, instance, len(payload), 24, 0, 0)
    return (header + payload).ljust(length, b"\x00")


def filename_attribute(name: str) -> bytes:
    encoded = name.encode("utf-16-le")
    value = struct.pack("<Q", (1 << 48) | 5) + bytes(56) + bytes([len(encoded) // 2, 3]) + encoded
    return resident_attribute(0x30, value)


def list_attribute(references: list[tuple[int, int]]) -> bytes:
    value = b"".join(
        struct.pack("<IHBBQQH", 0x30, 32, 0, 26, 0, (sequence << 48) | segment, 0).ljust(32, b"\x00")
        for segment, sequence in references
    )
    return resident_attribute(0x20, value, 2)


def file_record(
    segment: int,
    attributes: list[bytes],
    *,
    sequence: int = 1,
    active: bool = False,
    base: int = 0,
    terminated: bool = True,
) -> bytes:
    """Build an ordinary record without involving the parser under test."""
    data = bytearray(1024)
    payload = b"".join(attributes) + (b"\xff\xff\xff\xff\x00\x00\x00\x00" if terminated else b"")
    struct.pack_into(
        "<4sHHQHHHHIIQH",
        data,
        0,
        b"FILE",
        48,
        3,
        0,
        sequence,
        1,
        56,
        int(active),
        56 + len(payload),
        1024,
        base,
        len(attributes),
    )
    struct.pack_into("<I", data, 44, segment)
    data[56 : 56 + len(payload)] = payload
    data[48:54] = b"\xaa\xaa" + data[510:512] + data[1022:1024]
    data[510:512] = data[1022:1024] = b"\xaa\xaa"
    return bytes(data)


def open_mft(records: list[bytes], *, recover: bool) -> Mft:
    fs = NTFS()
    fs.mft = Mft(io.BytesIO(b"".join(records)), ntfs=fs, recover=recover)
    return fs.mft


@pytest.mark.parametrize("damage", ["zero_length", "record_overrun", "value_overrun", "truncated_header"])
def test_recover_names_before_malformed_attribute(damage: str) -> None:
    malformed = bytearray(resident_attribute(0x30, bytes(66)))
    if damage == "zero_length":
        struct.pack_into("<I", malformed, 4, 0)
    elif damage == "record_overrun":
        struct.pack_into("<I", malformed, 4, 2048)
    elif damage == "value_overrun":
        struct.pack_into("<I", malformed, 16, 2048)
    else:
        malformed = malformed[:16]
    data = file_record(
        1,
        [filename_attribute("deleted.txt"), resident_attribute(0x80, b"contents", 1), bytes(malformed)],
        terminated=False,
    )
    record = MftRecord.from_bytes(data, recover=True)
    assert record.filenames() == ["deleted.txt"]
    assert not record.attributes_complete
    assert any("attribute" in error.lower() for error in record.errors)
    for operation in (record.open, record.size, record.dataruns):
        with pytest.raises(BrokenMftError, match="incomplete"):
            operation()
    with pytest.raises(BrokenMftError):
        MftRecord.from_bytes(data).filenames()


@pytest.mark.parametrize("damage", ["missing", "fixup", "reused", "wrong_base", "valid"])
def test_recover_missing_extension_without_losing_other_names(damage: str) -> None:
    base = file_record(
        1,
        [
            filename_attribute("deleted.txt"),
            resident_attribute(0x80, b"contents", 1),
            list_attribute([(2, 1), (3, 1)]),
        ],
    )
    extension = file_record(
        2,
        [filename_attribute("first-link.txt")],
        sequence=2 if damage == "reused" else 1,
        active=damage == "reused",
        base=(1 << 48) | (9 if damage == "wrong_base" else 1),
    )
    if damage == "missing":
        extension = bytes(1024)
    elif damage == "fixup":
        extension = extension[:510] + b"\x00\x00" + extension[512:]
    later_extension = file_record(3, [filename_attribute("later-link.txt")], base=(1 << 48) | 1)
    records = [bytes(1024), base, extension, later_extension]
    record = open_mft(records, recover=True).get(1)
    expected = ["deleted.txt", "later-link.txt"]
    if damage in ("valid", "fixup"):
        expected.insert(1, "first-link.txt")
    assert record.filenames() == expected
    if damage == "valid":
        assert record.attributes_complete
        assert not record.errors
        assert record.open().read() == b"contents"
    else:
        assert not record.attributes_complete
        assert any("extension" in error.lower() for error in record.errors)
        with pytest.raises(BrokenMftError, match="incomplete"):
            record.open()


def test_recovered_fixup_metadata_cannot_open_unverified_contents() -> None:
    data = file_record(1, [filename_attribute("deleted.txt"), resident_attribute(0x80, b"contents", 1)])
    data = data[:510] + b"\x00\x00" + data[512:]
    record = MftRecord.from_bytes(data, recover=True)
    assert record.filename == "deleted.txt"
    assert any(error.startswith("fixup:") for error in record.errors)
    with pytest.raises(BrokenMftError, match="fixup"):
        record.open()


@pytest.mark.parametrize("sequence", [2, 0])
def test_deleted_extension_sequence_increment_is_not_reused(sequence: int) -> None:
    previous = (sequence - 1) & 0xFFFF
    base = file_record(1, [filename_attribute("deleted.txt"), list_attribute([(2, previous)])], sequence=sequence)
    extension = file_record(
        2,
        [filename_attribute("link.txt")],
        sequence=sequence,
        base=(previous << 48) | 1,
    )
    record = open_mft([bytes(1024), base, extension], recover=True).get(1)
    assert record.filenames() == ["deleted.txt", "link.txt"]
    assert record.attributes_complete


@pytest.mark.parametrize("active_base", [True, False])
def test_deleted_sequence_recovery_requires_both_records_inactive(active_base: bool) -> None:
    base = file_record(
        1,
        [filename_attribute("base.txt"), list_attribute([(2, 1)])],
        sequence=1 if active_base else 2,
        active=active_base,
    )
    extension = file_record(
        2,
        [filename_attribute("stale-link.txt")],
        sequence=2 if active_base else 1,
        active=not active_base,
        base=(1 << 48) | 1,
    )
    record = open_mft([bytes(1024), base, extension], recover=True).get(1)
    assert record.filenames() == ["base.txt"]
    assert not record.attributes_complete
    assert any("sequence" in error for error in record.errors)


def test_recursive_extension_cannot_recurse_or_claim_complete_data() -> None:
    base = file_record(1, [filename_attribute("deleted.txt"), list_attribute([(2, 1)])])
    extension = file_record(
        2,
        [filename_attribute("link.txt"), list_attribute([(1, 1)])],
        base=(1 << 48) | 1,
    )
    record = open_mft([bytes(1024), base, extension], recover=True).get(1)
    assert record.filenames() == ["deleted.txt", "link.txt"]
    assert not record.attributes_complete
    assert record.errors
    assert record.attributes[ATTRIBUTE_TYPE_CODE.ATTRIBUTE_LIST]


def test_standalone_attribute_list_reports_unavailable_context() -> None:
    record = MftRecord.from_bytes(
        file_record(1, [filename_attribute("deleted.txt"), list_attribute([(2, 1)])]),
        recover=True,
    )
    assert record.filename == "deleted.txt"
    assert not record.attributes_complete
    assert record.errors == ["attribute list requires an unavailable MFT"]
