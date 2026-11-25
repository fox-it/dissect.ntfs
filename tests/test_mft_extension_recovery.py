from __future__ import annotations

import io
import struct

import pytest

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
from dissect.ntfs.exceptions import BrokenMftError
from dissect.ntfs.mft import Mft, MftRecord
from dissect.ntfs.ntfs import NTFS
from tests.test_mft_attribute_recovery import file_record, filename_attribute, list_attribute, open_mft


def unavailable_list() -> bytes:
    """A nonresident list whose payload is only available from the absent volume."""
    header = struct.pack("<IIBBHHHQQHHIQQQ", 0x20, 72, 1, 0, 0, 0, 2, 0, 0, 64, 0, 0, 4096, 32, 32)
    return header + b"\x11\x01\x01\x00\x00\x00\x00\x00"


def named_stream(name: str) -> bytes:
    encoded = name.encode("utf-16-le")
    length = (24 + len(encoded) + 7) & ~7
    header = struct.pack("<IIBBHHHIHBB", 0x80, length, 0, len(name), 24, 0, 3, 0, length, 0, 0)
    return (header + encoded).ljust(length, b"\x00")


@pytest.mark.parametrize("active", [False, True])
@pytest.mark.parametrize("context", [False, True])
def test_recover_detached_extension_names_and_streams(active: bool, context: bool) -> None:
    base = file_record(1, [filename_attribute("base"), unavailable_list()], active=active)
    extension = file_record(
        99,  # Physical slot, not this untrusted modern-header number, identifies the extension.
        [filename_attribute("link"), filename_attribute("link"), named_stream("alternate")],
        base=(1 << 48) | 1,
        active=active,
    )
    records = [bytes(1024), base, extension]
    mft = open_mft(records, recover=True) if context else Mft(io.BytesIO(b"".join(records)), recover=True)
    record = mft.get(1)

    assert record.filenames() == ["base", "link", "link"]
    assert [attr.name for attr in record.attributes[ATTRIBUTE_TYPE_CODE.DATA]] == ["alternate"]
    assert not record.attributes_complete
    assert any("extension 2: inferred" in error for error in record.errors)
    assert record.filenames() == ["base", "link", "link"]  # Cached access must not add duplicates.
    for operation in (record.open, record.size, record.dataruns):
        with pytest.raises(BrokenMftError, match="incomplete"):
            operation("alternate")


@pytest.mark.parametrize("damage", ["wrong_base", "stale_sequence", "active", "fixup", "layout", "signature"])
def test_unverified_or_unrelated_extensions_are_not_merged(damage: str) -> None:
    base = file_record(1, [filename_attribute("base"), unavailable_list()], sequence=2)
    extension = bytearray(
        file_record(
            2,
            [filename_attribute("unrelated")],
            base=((1 if damage == "stale_sequence" else 2) << 48) | (3 if damage == "wrong_base" else 1),
            active=damage == "active",
        )
    )
    if damage == "fixup":
        extension[510:512] = b"\x00\x00"
    elif damage == "layout":
        struct.pack_into("<I", extension, 28, 2048)
    elif damage == "signature":
        extension[:4] = b"BAAD"
    later = file_record(3, [filename_attribute("valid")], base=(2 << 48) | 1)
    record = open_mft([bytes(1024), base, bytes(extension), later], recover=True).get(1)
    assert record.filenames() == ["base", "valid"]
    assert not record.attributes_complete


@pytest.mark.parametrize("mode", ["strict", "no_list", "resident_list", "unbound", "base_fixup", "extension"])
def test_reverse_scan_is_only_used_for_eligible_base_records(mode: str, monkeypatch: pytest.MonkeyPatch) -> None:
    attributes = [filename_attribute("base")]
    if mode == "resident_list":
        attributes.append(list_attribute([]))
    elif mode != "no_list":
        attributes.append(unavailable_list())
    base = file_record(1, attributes, base=(1 << 48) | 4 if mode == "extension" else 0)
    if mode == "base_fixup":
        base = base[:510] + b"\x00\x00" + base[512:]
    extension = file_record(2, [filename_attribute("link")], base=(1 << 48) | 1)
    mft = open_mft([bytes(1024), base, extension], recover=mode != "strict")

    def unexpected_scan(_: Mft) -> None:
        pytest.fail("Ineligible records must not scan the supplied stream")

    monkeypatch.setattr(Mft, "_extension_index", property(unexpected_scan), raising=False)
    record = MftRecord.from_bytes(base, recover=True) if mode == "unbound" else mft.get(1)
    assert record.filenames() == ["base"]


def test_extension_lists_do_not_cause_transitive_or_duplicate_merges() -> None:
    base = file_record(1, [filename_attribute("base"), unavailable_list(), unavailable_list()])
    first = file_record(2, [filename_attribute("first"), list_attribute([(1, 1), (3, 1)])], base=(1 << 48) | 1)
    unrelated = file_record(3, [filename_attribute("unrelated")], base=(1 << 48) | 9)
    second = file_record(4, [filename_attribute("second"), unavailable_list()], base=(1 << 48) | 1)
    record = open_mft([bytes(1024), base, first, unrelated, second], recover=True).get(1)
    assert record.filenames() == ["base", "first", "second"]
    assert not record.attributes_complete


def test_partial_extension_keeps_validated_names_and_continues() -> None:
    base = file_record(1, [filename_attribute("base"), unavailable_list()])
    partial = file_record(2, [filename_attribute("partial"), bytes(24)], base=(1 << 48) | 1, terminated=False)
    later = file_record(3, [filename_attribute("later")], base=(1 << 48) | 1)
    record = open_mft([bytes(1024), base, partial, later], recover=True).get(1)
    assert record.filenames() == ["base", "partial", "later"]
    assert any("extension 2: incomplete" in error for error in record.errors)


def test_scan_ignores_partial_tail_and_preserves_cursor() -> None:
    base = file_record(0, [filename_attribute("zero"), unavailable_list()])
    extension = file_record(1, [filename_attribute("link")], base=1 << 48)
    mft = Mft(io.BytesIO(base + extension + extension[:512]), recover=True)
    mft.fh.seek(17)
    assert mft._extension_index == {(0, 1): [1]}
    assert mft.fh.tell() == 17
    assert mft.get(0).filenames() == ["zero", "link"]


def test_index_is_shared_between_base_records() -> None:
    class CountedStream(io.BytesIO):
        end_seeks = 0

        def seek(self, offset: int, whence: int = 0) -> int:
            if whence == io.SEEK_END:
                self.end_seeks += 1
            return super().seek(offset, whence)

    records = [
        file_record(0, [unavailable_list()]),
        file_record(1, [unavailable_list()]),
        file_record(2, [filename_attribute("zero")], base=1 << 48),
        file_record(3, [filename_attribute("one")], base=(1 << 48) | 1),
    ]
    stream = CountedStream(b"".join(records))
    mft = Mft(stream, recover=True)
    assert mft.get(0).filenames() == ["zero"]
    assert mft.get(1).filenames() == ["one"]
    assert stream.end_seeks == 1


def test_scan_failure_retains_base_names_and_diagnostics() -> None:
    class UnboundedStream(io.BytesIO):
        def seek(self, offset: int, whence: int = 0) -> int:
            if whence == io.SEEK_END:
                raise OSError("Cannot determine size")
            return super().seek(offset, whence)

    base = file_record(0, [filename_attribute("base"), unavailable_list()])
    mft = Mft(UnboundedStream(base), recover=True)
    record = mft.get(0)
    assert record.filenames() == ["base"]
    assert not record.attributes_complete
    assert any("extension scan: Cannot determine size" in error for error in record.errors)


def test_extension_scan_uses_context_record_size() -> None:
    def expand(data: bytes) -> bytes:
        fixed = MftRecord.from_bytes(data).data
        attributes = fixed[56 : struct.unpack_from("<I", fixed, 24)[0]]
        result = bytearray(4096)
        result[:42] = fixed[:42]
        struct.pack_into("<HH", result, 4, 48, 9)
        struct.pack_into("<H", result, 20, 72)
        struct.pack_into("<II", result, 24, 72 + len(attributes), 4096)
        result[72 : 72 + len(attributes)] = attributes
        result[48:50] = b"\xaa\xaa"
        for sector in range(8):
            trailer = (sector + 1) * 512 - 2
            result[50 + sector * 2 : 52 + sector * 2] = result[trailer : trailer + 2]
            result[trailer : trailer + 2] = b"\xaa\xaa"
        return bytes(result)

    base = expand(file_record(0, [filename_attribute("base"), unavailable_list()]))
    extension = expand(file_record(1, [filename_attribute("large")], base=1 << 48))
    ntfs = NTFS()
    ntfs._record_size = 4096
    ntfs.mft = Mft(io.BytesIO(base + extension), ntfs=ntfs, recover=True)
    assert ntfs.mft.get(0).filenames() == ["base", "large"]
