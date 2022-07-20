from __future__ import annotations

from datetime import datetime
from functools import cached_property
from typing import TYPE_CHECKING, Any, BinaryIO, Iterator, Optional

from dissect.util.stream import RunlistStream
from dissect.util.ts import wintimestamp

from dissect.ntfs.c_ntfs import USN_PAGE_SIZE, c_ntfs, segment_reference
from dissect.ntfs.exceptions import Error
from dissect.ntfs.mft import MftRecord
from dissect.ntfs.util import ts_to_ns

if TYPE_CHECKING:
    from dissect.ntfs.ntfs import NTFS


class UsnJrnl:
    """Parse the USN journal from a file-like object of the $UsnJrnl:$J stream.

    Args:
        fh: A file-like object of the $UsnJrnl:$J stream.
        ntfs: An optional NTFS class instance, used for resolving file paths.
    """

    def __init__(self, fh: BinaryIO, ntfs: Optional[NTFS] = None):
        self.fh = fh
        self.ntfs = ntfs

    def records(self) -> Iterator[UsnRecord]:
        """Yield all parsed USN records.

        Only yields version 2 USN records, other record versions are ignored.
        """
        fh = self.fh
        offset = 0

        if isinstance(fh, RunlistStream):
            for run_offset, run_size in fh.runlist:
                if run_offset is not None:
                    break

                offset += run_size * fh.block_size

        while True:
            fh.seek(offset)

            if fh.read(4) == b"\x00" * 4:
                # Increment to USN_PAGE_SIZE
                offset += USN_PAGE_SIZE - (offset % USN_PAGE_SIZE)
                continue

            try:
                record = UsnRecord(self, fh, offset)
                if record.header.MajorVersion == 2:
                    yield record
            except EOFError:
                break

            offset += record.record.RecordLength
            if offset % 8:
                offset += -(offset) & (8 - 1)


class UsnRecord:
    """Parse a USN record from a file-like object and offset.

    Args:
        usnjrnl: The ``UsnJrnl`` class this record is parsed from.
        fh: The file-like object to parse a USN record from.
        offset: The offset to parse a USN record at.
    """

    def __init__(self, usnjrnl: UsnJrnl, fh: BinaryIO, offset: int):
        self.usnjrnl = usnjrnl
        self.offset = offset
        self.extents = []

        fh.seek(offset)
        self.header = c_ntfs.USN_RECORD_COMMON_HEADER(fh)

        fh.seek(offset)
        if self.header.MajorVersion == 2:
            self.record = c_ntfs.USN_RECORD_V2(fh)
        elif self.header.MajorVersion == 3:
            self.record = c_ntfs.USN_RECORD_V3(fh)
        elif self.header.MajorVersion == 4:
            self.record = c_ntfs.USN_RECORD_V4(fh)
            for _ in range(self.record.NumberOfExtents):
                self.extents.append(c_ntfs.USN_RECORD_EXTENT(fh))
        else:
            raise ValueError(f"Unsupported USN_RECORD version: {self.header.MajorVersion}")

        if self.header.MajorVersion in (2, 3):
            fh.seek(offset + self.record.FileNameOffset)
            self.filename = fh.read(self.record.FileNameLength).decode("utf-16-le")
        else:
            self.filename = None

    def __repr__(self) -> str:
        return f"<UsnRecord {self.record.Usn}>"

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.record, attr)

    @cached_property
    def file(self) -> Optional[MftRecord]:
        if self.usnjrnl.ntfs and self.usnjrnl.ntfs.mft:
            return self.usnjrnl.ntfs.mft(self.record.FileReferenceNumber)
        return None

    @cached_property
    def parent(self) -> Optional[MftRecord]:
        if self.usnjrnl.ntfs and self.usnjrnl.ntfs.mft:
            return self.usnjrnl.ntfs.mft(self.record.ParentFileReferenceNumber)
        return None

    @property
    def timestamp(self) -> datetime:
        return wintimestamp(self.record.TimeStamp)

    @property
    def timestamp_ns(self) -> int:
        return ts_to_ns(self.record.TimeStamp)

    @cached_property
    def full_path(self) -> str:
        try:
            parent = self.parent
        except Error:
            parent = None

        ref = segment_reference(self.record.ParentFileReferenceNumber)
        if parent is None:
            parent_path = (
                f"<unavailable_reference_0x{ref:x}" f"#{self.record.ParentFileReferenceNumber.SequenceNumber}>"
            )
        elif parent.header.SequenceNumber == self.record.ParentFileReferenceNumber.SequenceNumber:
            parent_path = parent.full_path()
        else:
            parent_path = f"<broken_reference_0x{ref:x}" f"#{self.record.ParentFileReferenceNumber.SequenceNumber}>"

        return "\\".join([parent_path, self.filename])
