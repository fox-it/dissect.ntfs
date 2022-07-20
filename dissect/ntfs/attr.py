from __future__ import annotations

import io
from datetime import datetime
from typing import TYPE_CHECKING, Any, BinaryIO, Iterator, List, Optional, Tuple

from dissect.util.stream import RangeStream, RunlistStream
from dissect.util.ts import wintimestamp

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, c_ntfs, segment_reference, varint
from dissect.ntfs.exceptions import MftNotAvailableError, VolumeNotAvailableError
from dissect.ntfs.util import ensure_volume, get_full_path, ts_to_ns

if TYPE_CHECKING:
    from dissect.ntfs.mft import MftRecord


class Attribute:
    """Parse and interact with MFT attributes.

    Wrapper for an AttributeHeader and AttributeRecord combination.

    Args:
        record: The MFT record this attribute belongs to.
        header: The AttributeHeader for this Attribute.
    """

    __slots__ = ("record", "header", "attribute")

    def __init__(self, header: AttributeHeader, record: Optional[MftRecord] = None):
        self.header = header
        self.record = record
        self.attribute = None

        if header.type in ATTRIBUTE_CLASS_MAP:
            # The attribute may be non-resident when we have no volume
            try:
                self.attribute = AttributeRecord.from_fh(header.open(), header.type, record)
            except VolumeNotAvailableError:
                pass

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.attribute, attr)

    def __repr__(self) -> str:
        return f"<${self.header.type.name} name={self.header.name}>"

    @classmethod
    def from_fh(cls, fh: BinaryIO, record: Optional[MftRecord] = None) -> Attribute:
        """Parse an attribute from a file-like object.

        Args:
            fh: The file-like object to parse an attribute from.
            record: The MFT record this attribute belongs to.
        """
        return cls(AttributeHeader(fh, 0, record), record)

    @classmethod
    def from_bytes(cls, data: bytes, record: Optional[MftRecord] = None) -> Attribute:
        """Parse an attribute from bytes.

        Args:
            data: The bytes to parse.
            record: The MFT record this attribute belongs to.
        """
        return Attribute.from_fh(io.BytesIO(data), record)

    @property
    def type(self) -> ATTRIBUTE_TYPE_CODE:
        """Return the attribute type."""
        return self.header.type

    @property
    def resident(self) -> bool:
        """Return whether this attribute is resident or not."""
        return self.header.resident

    @property
    def name(self) -> str:
        """Return the name of this attribute."""
        return self.header.name

    def dataruns(self) -> List[Tuple[int, int]]:
        """Return the dataruns of this attribute, if non-resident.

        Raises:
            TypeError: If attribute is resident.
        """
        return self.header.dataruns()

    def open(self) -> BinaryIO:
        """Open a file-like object for this attribute's data.

        Raises:
            VolumeNotAvailableError: If no volume is available.
        """
        return self.header.open()

    def data(self) -> bytes:
        """Read and return all the data of this attribute.

        Raises:
            VolumeNotAvailableError: If no volume is available.
        """
        return self.header.data()


class AttributeHeader:
    """Parse attribute headers.

    Args:
        record: The MFT record this attribute belongs to.
        fh: The file-like object to parse an attribute header from.
        offset: The offset in the file-like object to parse an attribute header from.
    """

    __slots__ = ("record", "fh", "offset", "header")

    def __init__(self, fh: BinaryIO, offset: int, record: Optional[MftRecord] = None):
        self.fh = fh
        self.offset = offset
        self.record = record

        fh.seek(offset)
        self.header = c_ntfs._ATTRIBUTE_RECORD_HEADER(fh)

    def __repr__(self) -> str:
        return f"<${self.type.name} size={self.size}>"

    @classmethod
    def from_bytes(cls, data: bytes, record: Optional[MftRecord] = None) -> AttributeHeader:
        """Parse an attribute header from bytes.

        Args:
            data: The bytes to parse.
            record: The MFT record this attribute belongs to.
        """
        return cls(io.BytesIO(data), 0, record)

    @property
    def type(self) -> ATTRIBUTE_TYPE_CODE:
        """Return the attribute type."""
        return self.header.TypeCode

    @property
    def resident(self) -> bool:
        """Return whether this attribute is resident or not."""
        return self.header.FormCode == 0

    @property
    def record_length(self) -> int:
        """Return the record length of this attribute."""
        return self.header.RecordLength

    @property
    def name(self) -> str:
        """Return the name of this attribute."""
        self.fh.seek(self.offset + self.header.NameOffset)
        return self.fh.read(self.header.NameLength * 2).decode("utf-16-le")

    @property
    def flags(self) -> int:
        """Return the attribute flags."""
        return self.header.Flags

    @property
    def size(self) -> int:
        """Return the data size of this attribute."""
        return self.header.Form.Resident.ValueLength if self.resident else self.header.Form.Nonresident.FileSize

    @property
    def allocated_size(self) -> Optional[int]:
        """Return the allocated size if non-resident, else None."""
        return self.header.Form.Nonresident.AllocatedLength if not self.resident else None

    @property
    def lowest_vcn(self) -> Optional[int]:
        """Return the lowest VCN if non-resident, else None."""
        return self.header.Form.Nonresident.LowestVcn if not self.resident else None

    @property
    def highest_vcn(self) -> Optional[int]:
        """Return the highest VCN if non-resident, else None."""
        return self.header.Form.Nonresident.HighestVcn if not self.resident else None

    @property
    def compression_unit(self) -> Optional[int]:
        """Return the compression unit if non-resident, else None."""
        return self.header.Form.Nonresident.CompressionUnit if not self.resident else None

    def dataruns(self) -> List[Tuple[int, int]]:
        """Return the dataruns of this attribute, if non-resident.

        Raises:
            TypeError: If attribute is resident.
        """
        if self.resident:
            raise TypeError("Resident attributes don't have dataruns")

        fh = self.fh

        fh.seek(self.offset + self.header.Form.Nonresident.MappingPairsOffset)

        runs = []
        run_offset = None
        run_size = None
        offset = 0

        while True:
            value = fh.read(1)[0]  # Get the integer value
            if value == 0:
                break

            size_len = value & 0xF
            offset_len = (value >> 4) & 0xF

            run_size = varint(fh.read(size_len))
            if offset_len == 0:  # Sparse run
                run_offset = None
            else:
                run_offset = offset = offset + varint(fh.read(offset_len))

            runs.append((run_offset, run_size))

        return runs

    def open(self) -> BinaryIO:
        """Open a file-like object for this attribute's data.

        Raises:
            VolumeNotAvailableError: If no volume is available.
        """
        if self.resident:
            return RangeStream(
                self.fh,
                self.offset + self.header.Form.Resident.ValueOffset,
                self.size,
            )
        else:
            ntfs = self.record.ntfs if self.record else None
            ensure_volume(ntfs)

            return RunlistStream(
                ntfs.fh,
                self.dataruns(),
                self.size,
                ntfs.cluster_size,
            )

    def data(self) -> bytes:
        """Read and return all the data of this attribute.

        Raises:
            VolumeNotAvailableError: If no volume is available.
        """
        return self.open().read()


class AttributeRecord:
    """Parse attribute records.

    Args:
        record: The MFT record this attribute belongs to.
        fh: The file-like object to parse an attribute record from.
    """

    __slots__ = ("record",)

    def __init__(self, fh: BinaryIO, record: Optional[MftRecord] = None):
        self.record = record

    @classmethod
    def from_fh(
        cls, fh: BinaryIO, attr_type: ATTRIBUTE_TYPE_CODE, record: Optional[MftRecord] = None
    ) -> AttributeRecord:
        """Parse an attribute from a file-like object.

        Selects a more specific AttributeRecord class if one is available for the given attribute type.

        Args:
            fh: The file-like object to parse an attribute from.
            attr_type: The attribute type to parse.
            record: The MFT record this attribute belongs to.
        """
        return ATTRIBUTE_CLASS_MAP.get(attr_type, cls)(fh, record)


class AttributeList(AttributeRecord):
    """Specific AttributeRecord parser for $ATTRIBUTE_LIST."""

    __slots__ = ("entries",)

    def __init__(self, fh: BinaryIO, record: Optional[MftRecord] = None):
        super().__init__(fh, record)

        offset = 0
        self.entries = []

        while True:
            fh.seek(offset)

            try:
                entry = c_ntfs._ATTRIBUTE_LIST_ENTRY(fh)
            except EOFError:
                break

            if entry.RecordLength == 0:
                break

            self.entries.append(entry)
            offset += entry.RecordLength

    def __repr__(self) -> str:
        return "<$ATTRIBUTE_LIST>"

    def attributes(self) -> Iterator[Attribute]:
        """Iterate all entries within this $ATTRIBUTE_LIST and yield all embedded attributes."""
        if not self.record:
            raise MftNotAvailableError("Can't iterate $ATTRIBUTE_LIST attributes without a bounded MFT record")

        seen = {self.record.segment}

        for entry in self.entries:
            segment = segment_reference(entry.SegmentReference)
            if segment == 0 or segment in seen:
                continue

            seen.add(segment)
            record = self.record.ntfs.mft(segment)

            for attr_list in record.attributes.values():
                yield from attr_list


class StandardInformation(AttributeRecord):
    """Specific AttributeRecord parser for $STANDARD_INFORMATION."""

    __slots__ = ("attr",)

    def __init__(self, fh: BinaryIO, record: Optional[MftRecord] = None):
        super().__init__(fh, record)
        # Data can be less than the _STANDARD_INFORMATION structure size, so pad remaining fields with null bytes
        data = fh.read().ljust(len(c_ntfs._STANDARD_INFORMATION), b"\x00")
        self.attr = c_ntfs._STANDARD_INFORMATION(data)

    def __repr__(self) -> str:
        return "<$STANDARD_INFORMATION>"

    @property
    def creation_time(self) -> datetime:
        """Return the $STANDARD_INFORMATION CreationTime."""
        return wintimestamp(self.attr.CreationTime)

    @property
    def creation_time_ns(self) -> int:
        """Return the $STANDARD_INFORMATION CreationTime in nanoseconds."""
        return ts_to_ns(self.attr.CreationTime)

    @property
    def last_modification_time(self) -> datetime:
        """Return the $STANDARD_INFORMATION LastModificationTime."""
        return wintimestamp(self.attr.LastModificationTime)

    @property
    def last_modification_time_ns(self) -> int:
        """Return the $STANDARD_INFORMATION LastModificationTime in nanoseconds."""
        return ts_to_ns(self.attr.LastModificationTime)

    @property
    def last_change_time(self) -> datetime:
        """Return the $STANDARD_INFORMATION LastChangeTime."""
        return wintimestamp(self.attr.LastChangeTime)

    @property
    def last_change_time_ns(self) -> int:
        """Return the $STANDARD_INFORMATION LastChangeTime in nanoseconds."""
        return ts_to_ns(self.attr.LastChangeTime)

    @property
    def last_access_time(self) -> datetime:
        """Return the $STANDARD_INFORMATION LastAccessTime."""
        return wintimestamp(self.attr.LastAccessTime)

    @property
    def last_access_time_ns(self) -> int:
        """Return the $STANDARD_INFORMATION LastAccessTime in nanoseconds."""
        return ts_to_ns(self.attr.LastAccessTime)

    @property
    def file_attributes(self) -> int:
        """Return the $STANDARD_INFORMATION FileAttributes."""
        return self.attr.FileAttributes

    @property
    def owner_id(self) -> int:
        """Return the $STANDARD_INFORMATION OwnerId."""
        return self.attr.OwnerId

    @property
    def security_id(self) -> int:
        """Return the $STANDARD_INFORMATION SecurityId."""
        return self.attr.SecurityId


class FileName(AttributeRecord):
    """Specific AttributeRecord parser for $FILE_NAME."""

    __slots__ = ("attr",)

    def __init__(self, fh: BinaryIO, record: Optional[MftRecord] = None):
        super().__init__(fh, record)
        data = fh.read().ljust(len(c_ntfs.STANDARD_INFORMATION_EX), b"\x00")
        self.attr = c_ntfs._FILE_NAME(data)

    def __repr__(self) -> str:
        return f"<$FILE_NAME {self.file_name}>"

    @property
    def creation_time(self) -> datetime:
        """Return the $FILE_NAME file CreationTime."""
        return wintimestamp(self.attr.CreationTime)

    @property
    def creation_time_ns(self) -> int:
        """Return the $FILE_NAME file CreationTime in nanoseconds."""
        return ts_to_ns(self.attr.CreationTime)

    @property
    def last_modification_time(self) -> datetime:
        """Return the $FILE_NAME file LastModificationTime."""
        return wintimestamp(self.attr.LastModificationTime)

    @property
    def last_modification_time_ns(self) -> int:
        """Return the $FILE_NAME file LastModificationTime in nanoseconds."""
        return ts_to_ns(self.attr.LastModificationTime)

    @property
    def last_change_time(self) -> datetime:
        """Return the $FILE_NAME file LastChangeTime."""
        return wintimestamp(self.attr.LastChangeTime)

    @property
    def last_change_time_ns(self) -> int:
        """Return the $FILE_NAME file LastChangeTime in nanoseconds."""
        return ts_to_ns(self.attr.LastChangeTime)

    @property
    def last_access_time(self) -> datetime:
        """Return the $FILE_NAME file LastAccessTime."""
        return wintimestamp(self.attr.LastAccessTime)

    @property
    def last_access_time_ns(self) -> int:
        """Return the $FILE_NAME file LastAccessTime in nanoseconds."""
        return ts_to_ns(self.attr.LastAccessTime)

    @property
    def file_size(self) -> int:
        """Return the $FILE_NAME file FileSize."""
        return self.attr.FileSize

    @property
    def file_attributes(self) -> int:
        """Return the $FILE_NAME file FileAttributes."""
        return self.attr.FileAttributes

    @property
    def flags(self) -> int:
        """Return the $FILE_NAME flags, which can be either FILE_NAME_NTFS or FILE_NAME_DOS."""
        return self.attr.Flags

    @property
    def file_name(self) -> str:
        """Return the file name string stored in this $FILE_NAME attribute."""
        return self.attr.FileName

    def full_path(self) -> str:
        """Use the parent directory reference to try to generate a full path from this file name."""
        return get_full_path(self.record.ntfs.mft, self.file_name, self.attr.ParentDirectory)


ATTRIBUTE_CLASS_MAP = {
    ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION: StandardInformation,
    ATTRIBUTE_TYPE_CODE.ATTRIBUTE_LIST: AttributeList,
    ATTRIBUTE_TYPE_CODE.FILE_NAME: FileName,
}
