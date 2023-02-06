from __future__ import annotations

import io
from enum import Enum, auto
from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, Any, BinaryIO, Callable, Iterator, List, Optional

from dissect.ntfs.attr import AttributeRecord
from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_TYPE_CODE,
    COLLATION,
    INDEX_ENTRY_END,
    INDEX_ENTRY_NODE,
    SECTOR_SHIFT,
    c_ntfs,
    segment_reference,
)
from dissect.ntfs.exceptions import (
    BrokenIndexError,
    Error,
    FileNotFoundError,
    MftNotAvailableError,
)
from dissect.ntfs.util import apply_fixup

if TYPE_CHECKING:
    from dissect.ntfs.mft import MftRecord


class Match(Enum):
    Less = auto()
    Equal = auto()
    Greater = auto()


class Index:
    """Open an index with he given name on the given MFT record.

    Args:
        name: The index to open.

    Raises:
        FileNotFoundError: If no index with that name can be found.
    """

    def __init__(self, record: MftRecord, name: str):
        self.record = record
        self.name = name

        self.root = IndexRoot(self, self.record.open(name, ATTRIBUTE_TYPE_CODE.INDEX_ROOT))

        if self.record.ntfs and self.record.ntfs.cluster_size <= self.root.bytes_per_index_buffer:
            self._vcn_size_shift = self.record.ntfs.cluster_size_shift
        else:
            self._vcn_size_shift = SECTOR_SHIFT

        try:
            self._index_stream = self.record.open(self.name, ATTRIBUTE_TYPE_CODE.INDEX_ALLOCATION)
        except FileNotFoundError:
            self._index_stream = None

    def __iter__(self) -> Iterator[IndexEntry]:
        return self.entries()

    @lru_cache(128)
    def index_buffer(self, vcn: int) -> IndexBuffer:
        """Return the IndexBuffer at the specified cluster number.

        Args:
            vcn: The virtual cluster number within the index allocation to read.

        Raises:
            FileNotFoundError: If this index has no index allocation.
        """
        if not self._index_stream:
            raise FileNotFoundError(f"Index has no index allocation: {self.name}")

        return IndexBuffer(self, self._index_stream, vcn << self._vcn_size_shift, self.root.bytes_per_index_buffer)

    def search(
        self, value: Any, exact: bool = True, cmp: Optional[Callable[[IndexEntry, Any], Match]] = None
    ) -> IndexEntry:
        """Perform a binary search on this index.

        Returns the matching node if performing an exact search. Otherwise return the first match that is greater
        than the search value.

        Args:
            value: The key to search.
            exact: Result must be an exact match.
            cmp: Optional custom comparator function.

        Raises:
            NotImplementedError: If there is no collation (comparator) function for the collation rule of this index.
            KeyError: If an exact match was requested but not found.
        """
        cmp_functions = {
            COLLATION.FILE_NAME: _cmp_filename,
            COLLATION.NTOFS_ULONG: _cmp_ulong,
        }

        cmp = cmp or cmp_functions.get(self.root.collation_rule)
        if not cmp:
            raise NotImplementedError(f"No collation function for collation rule: {self.root.collation_rule}")

        search_value = value
        if cmp == _cmp_filename:
            search_value = value.upper()

        entries = list(self.root.entries())

        while True:
            entry = _bsearch(entries, search_value, cmp)
            if not entry.is_node or (not entry.is_end and cmp(entry, search_value) == Match.Equal):
                break
            else:
                entries = list(self.index_buffer(entry.node_vcn).entries())

        if exact and (entry.is_end or cmp(entry, search_value) != Match.Equal):
            raise KeyError(f"Value not found: {value}")

        return entry

    def entries(self) -> Iterator[IndexEntry]:
        """Yield all IndexEntry's in this Index."""

        for entry in self.root.entries():
            if entry.is_end:
                break

            yield entry

        if self._index_stream:
            vcn = 0
            while True:
                try:
                    for entry in self.index_buffer(vcn).entries():
                        if entry.is_end:
                            break

                        yield entry
                except Error:
                    pass
                except EOFError:
                    break

                vcn += 1


class IndexRoot:
    """Represents the $INDEX_ROOT.

    Args:
        index: The Index class instance this IndexRoot belongs to.
        fh: The file-like object to parse an index root on.
    """

    def __init__(self, index: Index, fh: BinaryIO):
        self.index = index
        self.fh = fh

        self.header = c_ntfs._INDEX_ROOT(fh)

    @property
    def attribute_type(self) -> ATTRIBUTE_TYPE_CODE:
        """Return the indexed attribute type."""
        return self.header.AttributeType

    @property
    def collation_rule(self) -> COLLATION:
        """Return the collation rule."""
        return self.header.CollationRule

    @property
    def bytes_per_index_buffer(self) -> int:
        """Return the size of an index buffer in the index allocation in bytes."""
        return self.header.BytesPerIndexBuffer

    @property
    def clusters_per_index_buffer(self) -> int:
        """Return the size of an index buffer in the index allocation in clusters."""
        return self.header.ClustersPerIndexBuffer

    def entries(self) -> Iterator[IndexEntry]:
        """Yield all IndexEntry's in this IndexRoot."""
        yield from _iter_entries(
            self.index,
            self.fh,
            # Offset starts from the _INDEX_HEADER
            len(c_ntfs._INDEX_ROOT),
            self.header.IndexHeader.TotalSizeOfEntries,
        )


class IndexBuffer:
    """Represent an index buffer in $INDEX_ALLOCATION.

    Args:
        index: The Index class instance this IndexRoot belongs to.
        fh: The file-like object of $INDEX_ALLOCATION.
        offset: The offset in bytes to the index buffer on the file-like object we want to read.
        size: The size of the index buffer in bytes.

    Raises:
        EOFError: If there's not enough data available to read an index buffer.
        BrokenIndexError: If the index buffer doesn't start with the expected magic value.
    """

    def __init__(self, index: Index, fh: BinaryIO, offset: int, size: int):
        self.index = index
        self.offset = offset
        self.size = size

        fh.seek(offset)
        buf = fh.read(size)

        if len(buf) != size:
            raise EOFError()

        if buf[:4] != b"INDX":
            raise BrokenIndexError("Broken INDX header")

        self.data = apply_fixup(buf)
        self.header = c_ntfs._INDEX_ALLOCATION_BUFFER(self.data)

    def entries(self) -> Iterator[IndexEntry]:
        """Yield all IndexEntry's in this IndexBuffer."""
        yield from _iter_entries(
            self.index,
            io.BytesIO(self.data),
            # Offset starts from the _INDEX_HEADER
            self.header.IndexHeader.FirstEntryOffset + 0x18,
            self.header.IndexHeader.TotalSizeOfEntries,
        )


class IndexEntry:
    """Parse and interact with index entries.

    Args:
        index: The Index class instance this IndexEntry belongs to.
        fh: The file-like object to parse an index entry on.
        offset: The offset in the file-like object to parse an index entry at.
    """

    def __init__(self, index: Index, fh: BinaryIO, offset: int):
        self.index = index
        self.fh = fh
        self.offset = offset

        fh.seek(offset)
        self.header = c_ntfs._INDEX_ENTRY(fh)
        self.buf = fh.read(self.header.Length - len(c_ntfs._INDEX_ENTRY))

    def dereference(self) -> MftRecord:
        """Dereference this IndexEntry to the MFT record it points to.

        Note that the file reference is a union with the data part so only access this if you know the entry has
        a file reference and not a data part.

        Raises:
            MftNotAvailableError: If no MFT is available.
        """
        record = self.index.record
        if not record or not record.ntfs or not record.ntfs.mft:
            raise MftNotAvailableError()

        return record.ntfs.mft.get(segment_reference(self.header.FileReference))

    @cached_property
    def key(self) -> bytes:
        """Return the index key of this entry."""
        return self.buf[: self.header.KeyLength]

    @cached_property
    def data(self) -> bytes:
        """Return the data part of this entry.

        Note that the data part is a union with the file reference, so only access this if you know the entry has
        data and not a file reference.
        """
        offset = self.header.DataOffset - len(c_ntfs._INDEX_ENTRY)
        return self.buf[offset : offset + self.header.DataLength]

    @cached_property
    def attribute(self) -> Optional[AttributeRecord]:
        """Return the AttributeRecord of the attribute contained in this entry."""
        if self.key_length and self.index.root.attribute_type:
            return AttributeRecord.from_fh(
                io.BytesIO(self.buf),
                self.index.root.attribute_type,
                record=self.index.record,
            )
        return None

    @property
    def is_end(self) -> bool:
        """Return whether this entry marks the end."""
        return bool(self.header.Flags & INDEX_ENTRY_END) or self.header.Length == 0

    @property
    def is_node(self) -> bool:
        """Return whether this entry is a node."""
        return bool(self.header.Flags & INDEX_ENTRY_NODE)

    @property
    def node_vcn(self) -> int:
        """Return the node VCN if this entry is a node."""
        if self.is_node:
            return c_ntfs.ULONG64(memoryview(self.buf)[-8:])
        return None

    @property
    def length(self) -> int:
        """Return the length of this index entry."""
        return self.header.Length

    @property
    def key_length(self) -> int:
        """Return the length of this index entry."""
        return self.header.KeyLength


def _iter_entries(index: Index, fh: BinaryIO, offset: int, size: int) -> Iterator[IndexEntry]:
    max_offset = offset + size
    while offset < max_offset:
        try:
            entry = IndexEntry(index, fh, offset)
        except EOFError:
            break

        yield entry

        if entry.is_end:
            break

        offset += entry.length


def _bsearch(entries: List[IndexEntry], value: Any, cmp: Callable[[IndexEntry, Any], Match]) -> IndexEntry:
    min_idx = 0
    max_idx = len(entries) - 1

    while min_idx != max_idx:
        test_idx = min_idx + (max_idx - min_idx) // 2
        test_entry = entries[test_idx]

        result = cmp(test_entry, value)
        if not test_entry.is_end and result == Match.Greater:
            min_idx = test_idx + 1
        elif result == Match.Equal:
            return test_entry
        else:
            max_idx = test_idx

    return entries[min_idx]


def _cmp_filename(entry: IndexEntry, value: str) -> Match:
    # We could parse an entire _FILE_NAME here but for performance reasons we cheat
    # FileNameLength is at offset 64 and is a single byte
    length = entry.buf[64]
    # FileName starts at offset 66 and is double the FileNameLength because of UTF-16 encoding
    test_value = entry.buf[66 : 66 + (length * 2)].decode("utf-16-le").upper()

    if value < test_value:
        return Match.Less
    elif value == test_value:
        return Match.Equal
    else:
        return Match.Greater


def _cmp_ulong(entry: IndexEntry, value: int) -> Match:
    key = entry.key
    if len(key) != 4:
        raise ValueError(f"Invalid key length for ULONG collation: {len(key)}")
    test_value = int.from_bytes(key, "little")

    if value < test_value:
        return Match.Less
    elif value == test_value:
        return Match.Equal
    else:
        return Match.Greater
