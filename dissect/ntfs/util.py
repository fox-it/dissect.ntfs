from __future__ import annotations

import struct
from collections import UserDict
from typing import TYPE_CHECKING, Any, BinaryIO, List, Optional, Set, Tuple, Union

from dissect.cstruct import EnumInstance, Instance
from dissect.util.stream import RunlistStream

from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_FLAG_COMPRESSION_MASK,
    ATTRIBUTE_TYPE_CODE,
    FILE_NUMBER_ROOT,
    SECTOR_SHIFT,
    SECTOR_SIZE,
    segment_reference,
)
from dissect.ntfs.exceptions import FilenameNotAvailableError, VolumeNotAvailableError
from dissect.ntfs.stream import CompressedRunlistStream

if TYPE_CHECKING:
    from dissect.ntfs.mft import Mft
    from dissect.ntfs.ntfs import NTFS
    from dissect.ntfs.attr import Attribute


class AttributeMap(UserDict):
    """Utility dictionary-like object for interacting with a collection of attributes.

    Allows convenient accessing of attributes added to this collection. For example:
    - Get attributes by name, e.g. attributes.DATA to get all $DATA attributes.
    - Get attributes by type code enum or integer, e.g. attributes[0x80] or attributes[ATTRIBUTE_TYPE_CODE.DATA].
    - Check attribute membership by enum or integer, e.g. 0x80 in attributes or ATTRIBUTE_TYPE_CODE.DATA in attributes.
    - Find all attributes with a given name and type, e.g. attributes.find("$I30", ATTRIBUTE_TYPE_CODE.INDEX_ROOT).

    Note that any data retrieval from an ``AttributeMap`` will always succeed and return an
    :class:`~dissect.ntfs.util.AttributeCollection`, either empty or containing one or more attributes.
    """

    def __getattr__(self, attr: str) -> AttributeCollection:
        if attr in ATTRIBUTE_TYPE_CODE:
            return self[ATTRIBUTE_TYPE_CODE[attr]]

        return super().__getattribute__(self, attr)

    def __getitem__(self, item: Union[ATTRIBUTE_TYPE_CODE, int]) -> AttributeCollection:
        if isinstance(item, EnumInstance):
            item = item.value
        return self.data.get(item, AttributeCollection())

    def __contains__(self, key: Union[ATTRIBUTE_TYPE_CODE, int]) -> bool:
        if isinstance(key, EnumInstance):
            key = key.value
        return super().__contains__(key)

    def add(self, attr: Attribute) -> None:
        """Add an attribute to the collection.

        Note that this is the only intended way to modify the ``AttributeMap``!

        Args:
            attr: The attribute to add.
        """
        key = attr.header.type.value
        if key not in self:
            self[key] = AttributeCollection()

        self[key].append(attr)

    def find(self, name: str, attr_type: ATTRIBUTE_TYPE_CODE) -> AttributeCollection:
        """Find attributes by name and attribute type.

        Args:
            name: The name of the attribute to find, usually ``""``.
            attr_type: The attribute type to find.
        """
        name = name.lower()
        return AttributeCollection(
            [attr for attr in self.get(attr_type, AttributeCollection()) if attr.header.name.lower() == name]
        )


class AttributeCollection(list):
    """Utility list-like object for interacting with a list of attributes.

    Allows convenient access to attribute properties for a list of one or more attributes.

    For example, if we have only one attribute we want to access the "size", we want to be able
    to do attribute_list.size instead of attribute_list[0].size.

    Additionally, we can also provide functionality here that we want to perform on a group of
    attributes, like open() and size().
    """

    def __getattr__(self, attr: str) -> Any:
        if len(self) == 0:
            raise AttributeError("Attribute not found")

        if hasattr(self[0], attr):
            return getattr(self[0], attr)

        return super().__getattribute__(self, attr)

    def open(self, allocated: bool = False) -> BinaryIO:
        """Open the data streams on a list of attributes, resident or non-resident.

        Args:
            allocated: Use the actual stream size or the allocated stream size (i.e. include slack space or not).

        Returns:
            A file-like object for the data of this list of attributes.
        """
        if self.header.resident:
            return self.header.open()

        attrs = self._get_stream_attrs()
        # len(attrs) is always >= 1, because if we were empty we would've errored already, and if we have resident
        # attributes, we wouldn't reach this path
        ntfs = attrs[0].record.ntfs

        ensure_volume(ntfs)

        runs = self._get_dataruns(attrs)
        size = attrs[0].header.allocated_size if allocated else attrs[0].header.size

        if attrs[0].header.flags & ATTRIBUTE_FLAG_COMPRESSION_MASK:
            return CompressedRunlistStream(
                ntfs.fh,
                runs,
                size,
                ntfs.cluster_size,
                attrs[0].header.compression_unit,
            )
        else:
            return RunlistStream(
                ntfs.fh,
                runs,
                size,
                ntfs.cluster_size,
            )

    def size(self, allocated: bool = False) -> int:
        """Retrieve the data stream size for this list of attributes.

        Args:
            allocated: Return the actual stream size or the allocated stream size (i.e. include slack space or not).

        Returns:
            The requested stream size.
        """
        if self.header.resident:
            return self.header.size

        attrs = self._get_stream_attrs()
        return attrs[0].header.allocated_size if allocated else attrs[0].header.size

    def dataruns(self) -> List[Tuple[int, int]]:
        """Get the dataruns for this list of attributes.

        Raises:
            TypeError: If attribute is resident.
        """
        if self.header.resident:
            raise TypeError("Attribute is resident and has no dataruns")

        return self._get_dataruns()

    def _get_stream_attrs(self) -> List[Attribute]:
        return sorted((attr for attr in self if not attr.header.resident), key=lambda attr: attr.header.lowest_vcn)

    def _get_dataruns(self, attrs: Optional[List[Attribute]] = None) -> List[Tuple[int, int]]:
        attrs = attrs or self._get_stream_attrs()

        runs = []
        for attr in self._get_stream_attrs():
            runs += attr.header.dataruns()

        return runs


def apply_fixup(data: bytes) -> bytes:
    """Parse and apply fixup data from MULTI_SECTOR_HEADER to the given bytes.

    Args:
        data: The bytes to fixup

    Returns:
        The fixed up bytes.
    """
    data = bytearray(data)
    view = memoryview(data)

    fixup_offset = struct.unpack("<H", view[4:6])[0]
    fixup_count = len(data) >> SECTOR_SHIFT

    if (
        # The fixup offset must be even
        fixup_offset & 1
        # The end of the fixup array should not exceed SECTOR_SIZE
        or fixup_offset + (fixup_count + 1) * 2 > SECTOR_SIZE
        # Must have at least one fixup
        or fixup_count == 0
        # And the amount of fixups must match the amount of sectors we have data of
        or fixup_count * SECTOR_SIZE > len(data)
    ):
        raise ValueError(f"Fixup offset out of range: {fixup_offset}")

    fixup = view[fixup_offset:]
    sample = fixup[:2]
    fixup = fixup[2:]

    ptr = view[SECTOR_SIZE - 2 :]
    for _ in range(fixup_count):
        if ptr[:2] != sample:
            raise ValueError("Fixup mismatch")

        ptr[:2] = fixup[:2]
        fixup = fixup[2:]
        ptr = ptr[SECTOR_SIZE:]

    return bytes(data)


def ensure_volume(ntfs: NTFS) -> None:
    """Check if a volume is available for reading.

    A volume in this context refers to a disk or other file that contains the raw NTFS data, not contained
    in system files like the $MFT.

    Raises:
        VolumeNotAvailableError: If a volume is not available.
    """
    if not ntfs or not ntfs.fh:
        raise VolumeNotAvailableError()


def get_full_path(mft: Mft, name: str, parent: Instance, seen: Set[str] = None) -> str:
    """Walk up parent file references to construct a full path.

    Args:
        mft: The MFT object to use for looking up file references.
        name: The file name to use.
        parent: The parent reference to start backtracking from.

    Raises:
        FilenameNotAvailableError: If an MFT record has no filename.
    """
    seen = seen or set()

    path = [name]

    while True:
        parent_ref = segment_reference(parent)
        if parent_ref == FILE_NUMBER_ROOT:
            break

        if parent_ref in seen:
            path.append("<recursion>")
            break

        seen.add(parent_ref)

        try:
            record = mft.get(parent_ref)
            if not record.filename:
                raise FilenameNotAvailableError("No filename")

            if record.header.SequenceNumber != parent.SequenceNumber:
                path.append(f"<broken_reference_0x{parent_ref:x}#{parent.SequenceNumber}>")
                break

            path.append(record.filename)

            parent = record.attributes.FILE_NAME.attr.ParentDirectory
        except Exception:
            path.append(f"<unknown_segment_0x{parent_ref:x}>")
            break

    return "\\".join(path[::-1])


def ts_to_ns(ts: int) -> int:
    """Convert Windows timestamps to nanosecond timestamps."""
    return (ts * 100) - 11644473600000000000
