from __future__ import annotations

from functools import cached_property, lru_cache
from io import BytesIO
from operator import itemgetter
from typing import TYPE_CHECKING, Any, BinaryIO, Dict, Iterator, List, Optional, Tuple, Union

from dissect.cstruct import Instance

from dissect.ntfs.attr import Attribute, AttributeHeader
from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_TYPE_CODE,
    DEFAULT_RECORD_SIZE,
    FILE_FILE_NAME_INDEX_PRESENT,
    FILE_NAME_DOS,
    FILE_NUMBER_MFT,
    FILE_NUMBER_ROOT,
    c_ntfs,
    segment_reference,
)
from dissect.ntfs.exceptions import BrokenMftError, Error, FileNotFoundError, MftNotAvailableError, NotADirectoryError
from dissect.ntfs.index import Index, IndexEntry
from dissect.ntfs.util import AttributeCollection, AttributeMap, apply_fixup

if TYPE_CHECKING:
    from dissect.ntfs.ntfs import NTFS


class Mft:
    """Interact with the $MFT (Master File Table).

    Args:
        fh: A file-like object of the $MFT file.
        ntfs: An optional NTFS class instance.
    """

    def __init__(self, fh: BinaryIO, ntfs: Optional[NTFS] = None):
        self.fh = fh
        self.ntfs = ntfs

    def __call__(self, ref, *args, **kwargs) -> MftRecord:
        return self.get(ref, *args, **kwargs)

    @cached_property
    def root(self) -> MftRecord:
        """Return the root directory MFT record."""
        return self.get(FILE_NUMBER_ROOT)

    def _get_path(self, path: str, root: Optional[MftRecord] = None) -> MftRecord:
        """Resolve a file path to the correct MFT record.

        Args:
            path: The path to resolve.
            root: Optional root record to start resolving from. Useful for relative path lookups.
        """
        root = root or self.root

        search_path = path.replace("\\", "/")
        node = root

        for part in search_path.split("/"):
            if not part:
                continue

            if not node.is_dir():
                raise NotADirectoryError(f"Error finding path {path}: {self!r} is not a directory")

            index = node.index("$I30")
            try:
                node = index.search(part).dereference()
            except KeyError:
                raise FileNotFoundError(f"File not found: {path}")

        return node

    @lru_cache(4096)
    def get(self, ref: Union[int, str, Instance], root: Optional[MftRecord] = None) -> MftRecord:
        """Retrieve an MFT record using a variety of methods.

        Supported references are:
        - _MFT_SEGMENT_REFERENCE cstruct instance
        - integer segment number
        - string file path

        Args:
            ref: Reference to retrieve the record by.
            root: Optional root record to start resolving from. Useful for relative path lookups.

        Raises:
            TypeError: If the reference is of an unsupported type.
        """
        if isinstance(ref, Instance) and ref._type == c_ntfs._MFT_SEGMENT_REFERENCE:
            ref = segment_reference(ref)

        if isinstance(ref, int):
            record_size = self.ntfs._record_size if self.ntfs else DEFAULT_RECORD_SIZE

            record = MftRecord.from_fh(self.fh, ref * record_size, ntfs=self.ntfs)
            record.segment = ref
            return record
        elif isinstance(ref, str):
            return self._get_path(ref, root)
        else:
            raise TypeError(f"Invalid MFT reference: {ref!r}")

    def segments(self) -> Iterator[MftRecord]:
        """Yield all valid MFT records, regardless if they're allocated or not."""
        record_size = self.ntfs._record_size if self.ntfs else DEFAULT_RECORD_SIZE
        mft_size = self.get(FILE_NUMBER_MFT).size()

        for segment in range(mft_size // record_size):
            try:
                yield self.get(segment)
            except Error:
                continue
            except EOFError:
                break


class MftRecord:
    """MFT record parsing and interaction.

    Use the from_fh or from_bytes class methods to instantiate.
    """

    def __init__(self):
        self.ntfs: Optional[NTFS] = None
        self.segment: Optional[int] = None
        self.offset: Optional[int] = None
        self.data: Optional[bytes] = None
        self.header: Optional[Instance] = None

    def __repr__(self) -> str:
        return f"<MftRecord {self.segment}#{self.header.SequenceNumber}>"

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, MftRecord):
            return self.segment == other.segment and self.header.SequenceNumber == other.header.SequenceNumber
        return False

    __hash__ = object.__hash__

    @classmethod
    def from_fh(cls, fh: BinaryIO, offset: int, ntfs: Optional[NTFS] = None) -> MftRecord:
        """Parse an MFT record from a file-like object.

        Args:
            fh: The file-like object to parse an MFT record from.
            offset: The offset in the file-like object to parse the MFT record from.
            ntfs: An optional NTFS class instance.
        """
        record_size = ntfs._record_size if ntfs else DEFAULT_RECORD_SIZE

        fh.seek(offset)
        data = fh.read(record_size)

        obj = cls.from_bytes(data, ntfs)
        obj.offset = offset
        return obj

    @classmethod
    def from_bytes(cls, data: bytes, ntfs: Optional[NTFS] = None) -> MftRecord:
        """Parse an MFT record from bytes.

        Args:
            data: The bytes object to parse an MFT record from.
            ntfs: An optional NTFS class instance.

        Raises:
            BrokenMftError: If the MFT record signature is invalid.
        """
        obj = cls()
        obj.ntfs = ntfs

        if data[:4] != b"FILE":
            raise BrokenMftError(f"Invalid MFT record Signature: {data[:4]}")

        obj.data = apply_fixup(data)
        obj.header = c_ntfs._FILE_RECORD_SEGMENT_HEADER(obj.data)
        return obj

    def get(self, path: str) -> MftRecord:
        """Retrieve a MftRecord relative to this one.

        Args:
            path: The path to lookup.

        Raises:
            MftNotAvailableError: If no MFT is available.
        """
        if not self.ntfs or not self.ntfs.mft:
            raise MftNotAvailableError()
        return self.ntfs.mft.get(path, root=self)

    @cached_property
    def attributes(self) -> AttributeMap:
        """Parse and return the attributes in this MFT record.

        $ATTRIBUTE_LIST's are only parsed if there's an MFT available on the NTFS object.

        Raises:
            BrokenMftError: If an error occurred parsing the attributes.
        """
        fh = BytesIO(self.data)
        offset = self.header.FirstAttributeOffset
        attrs = AttributeMap()

        attr_list = None
        while True:
            try:
                header = AttributeHeader(fh, offset, self)
            except EOFError:
                break

            if header.type == ATTRIBUTE_TYPE_CODE.END:
                break

            if header.record_length == 0:
                raise BrokenMftError("Attribute RecordLength is 0 but end not yet reached")

            attr = Attribute(header, self)
            attrs.add(attr)

            # If we encounter an attribute list, store it for later use
            # The attribute list can be non-resident, so we need to check if parsing succeeded
            # by checking if attr.attribute exists, in the case we don't have a volume
            if header.type == ATTRIBUTE_TYPE_CODE.ATTRIBUTE_LIST and attr.attribute:
                attr_list = attr

            offset += header.record_length

        if attr_list and self.ntfs and self.ntfs.mft:
            for attr in attr_list.attributes():
                attrs.add(attr)

        return attrs

    @cached_property
    def resident(self) -> bool:
        """Return whether this record's default $DATA attribute is resident."""
        return any(attr.header.resident for attr in self.attributes[ATTRIBUTE_TYPE_CODE.DATA])

    @cached_property
    def filename(self) -> Optional[str]:
        """Return the first file name, or None if this record has no file names."""
        filenames = self.filenames()
        return filenames[0] if filenames else None

    def filenames(self, ignore_dos: bool = False) -> List[str]:
        """Return all file names of this record.

        Args:
            ignore_dos: Ignore DOS file name entries.
        """
        result = []
        for attr in self.attributes[ATTRIBUTE_TYPE_CODE.FILE_NAME]:
            if ignore_dos and attr.flags == FILE_NAME_DOS:
                continue
            result.append((attr.flags, attr.file_name))
        return [item[1] for item in sorted(result, key=itemgetter(0))]

    def full_path(self, ignore_dos: bool = False):
        """Return the first full path, or None if this record has no file names.

        Args:
            ignore_dos: Ignore DOS file name entries.
        """
        paths = self.full_paths(ignore_dos)
        return paths[0] if paths else None

    def full_paths(self, ignore_dos: bool = False):
        """Return all full paths of this record.

        Args:
            ignore_dos: Ignore DOS file name entries.
        """
        result = []

        for attr in self.attributes[ATTRIBUTE_TYPE_CODE.FILE_NAME]:
            if ignore_dos and attr.flags == FILE_NAME_DOS:
                continue
            result.append((attr.flags, attr.full_path()))

        return [item[1] for item in sorted(result, key=itemgetter(0))]

    def is_dir(self) -> bool:
        """Return whether this record is a directory."""
        return bool(self.header.Flags & FILE_FILE_NAME_INDEX_PRESENT)

    def is_file(self) -> bool:
        """Return whether this record is a file."""
        return not self.is_dir()

    def _get_stream_attributes(
        self, name: str, attr_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA
    ) -> AttributeCollection[Attribute]:
        """Return the AttributeCollection of all attributes with the given name and attribute type.

        Args:
            name: The attribute name, often an empty string.
            attr_type: The attribute type to find.

        Raises:
            FileNotFoundError: If there are no attributes with the given name and type.
        """
        attrs = self.attributes.find(name, attr_type)
        if not attrs:
            raise FileNotFoundError(f"No such stream on record {self}: ({name!r}, {attr_type})")
        return attrs

    def open(
        self,
        name: str = "",
        attr_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA,
        allocated: bool = False,
    ) -> BinaryIO:
        """Open a stream on the given stream name and type.

        Args:
            name: The stream name, an empty string for the "default" data stream.
            attr_type: The attribute type to open a stream on.
            allocated: Whether to use the real stream size or the allocated stream size (i.e. include slack space).

        Raises:
            FileNotFoundError: If there are no attributes with the given name and type.
        """
        return self._get_stream_attributes(name, attr_type).open(allocated)

    def size(
        self,
        name: str = "",
        attr_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA,
        allocated: bool = False,
    ) -> int:
        """Return the stream size of the given stream name and type.

        Args:
            name: The stream name, an empty string for the "default" data stream.
            attr_type: The attribute type to find the stream size of.
            allocated: Whether to use the real stream size or the allocated stream size (i.e. include slack space).

        Raises:
            FileNotFoundError: If there are no attributes with the given name and type.
        """
        return self._get_stream_attributes(name, attr_type).size(allocated)

    def dataruns(
        self, name: str = "", attr_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA
    ) -> List[Tuple[int, int]]:
        """Return the dataruns of the given stream name and type.

        Args:
            name: The stream name, an empty string for the "default" data stream.
            attr_type: The attribute type to get the dataruns of.

        Raises:
            FileNotFoundError: If there are no attributes with the given name and type.
        """
        return self._get_stream_attributes(name, attr_type).dataruns()

    def has_stream(self, name: str = "", attr_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA) -> bool:
        """Return whether or not this record has attributes with the given name and type."""
        return bool(self.attributes.find(name, attr_type))

    def index(self, name: str) -> Index:
        """Open an index on this record.

        Args:
            name: The index name to open. For example, "$I30".
        """
        return Index(self, name)

    def iterdir(self, dereference: bool = False, ignore_dos: bool = False) -> Iterator[Union[IndexEntry, MftRecord]]:
        """Yield directory entries of this record.

        Args:
            dereference: Determines whether to resolve the IndexEntry's to MftRecord's. This impacts performance.
            ignore_dos: Ignore DOS file name entries.

        Raises:
            NotADirectoryError: If this record is not a directory.
        """
        if not self.is_dir():
            raise NotADirectoryError(f"{self!r} is not a directory")

        for entry in self.index("$I30").entries():
            if ignore_dos and entry.attribute.flags == FILE_NAME_DOS:
                continue
            yield entry.dereference() if dereference else entry

    def listdir(self, dereference: bool = False, ignore_dos: bool = False) -> Dict[str, Union[IndexEntry, MftRecord]]:
        """Return a dictionary of the directory entries of this record.

        Args:
            dereference: Determines whether to resolve the IndexEntry's to MftRecord's. This impacts performance.
            ignore_dos: Ignore DOS file name entries.

        Raises:
            NotADirectoryError: If this record is not a directory.
        """
        result = {}
        for entry in self.iterdir(dereference, ignore_dos):
            filenames = entry.filenames(ignore_dos) if dereference else [entry.attribute.file_name]
            for filename in filenames:
                result[filename] = entry

        return result
