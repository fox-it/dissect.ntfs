from __future__ import annotations

import ntpath
from collections import defaultdict
from functools import cached_property, lru_cache
from io import SEEK_END, BytesIO
from operator import itemgetter
from typing import TYPE_CHECKING, BinaryIO

from dissect.ntfs.attr import Attribute, AttributeHeader
from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_TYPE_CODE,
    DEFAULT_RECORD_SIZE,
    FILE_FILE_NAME_INDEX_PRESENT,
    FILE_NAME_DOS,
    FILE_NUMBER_MFT,
    FILE_NUMBER_ROOT,
    FILE_RECORD_SEGMENT_IN_USE,
    IO_REPARSE_TAG,
    SECTOR_SIZE,
    c_ntfs,
)
from dissect.ntfs.exceptions import (
    BrokenMftError,
    Error,
    FileNotFoundError,
    MftNotAvailableError,
    NotADirectoryError,
    NotAReparsePointError,
)
from dissect.ntfs.index import Index
from dissect.ntfs.util import AttributeMap, apply_fixup, segment_reference

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.ntfs.index import IndexEntry
    from dissect.ntfs.ntfs import NTFS
    from dissect.ntfs.util import AttributeCollection


class Mft:
    """Interact with the ``$MFT`` (Master File Table).

    Args:
        fh: A file-like object of the $MFT file.
        ntfs: An optional NTFS class instance.
        recover: Recover readable metadata from damaged records and retain diagnostics.
            Defaults to the NTFS context's policy, or strict parsing without a context.
    """

    def __init__(self, fh: BinaryIO, ntfs: NTFS | None = None, *, recover: bool | None = None):
        self.fh = fh
        self.ntfs = ntfs
        self.recover = ntfs.recover if recover is None and ntfs else bool(recover)

        self.get = lru_cache(4096)(self.get)

    def __call__(self, ref: int | str | c_ntfs._MFT_SEGMENT_REFERENCE, *args, **kwargs) -> MftRecord:
        return self.get(ref, *args, **kwargs)

    @cached_property
    def root(self) -> MftRecord:
        """Return the root directory MFT record."""
        return self.get(FILE_NUMBER_ROOT)

    def _get_path(self, path: str, root: MftRecord | None = None) -> MftRecord:
        """Resolve a file path to the correct MFT record.

        ``.`` and ``..`` path components are normalized lexically first, like Win32 path normalization does
        (e.g. ``GetFullPathNameW``). This means a ``..`` cancels out the preceding component without that
        component being looked up, and without following any symlinks or mount points. Any leading ``..``
        components are resolved from ``root`` using the parent directory reference of its ``$FILE_NAME``
        attribute. The parent of the root directory is the root directory itself.

        Args:
            path: The path to resolve.
            root: Optional root record to start resolving from. Useful for relative path lookups.
        """
        root = root or self.root

        # Programmatically we will often use the `/` separator, so replace it with the native path separator of NTFS
        # `/` is an illegal character in NTFS filenames, so it's safe to replace
        search_path = path.replace("/", "\\")

        # Lexically normalize "." and ".." components
        parts: list[str] = []
        num_parents = 0
        for part in search_path.split("\\"):
            if not part or part == ".":
                continue

            if part == "..":
                if parts:
                    parts.pop()
                else:
                    num_parents += 1
                continue

            parts.append(part)

        node = root
        for _ in range(num_parents):
            node = self._get_parent(node)

        for part in parts:
            while node.is_symlink() or node.is_mount_point():
                node = node.reparse_point_record

            if not node.is_dir():
                raise NotADirectoryError(f"Error finding path {path}: {self!r} is not a directory")

            index = node.index("$I30")
            try:
                node = index.search(part).dereference()
            except KeyError:
                raise FileNotFoundError(f"File not found: {path}")

        return node

    def _get_parent(self, record: MftRecord) -> MftRecord:
        """Return the parent directory record of the given record, using its ``$FILE_NAME`` attribute.

        The root directory (and any record without a ``$FILE_NAME`` attribute) is its own parent.
        Records with multiple hard links have multiple parents, in which case a non-DOS name is preferred.
        """
        if record.segment == FILE_NUMBER_ROOT:
            return record

        attrs = record.attributes[ATTRIBUTE_TYPE_CODE.FILE_NAME]
        if not attrs:
            return record

        attr = next((attr for attr in attrs if attr.flags != FILE_NAME_DOS), attrs[0])
        return self.get(segment_reference(attr.attr.ParentDirectory))

    def get(self, ref: int | str | c_ntfs._MFT_SEGMENT_REFERENCE, root: MftRecord | None = None) -> MftRecord:
        """Retrieve an MFT record using a variety of methods.

        Supported references are:
            - ``_MFT_SEGMENT_REFERENCE`` cstruct structure
            - integer segment number
            - string file path

        Args:
            ref: Reference to retrieve the record by.
            root: Optional root record to start resolving from. Useful for relative path lookups.

        Raises:
            TypeError: If the reference is of an unsupported type.
        """
        if isinstance(ref, c_ntfs._MFT_SEGMENT_REFERENCE):
            ref = segment_reference(ref)

        if isinstance(ref, int):
            record_size = self.ntfs._record_size if self.ntfs else DEFAULT_RECORD_SIZE

            record = MftRecord.from_fh(self.fh, ref * record_size, ntfs=self.ntfs, recover=self.recover)
            record.segment = ref
            record._mft = self
            return record

        if isinstance(ref, str):
            return self._get_path(ref, root)

        raise TypeError(f"Invalid MFT reference: {ref!r}")

    @cached_property
    def _extension_index(self) -> dict[tuple[int, int], list[int]]:
        """Index verified physical extension slots once, without following attribute lists."""
        record_size = self.ntfs._record_size if self.ntfs else DEFAULT_RECORD_SIZE
        index = defaultdict(list)
        position = self.fh.tell()
        try:
            self.fh.seek(0, SEEK_END)
            count = self.fh.tell() // record_size
            for segment in range(count):
                self.fh.seek(segment * record_size)
                data = self.fh.read(record_size)
                # The fixed-header base reference is only a hint until layout and
                # sector fixups have been verified. Do not cache every base record.
                if data[:4] != b"FILE" or not int.from_bytes(data[32:40], "little"):
                    continue
                try:
                    record = MftRecord.from_bytes(data, self.ntfs, recover=False)
                except (BrokenMftError, EOFError, ValueError):
                    continue
                base = record.header.BaseFileRecordSegment
                index[(segment_reference(base), base.SequenceNumber)].append(segment)
        finally:
            self.fh.seek(position)
        return dict(index)

    def segments(self, start: int = 0, end: int = -1) -> Iterator[MftRecord]:
        """Yield all valid MFT records, regardless if they're allocated or not.

        Args:
            start: The starting segment number. Use ``-1`` to start from the last segment.
            end: The ending segment number. Use ``-1`` to end with the last segment.
        """
        record_size = self.ntfs._record_size if self.ntfs else DEFAULT_RECORD_SIZE
        last_segment = self.get(FILE_NUMBER_MFT).size() // record_size
        start = last_segment if start == -1 else start
        end = last_segment if end == -1 else end
        step = 1 if start <= end else -1

        for segment in range(start, end + step, step):
            try:
                yield self.get(segment)
            except Error:  # noqa: PERF203
                continue
            except EOFError:
                break


class MftRecord:
    """MFT record parsing and interaction.

    Use the :func:`~MftRecord.from_fh` or :func:`~MftRecord.from_bytes` class methods to instantiate.
    """

    def __init__(self):
        self.ntfs: NTFS | None = None
        self._mft: Mft | None = None
        self.segment: int | None = None
        self.offset: int | None = None
        self.data: bytes | None = None
        self.header: c_ntfs._FILE_RECORD_SEGMENT_HEADER | None = None
        self._attributes_complete = True
        self._attributes_loading = False
        self.recover = False
        self.errors: list[str] = []

    def __repr__(self) -> str:
        return f"<MftRecord {self.segment}#{self.header.SequenceNumber}>"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MftRecord):
            return self.segment == other.segment and self.header.SequenceNumber == other.header.SequenceNumber
        return False

    __hash__ = object.__hash__

    @classmethod
    def from_fh(cls, fh: BinaryIO, offset: int, ntfs: NTFS | None = None, *, recover: bool | None = None) -> MftRecord:
        """Parse an MFT record from a file-like object.

        Args:
            fh: The file-like object to parse an MFT record from.
            offset: The offset in the file-like object to parse the MFT record from.
            ntfs: An optional NTFS class instance.
            recover: Override the NTFS context's metadata recovery policy.
        """
        record_size = ntfs._record_size if ntfs else DEFAULT_RECORD_SIZE

        fh.seek(offset)
        data = fh.read(record_size)

        obj = cls.from_bytes(data, ntfs, recover=recover)
        obj.offset = offset
        return obj

    @classmethod
    def from_bytes(cls, data: bytes, ntfs: NTFS | None = None, *, recover: bool | None = None) -> MftRecord:
        """Parse an MFT record from bytes.

        Args:
            data: The bytes object to parse an MFT record from.
            ntfs: An optional NTFS class instance.
            recover: Override the NTFS context's metadata recovery policy. Recovery
                retains validation failures in ``errors`` and does not certify the
                integrity of a damaged record.

        Raises:
            BrokenMftError: If the MFT record signature, layout, or fixup data is invalid.
        """
        obj = cls()
        obj.ntfs = ntfs
        obj.recover = ntfs.recover if recover is None and ntfs else bool(recover)

        if data[:4] != b"FILE":
            raise BrokenMftError(f"Invalid MFT record Signature: {data[:4]}")

        # Legacy records have a 42-byte fixed header, with the update sequence
        # array immediately following it. Do not require the larger modern header.
        header_size = len(c_ntfs._FILE_RECORD_SEGMENT_HEADER)
        if len(data) < header_size:
            raise BrokenMftError(f"Invalid MFT record size: {len(data)}")

        header = c_ntfs._FILE_RECORD_SEGMENT_HEADER(data)
        if len(data) % SECTOR_SIZE or header.BytesAllocated != len(data):
            raise BrokenMftError(
                f"Invalid MFT record size: {len(data)} bytes supplied, {header.BytesAllocated} bytes declared"
            )

        fixup_offset = header.MultiSectorHeader.UpdateSequenceArrayOffset
        fixup_count = header.MultiSectorHeader.UpdateSequenceArraySize
        if fixup_count != len(data) // SECTOR_SIZE + 1:
            raise BrokenMftError(f"Invalid MFT record fixup: Fixup count does not match record size: {fixup_count}")

        fixup_end = fixup_offset + fixup_count * 2
        if fixup_offset < header_size or fixup_end > header.FirstAttributeOffset or fixup_end > SECTOR_SIZE - 2:
            raise BrokenMftError(f"Invalid MFT record fixup: Fixup offset out of range: {fixup_offset}")

        try:
            obj.data = apply_fixup(data)
        except ValueError as e:
            if not obj.recover:
                raise BrokenMftError(f"Invalid MFT record fixup: {e}") from e
            try:
                obj.data = apply_fixup(data, ignore_mismatch=True)
            except ValueError as recovery_error:
                raise BrokenMftError(f"Invalid MFT record fixup: {recovery_error}") from recovery_error
            obj.errors.append(f"fixup: {e}")
        obj.header = c_ntfs._FILE_RECORD_SEGMENT_HEADER(obj.data)
        return obj

    def get(self, path: str) -> MftRecord:
        """Retrieve a :class:`MftRecord` relative to this one.

        Args:
            path: The path to lookup.

        Raises:
            MftNotAvailableError: If no MFT is available.
        """
        if not self.ntfs or not self.ntfs.mft:
            raise MftNotAvailableError
        return self.ntfs.mft.get(path, root=self)

    @cached_property
    def attributes(self) -> AttributeMap:
        """Parse and return the attributes in this MFT record.

        ``$ATTRIBUTE_LIST``'s are only parsed if there's an MFT available on the NTFS object.
        Recovery retains validated attributes before malformed data and from readable
        extensions. For an unavailable nonresident list, recovery can infer extensions
        from verified physical records with an exact base reference and matching
        allocation state. This requires one scan of the supplied MFT stream.
        Check :attr:`attributes_complete` and :attr:`errors` before using
        recovered metadata. Record-level stream access is refused when attributes
        are incomplete or fixup data was recovered. Individual attribute objects
        remain available for inspecting raw evidence.

        Raises:
            BrokenMftError: If an error occurred parsing the attributes in strict mode.
        """
        if self._attributes_loading:
            raise BrokenMftError("Recursive attribute list")

        attrs = self._parse_attributes()
        attr_list = None
        unavailable_list = False
        for attr in attrs[ATTRIBUTE_TYPE_CODE.ATTRIBUTE_LIST]:
            if attr.attribute:
                attr_list = attr
            elif self.recover:
                self._mark_attributes_incomplete("attribute list requires unavailable volume data")
                unavailable_list = True

        if attr_list and self.ntfs and self.ntfs.mft:
            self._attributes_loading = True
            try:
                for attr in attr_list.attributes():
                    attrs.add(attr)
            finally:
                self._attributes_loading = False
        elif attr_list and self.recover:
            self._mark_attributes_incomplete("attribute list requires an unavailable MFT")
        elif unavailable_list:
            self._recover_extensions(attrs)

        return attrs

    def _parse_attributes(self) -> AttributeMap:
        """Parse only this record's validated attributes, without following references."""
        fh = BytesIO(self.data)
        offset = self.header.FirstAttributeOffset
        limit = min(self.header.BytesInUse, len(self.data))
        attrs = AttributeMap()

        while True:
            try:
                self._validate_attribute_offset(offset, limit)
                if int.from_bytes(self.data[offset : offset + 4], "little") == ATTRIBUTE_TYPE_CODE.END:
                    break

                header = AttributeHeader(fh, offset, self)
                self._validate_attribute_bounds(header, limit)
                attr = Attribute(header, self)
            except (BrokenMftError, EOFError, ValueError) as e:
                message = f"attribute at offset {offset:#x}: {e}"
                if not self.recover:
                    raise BrokenMftError(message) from e
                self._mark_attributes_incomplete(message)
                break

            attrs.add(attr)

            offset += header.record_length

        return attrs

    def _recover_extensions(self, attrs: AttributeMap) -> None:
        """Infer local extension metadata without claiming a complete attribute set."""
        base = self.header.BaseFileRecordSegment
        mft = self._mft or (self.ntfs.mft if self.ntfs else None)
        if (
            not mft
            or self.segment is None
            or segment_reference(base)
            or base.SequenceNumber
            or any(error.startswith("fixup:") for error in self.errors)
        ):
            return

        try:
            segments = mft._extension_index.get((self.segment, self.header.SequenceNumber), [])
        except (EOFError, OSError, ValueError) as e:
            self._mark_attributes_incomplete(f"extension scan: {e}")
            return

        for segment in segments:
            try:
                extension = mft.get(segment)
                reference = extension.header.BaseFileRecordSegment
                if (
                    segment == self.segment
                    or segment_reference(reference) != self.segment
                    or reference.SequenceNumber != self.header.SequenceNumber
                    or (self.header.Flags ^ extension.header.Flags) & FILE_RECORD_SEGMENT_IN_USE
                    or any(error.startswith("fixup:") for error in extension.errors)
                ):
                    continue
                # Only inspect the physical extension itself. A list stored in an
                # extension must not cause recursive or unrelated records to merge.
                for collection in extension._parse_attributes().values():
                    for attr in collection:
                        attrs.add(attr)
                self._mark_attributes_incomplete(
                    f"extension {segment}: inferred from base reference; attribute list unavailable"
                )
                if not extension._attributes_complete:
                    self._mark_attributes_incomplete(f"extension {segment}: incomplete recovered attributes")
            except (Error, EOFError, OSError, ValueError) as e:
                self._mark_attributes_incomplete(f"extension {segment}: {e}")

    @property
    def attributes_complete(self) -> bool:
        """Whether attribute parsing and available extension resolution completed.

        This does not establish the availability or integrity of external file data.
        Inferred extensions do not establish completeness when a detached MFT's
        nonresident attribute list cannot be read from a volume.
        """
        _ = self.attributes
        return self._attributes_complete

    def _mark_attributes_incomplete(self, message: str) -> None:
        self._attributes_complete = False
        self.errors.append(message)

    @staticmethod
    def _validate_attribute_offset(offset: int, limit: int) -> None:
        if offset < len(c_ntfs._FILE_RECORD_SEGMENT_HEADER) or offset + 4 > limit:
            raise BrokenMftError("Attribute offset is outside the used record data")

    @staticmethod
    def _validate_attribute_bounds(header: AttributeHeader, limit: int) -> None:
        """Validate the extent before decoding data belonging to an attribute."""
        if header.record_length == 0:
            raise BrokenMftError("Attribute RecordLength is 0 but end not yet reached")
        minimum = 24 if header.resident else 64
        if header.record_length < minimum or header.record_length % 8 or header.offset + header.record_length > limit:
            raise BrokenMftError("Attribute length is outside the used record data")

        name_length = header.header.NameLength * 2
        name_offset = header.header.NameOffset
        if name_length and (name_offset < minimum or name_offset + name_length > header.record_length):
            raise BrokenMftError("Attribute name is outside the attribute")

        if header.resident:
            value = header.header.Form.Resident
            if (
                value.ValueLength and value.ValueOffset < minimum
            ) or value.ValueOffset + value.ValueLength > header.record_length:
                raise BrokenMftError("Resident value is outside the attribute")

    @cached_property
    def resident(self) -> bool:
        """Return whether this record's default ``$DATA`` attribute is resident."""
        return any(attr.header.resident for attr in self.attributes[ATTRIBUTE_TYPE_CODE.DATA])

    @cached_property
    def filename(self) -> str | None:
        """Return the first file name, or ``None`` if this record has no file names."""
        filenames = self.filenames()
        return filenames[0] if filenames else None

    def filenames(self, ignore_dos: bool = False) -> list[str]:
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

    def full_path(self, ignore_dos: bool = False) -> str | None:
        """Return the first full path, or ``None`` if this record has no file names.

        Args:
            ignore_dos: Ignore DOS file name entries.
        """
        paths = self.full_paths(ignore_dos)
        return paths[0] if paths else None

    def full_paths(self, ignore_dos: bool = False) -> list[str]:
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

    def is_reparse_point(self) -> bool:
        """Return whether this record is a reparse point."""
        return ATTRIBUTE_TYPE_CODE.REPARSE_POINT in self.attributes

    def is_symlink(self) -> bool:
        """Return whether this record is a symlink reparse point."""
        attr = self.attributes[ATTRIBUTE_TYPE_CODE.REPARSE_POINT]
        return bool(attr) and attr.tag == IO_REPARSE_TAG.SYMLINK

    def is_mount_point(self) -> bool:
        """Return whether this record is a mount point reparse point."""
        attr = self.attributes[ATTRIBUTE_TYPE_CODE.REPARSE_POINT]
        return bool(attr) and attr.tag == IO_REPARSE_TAG.MOUNT_POINT

    def is_cloud_file(self) -> bool:
        """Return whether this record is a cloud reparse point."""
        attr = self.attributes[ATTRIBUTE_TYPE_CODE.REPARSE_POINT]
        return bool(attr) and attr.tag in (
            IO_REPARSE_TAG.CLOUD,
            IO_REPARSE_TAG.CLOUD_1,
            IO_REPARSE_TAG.CLOUD_2,
            IO_REPARSE_TAG.CLOUD_3,
            IO_REPARSE_TAG.CLOUD_4,
            IO_REPARSE_TAG.CLOUD_5,
            IO_REPARSE_TAG.CLOUD_6,
            IO_REPARSE_TAG.CLOUD_7,
            IO_REPARSE_TAG.CLOUD_8,
            IO_REPARSE_TAG.CLOUD_9,
            IO_REPARSE_TAG.CLOUD_A,
            IO_REPARSE_TAG.CLOUD_B,
            IO_REPARSE_TAG.CLOUD_C,
            IO_REPARSE_TAG.CLOUD_D,
            IO_REPARSE_TAG.CLOUD_E,
            IO_REPARSE_TAG.CLOUD_F,
        )

    @cached_property
    def reparse_point_name(self) -> str:
        """Return the (printable) name of this reparse point."""
        if not self.is_reparse_point():
            raise NotAReparsePointError(f"{self!r} is not a reparse point")
        return self.attributes[ATTRIBUTE_TYPE_CODE.REPARSE_POINT].print_name

    @cached_property
    def reparse_point_substitute_name(self) -> str:
        """Return the substitute name of this reparse point."""
        if not self.is_reparse_point():
            raise NotAReparsePointError(f"{self!r} is not a reparse point")
        return self.attributes[ATTRIBUTE_TYPE_CODE.REPARSE_POINT].substitute_name

    @cached_property
    def reparse_point_record(self) -> MftRecord:
        """Resolve a reparse point and return the target record.

        Note: absolute links (such as directory junctions) will *always* fail in the context of a single filesystem.
        Absolute links include the drive letter, of which we have no knowledge here.
        """
        if not self.is_reparse_point():
            raise NotAReparsePointError(f"{self!r} is not a reparse point")

        if not self.ntfs or not self.ntfs.mft:
            raise MftNotAvailableError

        reparse_point = self.attributes[ATTRIBUTE_TYPE_CODE.REPARSE_POINT]

        target_name = reparse_point.print_name
        if reparse_point.relative:
            target_name = ntpath.join(ntpath.dirname(self.full_path()), target_name)

        if not target_name:
            raise NotAReparsePointError(f"{self!r} does not have a valid reparse target")

        return self.ntfs.mft.get(target_name)

    def _get_stream_attributes(
        self, name: str, attr_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA
    ) -> AttributeCollection[Attribute]:
        """Return the :class:`~dissect.ntfs.util.AttributeCollection` of all attributes with the given name and attribute type.

        Args:
            name: The attribute name, often an empty string.
            attr_type: The attribute type to find.

        Raises:
            FileNotFoundError: If there are no attributes with the given name and type.
            BrokenMftError: If recovery found incomplete attributes or invalid fixup data.
        """  # noqa: E501
        attrs = self.attributes.find(name, attr_type)
        if not self._attributes_complete:
            raise BrokenMftError("Cannot access a stream with incomplete recovered attributes")
        if any(error.startswith("fixup:") for error in self.errors):
            raise BrokenMftError("Cannot access a stream with recovered fixup data")
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
            BrokenMftError: If recovery found incomplete attributes or invalid fixup data.
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
            BrokenMftError: If recovery found incomplete attributes or invalid fixup data.
        """
        return self._get_stream_attributes(name, attr_type).size(allocated)

    def dataruns(
        self, name: str = "", attr_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA
    ) -> list[tuple[int, int]]:
        """Return the dataruns of the given stream name and type.

        Args:
            name: The stream name, an empty string for the "default" data stream.
            attr_type: The attribute type to get the dataruns of.

        Raises:
            FileNotFoundError: If there are no attributes with the given name and type.
            BrokenMftError: If recovery found incomplete attributes or invalid fixup data.
        """
        return self._get_stream_attributes(name, attr_type).dataruns()

    def has_stream(self, name: str = "", attr_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA) -> bool:
        """Return whether or not this record has attributes with the given name and type."""
        return bool(self.attributes.find(name, attr_type))

    def index(self, name: str) -> Index:
        """Open an index on this record.

        Args:
            name: The index name to open. For example, ``"$I30"``.
        """
        return Index(self, name)

    def iterdir(self, dereference: bool = False, ignore_dos: bool = False) -> Iterator[IndexEntry | MftRecord]:
        """Yield directory entries of this record.

        Args:
            dereference: Determines whether to resolve the :class:`~dissect.ntfs.index.IndexEntry`'s to :class:`MftRecord`'s. This impacts performance.
            ignore_dos: Ignore DOS file name entries.

        Raises:
            NotADirectoryError: If this record is not a directory.
        """  # noqa: E501
        if not self.is_dir():
            raise NotADirectoryError(f"{self!r} is not a directory")

        for entry in self.index("$I30").entries():
            if ignore_dos and entry.attribute.flags == FILE_NAME_DOS:
                continue
            yield entry.dereference() if dereference else entry

    def listdir(self, dereference: bool = False, ignore_dos: bool = False) -> dict[str, IndexEntry | MftRecord]:
        """Return a dictionary of the directory entries of this record.

        Args:
            dereference: Determines whether to resolve the :class:`~dissect.ntfs.index.IndexEntry`'s to :class:`MftRecord`'s. This impacts performance.
            ignore_dos: Ignore DOS file name entries.

        Raises:
            NotADirectoryError: If this record is not a directory.
        """  # noqa: E501
        result = {}
        for entry in self.iterdir(dereference, ignore_dos):
            filenames = entry.filenames(ignore_dos) if dereference else [entry.attribute.file_name]
            for filename in filenames:
                result[filename] = entry

        return result
