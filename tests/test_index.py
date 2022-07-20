import io
import struct
from unittest.mock import Mock

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, c_ntfs
from dissect.ntfs.index import _cmp_filename, _cmp_ulong, IndexEntry, Match
from dissect.ntfs.ntfs import NTFS


def mock_filename_entry(filename):
    attribute = c_ntfs._FILE_NAME(
        FileNameLength=len(filename),
        FileName=filename,
    ).dumps()
    header = c_ntfs._INDEX_ENTRY(
        Length=len(c_ntfs._INDEX_ENTRY) + len(attribute),
        KeyLength=len(attribute),
    )
    data = header.dumps() + attribute

    mock_root = Mock(attribute_type=ATTRIBUTE_TYPE_CODE.FILE_NAME)
    mock_index = Mock(root=mock_root)
    return IndexEntry(mock_index, io.BytesIO(data), 0)


def mock_ulong_entry(value):
    header = c_ntfs._INDEX_ENTRY(
        Length=len(c_ntfs._INDEX_ENTRY) + 4,
        KeyLength=4,
    )
    data = header.dumps() + struct.pack("<I", value)

    mock_root = Mock(attribute_type=ATTRIBUTE_TYPE_CODE.UNUSED)
    mock_index = Mock(root=mock_root)
    return IndexEntry(mock_index, io.BytesIO(data), 0)


def test_cmp_filename():
    entry = mock_filename_entry("bbbb")

    assert _cmp_filename(entry, "CCCC") == Match.Greater
    assert _cmp_filename(entry, "BBBB") == Match.Equal
    assert _cmp_filename(entry, "BBBA") == Match.Less
    assert _cmp_filename(entry, "BBBBA") == Match.Greater
    assert _cmp_filename(entry, "BBBBB") == Match.Greater

    entry = mock_filename_entry("C_20127.NLS")
    assert _cmp_filename(entry, "CONFIG") == Match.Less


def test_cmp_ulong():
    entry = mock_ulong_entry(100)

    assert _cmp_ulong(entry, 99) == Match.Less
    assert _cmp_ulong(entry, 100) == Match.Equal
    assert _cmp_ulong(entry, 101) == Match.Greater


def test_index_lookup(ntfs_bin):
    fs = NTFS(ntfs_bin)

    root = fs.mft.get("Large Directory")
    assert len(root.listdir()) == 2048

    for i in range(2048):
        entry = root.get(f"Directory {i}")
        assert entry.filename == f"Directory {i}"
