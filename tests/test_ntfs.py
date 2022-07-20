import pytest

from dissect.ntfs.ntfs import NTFS
from dissect.ntfs.exceptions import FileNotFoundError, NotADirectoryError


def test_ntfs(ntfs_bin):
    fs = NTFS(ntfs_bin)

    assert fs.sector_size == 512
    assert fs.cluster_size == 4096
    assert fs._record_size == 1024
    assert fs._index_size == 4096
    assert fs.volume_name == "New Volume"

    small_file = fs.mft.get("File.txt")
    assert small_file.segment == 41
    assert small_file.resident
    assert small_file.is_file()
    assert not small_file.is_dir()
    assert small_file.filename == "File.txt"
    assert small_file.size() == 13
    assert small_file.open().read() == b"Contents here"

    with pytest.raises(FileNotFoundError):
        small_file.index("$I30")

    large_file = fs.mft.get("Large.txt")
    assert large_file.segment == 44
    assert not large_file.resident
    assert large_file.is_file()
    assert not large_file.is_dir()
    assert large_file.filename == "Large.txt"
    assert large_file.size() == 2097152
    assert large_file.open().read() == 2097152 * b"A"

    with pytest.raises(NotADirectoryError):
        large_file.get("Something")

    directory = fs.mft.get("Directory")
    assert not directory.is_file()
    assert directory.is_dir()
    assert directory.index("$I30")
    assert list(directory.listdir().keys()) == ["File 1.txt", "File 2.txt"]

    assert directory.get("File 1.txt") == fs.mft.get("Directory/File 1.txt")
    assert fs.mft.get("Directory/File 1.txt").full_path() == "Directory\\File 1.txt"


def test_ntfs_large_sector(boot_2m_bin):
    fs = NTFS(boot=boot_2m_bin)
    assert fs.cluster_size == 0x200000


def test_fragmented_mft(ntfs_fragmented_mft_fh):
    fs = NTFS(ntfs_fragmented_mft_fh)
    assert len(fs.mft.fh.runlist) == 238
