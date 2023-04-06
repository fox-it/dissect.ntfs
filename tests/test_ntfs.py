from io import BytesIO

import pytest

from dissect.ntfs.exceptions import FileNotFoundError, NotADirectoryError
from dissect.ntfs.ntfs import NTFS


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


def test_ntfs_64k_sector():
    boot_sector = """
    eb52904e5446532020202000028000000000000000f800003f00ff0000080400
    0000000080008000ffef3b060000000000c00000000000000100000000000000
    f6000000f4000000dcf8511e0a521e0000000000fa33c08ed0bc007cfb68c007
    1f1e686600cb88160e0066813e03004e5446537515b441bbaa55cd13720c81fb
    55aa7506f7c101007503e9dd001e83ec18681a00b4488a160e008bf4161fcd13
    9f83c4189e581f72e13b060b0075dba30f00c12e0f00041e5a33dbb900202bc8
    66ff06110003160f008ec2ff061600e84b002bc877efb800bbcd1a6623c0752d
    6681fb54435041752481f90201721e166807bb16685211166809006653665366
    5516161668b80166610e07cd1a33c0bf0a13b9f60cfcf3aae9fe01909066601e
    0666a111006603061c001e66680000000066500653680100681000b4428a160e
    00161f8bf4cd1366595b5a665966591f0f82160066ff06110003160f008ec2ff
    0e160075bc071f6661c3a1f601e80900a1fa01e80300f4ebfd8bf0ac3c007409
    b40ebb0700cd10ebf2c30d0a41206469736b2072656164206572726f72206f63
    637572726564000d0a424f4f544d475220697320636f6d70726573736564000d
    0a5072657373204374726c2b416c742b44656c20746f20726573746172740d0a
    000000000000000000000000000000000000000000008a01a701bf01000055aa
    """

    fs = NTFS(boot=BytesIO(bytes.fromhex(boot_sector)))
    assert fs.cluster_size == 0x10000


def test_fragmented_mft(ntfs_fragmented_mft_fh):
    fs = NTFS(ntfs_fragmented_mft_fh)
    assert len(fs.mft.fh.runlist) == 238
