import csv
import io
import gzip
import os

from dissect.util.stream import MappingStream
import pytest


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


def open_file_gz(name, mode="rb"):
    with gzip.GzipFile(absolute_path(name), mode) as f:
        yield f


@pytest.fixture
def ntfs_bin():
    yield from open_file_gz("data/ntfs.bin.gz")


@pytest.fixture
def mft_bin():
    yield from open_file_gz("data/mft.bin.gz")


@pytest.fixture
def sds_bin():
    yield from open_file_gz("data/sds.bin.gz")


@pytest.fixture
def boot_2m_bin():
    yield from open_file_gz("data/boot_2m.bin.gz")


@pytest.fixture
def ntfs_fragmented_mft_fh():
    # Test data from https://github.com/msuhanov/ntfs-samples
    # This is from the file ntfs_extremely_fragmented_mft.raw which has, as the name implies, a heavily fragmented MFT
    # The entire file is way too large, so only take just enough data that we actually need to make dissect.ntfs happy
    # We use a MappingStream to stitch everything together at the correct offsets

    stream = MappingStream(align=512)
    with io.TextIOWrapper(gzip.open(absolute_path("data/ntfs_fragmented_mft.csv.gz"), "r")) as fh:
        for offset, data in csv.reader(fh):
            buf = bytes.fromhex(data)
            stream.add(int(offset), len(buf), io.BytesIO(buf), 0)

    yield stream
