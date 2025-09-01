from __future__ import annotations

import csv
import gzip
import io
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest
from dissect.util.stream import MappingStream

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def open_file_gz(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(name), mode) as f:
        yield f


@pytest.fixture
def ntfs_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ntfs.bin.gz")


@pytest.fixture
def mft_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/mft.bin.gz")


@pytest.fixture
def ntfs_cloud_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ntfs-cloud.bin.gz")


@pytest.fixture
def sds_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/sds.bin.gz")


@pytest.fixture
def sds_complex_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/sds_complex.bin.gz")


@pytest.fixture
def boot_2m_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/boot_2m.bin.gz")


@pytest.fixture
def ntfs_fragmented_mft_fh() -> BinaryIO:
    # Test data from https://github.com/msuhanov/ntfs-samples
    # This is from the file ntfs_extremely_fragmented_mft.raw which has, as the name implies, a heavily fragmented MFT
    # The entire file is way too large, so only take just enough data that we actually need to make dissect.ntfs happy
    # We use a MappingStream to stitch everything together at the correct offsets

    stream = MappingStream(align=512)
    with io.TextIOWrapper(gzip.open(absolute_path("_data/ntfs_fragmented_mft.csv.gz"), "r")) as fh:
        for offset, data in csv.reader(fh):
            buf = bytes.fromhex(data)
            stream.add(int(offset), len(buf), io.BytesIO(buf), 0)

    return stream
