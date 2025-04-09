from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

import pytest
from dissect.util.compression import lzxpress_huffman

from dissect.ntfs.stream import WofCompressedStream
from tests.conftest import open_file_gz

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import Callable


@pytest.fixture
def lzxpress4k() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/wof/test4k.txt:WofCompressedData.gz")


@pytest.fixture
def lzxpress8k() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/wof/test8k.txt:WofCompressedData.gz")


@pytest.fixture
def lzxpress16k() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/wof/test16k.txt:WofCompressedData.gz")


@pytest.mark.parametrize(
    ("fixture", "decompressor", "original_size", "compressed_size", "chunk_size"),
    [
        ("lzxpress4k", lzxpress_huffman.decompress, 24408, 1634, 4096),
        ("lzxpress8k", lzxpress_huffman.decompress, 32832, 1156, 8192),
        ("lzxpress16k", lzxpress_huffman.decompress, 17004, 542, 16384),
    ],
)
def test_lzxpress(
    fixture: BinaryIO,
    decompressor: Callable,
    original_size: int,
    compressed_size: int,
    chunk_size: int,
    request: pytest.FixtureRequest,
) -> None:
    file = request.getfixturevalue(fixture)

    data = WofCompressedStream(file, 0, compressed_size, original_size, decompressor, chunk_size).read()
    assert len(data) == original_size
