from __future__ import annotations

import io
import struct
from typing import BinaryIO

from dissect.util import lznt1
from dissect.util.stream import CompressedStream, RunlistStream

DEFAULT_CHUNK_SIZE = 4 * 1024


class CompressedRunlistStream(RunlistStream):
    """Specialized :class:`~dissect.util.stream.RunlistStream` for reading NTFS compressed streams.

    Args:
        fh: The source file-like object.
        runlist: The runlist for this stream in block units.
        size: The size of the stream. This can be smaller than the total sum of blocks (to account for slack space).
        compression_unit: The compression unit of for this stream.
    """

    def __init__(
        self, fh: BinaryIO, runlist: list[tuple[int, int]], size: int, cluster_size: int, compression_unit: int
    ):
        # RunlistStream has block_size but we want to make cluster_size available to be more in line with NTFS naming
        self.cluster_size = cluster_size
        self.compression_unit = compression_unit
        self.compression_unit_size = cluster_size << compression_unit

        self._cu_blocks = []

        # First use the compression_unit_size to set the alignment of AlignedStream
        super().__init__(fh, runlist, size, self.compression_unit_size)
        # This also sets the block_size of RunlistStream, so reset that to the correct cluster_size
        self.block_size = cluster_size

    @property
    def runlist(self) -> list[tuple[int, int]]:
        return self._runlist

    @runlist.setter
    def runlist(self, runlist: list[tuple[int, int]]) -> None:
        self._runlist = runlist

        runs = []
        block_num = 0
        current = 2**self.compression_unit

        # Build a list of aligned CU blocks
        for lcn, count in runlist:
            while count > 0:
                use = min(count, current)
                runs.append((lcn, use))

                current -= use
                count -= use
                if lcn is not None:
                    lcn += use

                if current == 0:
                    block_num += 1
                    self._cu_blocks.append(runs)
                    runs = []
                    current = 2**self.compression_unit

    def _read(self, offset: int, length: int) -> bytes:
        # Compressed data is split over compression units (typically 64KB, or 16 clusters)
        # Each compression unit is exactly this size. Compressed data uncompresses to this size
        # Since the AlignedStream is aligned to this size, we just have to take care of reading
        # these compression units and decompressing them
        read_list = []

        # Calculate which CU block we should be reading from
        cu_block = offset // self.compression_unit_size
        cu_offset = cu_block * self.compression_unit_size

        total_remaining = self.size - cu_offset

        while length > 0:
            buf = []
            buf_len = 0
            compressed = False

            for lcn, run_count in self._cu_blocks[cu_block]:
                # If a run is followed by a sparse run within the same CU, the run is compressed
                if lcn is None:
                    compressed = True
                    continue

                run_len = run_count * self.block_size
                self._fh.seek(lcn * self.block_size)
                buf.append(self._fh.read(run_len))
                buf_len += run_len

                if buf_len == total_remaining:
                    break

            if not buf:
                # Completely sparse CU
                read_list.append(b"\x00" * self.compression_unit_size)
            elif compressed:
                # Compressed CU
                try:
                    buf.append(b"\x00" * 64)
                    read_list.append(lznt1.decompress(io.BytesIO(b"".join(buf)))[: self.compression_unit_size])
                except Exception:
                    raise IOError("Decompression failed")
            else:
                # Uncompressed CU
                read_list.append(b"".join(buf))

            length -= self.compression_unit_size
            total_remaining -= self.compression_unit_size
            cu_block += 1

        return b"".join(read_list)


class WofCompressedStream(CompressedStream):
    """Compressed stream for Windows Overlay Filter (WOF) files. This class handles the decompression of WOF compressed
    files using the specified decompressor.

    WOF Compressed files start with a chunk table, which is a list of offsets to the start of each chunk in the
    compressed data. The chunk table is followed by the compressed data itself.

    Supported decompression methods are currently:
        * LZXPRESS4K Huffman (default)
        * LZXPRESS8K Huffman
        * LZXPRESS16K Huffman
        * LZXPRESS32K Huffman

    Note that LZX and LZNT1 decompression are not yet supported.

    Args:
        fh: A file-like object for the compressed data.
        offset: The offset to the start of the chunk table.
        size: The size of the compressed data.
        original_size: The original size of the uncompressed data.
        decompress: The decompressor function to use.
        chunk_size: The size of the chunks to read from the compressed data. (default: 4 KiB)
    """

    def __init__(
        self,
        fh: BinaryIO,
        offset: int,
        size: int,
        original_size: int,
        decompress: callable,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        fh.seek(offset)
        num_chunks = (original_size + chunk_size - 1) // chunk_size - 1

        entry_size = "Q" if original_size > 0xFFFFFFFF else "I"
        pattern = f"<{num_chunks}{entry_size}"
        chunks = (0, *struct.unpack(pattern, fh.read(struct.calcsize(pattern))))

        super().__init__(fh, fh.tell(), size, original_size, decompress, chunk_size, chunks)

    def _read_chunk(self, offset: int, size: int) -> bytes:
        self.fh.seek(self.offset + offset)
        buf = self.fh.read(size)

        # https://github.com/ebiggers/ntfs-3g-system-compression/blob/53f7bcba9c1c54d8e15e87649ed66654474885ab/src/system_compression.c#L556
        uncompressed_size = (
            ((self.original_size - 1) & (self.chunk_size - 1)) + 1 if offset == self.chunks[-1] else self.chunk_size
        )

        # https://github.com/ebiggers/ntfs-3g-system-compression/blob/53f7bcba9c1c54d8e15e87649ed66654474885ab/src/system_compression.c#L570
        return buf if len(buf) == uncompressed_size else self.decompressor(buf)
