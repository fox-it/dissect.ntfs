from __future__ import annotations

from typing import BinaryIO

from dissect.ntfs.bitmap import Bitmap
from dissect.ntfs.ntfs import NTFS


def test_ntfs(ntfs_bin: BinaryIO) -> None:
    fs = NTFS(ntfs_bin)
    bitmap = Bitmap(fs)
    assert bitmap.cluster_size_bytes == 4096
    assert bitmap.last_cluster == 1790

    streams = list(bitmap.iter())
    unallocated_streams, allocated_streams = zip(*streams, strict=True)

    assert len(unallocated_streams) == 1
    assert unallocated_streams[0].runlist == [(1629, 36)]
    assert unallocated_streams[0].block_size == 4096

    assert len(allocated_streams) == 1
    assert allocated_streams[0].runlist == [(0, 1629), (1665, 125)]
    assert allocated_streams[0].block_size == 4096
