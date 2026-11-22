from __future__ import annotations

import math
from typing import TYPE_CHECKING

from dissect.util.bitmap import bitmap_to_runlists
from dissect.util.stream import RunlistStream

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.ntfs.ntfs import NTFS

BLOCK_SIZE = 4096  # How many bytes to read at once from $Bitmap


class Bitmap:
    """Parse the Bitmap from a file-like object. The Bitmap records space allocation, with each bit of the Bitmap
    recording allocation for a cluster.

    Args:
        ntfs: The NTFS filesystem to retrieve the Bitmap file-like object from for parsing.
    """

    def __init__(self, ntfs: NTFS):
        self.ntfs = ntfs
        self.bitmap_fh = self.ntfs.mft.get("$Bitmap").open()
        self.last_cluster = (ntfs.boot_sector.NumberSectors // ntfs.boot_sector.Bpb.SectorsPerCluster) - 1
        self.cluster_size_bytes = ntfs.boot_sector.Bpb.SectorsPerCluster * ntfs.boot_sector.Bpb.BytesPerSector

    def iter(self, cluster_offset: int = 0) -> Iterator[RunlistStream, RunlistStream]:
        """Parse the Bitmap from a given offset (0 by default) and yield tuples of (unallocated, allocated) streams."""
        current_cluster = cluster_offset

        while True:
            max_clusters_in_a_block = BLOCK_SIZE * 8
            clusters_to_read = min(self.last_cluster - current_cluster, max_clusters_in_a_block)
            if clusters_to_read <= 0:
                break
            bytes_needed = math.ceil(clusters_to_read / 8)
            block = self.bitmap_fh.read(bytes_needed)
            if block == b"":
                break
            unallocated_runlist, allocated_runlist = bitmap_to_runlists(block, current_cluster, clusters_to_read)
            yield (
                RunlistStream(
                    self.ntfs.fh,
                    unallocated_runlist,
                    sum(length for _, length in unallocated_runlist) * self.cluster_size_bytes,
                    self.cluster_size_bytes,
                ),
                RunlistStream(
                    self.ntfs.fh,
                    allocated_runlist,
                    sum(length for _, length in allocated_runlist) * self.cluster_size_bytes,
                    self.cluster_size_bytes,
                ),
            )
            current_cluster += clusters_to_read
