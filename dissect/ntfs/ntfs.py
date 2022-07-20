from functools import cached_property
from typing import BinaryIO, Iterator, List, Optional, Tuple

from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_TYPE_CODE,
    DEFAULT_CLUSTER_SIZE,
    DEFAULT_INDEX_SIZE,
    DEFAULT_RECORD_SIZE,
    DEFAULT_SECTOR_SIZE,
    FILE_NUMBER_VOLUME,
    NTFS_SIGNATURE,
    c_ntfs,
    bsf,
)
from dissect.ntfs.exceptions import Error, FileNotFoundError, VolumeNotAvailableError
from dissect.ntfs.mft import Mft, MftRecord
from dissect.ntfs.secure import Secure
from dissect.ntfs.usnjrnl import UsnJrnl


class NTFS:
    """Implementation for Microsoft NTFS.

    This implementation supports parsing NTFS from either a full NTFS volume or from separate files.
    If you have a file-like object of an NTFS volume, simply pass it as the fh argument. If you have separate
    file-like objects for things like $BOOT or $MFT, pass those as the boot and mft arguments.
    The separate arguments take precedence over parsing from the volume file-like object.

    Args:
        fh: A file-like object for the volume to use for parsing NTFS. This is where "data on disk" is read from.
        boot: A file-like object for the $BOOT file.
        mft: A file-like object for the $MFT file.
        usnjrnl: A file-like object for the $Extend/$Usnjrnl:$J file.
        sds: A file-like object for the $Secure:$SDS file.
    """

    def __init__(
        self,
        fh: Optional[BinaryIO] = None,
        boot: Optional[BinaryIO] = None,
        mft: Optional[BinaryIO] = None,
        usnjrnl: Optional[BinaryIO] = None,
        sds: Optional[BinaryIO] = None,
    ):
        self.fh = fh

        boot_fh = boot or fh
        if boot_fh:
            boot_fh.seek(0)
            self.boot_sector = c_ntfs.BOOT_SECTOR(boot_fh)

            if self.boot_sector.Oem != NTFS_SIGNATURE:
                raise Error(f"Invalid NTFS magic: {self.boot_sector.Oem}")

            self.sector_size = self.boot_sector.Bpb.BytesPerSector
            if self.boot_sector.Bpb.SectorsPerCluster < 0:
                sectors_per_cluster = 1 << (-self.boot_sector.Bpb.SectorsPerCluster)
            else:
                sectors_per_cluster = self.boot_sector.Bpb.SectorsPerCluster
            self.cluster_size = sectors_per_cluster * self.sector_size

            if self.boot_sector.ClustersPerFileRecordSegment < 0:
                self._record_size = 1 << (-self.boot_sector.ClustersPerFileRecordSegment)
            else:
                self._record_size = self.boot_sector.ClustersPerFileRecordSegment * self.cluster_size

            if self.boot_sector.ClustersPerIndexBuffer < 0:
                self._index_size = 2 << (-self.boot_sector.ClustersPerIndexBuffer)
            else:
                self._index_size = self.boot_sector.ClustersPerIndexBuffer * self.cluster_size
        else:
            # Provide some defaults if we don't have a volume or $BOOT file
            self.boot_sector = None
            self.sector_size = DEFAULT_SECTOR_SIZE
            self.cluster_size = DEFAULT_CLUSTER_SIZE
            self._record_size = DEFAULT_RECORD_SIZE
            self._index_size = DEFAULT_INDEX_SIZE

        self.sector_size_shift = bsf(self.sector_size)
        self.cluster_size_shift = bsf(self.cluster_size)

        self.mft = None
        self.secure = None
        self.usnjrnl = None

        if mft:
            self.mft = Mft(mft, ntfs=self)
        elif self.fh:
            # Small preface for what's happening here:
            # - MFT records have one or more $DATA attributes to describe where data is stored on disk
            # - When data is extremely fragmented, you need more than one $DATA attribute
            # - When you run out of space in the MFT record itself, attributes are stored in other MFT records
            #   and referenced by an $ATTRIBUTE_LIST in the main MFT record
            # - To be able to look up these other MFT records, you need to be able to find them in the $MFT file
            #
            # This is all fine, until you realize that the $MFT file itself can be extremely fragmented,
            # creating a chicken-egg problem. We need the MFT in order to open the $MFT file.

            # First, parse just the MFT record
            mft_offset = self.boot_sector.MftStartLcn * self.cluster_size
            mft_record = MftRecord.from_fh(fh, mft_offset, ntfs=self)

            # Second, we open a temporary MFT with the resident $DATA attributes we parsed from the MFT record
            # This is because if there's no MFT loaded yet (mft attribute on this class) we don't load attribute lists
            self.mft = Mft(mft_record.open(), ntfs=self)

            # With this initial MFT object we can properly resolve attribute list entries, since the next MFT record
            # containing the next $DATA attribute is guaranteed to be within the $DATA runs that we already parsed
            if ATTRIBUTE_TYPE_CODE.ATTRIBUTE_LIST in mft_record.attributes:
                for datarun in _get_dataruns_from_attribute_list(mft_record):
                    # Update the RunlistStream of the MFT with new runs as we find them as the next
                    # attribute list entry may point to an MFT record that is contained in the previous
                    # attribute list entry's $DATA
                    self.mft.fh.runlist += datarun

        if sds:
            self.secure = Secure(sds=sds)
        elif self.mft:
            try:
                self.secure = Secure(self.mft.get("$Secure"))
            except (FileNotFoundError, VolumeNotAvailableError):
                pass

        if usnjrnl:
            self.usnjrnl = UsnJrnl(usnjrnl, ntfs=self)
        elif self.mft:
            try:
                self.usnjrnl = UsnJrnl(self.mft.get("$Extend/$Usnjrnl").open("$J"), ntfs=self)
            except (FileNotFoundError, NotADirectoryError, VolumeNotAvailableError):
                pass

    @cached_property
    def serial(self) -> Optional[int]:
        return self.boot_sector.SerialNumber if self.boot_sector else None

    @cached_property
    def volume_name(self) -> Optional[str]:
        if not self.mft:
            return None

        try:
            volume_file = self.mft.get(FILE_NUMBER_VOLUME)
            volume_name = volume_file.attributes[ATTRIBUTE_TYPE_CODE.VOLUME_NAME].data()
            return volume_name.decode("utf-16-le")
        except (AttributeError, FileNotFoundError):
            return None


def _get_dataruns_from_attribute_list(record: MftRecord) -> Iterator[List[Tuple[int, int]]]:
    for attr in record.attributes[ATTRIBUTE_TYPE_CODE.ATTRIBUTE_LIST].attributes():
        if attr.type == ATTRIBUTE_TYPE_CODE.DATA:
            yield attr.dataruns()
