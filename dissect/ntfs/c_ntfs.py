import struct

from dissect import cstruct

ntfs_def = """
/* ================ Generic stuff ================ */

flag FILE_ATTRIBUTE : DWORD {
    READONLY                = 0x00000001,
    HIDDEN                  = 0x00000002,
    SYSTEM                  = 0x00000004,
    DIRECTORY               = 0x00000010,
    ARCHIVE                 = 0x00000020,
    DEVICE                  = 0x00000040,
    NORMAL                  = 0x00000080,
    TEMPORARY               = 0x00000100,
    SPARSE_FILE             = 0x00000200,
    REPARSE_POINT           = 0x00000400,
    COMPRESSED              = 0x00000800,
    OFFLINE                 = 0x00001000,
    NOT_CONTENT_INDEXED     = 0x00002000,
    ENCRYPTED               = 0x00004000,
    INTEGRITY_STREAM        = 0x00008000,
    VIRTUAL                 = 0x00010000,
    NO_SCRUB_DATA           = 0x00020000,
    RECALL_ON_OPEN          = 0x00040000,
    PINNED                  = 0x00080000,
    UNPINNED                = 0x00100000,
    RECALL_ON_DATA_ACCESS   = 0x00400000,
};

/* ================ Volume headers ================ */

typedef struct _BIOS_PARAMETER_BLOCK {
    USHORT      BytesPerSector;
    INT8        SectorsPerCluster;
    USHORT      ReservedSectors;
    UCHAR       Fats;
    USHORT      RootEntries;
    USHORT      Sectors;
    UCHAR       Media;
    USHORT      SectorsPerFat;
    USHORT      SectorsPerTrack;
    USHORT      Heads;
    ULONG       HiddenSectors;
    ULONG       LargeSectors;
} BIOS_PARAMETER_BLOCK;

typedef struct _BOOT_SECTOR {
    CHAR        Jump[3];
    CHAR        Oem[8];
    BIOS_PARAMETER_BLOCK    Bpb;
    CHAR        Unused0[4];
    ULONG64     NumberSectors;
    ULONG64     MftStartLcn;
    ULONG64     Mft2StartLcn;
    INT8        ClustersPerFileRecordSegment;
    CHAR        Reserved0[3];
    INT8        ClustersPerIndexBuffer;
    CHAR        Reserved1[3];
    ULONG64     SerialNumber;
    ULONG       Checksum;
    CHAR        BootStrap[0x200-0x054];
} BOOT_SECTOR;

/* ================ MFT stuff ================ */

typedef struct _MFT_SEGMENT_REFERENCE {
    ULONG       SegmentNumberLowPart;
    USHORT      SegmentNumberHighPart;
    USHORT      SequenceNumber;
} MFT_SEGMENT_REFERENCE;

typedef MFT_SEGMENT_REFERENCE FILE_REFERENCE;

typedef struct _MULTI_SECTOR_HEADER {
    CHAR        Signature[4];
    USHORT      UpdateSequenceArrayOffset;
    USHORT      UpdateSequenceArraySize;
} MULTI_SECTOR_HEADER;

typedef struct _FILE_RECORD_SEGMENT_HEADER {
    MULTI_SECTOR_HEADER MultiSectorHeader;
    ULONG64     Lsn;
    USHORT      SequenceNumber;
    USHORT      ReferenceCount;
    USHORT      FirstAttributeOffset;
    USHORT      Flags;
    ULONG       BytesInUse;
    ULONG       BytesAllocated;
    FILE_REFERENCE  BaseFileRecordSegment;
    USHORT      NextAttributeInstance;
} FILE_RECORD_SEGMENT_HEADER;

/* ================ Attributes ================ */

enum ATTRIBUTE_TYPE_CODE : ULONG {
    UNUSED                  = 0x00,
    STANDARD_INFORMATION    = 0x10,
    ATTRIBUTE_LIST          = 0x20,
    FILE_NAME               = 0x30,
    OBJECT_ID               = 0x40,
    SECURITY_DESCRIPTOR     = 0x50,
    VOLUME_NAME             = 0x60,
    VOLUME_INFORMATION      = 0x70,
    DATA                    = 0x80,
    INDEX_ROOT              = 0x90,
    INDEX_ALLOCATION        = 0xA0,
    BITMAP                  = 0xB0,
    REPARSE_POINT           = 0xC0,
    EA_INFORMATION          = 0xD0,
    EA                      = 0xE0,
    PROPERTY_SET            = 0xF0,
    LOGGED_UTILITY_STREAM   = 0x100,
    END                     = 0xFFFFFFFF,
};

typedef struct _ATTRIBUTE_RECORD_HEADER {
    ATTRIBUTE_TYPE_CODE TypeCode;
    ULONG       RecordLength;
    UCHAR       FormCode;
    UCHAR       NameLength;
    USHORT      NameOffset;
    USHORT      Flags;
    USHORT      Instance;
    union {
        struct {
            ULONG   ValueLength;
            USHORT  ValueOffset;
            UCHAR   Flags;
            UCHAR   Reserved;
        } Resident;
        struct {
            ULONG64     LowestVcn;
            ULONG64     HighestVcn;
            USHORT      MappingPairsOffset;
            UCHAR       CompressionUnit;
            UCHAR       Reserved[5];
            LONGLONG    AllocatedLength;
            LONGLONG    FileSize;
            LONGLONG    ValidDataLength;
            LONGLONG    TotalAllocated;
        } Nonresident;
    } Form;
} ATTRIBUTE_RECORD_HEADER;

typedef struct _STANDARD_INFORMATION {
    LONGLONG    CreationTime;
    LONGLONG    LastModificationTime;
    LONGLONG    LastChangeTime;
    LONGLONG    LastAccessTime;
    ULONG       FileAttributes;
    ULONG       MaximumVersions;
    ULONG       VersionNumber;
    ULONG       ClassId;
    ULONG       OwnerId;
    ULONG       SecurityId;
    ULONGLONG   QuotaCharged;
    ULONGLONG   Usn;
} STANDARD_INFORMATION_EX;

typedef struct _ATTRIBUTE_LIST_ENTRY {
    ATTRIBUTE_TYPE_CODE AttributeTypeCode;
    USHORT      RecordLength;
    UCHAR       AttributeNameLength;
    UCHAR       AttributeNameOffset;
    ULONG64     LowestVcn;
    MFT_SEGMENT_REFERENCE   SegmentReference;
    USHORT      Reserved;
    WCHAR       AttributeName[AttributeNameLength];
} ATTRIBUTE_LIST_ENTRY;

typedef struct _FILE_NAME {
    FILE_REFERENCE  ParentDirectory;
    LONGLONG    CreationTime;
    LONGLONG    LastModificationTime;
    LONGLONG    LastChangeTime;
    LONGLONG    LastAccessTime;
    LONGLONG    AllocatedLength;
    LONGLONG    FileSize;
    ULONG       FileAttributes;
    union {
        struct {
            USHORT  EaSize;
            USHORT  _;
        };
        ULONG   ReparsePointTag;
    };
    UCHAR       FileNameLength;
    UCHAR       Flags;
    WCHAR       FileName[FileNameLength];
} FILE_NAME;

/* ================ Index ================ */

enum COLLATION : ULONG {
    BINARY                  = 0,
    FILE_NAME               = 1,
    UNICODE_STRING          = 2,
    NUMBER_RULES            = 3,
    NTOFS_ULONG             = 16,
    NTOFS_SID               = 17,
    NTOFS_SECURITY_HASH     = 18,
    NTOFS_ULONGS            = 19,
};

typedef COLLATION COLLATION_RULE;

typedef struct _INDEX_HEADER {
    ULONG       FirstEntryOffset;
    ULONG       TotalSizeOfEntries;
    ULONG       AllocatedSize;
    UCHAR       Flags;
    UCHAR       Reserved[3];
} INDEX_HEADER;

typedef struct _INDEX_ROOT {
    ATTRIBUTE_TYPE_CODE AttributeType;
    COLLATION_RULE  CollationRule;
    ULONG       BytesPerIndexBuffer;
    UCHAR       ClustersPerIndexBuffer;
    UCHAR       Reserved[3];
    INDEX_HEADER    IndexHeader;
} INDEX_ROOT;

typedef struct _INDEX_ALLOCATION_BUFFER {
    MULTI_SECTOR_HEADER     MultiSectorHeader;
    ULONG64     Lsn;
    ULONG64     Vcn;
    INDEX_HEADER    IndexHeader;
} INDEX_ALLOCATION_BUFFER;

typedef struct _INDEX_ENTRY {
    union {
        FILE_REFERENCE  FileReference;
        struct {
            USHORT      DataOffset;
            USHORT      DataLength;
            ULONG       _;
        };
    };
    USHORT      Length;
    USHORT      KeyLength;
    USHORT      Flags;
    USHORT      Reserved;
} INDEX_ENTRY;

/* ================ Security Descriptors ================ */

flag SECURITY_DESCRIPTOR_CONTROL : WORD {
    SE_OWNER_DEFAULTED          = 0x0001,
    SE_GROUP_DEFAULTED          = 0x0002,
    SE_DACL_PRESENT             = 0x0004,
    SE_DACL_DEFAULTED           = 0x0008,
    SE_SACL_PRESENT             = 0x0010,
    SE_SACL_DEFAULTED           = 0x0020,
    SE_DACL_AUTO_INHERIT_REQ    = 0x0100,
    SE_SACL_AUTO_INHERIT_REQ    = 0x0200,
    SE_DACL_AUTO_INHERITED      = 0x0400,
    SE_SACL_AUTO_INHERITED      = 0x0800,
    SE_DACL_PROTECTED           = 0x1000,
    SE_SACL_PROTECTED           = 0x2000,
    SE_RM_CONTROL_VALID         = 0x4000,
    SE_SELF_RELATIVE            = 0x8000,
};

flag ACCESS_MASK : DWORD {
    FILE_READ_DATA              = 0x00000001,
    FILE_LIST_DIRECTORY         = 0x00000001,
    FILE_WRITE_DATA             = 0x00000002,
    FILE_ADD_FILE               = 0x00000002,
    FILE_APPEND_DATA            = 0x00000004,
    FILE_ADD_SUBDIRECTORY       = 0x00000004,
    FILE_READ_EA                = 0x00000008,
    FILE_WRITE_EA               = 0x00000010,
    FILE_EXECUTE                = 0x00000020,
    FILE_TRAVERSE               = 0x00000020,
    FILE_DELETE_CHILD           = 0x00000040,
    FILE_READ_ATTRIBUTES        = 0x00000080,
    FILE_WRITE_ATTRIBUTES       = 0x00000100,
    DELETE                      = 0x00010000,
    READ_CONTROL                = 0x00020000,
    WRITE_DAC                   = 0x00040000,
    WRITE_OWNER                 = 0x00080000,
    SYNCHRONIZE                 = 0x00100000,
    STANDARD_RIGHTS_READ        = 0x00020000,
    STANDARD_RIGHTS_WRITE       = 0x00020000,
    STANDARD_RIGHTS_EXECUTE     = 0x00020000,
    STANDARD_RIGHTS_REQUIRED    = 0x000f0000,
    STANDARD_RIGHTS_ALL         = 0x001f0000,
    ACCESS_SYSTEM_SECURITY      = 0x01000000,
    MAXIMUM_ALLOWED             = 0x02000000,
    GENERIC_ALL                 = 0x10000000,
    GENERIC_EXECUTE             = 0x20000000,
    GENERIC_WRITE               = 0x40000000,
    GENERIC_READ                = 0x80000000,
};

enum ACE_TYPE : BYTE {
    ACCESS_ALLOWED                  = 0x00,
    ACCESS_DENIED                   = 0x01,
    SYSTEM_AUDIT                    = 0x02,
    SYSTEM_ALARM                    = 0x03,
    ACCESS_ALLOWED_COMPOUND         = 0x04,
    ACCESS_ALLOWED_OBJECT           = 0x05,
    ACCESS_DENIED_OBJECT            = 0x06,
    SYSTEM_AUDIT_OBJECT             = 0x07,
    SYSTEM_ALARM_OBJECT             = 0x08,
    ACCESS_ALLOWED_CALLBACK         = 0x09,
    ACCESS_DENIED_CALLBACK          = 0x0A,
    ACCESS_ALLOWED_CALLBACK_OBJECT  = 0x0B,
    ACCESS_DENIED_CALLBACK_OBJECT   = 0x0C,
    SYSTEM_AUDIT_CALLBACK           = 0x0D,
    SYSTEM_ALARM_CALLBACK           = 0x0E,
    SYSTEM_AUDIT_CALLBACK_OBJECT    = 0x0F,
    SYSTEM_ALARM_CALLBACK_OBJECT    = 0x10,
    SYSTEM_MANDATORY_LABEL          = 0x11,
    SYSTEM_RESOURCE_ATTRIBUTE       = 0x12,
    SYSTEM_SCOPED_POLICY_ID         = 0x13,
};

flag ACE_FLAGS : BYTE {
    OBJECT_INHERIT_ACE          = 0x01,
    CONTAINER_INHERIT_ACE       = 0x02,
    NO_PROPAGATE_INHERIT_ACE    = 0x04,
    INHERIT_ONLY_ACE            = 0x08,
    INHERITED_ACE               = 0x10,
    SUCCESSFUL_ACCESS_ACE_FLAG  = 0x40,
    FAILED_ACCESS_ACE_FLAG      = 0x80,
};

typedef struct _ACL {
    BYTE        AclRevision;
    BYTE        Sbz1;
    WORD        AclSize;
    WORD        AceCount;
    WORD        Sbz2;
} ACL;

typedef struct _ACE_HEADER {
    ACE_TYPE    AceType;
    ACE_FLAGS   AceFlags;
    WORD        AceSize;
} ACE_HEADER;

typedef struct _SECURITY_DESCRIPTOR_HEADER {
    ULONG       HashId;
    ULONG       SecurityId;
    ULONG64     Offset;
    ULONG       Length;
} SECURITY_DESCRIPTOR_HEADER;

typedef struct _SECURITY_DESCRIPTOR_RELATIVE {
    BYTE        Revision;
    BYTE        Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    ULONG       Owner;
    ULONG       Group;
    ULONG       Sacl;
    ULONG       Dacl;
} SECURITY_DESCRIPTOR_RELATIVE;

/* ================ USN Journal ================ */

flag USN_REASON : DWORD {
    DATA_OVERWRITE          = 0x00000001,
    DATA_EXTEND             = 0x00000002,
    DATA_TRUNCATION         = 0x00000004,
    NAMED_DATA_OVERWRITE    = 0x00000010,
    NAMED_DATA_EXTEND       = 0x00000020,
    NAMED_DATA_TRUNCATION   = 0x00000040,
    FILE_CREATE             = 0x00000100,
    FILE_DELETE             = 0x00000200,
    EA_CHANGE               = 0x00000400,
    SECURITY_CHANGE         = 0x00000800,
    RENAME_OLD_NAME         = 0x00001000,
    RENAME_NEW_NAME         = 0x00002000,
    INDEXABLE_CHANGE        = 0x00004000,
    BASIC_INFO_CHANGE       = 0x00008000,
    HARD_LINK_CHANGE        = 0x00010000,
    COMPRESSION_CHANGE      = 0x00020000,
    ENCRYPTION_CHANGE       = 0x00040000,
    OBJECT_ID_CHANGE        = 0x00080000,
    REPARSE_POINT_CHANGE    = 0x00100000,
    STREAM_CHANGE           = 0x00200000,
    TRANSACTED_CHANGE       = 0x00400000,
    INTEGRITY_CHANGE        = 0x00800000,
    CLOSE                   = 0x80000000,
};

flag USN_SOURCE : DWORD {
    NORMAL                  = 0x00000000,
    DATA_MANAGEMENT         = 0x00000001,
    AUXILIARY_DATA          = 0x00000002,
    REPLICATION_MANAGEMENT  = 0x00000004,
    CLIENT_REPLICATION_MANAGEMENT   = 0x00000008,
};

typedef struct _FILE_ID_128 {
    BYTE    Identifier[16];
} FILE_ID_128;

typedef struct {
    DWORD       RecordLength;
    WORD        MajorVersion;
    WORD        MinorVersion;
} USN_RECORD_COMMON_HEADER;

typedef struct {
    DWORD       RecordLength;
    WORD        MajorVersion;
    WORD        MinorVersion;
    MFT_SEGMENT_REFERENCE   FileReferenceNumber;
    MFT_SEGMENT_REFERENCE   ParentFileReferenceNumber;
    ULONG64     Usn;
    ULONG64     TimeStamp;
    USN_REASON  Reason;
    USN_SOURCE  SourceInfo;
    DWORD       SecurityId;
    FILE_ATTRIBUTE  FileAttributes;
    WORD        FileNameLength;
    WORD        FileNameOffset;
} USN_RECORD_V2;

typedef struct {
    DWORD       RecordLength;
    WORD        MajorVersion;
    WORD        MinorVersion;
    FILE_ID_128 FileReferenceNumber;
    FILE_ID_128 ParentFileReferenceNumber;
    ULONG64     Usn;
    ULONG64     TimeStamp;
    USN_REASON  Reason;
    USN_SOURCE  SourceInfo;
    DWORD       SecurityId;
    FILE_ATTRIBUTE  FileAttributes;
    WORD        FileNameLength;
    WORD        FileNameOffset;
} USN_RECORD_V3;

typedef struct {
    LONGLONG    Offset;
    LONGLONG    Length;
} USN_RECORD_EXTENT;

typedef struct {
    DWORD       RecordLength;
    WORD        MajorVersion;
    WORD        MinorVersion;
    FILE_ID_128 FileReferenceNumber;
    FILE_ID_128 ParentFileReferenceNumber;
    ULONG64     Usn;
    USN_REASON  Reason;
    USN_SOURCE  SourceInfo;
    DWORD       RemainingExtents;
    WORD        NumberOfExtents;
    WORD        ExtentSize;
} USN_RECORD_V4;
"""

c_ntfs = cstruct.cstruct()
c_ntfs.load(ntfs_def)

# Useful enums and flags
ATTRIBUTE_TYPE_CODE = c_ntfs.ATTRIBUTE_TYPE_CODE
ACCESS_MASK = c_ntfs.ACCESS_MASK
ACE_TYPE = c_ntfs.ACE_TYPE
COLLATION = c_ntfs.COLLATION

# Some useful magic numbers and constants
NTFS_SIGNATURE = b"NTFS    "

SECTOR_SIZE = 512
SECTOR_SHIFT = 9

USN_PAGE_SIZE = 4096

DEFAULT_SECTOR_SIZE = 512
DEFAULT_CLUSTER_SIZE = 4096
DEFAULT_RECORD_SIZE = 1024
DEFAULT_INDEX_SIZE = 4096

# File numbers of various system files
FILE_NUMBER_MFT = 0
FILE_NUMBER_MFTMIRR = 1
FILE_NUMBER_LOGFILE = 2
FILE_NUMBER_VOLUME = 3
FILE_NUMBER_ATTRDEF = 4
FILE_NUMBER_ROOT = 5
FILE_NUMBER_BITMAP = 6
FILE_NUMBER_BOOT = 7
FILE_NUMBER_BADCLUS = 8
FILE_NUMBER_SECURE = 9
FILE_NUMBER_UPCASE = 10
FILE_NUMBER_EXTEND = 11

# File record flags
FILE_RECORD_SEGMENT_IN_USE = 0x0001
FILE_FILE_NAME_INDEX_PRESENT = 0x0002

# Attribute flags
ATTRIBUTE_FLAG_COMPRESSION_MASK = 0x00FF
ATTRIBUTE_FLAG_ENCRYPTED = 0x4000
ATTRIBUTE_FLAG_SPARSE = 0x8000

# Filename flags
FILE_NAME_NTFS = 0x01
FILE_NAME_DOS = 0x02

# Compression flags
COMPRESSION_FORMAT_NONE = 0x0000
COMPRESSION_FORMAT_DEFAULT = 0x0001
COMPRESSION_FORMAT_LZNT1 = 0x0002

# Index and index entry flags
INDEX_NODE = 0x01
INDEX_ENTRY_NODE = 0x01
INDEX_ENTRY_END = 0x02


def segment_reference(reference: cstruct.Instance) -> int:
    """Helper to calculate the complete segment number from a cstruct MFT segment reference.

    Args:
        reference: A cstruct _MFT_SEGMENT_REFERENCE instance to return the complete segment number of.
    """
    return reference.SegmentNumberLowPart | (reference.SegmentNumberHighPart << 32)


def varint(buf: bytes) -> int:
    """Parse variable integers.

    Dataruns in NTFS are stored as a tuple of variable sized integers. The size of each integer is
    stored in the first byte, 4 bits for each integer. This logic can be seen in
    :func:`AttributeHeader.dataruns <dissect.ntfs.attr.AttributeHeader.dataruns>`.

    This function only parses those variable amount of bytes into actual integers. To do that, we
    simply pad the bytes to 8 bytes long and parse it as a signed 64 bit integer. We pad with 0xff
    if the number is negative and 0x00 otherwise.

    Args:
        buf: The byte buffer to parse a varint from.
    """
    if len(buf) < 8:
        buf += (b"\xff" if buf[-1] & 0x80 else b"\x00") * (8 - len(buf))

    return struct.unpack("<q", buf)[0]


def bsf(value: int, size: int = 32) -> int:
    """Count the number of trailing zero bits in an integer of a given size.

    Args:
        value: The integer to count trailing zero bits in.
        size: Integer size to limit to.
    """
    for i in range(size):
        if value & (1 << i):
            return i
