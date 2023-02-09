from __future__ import annotations

import io
from typing import BinaryIO, Iterator
from uuid import UUID

from dissect.cstruct import Instance
from dissect.util.sid import read_sid

from dissect.ntfs.c_ntfs import ACE_TYPE, c_ntfs
from dissect.ntfs.mft import MftRecord


class Secure:
    """Lookup security descriptors from the $Secure file, or optionally just a file-like object of the $SDS.

    Only one the record or sds arguments needs to be provided.

    Args:
        record: The MFT record of the $Secure file, used when opening from a full NTFS volume.
        sds: A file-like object of the $SDS stream, used when opening from separate system files.
    """

    def __init__(self, record: MftRecord = None, sds: BinaryIO = None):
        self.record = record
        self.sds = None
        self.sii = None

        if record:
            self.sds = record.open("$SDS")
            self.sii = record.index("$SII")
        elif sds:
            self.sds = sds

        if not self.sds:
            raise ValueError("Either record or SDS stream is required")

        # Hack for file-like objects that don't have a .size attribute
        if not hasattr(self.sds, "size"):
            self.sds.size = self.sds.seek(0, io.SEEK_END)

    def _iter_entries(self, offset: int = 0) -> Iterator[Instance]:
        """Iterate over all SDS entries, optionally starting from a specific offset.

        Args:
            offset: Optional offset to start iterating from.
        """
        fh = self.sds
        while True:
            fh.seek(offset)

            try:
                entry = c_ntfs._SECURITY_DESCRIPTOR_HEADER(fh)
            except EOFError:
                break

            if entry.Length == 0 or entry.Offset > self.sds.size or entry.Length > 0x10000:
                # The SDS is supposedly duplicated at 0x40000 increments (256k)? Try to parse again from there
                offset += 0x40000 - (offset % 0x40000)
                continue

            yield entry

            offset += entry.Length
            # Align to 16 bytes with some bit magic
            offset += -(offset) & 0xF

    def lookup(self, security_id: int) -> SecurityDescriptor:
        """Lookup a security descriptor by the security ID.

        An index is used if available ($SII), otherwise we iterate all entries until we find the correct one.

        Args:
            security_id: The security ID to lookup.

        Raises:
            KeyError: If the security ID can't be found.
        """
        if self.sii:
            # If we have an index, we can land directly at the right offset
            sii_entry = c_ntfs._SECURITY_DESCRIPTOR_HEADER(self.sii.search(security_id).data)
            offset = sii_entry.Offset
        else:
            # Otherwise we need to "bruteforce" our way to the correct offset
            offset = 0

        for entry in self._iter_entries(offset):
            if entry.SecurityId == security_id:
                # Jackpot
                return SecurityDescriptor(self.sds)

        raise KeyError(f"Couldn't find security ID: {security_id}")

    def descriptors(self) -> Iterator[SecurityDescriptor]:
        """Return all security descriptors."""
        for _ in self._iter_entries():
            yield SecurityDescriptor(self.sds)


class SecurityDescriptor:
    """Parse a security descriptor from a file-like object.

    Args:
        fh: The file-like object to parse a security descriptor from.
    """

    def __init__(self, fh: BinaryIO):
        offset = fh.tell()
        self.header = c_ntfs._SECURITY_DESCRIPTOR_RELATIVE(fh)

        self.owner = None
        self.group = None
        self.sacl = None
        self.dacl = None

        if self.header.Owner:
            fh.seek(offset + self.header.Owner)
            self.owner = read_sid(fh)

        if self.header.Group:
            fh.seek(offset + self.header.Group)
            self.group = read_sid(fh)

        if self.header.Sacl:
            fh.seek(offset + self.header.Sacl)
            self.sacl = ACL(fh)

        if self.header.Dacl:
            fh.seek(offset + self.header.Dacl)
            self.dacl = ACL(fh)


class ACL:
    """Parse an ACL from a file-like object.

    Args:
        fh: The file-like object to parse an ACL from.
    """

    def __init__(self, fh: BinaryIO):
        self.header = c_ntfs._ACL(fh)
        self.ace = [ACE(fh) for _ in range(self.header.AceCount)]


class ACE:
    """Parse an ACE from a file-like object.

    Args:
        fh: The file-like object to parse an ACE from.
    """

    def __init__(self, fh: BinaryIO):
        self.header = c_ntfs._ACE_HEADER(fh)
        self.data = fh.read(self.header.AceSize - len(c_ntfs._ACE_HEADER))

        self.mask = None
        self.flags = None
        self.object_type = None
        self.inherited_object_type = None
        self.sid = None

        buf = io.BytesIO(self.data)
        if self.is_standard_ace:
            self.mask = c_ntfs.DWORD(buf)
            self.sid = read_sid(buf)
        elif self.is_object_ace:
            self.mask = c_ntfs.DWORD(buf)
            self.flags = c_ntfs.DWORD(buf)
            self.object_type = UUID(bytes_le=buf.read(16))
            self.inherited_object_type = UUID(bytes_le=buf.read(16))
            self.sid = read_sid(buf)

        self.application_data = buf.read() or None

    def __repr__(self) -> str:
        if self.is_standard_ace:
            return f"<{self.header.AceType.name} mask=0x{self.mask:x} sid={self.sid}>"
        elif self.is_object_ace:
            return (
                f"<{self.header.AceType.name} mask=0x{self.mask:x} flags={self.flags} object_type={self.object_type}"
                f" inherited_object_type={self.inherited_object_type} sid={self.sid}>"
            )
        else:
            return f"<ACE type={self.header.AceType} flags={self.header.AceFlags} size={self.header.AceSize}>"

    @property
    def type(self) -> ACE_TYPE:
        """Return the ACE type."""
        return self.header.AceType

    @property
    def is_standard_ace(self) -> bool:
        """Return whether this ACE is a standard ACE."""
        return self.header.AceType in (
            ACE_TYPE.ACCESS_ALLOWED,
            ACE_TYPE.ACCESS_DENIED,
            ACE_TYPE.SYSTEM_AUDIT,
            ACE_TYPE.SYSTEM_ALARM,
            ACE_TYPE.ACCESS_ALLOWED_COMPOUND,
            ACE_TYPE.ACCESS_ALLOWED_CALLBACK,
            ACE_TYPE.ACCESS_DENIED_CALLBACK,
            ACE_TYPE.SYSTEM_AUDIT_CALLBACK,
            ACE_TYPE.SYSTEM_ALARM_CALLBACK,
            ACE_TYPE.SYSTEM_MANDATORY_LABEL,
            ACE_TYPE.SYSTEM_RESOURCE_ATTRIBUTE,
            ACE_TYPE.SYSTEM_SCOPED_POLICY_ID,
        )

    @property
    def is_object_ace(self) -> bool:
        """Return whether this ACE is an object ACE."""
        return self.header.AceType in (
            ACE_TYPE.ACCESS_ALLOWED_OBJECT,
            ACE_TYPE.ACCESS_DENIED_OBJECT,
            ACE_TYPE.SYSTEM_AUDIT_OBJECT,
            ACE_TYPE.SYSTEM_ALARM_OBJECT,
            ACE_TYPE.ACCESS_ALLOWED_CALLBACK_OBJECT,
            ACE_TYPE.ACCESS_DENIED_CALLBACK_OBJECT,
            ACE_TYPE.SYSTEM_AUDIT_CALLBACK_OBJECT,
            ACE_TYPE.SYSTEM_ALARM_CALLBACK_OBJECT,
        )
