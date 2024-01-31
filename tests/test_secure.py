from typing import BinaryIO

import pytest

from dissect.ntfs.ntfs import NTFS
from dissect.ntfs.secure import Secure


def test_secure(ntfs_bin: BinaryIO) -> None:
    fs = NTFS(ntfs_bin)

    assert fs.secure

    sd = fs.secure.lookup(256)
    assert sd.owner == "S-1-5-18"
    assert sd.group == "S-1-5-32-544"

    assert sd.dacl
    assert len(sd.dacl.ace) == 2
    assert sd.dacl.ace[0].type.name == "ACCESS_ALLOWED"
    assert sd.dacl.ace[0].mask == 0x120089
    assert sd.dacl.ace[0].sid == "S-1-5-18"
    assert sd.dacl.ace[1].type.name == "ACCESS_ALLOWED"
    assert sd.dacl.ace[1].mask == 0x120089
    assert sd.dacl.ace[1].sid == "S-1-5-32-544"

    with pytest.raises(KeyError):
        fs.secure.lookup(1337)

    assert len(list(fs.secure.descriptors())) == 24


def test_secure_file(sds_bin: BinaryIO) -> None:
    secure = Secure(sds=sds_bin)

    sd = secure.lookup(256)
    assert sd.owner == "S-1-5-18"
    assert sd.group == "S-1-5-32-544"


def test_secure_complex_acl(sds_complex_bin: BinaryIO) -> None:
    secure = Secure(sds=sds_complex_bin)

    sd = secure.lookup(259)
    assert sd.owner == "S-1-5-21-3090333131-159632407-777084872-1001"
    assert sd.group == "S-1-5-21-3090333131-159632407-777084872-513"
    assert len(sd.sacl.ace) == 2
    assert list(map(repr, sd.sacl.ace)) == [
        "<SYSTEM_MANDATORY_LABEL mask=0x7 sid=S-1-16-4096>",
        "<SYSTEM_ACCESS_FILTER mask=0x1200a9 sid=S-1-1-0>",
    ]
    assert len(sd.dacl.ace) == 3
    assert list(map(repr, sd.dacl.ace)) == [
        "<ACCESS_ALLOWED_COMPOUND mask=0x1f01ff type=COMPOUND_ACE_IMPERSONATION server_sid=S-1-5-11 client_sid=S-1-5-32-545>",  # noqa: E501
        "<ACCESS_ALLOWED_OBJECT mask=0x1f01ff flags=0 object_type=None inherited_object_type=None sid=S-1-1-0>",
        "<ACCESS_ALLOWED_CALLBACK_OBJECT mask=0x1f01ff flags=3 object_type=01234567-89ab-cdef-1111-111111111111 inherited_object_type=22222222-2222-2222-0123-456789abcdef sid=S-1-5-32-545>",  # noqa: E501
    ]


def test_secure_fail() -> None:
    with pytest.raises(ValueError):
        Secure()
