import pytest

from dissect.ntfs.ntfs import NTFS
from dissect.ntfs.secure import Secure


def test_secure(ntfs_bin):
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


def test_secure_file(sds_bin):
    secure = Secure(sds=sds_bin)

    sd = secure.lookup(256)
    assert sd.owner == "S-1-5-18"
    assert sd.group == "S-1-5-32-544"


def test_secure_fail():
    with pytest.raises(ValueError):
        Secure()
