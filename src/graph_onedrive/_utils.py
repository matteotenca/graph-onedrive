import datetime
import os
import platform
import typing
from ctypes import *
import re

# int statx(int dirfd, const char *restrict pathname, int flags,
#           unsigned int mask, struct statx *restrict statxbuf);
# import graph_onedrive


class StatxTimestamp(Structure):
    _fields_ = [
        ("tv_sec", c_int64),
        ("tv_nsec", c_uint32),
        ("__statx_timestamp_pad1", c_int32 * 1),
    ]


class StatxStruct(Structure):
    _fields_ = [
        ("stx_mask", c_uint32),
        ("stx_blksize", c_uint32),
        ("stx_attributes", c_uint64),
        ("stx_nlink", c_uint32),
        ("stx_uid", c_uint32),
        ("stx_gid", c_uint32),
        ("stx_mode", c_uint16),
        ("__statx_pad1", c_uint16 * 1),
        ("stx_ino", c_uint64),
        ("stx_size", c_uint64),
        ("stx_blocks", c_uint64),
        ("stx_attributes_mask", c_uint64),
        ("stx_atime", StatxTimestamp),
        ("stx_btime", StatxTimestamp),
        ("stx_ctime", StatxTimestamp),
        ("stx_mtime", StatxTimestamp),
        ("stx_rdev_major", c_uint32),
        ("stx_rdev_minor", c_uint32),
        ("stx_dev_major", c_uint32),
        ("stx_dev_minor", c_uint32),
        ("__statx_pad2", c_uint64 * 14),
    ]


AT_FDCWD = (
    -100
)  # Special value used to indicate openat should use the current working directory.
AT_SYMLINK_NOFOLLOW = c_uint32(0x100)  # Do not follow symbolic links.
AT_EACCESS = 0x200  # Test access permitted for effective IDs, not real IDs.
AT_REMOVEDIR = 0x200  # Remove directory instead of unlinking file.
AT_SYMLINK_FOLLOW = 0x400  # Follow symbolic links.
AT_NO_AUTOMOUNT = 0x800  # Suppress terminal automount traversal
AT_EMPTY_PATH = 0x1000  # Allow empty relative pathname
AT_STATX_SYNC_TYPE = 0x6000  # Type of synchronisation required from statx()
AT_STATX_SYNC_AS_STAT = 0x0000  # - Do whatever stat() does
AT_STATX_FORCE_SYNC = 0x2000  # - Force the attributes to be synced with the server
AT_STATX_DONT_SYNC = 0x4000  # - Don't sync attributes with the server
AT_RECURSIVE = 0x8000  # Apply to the entire subtree
STATX_TYPE = 0x00000001  # Want/got stx_mode & S_IFMT
STATX_MODE = 0x00000002  # Want/got stx_mode & ~S_IFMT
STATX_NLINK = 0x00000004  # Want/got stx_nlink
STATX_UID = 0x00000008  # Want/got stx_uid
STATX_GID = 0x00000010  # Want/got stx_gid
STATX_ATIME = c_uint32(0x00000020)  # Want/got stx_atime
STATX_MTIME = c_uint32(0x00000040)  # Want/got stx_mtime
STATX_CTIME = c_uint32(0x00000080)  # Want/got stx_ctime
STATX_INO = 0x00000100  # Want/got stx_ino
STATX_SIZE = 0x00000200  # Want/got stx_size
STATX_BLOCKS = 0x00000400  # Want/got stx_blocks
STATX_BASIC_STATS = c_uint32(0x000007FF)  # The stuff in the normal stat struct
STATX_BTIME = c_uint32(0x00000800)  # Want/got stx_btime
STATX_MNT_ID = 0x00001000  # Got stx_mnt_id

STATX__RESERVED = 0x80000000  # Reserved for future struct statx expansion

# This is deprecated, and shall remain the same value in the future.  To avoid
# confusion please use the equivalent (STATX_BASIC_STATS | STATX_BTIME)
# instead.
STATX_ALL = 0x00000FFF

# Attributes to be found in stx_attributes and masked in stx_attributes_mask.
#
# These give information about the features or the state of a file that might
# be of use to ordinary userspace programs such as GUIs or ls rather than
# specialised tools.
#
# Note that the flags marked [I] correspond to the FS_IOC_SETFLAGS flags
# semantically.  Where possible, the numerical value is picked to correspond
# also.  Note that the DAX attribute indicates that the file is in the CPU
# direct access state.  It does not correspond to the per-inode flag that
# some filesystems support.

STATX_ATTR_COMPRESSED = 0x00000004  # [I] File is compressed by the fs
STATX_ATTR_IMMUTABLE = 0x00000010  # [I] File is marked immutable
STATX_ATTR_APPEND = 0x00000020  # [I] File is append-only
STATX_ATTR_NODUMP = 0x00000040  # [I] File is not to be dumped
STATX_ATTR_ENCRYPTED = 0x00000800  # [I] File requires key to decrypt in fs
STATX_ATTR_AUTOMOUNT = 0x00001000  # Dir: Automount trigger
STATX_ATTR_MOUNT_ROOT = 0x00002000  # Root of a mount
STATX_ATTR_VERITY = 0x00100000  # [I] Verity protected file
STATX_ATTR_DAX = 0x00200000  # File is currently in DAX state


def get_creation_time(file_name: str) -> typing.Union[typing.List[int], None]:
    if platform.system() != "Linux":
        return None
    else:
        match = re.search(r"^[\d.]+", platform.release())
        if match:
            kernel_version = match.group(0)
            if VersionCmp(kernel_version) < VersionCmp("4.11"):
                return None
    libc = cdll.LoadLibrary("libc.so.6")
    gnu_get_libc_version = libc.gnu_get_libc_version
    gnu_get_libc_version.restype = c_char_p
    libc_version: bytes = gnu_get_libc_version()
    if VersionCmp(libc_version.decode(encoding="utf-8")) < VersionCmp("2.28"):
        return None
    statx = libc.statx
    # statx.argtypes = [c_int, c_char, c_int, c_uint, POINTER(StatxStruct)]
    statx.restype = c_int
    # statx_proto = CFUNCTYPE(c_int, c_int, c_char_p, c_int, c_uint, POINTER(StatxStruct))
    statx_buf = StatxStruct()
    file_name_bin = create_unicode_buffer(file_name)
    # mask = c_uint32(STATX_ATIME.value | STATX_MTIME.value | STATX_CTIME.value | STATX_BTIME.value | STATX_BASIC_STATS.value)
    mask = c_uint32(STATX_ALL)
    # print(f"mask: {hex(mask)}")
    result = statx(0, byref(file_name_bin), 0, mask, byref(statx_buf))
    values = list()
    if result >= 0:
        atime = statx_buf.stx_atime.tv_sec
        btime = statx_buf.stx_btime.tv_sec
        ctime = statx_buf.stx_ctime.tv_sec
        mtime = statx_buf.stx_mtime.tv_sec
        values.append(atime)
        values.append(btime)
        values.append(ctime)
        values.append(mtime)
        print(
            atime, "Access",
            datetime.datetime.fromtimestamp(atime).strftime("%Y-%m-%dT%H:%M:%S.%f"),
        )
        print(
            btime, "Birth",
            datetime.datetime.fromtimestamp(btime).strftime("%Y-%m-%dT%H:%M:%S.%f"),
        )
        print(
            ctime, "Change",
            datetime.datetime.fromtimestamp(ctime).strftime("%Y-%m-%dT%H:%M:%S.%f"),
        )
        print(
            mtime, "Modified",
            datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%dT%H:%M:%S.%f"),
        )
        return values
    else:
        return None


class VersionCmp:

    _num_split_re = re.compile(r'([0-9]+|[^0-9]+)')
    _ver_list = list()
    _ver_str = str()

    def __init__(self, ver: typing.Union[str, object]) -> None:
        if isinstance(ver, str):
            self._ver_str: str = ver
            self._ver_list: list = self._ver_as_list(ver)
        else:
            self._ver_list: list = ver._ver_list
            self._ver_str: str = ver._ver_str

    def _try_int(self, i: str, fallback=None) -> typing.Union[int, str]:
        try:
            q = int(i)
            return int(i)
        except ValueError:
            pass
        except TypeError:
            pass
        return fallback

    def _ver_as_list(self, ver: typing.Union[str, typing.Any]) -> typing.List:
        if isinstance(ver, str):
            ll = [self._try_int(i, i) for i in self._num_split_re.findall(ver)]
            return ll
        elif isinstance(ver, type(self)):
            return ver._ver_list
        else:
            raise TypeError()

    def __lt__(self, other: typing.Union[str, typing.Any]) -> bool:
        if isinstance(other, str):
            other_ls = self._ver_as_list(other)
        elif isinstance(other, type(self)):
            other_ls = other._ver_list
        else:
            raise TypeError()
        return self._ver_list < other_ls

    def __le__(self, other: typing.Union[str, typing.Any]) -> bool:
        if isinstance(other, str):
            other_ls = self._ver_as_list(other)
        elif isinstance(other, type(self)):
            other_ls = other._ver_list
        else:
            raise TypeError()
        return self._ver_list <= other_ls

    def __eq__(self, other: typing.Union[str, typing.Any]) -> bool:
        if isinstance(other, str):
            other_ls = self._ver_as_list(other)
        elif isinstance(other, type(self)):
            other_ls = other._ver_list
        else:
            raise TypeError()
        return self._ver_list == other_ls

    def __ne__(self, other: typing.Union[str, typing.Any]) -> bool:
        if isinstance(other, str):
            other_ls = self._ver_as_list(other)
        elif isinstance(other, type(self)):
            other_ls = other._ver_list
        else:
            raise TypeError()
        return self._ver_list != other_ls

    def __gt__(self, other: typing.Union[str, typing.Any]) -> bool:
        if isinstance(other, str):
            other_ls = self._ver_as_list(other)
        elif isinstance(other, type(self)):
            other_ls = other._ver_list
        else:
            raise TypeError()
        return self._ver_list > other_ls

    def __ge__(self, other: typing.Union[str, typing.Any]) -> bool:
        if isinstance(other, str):
            other_ls = self._ver_as_list(other)
        elif isinstance(other, type(self)):
            other_ls = other._ver_list
        else:
            raise TypeError()
        return self._ver_list >= other_ls

    def __str__(self) -> str:
        return self._ver_str

    def __bytes__(self) -> bytes:
        return self._ver_str.encode(encoding="utf-8")

    def __repr__(self) -> str:
        return self._ver_str.__repr__()
