import os
import stat
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes
else:
    import fcntl


class CacheLockTimeoutError(TimeoutError):
    pass


class UnsafeCacheStorageError(OSError):
    pass


def open_owner_only_file(path: Path) -> BinaryIO:
    if os.name == "nt":
        handle = _windows_create_owner_only_file(path)
    else:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            handle = os.fdopen(descriptor, "w+b")
        except Exception:
            os.close(descriptor)
            raise
    try:
        _validate_open_file(path, handle)
    except Exception:
        handle.close()
        raise
    return handle


def replace_file_durably(source: Path, destination: Path) -> None:
    if os.name == "nt":
        _windows_replace_file_durably(source, destination)
    else:
        _posix_replace_file_durably(source, destination)


def _posix_replace_file_durably(source: Path, destination: Path) -> None:
    os.replace(source, destination)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(destination.parent, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def locked_cache_file(
    path: Path,
    *,
    timeout: float = 5.0,
    lock_opener: Callable[[Path], BinaryIO] | None = None,
    private_storage: bool = False,
) -> Iterator[None]:
    if private_storage:
        _ensure_private_directory(path.parent)
        validate_private_cache_storage(path)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    opener = lock_opener or (_open_private_lock if private_storage else lambda candidate: candidate.open("a+b"))
    with opener(lock_path) as handle:
        if private_storage:
            _validate_open_file(lock_path, handle)
        deadline = time.monotonic() + timeout
        while True:
            try:
                _lock(handle)
                break
            except OSError as error:
                if time.monotonic() >= deadline:
                    raise CacheLockTimeoutError("The cache lock timed out.") from error
                time.sleep(0.01)
        try:
            yield
        finally:
            _unlock(handle)


def validate_private_cache_storage(path: Path) -> None:
    try:
        _assert_no_reparse_ancestors(path.parent)
        if os.path.lexists(path.parent):
            _validate_named_path(path.parent, directory=True)
        for candidate in (path, path.with_suffix(path.suffix + ".lock")):
            if os.path.lexists(candidate):
                _validate_named_path(candidate, directory=False)
    except UnsafeCacheStorageError:
        raise
    except Exception:
        raise UnsafeCacheStorageError("The private cache storage is unsafe.") from None


def _lock(handle) -> None:
    if os.name == "nt":
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(handle) -> None:
    if os.name == "nt":
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _ensure_private_directory(path: Path) -> None:
    missing: list[Path] = []
    cursor = path.absolute()
    while not os.path.lexists(cursor):
        missing.append(cursor)
        if cursor == cursor.parent:
            raise UnsafeCacheStorageError("The private cache directory is invalid.")
        cursor = cursor.parent
    _assert_no_reparse_ancestors(cursor)
    for directory in reversed(missing):
        try:
            if os.name == "nt":
                _windows_create_private_directory(directory)
            else:
                directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        _validate_named_path(directory, directory=True)
    _validate_named_path(path, directory=True)


def _open_private_lock(path: Path) -> BinaryIO:
    if os.path.lexists(path):
        _validate_named_path(path, directory=False)
    if os.name == "nt":
        handle = _windows_open_private_lock(path)
    else:
        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        handle = os.fdopen(descriptor, "a+b")
    try:
        if os.name != "nt":
            os.chmod(path, 0o600, follow_symlinks=False)
        _validate_open_file(path, handle)
    except Exception:
        handle.close()
        raise
    return handle


def _validate_open_file(path: Path, handle: BinaryIO) -> None:
    opened = os.fstat(handle.fileno())
    named = path.lstat()
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or stat.S_ISLNK(named.st_mode)
        or _is_reparse(opened)
        or _is_reparse(named)
        or opened.st_dev != named.st_dev
        or opened.st_ino != named.st_ino
        or opened.st_nlink != 1
        or named.st_nlink != 1
    ):
        raise UnsafeCacheStorageError("The private cache lock is unsafe.")
    _validate_permissions(path, opened, directory=False)


def _validate_named_path(path: Path, *, directory: bool) -> None:
    info = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or _is_reparse(info)
        or (not directory and info.st_nlink != 1)
    ):
        raise UnsafeCacheStorageError("The private cache path is unsafe.")
    _validate_permissions(path, info, directory=directory)


def _validate_permissions(path: Path, info: os.stat_result, *, directory: bool) -> None:
    if os.name == "nt":
        if not _windows_permissions_are_private(path):
            raise UnsafeCacheStorageError("The private cache ACL is unsafe.")
        return
    required = 0o700 if directory else 0o600
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != required:
        raise UnsafeCacheStorageError("The private cache permissions are unsafe.")


def _assert_no_reparse_ancestors(path: Path) -> None:
    absolute = path.absolute()
    parts = absolute.parts
    if not parts:
        raise UnsafeCacheStorageError("The private cache ancestor is unsafe.")
    candidate = Path(parts[0])
    for index, part in enumerate(parts):
        if index:
            candidate /= part
        if not os.path.lexists(candidate):
            break
        info = candidate.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            raise UnsafeCacheStorageError("The private cache ancestor is unsafe.")


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


if os.name == "nt":
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _OWNER_SECURITY_INFORMATION = 0x00000001
    _DACL_SECURITY_INFORMATION = 0x00000004
    _SE_FILE_OBJECT = 1
    _ACL_SIZE_INFORMATION_CLASS = 2
    _ACCESS_ALLOWED_ACE_TYPE = 0
    _NON_ACCESS_GRANTING_ACE_TYPES = frozenset(
        {
            0x01,  # ACCESS_DENIED_ACE_TYPE
            0x02,  # SYSTEM_AUDIT_ACE_TYPE
            0x03,  # SYSTEM_ALARM_ACE_TYPE
            0x06,  # ACCESS_DENIED_OBJECT_ACE_TYPE
            0x07,  # SYSTEM_AUDIT_OBJECT_ACE_TYPE
            0x08,  # SYSTEM_ALARM_OBJECT_ACE_TYPE
            0x0A,  # ACCESS_DENIED_CALLBACK_ACE_TYPE
            0x0C,  # ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
            0x0D,  # SYSTEM_AUDIT_CALLBACK_ACE_TYPE
            0x0E,  # SYSTEM_ALARM_CALLBACK_ACE_TYPE
            0x0F,  # SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
            0x10,  # SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
            0x11,  # SYSTEM_MANDATORY_LABEL_ACE_TYPE
            0x12,  # SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
            0x13,  # SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
            0x14,  # SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE
            0x15,  # SYSTEM_ACCESS_FILTER_ACE_TYPE
        }
    )
    _ERROR_ALREADY_EXISTS = 183
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _WRITE_OWNER = 0x00080000
    _READ_CONTROL = 0x00020000
    _FILE_READ_ATTRIBUTES = 0x0080
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _MOVEFILE_REPLACE_EXISTING = 0x00000001
    _MOVEFILE_WRITE_THROUGH = 0x00000008
    _CREATE_NEW = 1
    _OPEN_EXISTING = 3
    _OPEN_ALWAYS = 4
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _SAFE_WINDOWS_SIDS = {"S-1-5-18", "S-1-5-32-544"}

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class _ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", ctypes.c_ushort),
        ]

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _KERNEL32.GetCurrentProcess.restype = wintypes.HANDLE
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = wintypes.BOOL
    _KERNEL32.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    _KERNEL32.MoveFileExW.restype = wintypes.BOOL
    _KERNEL32.LocalFree.argtypes = [ctypes.c_void_p]
    _KERNEL32.LocalFree.restype = ctypes.c_void_p
    _KERNEL32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SECURITY_ATTRIBUTES)]
    _KERNEL32.CreateDirectoryW.restype = wintypes.BOOL
    _KERNEL32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _KERNEL32.CreateFileW.restype = wintypes.HANDLE
    _ADVAPI32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _ADVAPI32.OpenProcessToken.restype = wintypes.BOOL
    _ADVAPI32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _ADVAPI32.GetTokenInformation.restype = wintypes.BOOL
    _ADVAPI32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    _ADVAPI32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _ADVAPI32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    _ADVAPI32.ConvertStringSidToSidW.restype = wintypes.BOOL
    _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    _ADVAPI32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _ADVAPI32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    _ADVAPI32.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    _ADVAPI32.GetAclInformation.restype = wintypes.BOOL
    _ADVAPI32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    _ADVAPI32.GetAce.restype = wintypes.BOOL
    _ADVAPI32.IsValidSid.argtypes = [ctypes.c_void_p]
    _ADVAPI32.IsValidSid.restype = wintypes.BOOL
    _ADVAPI32.GetLengthSid.argtypes = [ctypes.c_void_p]
    _ADVAPI32.GetLengthSid.restype = wintypes.DWORD
    _ADVAPI32.SetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    _ADVAPI32.SetSecurityInfo.restype = wintypes.DWORD


def _windows_create_private_directory(path: Path) -> None:
    with _windows_private_security_attributes(directory=True) as attributes:
        if not _KERNEL32.CreateDirectoryW(_windows_path(path), ctypes.byref(attributes)):
            error = ctypes.get_last_error()
            if error == _ERROR_ALREADY_EXISTS:
                raise FileExistsError(path)
            raise ctypes.WinError(error)
    handle = _KERNEL32.CreateFileW(
        _windows_path(path),
        _FILE_READ_ATTRIBUTES | _READ_CONTROL | _WRITE_OWNER,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        _windows_set_current_owner_handle(handle)
    finally:
        _KERNEL32.CloseHandle(handle)


def _windows_open_private_lock(path: Path) -> BinaryIO:
    with _windows_private_security_attributes(directory=False) as attributes:
        ctypes.set_last_error(0)
        handle = _KERNEL32.CreateFileW(
            _windows_path(path),
            _GENERIC_READ | _GENERIC_WRITE | _WRITE_OWNER,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            ctypes.byref(attributes),
            _OPEN_ALWAYS,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        create_error = ctypes.get_last_error()
    if handle == _INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if create_error != _ERROR_ALREADY_EXISTS:
            _windows_set_current_owner_handle(handle)
        descriptor = msvcrt.open_osfhandle(handle, os.O_BINARY | os.O_RDWR)
    except Exception:
        _KERNEL32.CloseHandle(handle)
        raise
    opened = os.fdopen(descriptor, "a+b")
    opened.seek(0, os.SEEK_END)
    return opened


def _windows_create_owner_only_file(path: Path) -> BinaryIO:
    with _windows_private_security_attributes(directory=False) as attributes:
        handle = _KERNEL32.CreateFileW(
            _windows_path(path),
            _GENERIC_READ | _GENERIC_WRITE | _WRITE_OWNER,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            ctypes.byref(attributes),
            _CREATE_NEW,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    if handle == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        if error == _ERROR_ALREADY_EXISTS:
            raise FileExistsError(path)
        raise ctypes.WinError(error)
    try:
        _windows_set_current_owner_handle(handle)
        descriptor = msvcrt.open_osfhandle(handle, os.O_BINARY | os.O_RDWR)
    except Exception:
        _KERNEL32.CloseHandle(handle)
        raise
    try:
        return os.fdopen(descriptor, "w+b")
    except Exception:
        os.close(descriptor)
        raise


def _windows_replace_file_durably(source: Path, destination: Path) -> None:
    flags = _MOVEFILE_REPLACE_EXISTING | _MOVEFILE_WRITE_THROUGH
    if not _KERNEL32.MoveFileExW(_windows_path(source), _windows_path(destination), flags):
        raise ctypes.WinError(ctypes.get_last_error())


@contextmanager
def _windows_private_security_attributes(*, directory: bool) -> Iterator[object]:
    descriptor = _windows_private_descriptor(directory=directory)
    attributes = _SECURITY_ATTRIBUTES(ctypes.sizeof(_SECURITY_ATTRIBUTES), descriptor, False)
    try:
        yield attributes
    finally:
        _KERNEL32.LocalFree(descriptor)


def _windows_private_descriptor(*, directory: bool) -> object:
    sid = _windows_current_sid_string()
    inheritance = "OICI" if directory else ""
    descriptor = ctypes.c_void_p()
    sddl = f"D:P(A;{inheritance};FA;;;{sid})"
    if not _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        1,
        ctypes.byref(descriptor),
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return descriptor


def _windows_path(path: Path) -> str:
    value = str(path.absolute())
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    if not value.startswith("\\\\?\\"):
        return "\\\\?\\" + value
    return value


def _windows_current_sid_string() -> str:
    token = wintypes.HANDLE()
    if not _ADVAPI32.OpenProcessToken(_KERNEL32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        _ADVAPI32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))
        if needed.value == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(needed.value)
        if not _ADVAPI32.GetTokenInformation(token, _TOKEN_USER, buffer, needed, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.c_void_p.from_buffer(buffer).value
        return _windows_sid_string(sid)
    finally:
        _KERNEL32.CloseHandle(token)


def _windows_set_current_owner_handle(handle: object) -> None:
    current_sid = ctypes.c_void_p()
    if not _ADVAPI32.ConvertStringSidToSidW(_windows_current_sid_string(), ctypes.byref(current_sid)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        result = _ADVAPI32.SetSecurityInfo(
            handle,
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION,
            current_sid,
            None,
            None,
            None,
        )
        if result != 0:
            raise OSError(result, "failed to set private cache owner")
    finally:
        _KERNEL32.LocalFree(current_sid)


def _windows_sid_string(sid: object) -> str:
    sid_text = wintypes.LPWSTR()
    if not _ADVAPI32.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return str(sid_text.value)
    finally:
        _KERNEL32.LocalFree(sid_text)


def _windows_permissions_are_private(path: Path) -> bool:
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = _ADVAPI32.GetNamedSecurityInfoW(
        _windows_path(path),
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result != 0 or not owner.value or not dacl.value or not descriptor.value:
        if descriptor.value:
            _KERNEL32.LocalFree(descriptor)
        return False
    try:
        owner_sid = _windows_sid_string(owner)
        if owner_sid != _windows_current_sid_string():
            return False
        allowed_sids = _SAFE_WINDOWS_SIDS | {owner_sid}
        information = _ACL_SIZE_INFORMATION()
        if not _ADVAPI32.GetAclInformation(
            dacl,
            ctypes.byref(information),
            ctypes.sizeof(information),
            _ACL_SIZE_INFORMATION_CLASS,
        ):
            return False
        for index in range(information.AceCount):
            ace = ctypes.c_void_p()
            if not _ADVAPI32.GetAce(dacl, index, ctypes.byref(ace)):
                return False
            if not _windows_ace_is_private(ace, allowed_sids):
                return False
        return True
    finally:
        _KERNEL32.LocalFree(descriptor)


def _windows_ace_is_private(ace: object, allowed_sids: set[str]) -> bool:
    address = getattr(ace, "value", None)
    if not isinstance(address, int) or address <= 0:
        return False
    header = ctypes.cast(ace, ctypes.POINTER(_ACE_HEADER)).contents
    if header.AceSize < ctypes.sizeof(_ACE_HEADER):
        return False
    if header.AceType != _ACCESS_ALLOWED_ACE_TYPE:
        return header.AceType in _NON_ACCESS_GRANTING_ACE_TYPES

    sid_offset = ctypes.sizeof(_ACE_HEADER) + ctypes.sizeof(wintypes.DWORD)
    minimum_sid_bytes = 8
    if header.AceSize < sid_offset + minimum_sid_bytes:
        return False
    sid = ctypes.c_void_p(address + sid_offset)
    if not _ADVAPI32.IsValidSid(sid):
        return False
    sid_length = int(_ADVAPI32.GetLengthSid(sid))
    if sid_length < minimum_sid_bytes or sid_length > header.AceSize - sid_offset:
        return False
    return _windows_sid_string(sid) in allowed_sids
