from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes


class SafePathError(OSError):
    pass


@dataclass(frozen=True)
class _HeldDirectory:
    path: Path
    descriptor: int
    parent_descriptor: int | None
    name: str | None


@dataclass(frozen=True)
class SafeDirectoryEntry:
    name: str
    mode: int
    reparse: bool
    device: int | None
    inode: int


class SafeDirectoryHandle:
    def __init__(
        self,
        path: Path,
        descriptor: int,
        *,
        parent_descriptor: int | None = None,
        name: str | None = None,
    ) -> None:
        self.path = path
        self.descriptor = descriptor
        self.parent_descriptor = parent_descriptor
        self.name = name

    @contextmanager
    def entries(self) -> Iterator[Iterator[SafeDirectoryEntry]]:
        self._require_open()
        self._verify_binding()
        iterator = _directory_entries(
            _HeldDirectory(self.path, self.descriptor, None, None),
        )
        try:
            yield iterator
        finally:
            iterator.close()
            self._verify_binding()

    def open_child(self, entry: SafeDirectoryEntry) -> SafeDirectoryHandle:
        self._require_open()
        child_path = self.path / entry.name
        descriptor = _open_directory(child_path, self.descriptor, entry.name)
        parent_descriptor: int | None = None
        try:
            opened = os.fstat(descriptor)
            if entry.device is not None and opened.st_dev != entry.device:
                raise SafePathError("The directory entry changed before it was opened.")
            if opened.st_ino != entry.inode:
                raise SafePathError("The directory entry changed before it was opened.")
            parent_descriptor = os.dup(self.descriptor)
            return SafeDirectoryHandle(
                child_path,
                descriptor,
                parent_descriptor=parent_descriptor,
                name=entry.name,
            )
        except Exception:
            if parent_descriptor is not None:
                os.close(parent_descriptor)
            os.close(descriptor)
            raise

    def close(self) -> None:
        if self.descriptor < 0:
            return
        descriptor = self.descriptor
        self.descriptor = -1
        try:
            os.close(descriptor)
        finally:
            if self.parent_descriptor is not None:
                parent_descriptor = self.parent_descriptor
                self.parent_descriptor = None
                os.close(parent_descriptor)

    def _require_open(self) -> None:
        if self.descriptor < 0:
            raise SafePathError("The directory handle is closed.")

    def _verify_binding(self) -> None:
        if self.parent_descriptor is None:
            return
        assert self.name is not None
        try:
            opened = os.fstat(self.descriptor)
            if os.name == "nt":
                named = self.path.lstat()
            else:
                named = os.stat(
                    self.name,
                    dir_fd=self.parent_descriptor,
                    follow_symlinks=False,
                )
            _validate_directory_info(opened)
            _validate_directory_info(named)
            _require_same_object(opened, named)
        except FileNotFoundError:
            raise
        except SafePathError:
            raise
        except Exception as error:
            raise SafePathError("The directory entry changed during traversal.") from error


def local_absolute_path(value: str | Path, *, base: Path | None = None) -> Path:
    text = str(value)
    if not text or "\x00" in text or any(ord(character) < 32 for character in text):
        raise SafePathError("The path is not a safe local path.")
    if os.name == "nt" and _windows_text_is_nonlocal(text):
        raise SafePathError("The path is not a safe local path.")
    candidate = Path(text)
    if not candidate.is_absolute():
        candidate = (base or Path.cwd()) / candidate
    absolute = Path(os.path.abspath(candidate))
    if os.name == "nt" and _windows_path_is_remote(absolute):
        raise SafePathError("The path is not a safe local path.")
    return absolute


@contextmanager
def hold_directory_nofollow(path: Path) -> Iterator[Path]:
    absolute = local_absolute_path(path)
    held = _open_directory_chain(absolute)
    try:
        yield absolute
        _verify_directory_chain(held)
    finally:
        _close_directory_chain(held)


@contextmanager
def open_directory_handle_nofollow(path: Path) -> Iterator[SafeDirectoryHandle]:
    absolute = local_absolute_path(path)
    held = _open_directory_chain(absolute)
    leaf = held.pop()
    parent_descriptor: int | None = None
    try:
        if leaf.parent_descriptor is not None:
            parent_descriptor = os.dup(leaf.parent_descriptor)
        handle = SafeDirectoryHandle(
            leaf.path,
            leaf.descriptor,
            parent_descriptor=parent_descriptor,
            name=leaf.name,
        )
    except Exception:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        os.close(leaf.descriptor)
        _close_directory_chain(held)
        raise
    _close_directory_chain(held)
    try:
        yield handle
    finally:
        handle.close()


@contextmanager
def iterate_directory_nofollow(path: Path) -> Iterator[Iterator[SafeDirectoryEntry]]:
    with open_directory_handle_nofollow(path) as directory:
        with directory.entries() as iterator:
            yield iterator


@contextmanager
def open_regular_file_nofollow(path: Path) -> Iterator[BinaryIO]:
    absolute = local_absolute_path(path)
    held = _open_directory_chain(absolute.parent)
    descriptor: int | None = None
    handle: BinaryIO | None = None
    try:
        descriptor = _open_file(absolute, held[-1].descriptor)
        _verify_regular_file(absolute, descriptor, held[-1].descriptor)
        handle = os.fdopen(descriptor, "rb")
        descriptor = None
        yield handle
        _verify_regular_file(absolute, handle.fileno(), held[-1].descriptor)
        _verify_directory_chain(held)
    finally:
        if handle is not None:
            handle.close()
        elif descriptor is not None:
            os.close(descriptor)
        _close_directory_chain(held)


def read_text_file_nofollow(path: Path, *, max_bytes: int) -> str:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    with open_regular_file_nofollow(path) as handle:
        encoded = handle.read(max_bytes + 1)
    if len(encoded) > max_bytes:
        raise SafePathError("The file exceeds its safety limit.")
    try:
        return encoded.decode("utf-8", "strict")
    except UnicodeError as error:
        raise SafePathError("The file is not valid UTF-8.") from error


def verify_regular_file_nofollow(path: Path) -> None:
    with open_regular_file_nofollow(path):
        pass


def _open_directory_chain(path: Path) -> list[_HeldDirectory]:
    parts = path.parts
    if not parts:
        raise SafePathError("The directory path is invalid.")
    held: list[_HeldDirectory] = []
    candidate = Path(parts[0])
    try:
        descriptor = _open_directory(candidate, None, None)
        held.append(_HeldDirectory(candidate, descriptor, None, None))
        for name in parts[1:]:
            parent = held[-1]
            candidate /= name
            descriptor = _open_directory(candidate, parent.descriptor, name)
            held.append(_HeldDirectory(candidate, descriptor, parent.descriptor, name))
        _verify_directory_chain(held)
        return held
    except Exception:
        _close_directory_chain(held)
        raise


def _open_directory(path: Path, parent_descriptor: int | None, name: str | None) -> int:
    descriptor: int | None = None
    try:
        if os.name == "nt":
            descriptor = _windows_open(path, directory=True)
        elif parent_descriptor is None:
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
        else:
            assert name is not None
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
        _validate_directory_info(os.fstat(descriptor))
        return descriptor
    except FileNotFoundError:
        raise
    except Exception as error:
        if descriptor is not None:
            os.close(descriptor)
        raise SafePathError("The directory path is unsafe.") from error


def _open_file(path: Path, parent_descriptor: int) -> int:
    try:
        if os.name == "nt":
            return _windows_open(path, directory=False)
        return os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
    except FileNotFoundError:
        raise
    except Exception as error:
        raise SafePathError("The file path is unsafe.") from error


def _verify_directory_chain(held: list[_HeldDirectory]) -> None:
    try:
        for item in held:
            opened = os.fstat(item.descriptor)
            _validate_directory_info(opened)
            if os.name == "nt" or item.parent_descriptor is None:
                named = item.path.lstat()
            else:
                assert item.name is not None
                named = os.stat(item.name, dir_fd=item.parent_descriptor, follow_symlinks=False)
            _validate_directory_info(named)
            _require_same_object(opened, named)
    except FileNotFoundError:
        raise
    except SafePathError:
        raise
    except Exception as error:
        raise SafePathError("The directory path changed during validation.") from error


def _verify_regular_file(path: Path, descriptor: int, parent_descriptor: int) -> None:
    try:
        opened = os.fstat(descriptor)
        if os.name == "nt":
            named = path.lstat()
        else:
            named = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        _validate_regular_info(opened)
        _validate_regular_info(named)
        _require_same_object(opened, named)
    except FileNotFoundError:
        raise
    except SafePathError:
        raise
    except Exception as error:
        raise SafePathError("The file path changed during validation.") from error


def _validate_directory_info(info: os.stat_result) -> None:
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise SafePathError("The directory path is unsafe.")


def _validate_regular_info(info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or _is_reparse(info)
        or info.st_nlink != 1
    ):
        raise SafePathError("The file path is unsafe.")


def _require_same_object(opened: os.stat_result, named: os.stat_result) -> None:
    if opened.st_dev != named.st_dev or opened.st_ino != named.st_ino:
        raise SafePathError("The path changed during validation.")


def _close_directory_chain(held: list[_HeldDirectory]) -> None:
    for item in reversed(held):
        try:
            os.close(item.descriptor)
        except OSError:
            pass


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _directory_entries(directory: _HeldDirectory) -> Iterator[SafeDirectoryEntry]:
    if os.name == "nt":
        yield from _windows_directory_entries(directory.descriptor)
        return
    try:
        with os.scandir(directory.descriptor) as iterator:
            for entry in iterator:
                info = entry.stat(follow_symlinks=False)
                yield SafeDirectoryEntry(
                    entry.name,
                    info.st_mode,
                    _is_reparse(info),
                    info.st_dev,
                    info.st_ino,
                )
    except OSError as error:
        raise SafePathError("The directory could not be enumerated safely.") from error


if os.name == "nt":
    _GENERIC_READ = 0x80000000
    _FILE_LIST_DIRECTORY = 0x00000001
    _READ_CONTROL = 0x00020000
    _FILE_READ_ATTRIBUTES = 0x0080
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _DRIVE_REMOTE = 4

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _KERNEL32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _KERNEL32.CreateFileW.restype = wintypes.HANDLE
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = wintypes.BOOL
    _KERNEL32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    _KERNEL32.GetDriveTypeW.restype = wintypes.UINT
    _KERNEL32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    _KERNEL32.GetFileInformationByHandleEx.restype = wintypes.BOOL

    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_ID_BOTH_DIRECTORY_INFO = 10
    _FILE_ID_BOTH_DIRECTORY_RESTART_INFO = 11
    _ERROR_NO_MORE_FILES = 18
    _WINDOWS_DIRECTORY_BUFFER_BYTES = 64 * 1024
    _WINDOWS_DIRECTORY_ATTRIBUTES_OFFSET = 56
    _WINDOWS_DIRECTORY_NAME_LENGTH_OFFSET = 60
    _WINDOWS_DIRECTORY_FILE_ID_OFFSET = 96
    _WINDOWS_DIRECTORY_NAME_OFFSET = 104


def _windows_open(path: Path, *, directory: bool) -> int:
    access = (
        _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _READ_CONTROL
        if directory
        else _GENERIC_READ | _READ_CONTROL
    )
    flags = _FILE_FLAG_OPEN_REPARSE_POINT | (_FILE_FLAG_BACKUP_SEMANTICS if directory else _FILE_ATTRIBUTE_NORMAL)
    handle = _KERNEL32.CreateFileW(
        _windows_path(path),
        access,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        if error in {2, 3}:
            raise FileNotFoundError(path)
        raise ctypes.WinError(error)
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        _KERNEL32.CloseHandle(handle)
        raise


def _windows_directory_entries(descriptor: int) -> Iterator[SafeDirectoryEntry]:
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(descriptor))
    first = True
    while True:
        buffer = ctypes.create_string_buffer(_WINDOWS_DIRECTORY_BUFFER_BYTES)
        info_class = (
            _FILE_ID_BOTH_DIRECTORY_RESTART_INFO
            if first
            else _FILE_ID_BOTH_DIRECTORY_INFO
        )
        if not _KERNEL32.GetFileInformationByHandleEx(
            handle,
            info_class,
            buffer,
            len(buffer),
        ):
            error = ctypes.get_last_error()
            if error == _ERROR_NO_MORE_FILES:
                return
            raise SafePathError("The directory could not be enumerated safely.") from ctypes.WinError(error)
        first = False
        offset = 0
        while True:
            next_offset = int.from_bytes(buffer[offset : offset + 4], "little")
            attributes = int.from_bytes(
                buffer[
                    offset + _WINDOWS_DIRECTORY_ATTRIBUTES_OFFSET :
                    offset + _WINDOWS_DIRECTORY_ATTRIBUTES_OFFSET + 4
                ],
                "little",
            )
            name_length = int.from_bytes(
                buffer[
                    offset + _WINDOWS_DIRECTORY_NAME_LENGTH_OFFSET :
                    offset + _WINDOWS_DIRECTORY_NAME_LENGTH_OFFSET + 4
                ],
                "little",
            )
            name_start = offset + _WINDOWS_DIRECTORY_NAME_OFFSET
            name = bytes(buffer[name_start : name_start + name_length]).decode("utf-16-le", "strict")
            file_id = int.from_bytes(
                buffer[
                    offset + _WINDOWS_DIRECTORY_FILE_ID_OFFSET :
                    offset + _WINDOWS_DIRECTORY_FILE_ID_OFFSET + 8
                ],
                "little",
            )
            if name not in {".", ".."}:
                mode = stat.S_IFDIR if attributes & _FILE_ATTRIBUTE_DIRECTORY else stat.S_IFREG
                yield SafeDirectoryEntry(
                    name,
                    mode,
                    bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT),
                    None,
                    file_id,
                )
            if next_offset == 0:
                break
            offset += next_offset


def _windows_path(path: Path) -> str:
    value = str(path.absolute())
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    if not value.startswith("\\\\?\\"):
        return "\\\\?\\" + value
    return value


def _windows_text_is_nonlocal(value: str) -> bool:
    normalized = value.replace("/", "\\")
    lowered = normalized.lower()
    if normalized.startswith("\\\\") or lowered.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")):
        return True
    drive, tail = os.path.splitdrive(normalized)
    return bool(drive and tail and not tail.startswith("\\"))


def _windows_path_is_remote(path: Path) -> bool:
    drive, _tail = os.path.splitdrive(str(path))
    if not drive:
        return True
    root = drive + "\\"
    return int(_KERNEL32.GetDriveTypeW(root)) == _DRIVE_REMOTE
