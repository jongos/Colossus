"""Narrow Win32 helpers extracted from repository_cleanup.py and hardened.

No repository ZIP workflow or generic Colossus cleanup policy is imported.
"""
import ctypes
from ctypes import wintypes as w
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re

MAX_CONTROL = 1024 * 1024


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def path_check(value):
    require(os.name == "nt", "Windows NTFS only")
    require(isinstance(value, (str, Path)), "path must be text")
    raw = str(value)
    require(bool(re.match(r"^[A-Za-z]:\\", raw)), "absolute local drive path required")
    require("/" not in raw, "use exact native path separators")
    parts = raw[3:].split("\\") if len(raw) > 3 else []
    for part in parts:
        require(part not in ("", ".", "..") and not part.endswith((" ", ".")),
                "noncanonical path component")
        require(not any(ord(c) < 32 or c in ':*?<>|"~' for c in part), "unsafe path component")
        require(not re.fullmatch(r"(?i)(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?", part),
                "reserved path component")
    return Path(raw)


class Info(ctypes.Structure):
    _fields_ = [("attrs", w.DWORD), ("created", w.FILETIME), ("accessed", w.FILETIME),
                ("modified", w.FILETIME), ("volume", w.DWORD), ("high", w.DWORD),
                ("low", w.DWORD), ("links", w.DWORD), ("index_high", w.DWORD), ("index_low", w.DWORD)]


class Standard(ctypes.Structure):
    _fields_ = [("allocated", ctypes.c_longlong), ("end", ctypes.c_longlong),
                ("links", w.DWORD), ("pending", w.BOOLEAN), ("directory", w.BOOLEAN)]


class FileId(ctypes.Structure):
    _fields_ = [("volume", ctypes.c_ulonglong), ("identifier", ctypes.c_ubyte * 16)]


def api():
    require(os.name == "nt", "Windows NTFS only")
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    k.CreateFileW.restype = w.HANDLE
    k.CloseHandle.argtypes = [w.HANDLE]
    k.GetFileInformationByHandle.argtypes = [w.HANDLE, ctypes.POINTER(Info)]
    k.GetFileInformationByHandleEx.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
    k.SetFileInformationByHandle.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
    k.ReadFile.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p]
    k.SetFilePointerEx.argtypes = [w.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), w.DWORD]
    k.GetVolumeInformationByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD, ctypes.POINTER(w.DWORD),
                                               ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD), w.LPWSTR, w.DWORD]
    k.GetDriveTypeW.argtypes = [w.LPCWSTR]
    k.GetDriveTypeW.restype = w.DWORD
    k.GetFinalPathNameByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD]
    k.GetFinalPathNameByHandleW.restype = w.DWORD
    return k


class Handle:
    def __init__(self, path, *, exclusive=False, delete=False, deny_write=False):
        self.path = path_check(path)
        self.k = api()
        self.handle = self.k.CreateFileW(str(self.path), 0x80000000 | (0x10000 if delete else 0),
                                         0 if exclusive else (1 if deny_write else 3),
                                         None, 3, 0x02000000 | 0x00200000, None)
        if self.handle == w.HANDLE(-1).value:
            self.handle = None
            raise OSError(ctypes.get_last_error(), "native open refused")
        try:
            s = self.stat()
            require(not s["attrs"] & (0x400 | 0x1000 | 0x40000 | 0x400000),
                    "reparse/offline/recall path refused")
            buf = ctypes.create_unicode_buffer(32768)
            length = self.k.GetFinalPathNameByHandleW(self.handle, buf, len(buf), 0)
            require(0 < length < len(buf), "canonical path unavailable")
            require(buf.value.removeprefix("\\\\?\\").casefold() == str(self.path).casefold(),
                    "native path alias refused")
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.handle is not None:
            handle, self.handle = self.handle, None
            require(self.k.CloseHandle(handle), "native close failed; outcome uncertain")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def stat(self):
        i, s, fid = Info(), Standard(), FileId()
        for ok in (self.k.GetFileInformationByHandle(self.handle, ctypes.byref(i)),
                   self.k.GetFileInformationByHandleEx(self.handle, 1, ctypes.byref(s), ctypes.sizeof(s)),
                   self.k.GetFileInformationByHandleEx(self.handle, 18, ctypes.byref(fid), ctypes.sizeof(fid))):
            if not ok:
                raise OSError(ctypes.get_last_error(), "native metadata refused")
        require(not s.pending, "delete-pending file refused")
        return {"identity": f"{fid.volume:016x}:{bytes(fid.identifier).hex()}", "volume": fid.volume,
                "bytes": s.end, "allocated": s.allocated, "links": s.links, "directory": bool(s.directory),
                "modified": (i.modified.dwHighDateTime << 32) | i.modified.dwLowDateTime, "attrs": i.attrs}

    def ntfs(self):
        require(self.k.GetDriveTypeW(self.path.anchor) in (2, 3, 6), "remote or unknown drive refused")
        name = ctypes.create_unicode_buffer(32)
        require(self.k.GetVolumeInformationByHandleW(self.handle, None, 0, None, None, None, name, 32)
                and name.value == "NTFS", "local NTFS required")

    def chunks(self, limit):
        require(self.k.SetFilePointerEx(self.handle, 0, None, 0), "rewind failed")
        count, buf = 0, ctypes.create_string_buffer(65536)
        while True:
            got = w.DWORD()
            require(self.k.ReadFile(self.handle, buf, len(buf), ctypes.byref(got), None), "native read failed")
            if not got.value:
                break
            count += got.value
            require(count <= limit, "read limit exceeded")
            yield buf.raw[:got.value]

    def fingerprint(self, limit):
        before, h, count = self.stat(), hashlib.sha256(), 0
        for data in self.chunks(limit):
            h.update(data)
            count += len(data)
        require(before == self.stat() and count == before["bytes"], "file changed during hash")
        return h.hexdigest()

    def remove(self):
        flag = w.BOOL(1)
        require(self.k.SetFileInformationByHandle(self.handle, 4, ctypes.byref(flag), ctypes.sizeof(flag)),
                "native disposition failed")


def pin_ancestors(stack, path):
    result = []
    for p in reversed([path, *path.parents]):
        h = stack.enter_context(Handle(p))
        h.ntfs()
        require(h.stat()["directory"], "ancestor must be directory")
        result.append(h)
    return result


def read_control(path):
    path = path_check(path)
    with ExitStack() as stack:
        pin_ancestors(stack, path.parent)
        h = stack.enter_context(Handle(path, deny_write=True))
        h.ntfs()
        before = h.stat()
        require(not before["directory"] and before["links"] == 1 and before["bytes"] <= MAX_CONTROL,
                "control file type/link/size refused")
        raw = b"".join(h.chunks(MAX_CONTROL))
        require(h.stat() == before, "control file changed")
        return raw.decode("utf-8-sig")


def new_output(path, root):
    path, root, stack = path_check(path), path_check(root), ExitStack()
    try:
        require(not path.is_relative_to(root), "control output must be outside root")
        parents = pin_ancestors(stack, path.parent)
        h = stack.enter_context(Handle(root))
        h.ntfs()
        require(h.stat()["identity"] not in [p.stat()["identity"] for p in parents], "output aliases root")
        import msvcrt
        k = api()
        raw = k.CreateFileW(str(path), 0x80000000 | 0x40000000, 0, None, 1, 0x00200000, None)
        if raw == w.HANDLE(-1).value:
            raise OSError(ctypes.get_last_error(), "exclusive new control file refused")
        try:
            fd = msvcrt.open_osfhandle(int(raw), os.O_RDWR | os.O_BINARY)
        except BaseException:
            k.CloseHandle(raw)
            raise
        f = stack.enter_context(os.fdopen(fd, "w", encoding="utf-8", newline="\n"))
        return stack, f
    except BaseException:
        stack.close()
        raise
