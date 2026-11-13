"""Keep remembered SSH passwords in the current Windows user's vault."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from functools import lru_cache
import os
import re
from uuid import uuid4


_GENERIC = 1
_LOCAL_MACHINE = 2  # Persists for this user on this computer without roaming.
_NOT_FOUND = 1168
_MAX_BLOB_BYTES = 2560
_TARGET_PREFIX = "VPS Ops/SSH/"
_ID_PATTERN = re.compile(r"[0-9a-f]{32}")


class CredentialError(RuntimeError):
    """A credential operation failed without exposing password data."""


class _Credential(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


_CredentialPointer = ctypes.POINTER(_Credential)


@lru_cache(maxsize=1)
def _vault():
    if os.name != "nt":
        raise CredentialError("当前系统不支持在 Windows 凭据管理器中保存密码。")
    try:
        api = ctypes.WinDLL("advapi32.dll", use_last_error=True)
        api.CredWriteW.argtypes = [_CredentialPointer, wintypes.DWORD]
        api.CredWriteW.restype = wintypes.BOOL
        api.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(_CredentialPointer)]
        api.CredReadW.restype = wintypes.BOOL
        api.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        api.CredDeleteW.restype = wintypes.BOOL
        api.CredFree.argtypes = [ctypes.c_void_p]
        api.CredFree.restype = None
    except (AttributeError, OSError):
        raise CredentialError("无法访问 Windows 凭据管理器。") from None
    return api


def available() -> bool:
    try:
        _vault()
    except CredentialError:
        return False
    return True


def validate_password(password: str) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("请输入 SSH 密码。")
    max_units = _MAX_BLOB_BYTES // 2
    if len(password) > max_units or len(password) + sum(ord(char) > 0xFFFF for char in password) > max_units:
        raise ValueError("SSH 密码过长。")
    if any(char == "\x00" or 0xD800 <= ord(char) <= 0xDFFF for char in password):
        raise ValueError("SSH 密码包含无效字符。")
    return password


def _target(credential_id: str) -> str:
    if not isinstance(credential_id, str) or not _ID_PATTERN.fullmatch(credential_id):
        raise CredentialError("已保存的 SSH 密码引用无效，请重新输入密码。")
    return _TARGET_PREFIX + credential_id


def save_password(password: str) -> str:
    validate_password(password)
    api = _vault()
    credential_id = uuid4().hex
    encoded = bytearray(password, "utf-16-le")
    blob = (ctypes.c_ubyte * len(encoded)).from_buffer(encoded)
    try:
        credential = _Credential(
            Type=_GENERIC,
            TargetName=_target(credential_id),
            Comment="Constellation Ops SSH password",
            CredentialBlobSize=len(encoded),
            CredentialBlob=blob,
            Persist=_LOCAL_MACHINE,
        )
        if not api.CredWriteW(ctypes.byref(credential), 0):
            raise CredentialError("无法将 SSH 密码保存到 Windows 凭据管理器。")
    finally:
        ctypes.memset(blob, 0, len(encoded))
    return credential_id


def read_password(credential_id: str) -> str | None:
    target = _target(credential_id)
    api = _vault()
    pointer = _CredentialPointer()
    if not api.CredReadW(target, _GENERIC, 0, ctypes.byref(pointer)):
        if ctypes.get_last_error() == _NOT_FOUND:
            return None
        raise CredentialError("无法从 Windows 凭据管理器读取 SSH 密码。")
    try:
        credential = pointer.contents
        size = credential.CredentialBlobSize
        if not 0 < size <= _MAX_BLOB_BYTES or size % 2 or not credential.CredentialBlob:
            raise CredentialError("已保存的 SSH 密码无法读取，请重新输入密码。")
        encoded = bytearray(size)
        blob = (ctypes.c_ubyte * size).from_buffer(encoded)
        try:
            ctypes.memmove(blob, credential.CredentialBlob, size)
            return validate_password(encoded.decode("utf-16-le"))
        except ValueError:
            raise CredentialError("已保存的 SSH 密码无法读取，请重新输入密码。") from None
        finally:
            ctypes.memset(blob, 0, size)
    finally:
        api.CredFree(pointer)


def delete_password(credential_id: str) -> None:
    target = _target(credential_id)
    api = _vault()
    if not api.CredDeleteW(target, _GENERIC, 0) and ctypes.get_last_error() != _NOT_FOUND:
        raise CredentialError("无法从 Windows 凭据管理器移除 SSH 密码。")
