"""Encrypt portable sync archives and store them in a WebDAV folder."""

from base64 import b64encode
from http.client import HTTPException, HTTPSConnection
from ipaddress import IPv6Address
import json
from secrets import token_bytes
import re
import ssl
from time import monotonic
from urllib.parse import quote, unquote, urlsplit
from xml.etree import ElementTree

from dashboard_password_crypto import prepare_password_dependencies


ARCHIVE_FILENAME = "vps-ops-sync.v1.enc"
DEDICATED_FOLDER_NAME = "VPS-Ops"
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MIN_PASSPHRASE_LENGTH = 12
MAX_PASSPHRASE_LENGTH = 512
REQUEST_TIMEOUT = 12
FOLDER_RESPONSE_LIMIT = 64 * 1024
MAGIC = b"VPSOPS-SYNC\x01"
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
HEADER_BYTES = len(MAGIC) + SALT_BYTES + NONCE_BYTES
DAV_NAMESPACE = "{DAV:}"
PROPFIND_BODY = b'<?xml version="1.0"?><propfind xmlns="DAV:"><prop><resourcetype/></prop></propfind>'


class WebDAVError(ValueError):
    """An expected archive or WebDAV error safe to display."""


class WebDAVConflict(WebDAVError):
    """The remote backup changed or was created by another client."""


def _passphrase_bytes(passphrase):
    if not isinstance(passphrase, str) or not MIN_PASSPHRASE_LENGTH <= len(passphrase) <= MAX_PASSPHRASE_LENGTH:
        raise WebDAVError(f"同步密码须为 {MIN_PASSPHRASE_LENGTH} 至 {MAX_PASSPHRASE_LENGTH} 个字符。")
    try:
        return passphrase.encode("utf-8")
    except UnicodeEncodeError:
        raise WebDAVError("同步密码包含无效字符。") from None


def _crypto():
    prepare_password_dependencies()
    try:
        from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except (ImportError, OSError):
        raise WebDAVError("本机缺少星图加密组件，请先安装 SSH 依赖。") from None
    return AESGCM, Scrypt, InvalidTag, UnsupportedAlgorithm


def _archive_bytes(data):
    if not isinstance(data, bytes) or not HEADER_BYTES + TAG_BYTES <= len(data) <= MAX_ARCHIVE_BYTES:
        raise WebDAVError("同步备份大小不受支持。")
    if not data.startswith(MAGIC):
        raise WebDAVError("星图无法读取此加密备份格式。")
    return data


def encrypt_archive(payload, passphrase):
    """Return the versioned binary envelope. No settings appear in its header."""
    secret = _passphrase_bytes(passphrase)
    if not isinstance(payload, dict):
        raise WebDAVError("同步设置格式无效。")
    try:
        plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise WebDAVError("同步设置格式无效。") from None
    if len(plaintext) > MAX_ARCHIVE_BYTES - HEADER_BYTES - TAG_BYTES:
        raise WebDAVError("同步备份超过 10 MiB，请减少同步的私钥文件。")
    aes_gcm, scrypt, _, unsupported = _crypto()
    salt, nonce = token_bytes(SALT_BYTES), token_bytes(NONCE_BYTES)
    header = MAGIC + salt + nonce
    try:
        # Version 1 fixes the work factor at 128 MiB, with fresh salt and nonce per archive.
        key = scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(secret)
        return header + aes_gcm(key).encrypt(nonce, plaintext, header)
    except (MemoryError, unsupported):
        raise WebDAVError("本机无法运行同步加密，请检查可用内存及星图加密组件。") from None


def _invalid_constant(_value):
    raise ValueError("Non-finite JSON number")


def decrypt_archive(data, passphrase):
    """Authenticate before parsing. A wrong password and ciphertext tampering both fail closed."""
    secret = _passphrase_bytes(passphrase)
    data = _archive_bytes(data)
    aes_gcm, scrypt, invalid_tag, unsupported = _crypto()
    salt = data[len(MAGIC):len(MAGIC) + SALT_BYTES]
    nonce = data[len(MAGIC) + SALT_BYTES:HEADER_BYTES]
    try:
        key = scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(secret)
        plaintext = aes_gcm(key).decrypt(nonce, data[HEADER_BYTES:], data[:HEADER_BYTES])
    except invalid_tag:
        raise WebDAVError("同步密码不匹配，或远端备份已损坏。") from None
    except (MemoryError, unsupported):
        raise WebDAVError("本机无法运行同步解密，请检查可用内存及星图加密组件。") from None
    try:
        payload = json.loads(plaintext.decode("utf-8"), parse_constant=_invalid_constant)
    except (ValueError, RecursionError):
        raise WebDAVError("解密后的同步设置格式无效。") from None
    if not isinstance(payload, dict):
        raise WebDAVError("解密后的同步设置格式无效。")
    return payload


def _folder_url(value):
    message = "请输入 WebDAV 文件夹的 HTTPS 地址，认证信息请单独填写。"
    if not isinstance(value, str) or not 1 <= len(value) <= 2048 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise WebDAVError(message)
    value = value.strip()
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None
                or "?" in value or "#" in value or "\\" in value):
            raise ValueError
        host = parsed.hostname
        if ":" in host:
            if "%" in host:
                raise ValueError
            host = IPv6Address(host).compressed
        else:
            host = host.encode("idna").decode("ascii")
            if not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", host):
                raise ValueError
        port = parsed.port
        if port == 0:
            raise ValueError
        path = parsed.path.strip("/")
        parts = []
        if path:
            for segment in path.split("/"):
                if re.search(r"%(?![0-9a-fA-F]{2})", segment):
                    raise ValueError
                decoded = unquote(segment, encoding="utf-8", errors="strict")
                if (not decoded or decoded in (".", "..") or "/" in decoded or "\\" in decoded
                        or re.search(r"%[0-9a-fA-F]{2}", decoded)
                        or any(ord(char) < 32 or ord(char) == 127 for char in decoded)):
                    raise ValueError
                parts.append(quote(decoded, safe=""))
        folder = "/" + "/".join(parts) + ("/" if parts else "")
        return host, 443 if port is None else port, folder
    except (ValueError, UnicodeError):
        raise WebDAVError(message) from None


def _authorization(username, password):
    if not isinstance(username, str) or not isinstance(password, str) or len(username) > 256 or len(password) > 512:
        raise WebDAVError("WebDAV 账号或密码格式无效。")
    if not username and not password:
        return None
    if not username or ":" in username or any(ord(char) < 32 or ord(char) == 127 for char in username + password):
        raise WebDAVError("WebDAV 账号或密码格式无效。")
    try:
        return "Basic " + b64encode((username + ":" + password).encode("utf-8")).decode("ascii")
    except UnicodeEncodeError:
        raise WebDAVError("WebDAV 账号或密码格式无效。") from None


def _strong_etag(value):
    if not isinstance(value, str) or len(value) > 1024 or not re.fullmatch(r'"[\x21\x23-\x7e\x80-\xff]*"', value):
        return None
    return value


def _response_etag(headers):
    values = headers.get_all("ETag", [])
    return _strong_etag(values[0].strip()) if len(values) == 1 else None


def _read_bounded(response, limit, deadline, connection_socket):
    length = response.length
    if length is not None and length > limit:
        raise WebDAVError("WebDAV 返回的文件超出大小限制。")
    result = bytearray()
    while True:
        if response.length == 0:
            return bytes(result)
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError
        if connection_socket is not None:
            connection_socket.settimeout(remaining)
        chunk = response.read1(min(64 * 1024, limit + 1 - len(result)))
        if not chunk:
            if response.length not in (None, 0):
                raise WebDAVError("WebDAV 返回的文件不完整，请重试。")
            return bytes(result)
        result.extend(chunk)
        if len(result) > limit:
            raise WebDAVError("WebDAV 返回的文件超出大小限制。")


def _is_collection(body):
    try:
        encoding = "utf-16" if body.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        xml = body.decode(encoding)
        if "<!DOCTYPE" in xml or "<!ENTITY" in xml or "\x00" in xml:
            return False
        root = ElementTree.fromstring(xml)
    except (UnicodeError, ElementTree.ParseError):
        return False
    return root.find(".//" + DAV_NAMESPACE + "resourcetype/" + DAV_NAMESPACE + "collection") is not None


class WebDAV:
    """Access only the fixed archive and its containing HTTPS WebDAV folder."""

    def __init__(self, folder_url, username="", password="", *, dedicated_folder=False):
        if type(dedicated_folder) is not bool:
            raise WebDAVError("WebDAV 专用文件夹选项无效。")
        self._host, self._port, self._base_folder = _folder_url(folder_url)
        self._dedicated_folder = dedicated_folder
        self._folder = self._base_folder + DEDICATED_FOLDER_NAME + "/" if dedicated_folder else self._base_folder
        self._authorization = _authorization(username, password)

    def _request(self, method, path, *, body=None, headers=None, expected, read_limit=0):
        request_headers = {"Accept-Encoding": "identity", "Connection": "close", **(headers or {})}
        if self._authorization:
            request_headers["Authorization"] = self._authorization
        connection = HTTPSConnection(self._host, port=self._port, timeout=REQUEST_TIMEOUT, context=ssl.create_default_context())
        deadline = monotonic() + REQUEST_TIMEOUT
        try:
            connection.request(method, path, body=body, headers=request_headers)
            connection_socket = connection.sock
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError
            if connection_socket is not None:
                connection_socket.settimeout(remaining)
            with connection.getresponse() as response:
                if response.status not in expected:
                    self._status_error(response.status, method)
                if not read_limit or response.status == 404:
                    return response.status, response.headers, b""
                encoding = response.headers.get("Content-Encoding", "").strip().lower()
                if encoding not in ("", "identity"):
                    raise WebDAVError("WebDAV 返回了不受支持的压缩编码。")
                result = _read_bounded(response, read_limit, deadline, connection_socket)
                return response.status, response.headers, result
        except ssl.SSLCertVerificationError:
            raise WebDAVError("无法验证 WebDAV 的 HTTPS 证书。请检查地址及本机信任的证书。") from None
        except TimeoutError:
            raise WebDAVError("连接 WebDAV 超时，请检查地址和网络。") from None
        except (OSError, HTTPException):
            raise WebDAVError("无法连接 WebDAV，请检查地址、网络及 HTTPS 服务。") from None
        finally:
            connection.close()

    @staticmethod
    def _status_error(status, method):
        if method == "PUT" and status in (412, 428):
            raise WebDAVConflict("远端备份已变更，请重新读取并预览后再同步。")
        if status in (401, 403):
            raise WebDAVError("WebDAV 账号、密码或目录权限有误。")
        if 300 <= status < 400:
            raise WebDAVError("WebDAV 返回了重定向，请填写最终的 HTTPS 文件夹地址。")
        if status in (404, 409):
            if method == "MKCOL":
                raise WebDAVError("WebDAV 上级文件夹不存在，请填写已经存在的文件夹地址。")
            raise WebDAVError("WebDAV 文件夹不存在，请先在服务器上创建。")
        if status in (405, 501):
            raise WebDAVError("此地址不支持所需的 WebDAV 操作。")
        if status == 423:
            raise WebDAVError("WebDAV 文件夹或备份已锁定，请稍后重试。")
        if status in (413, 507):
            raise WebDAVError("WebDAV 备份超过服务器容量限制。")
        raise WebDAVError(f"WebDAV 请求失败（HTTP {status}）。")

    def download(self):
        """Return the encrypted bytes and a strong ETag, or None for a missing archive."""
        status, headers, data = self._request(
            "GET", self._folder + ARCHIVE_FILENAME, expected=(200, 404), read_limit=MAX_ARCHIVE_BYTES,
        )
        if status == 404:
            return None
        return _archive_bytes(data), _response_etag(headers)

    def _collection_exists(self, path):
        status, _, data = self._request(
            "PROPFIND", path, body=PROPFIND_BODY,
            headers={"Depth": "0", "Content-Type": "application/xml; charset=utf-8"},
            expected=(207, 404), read_limit=FOLDER_RESPONSE_LIMIT,
        )
        if status == 404:
            return False
        if not _is_collection(data):
            raise WebDAVError("此地址未返回 WebDAV 文件夹，请核对路径。")
        return True

    def ensure_folder(self):
        """Create the fixed child collection if needed. An existing folder is reused."""
        if not self._dedicated_folder or self._collection_exists(self._folder):
            return
        status, _, _ = self._request("MKCOL", self._folder, expected=(201, 405, 409, 412))
        if status == 201 or self._collection_exists(self._folder):
            return
        if status == 412:
            raise WebDAVError("创建 WebDAV 专用文件夹失败，请检查上级文件夹的权限。")
        self._status_error(status, "MKCOL")

    def upload(self, encrypted, etag, *, create=False):
        """Create only when absent, or overwrite only the previously read version."""
        data = _archive_bytes(encrypted)
        headers = {"Content-Type": "application/octet-stream"}
        if create:
            if etag is not None:
                raise WebDAVError("首次上传不能指定已有的备份版本。")
            headers["If-None-Match"] = "*"
            self.ensure_folder()
        elif _strong_etag(etag):
            headers["If-Match"] = etag
        else:
            raise WebDAVError("WebDAV 未返回可用于核对的版本标记，无法安全覆盖现有备份。")
        _, response_headers, _ = self._request(
            "PUT", self._folder + ARCHIVE_FILENAME, body=data, headers=headers, expected=(200, 201, 204),
        )
        return _response_etag(response_headers)

    def test(self):
        """Check the folder and backup without writing or testing credentials elsewhere."""
        if not self._collection_exists(self._folder):
            if not self._dedicated_folder or not self._collection_exists(self._base_folder):
                raise WebDAVError("WebDAV 文件夹不存在，请填写已经存在的文件夹地址。")
            return {"exists": False, "can_update": True, "folder_exists": False}
        archive = self.download()
        return {"exists": archive is not None, "can_update": archive is None or archive[1] is not None,
                "folder_exists": True}
