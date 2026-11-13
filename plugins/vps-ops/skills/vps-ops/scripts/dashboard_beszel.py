"""Read systems and measurements from the PocketBase API used by Beszel."""

from datetime import datetime, timedelta, timezone
from http.client import HTTPException
from ipaddress import ip_address
import json
import re
from threading import Lock
from time import monotonic
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


TIMEOUT = 4
MAX_BYTES = 2 * 1024 * 1024
SESSION_SECONDS = 300
RECORD_ID = re.compile(r"[a-z0-9]{15}")
SYSTEM_FIELDS = "id,name,status,info,updated"


def record_id(value):
    return value if isinstance(value, str) and RECORD_ID.fullmatch(value) else None


def secure_endpoint(endpoint):
    url = urlsplit(endpoint)
    if url.scheme == "https":
        return True
    if url.scheme == "http":
        try:
            return ip_address(url.hostname).is_loopback
        except ValueError:
            pass
    return False


def validate_credentials(value):
    if not isinstance(value, dict) or set(value) != {"identity", "password"}:
        raise ValueError("请输入 Beszel 账号和密码。")
    identity, password = value["identity"], value["password"]
    if (not isinstance(identity, str) or not isinstance(password, str) or not identity.strip()
            or not password or len(identity) > 254 or len(password) > 512
            or any(char == "\x00" or 0xD800 <= ord(char) <= 0xDFFF for char in identity + password)):
        raise ValueError("Beszel 账号或密码格式无效。")
    return {"identity": identity.strip(), "password": password}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _Unauthorized(ValueError):
    pass


def _request(endpoint, path, *, token=None, data=None, query=None):
    if not secure_endpoint(endpoint):
        raise ValueError("Beszel 地址须使用 HTTPS。本机回环 IP 可使用 HTTP。")
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = token
    if data is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(data).encode("utf-8")
    url = endpoint + path
    if query:
        url += "?" + urlencode(query)
    request = Request(url, data=data, headers=headers)
    try:
        with build_opener(ProxyHandler({}), _NoRedirect()).open(request, timeout=TIMEOUT) as response:
            raw = response.read(MAX_BYTES + 1)
    except HTTPError as error:
        if 300 <= error.code < 400:
            raise ValueError("Beszel 返回了重定向，请填写最终的 HTTPS 地址。") from None
        if error.code == 401 and data is None:
            raise _Unauthorized("Beszel 会话已失效，请重新检查连接。") from None
        if data is not None and error.code in (400, 401, 403):
            raise ValueError("Beszel 登录失败，请检查账号、密码和登录方式。") from None
        if error.code == 403:
            raise ValueError("Beszel 拒绝访问，请检查该账号的设备读取权限。") from None
        raise ValueError(f"Beszel 接口返回 HTTP {error.code}。") from None
    except (URLError, OSError, HTTPException, ValueError):
        raise ValueError("无法连接 Beszel，请检查地址、网络和 TLS 证书。") from None
    if len(raw) > MAX_BYTES:
        raise ValueError("Beszel 返回的数据超过读取限制。")
    try:
        result = json.loads(raw)
    except (UnicodeError, RecursionError, ValueError):
        raise ValueError("Beszel 返回的接口格式无效。") from None
    if not isinstance(result, dict):
        raise ValueError("Beszel 返回的接口格式无效。")
    return result


def authenticate(endpoint, credentials):
    result = _request(endpoint, "/api/collections/users/auth-with-password", data=credentials)
    token = result.get("token")
    if not isinstance(token, str) or not re.fullmatch(r"[\x21-\x7e]{1,4096}", token):
        raise ValueError("Beszel 返回的登录会话无效。")
    return token


class BeszelSession:
    def __init__(self):
        self.lock = Lock()
        self.key = None
        self.token = None
        self.expires = 0

    def _token(self, key, read_credentials, rejected=None):
        with self.lock:
            if (self.key != key or self.token is None or monotonic() >= self.expires
                    or self.token == rejected):
                self.token = authenticate(key[0], read_credentials())
                self.key = key
                self.expires = monotonic() + SESSION_SECONDS
            return self.token

    def read(self, config, read_credentials, operation, *args):
        token = self._token(config, read_credentials)
        try:
            return operation(config[0], token, *args)
        except _Unauthorized:
            return operation(config[0], self._token(config, read_credentials, token), *args)


def _records(endpoint, token, collection, fields, *, filter_by="", sort="", per_page=100, max_pages=1):
    query = {"fields": fields, "perPage": per_page, "skipTotal": "true"}
    if filter_by:
        query["filter"] = filter_by
    if sort:
        query["sort"] = sort
    for page in range(1, max_pages + 1):
        query["page"] = page
        result = _request(endpoint, f"/api/collections/{collection}/records", token=token, query=query)
        items = result.get("items")
        if not isinstance(items, list) or len(items) > per_page:
            raise ValueError("Beszel 返回的记录列表格式无效。")
        yield from (item for item in items if isinstance(item, dict))
        if len(items) < per_page:
            return


def systems(endpoint, token, ids=None):
    if ids is None:
        return list(_records(endpoint, token, "systems", SYSTEM_FIELDS, sort="name,id", max_pages=10))
    ids = [value for value in ids if record_id(value)]
    records = []
    for offset in range(0, len(ids), 40):
        filters = " || ".join(f'id = "{value}"' for value in ids[offset:offset + 40])
        records.extend(_records(endpoint, token, "systems", SYSTEM_FIELDS, filter_by=filters))
    return records


def history(endpoint, token, system_id):
    if not record_id(system_id):
        raise ValueError("请选择有效的 Beszel 节点。")
    now = datetime.now(timezone.utc)
    # Match Beszel's retention windows, leaving denser measurements near the present.
    windows = (
        ("1m", now - timedelta(hours=1), now),
        ("10m", now - timedelta(hours=12), now - timedelta(hours=1)),
        ("20m", now - timedelta(hours=24), now - timedelta(hours=12)),
    )
    ranges = " || ".join(
        f'(type = "{interval}" && created >= "{start:%Y-%m-%d %H:%M:%S}.000Z"'
        f' && created < "{end:%Y-%m-%d %H:%M:%S}.000Z")'
        for interval, start, end in windows
    )
    filters = f'system = "{system_id}" && ({ranges})'
    return list(_records(endpoint, token, "system_stats", "system,created,stats",
                         filter_by=filters, sort="-created,id", per_page=50, max_pages=4))
