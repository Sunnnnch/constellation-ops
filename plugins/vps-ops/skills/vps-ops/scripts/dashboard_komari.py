"""Manage VPS bindings and read status from Komari or Beszel."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.client import HTTPException
from ipaddress import ip_address
import json
from math import isfinite
import re
from time import monotonic
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

import dashboard_beszel as beszel
from dashboard_credentials import CredentialError, delete_password, read_password, save_password


TIMEOUT = 4
REFRESH_INTERVAL = 20
MAX_BYTES = 1_048_576
MAX_NODES = 1000
MAX_HISTORY = 240
METHODS = frozenset(("common:getNodes", "common:getNodesLatestStatus", "common:getRecords"))
PROVIDERS = {"komari": "Komari", "beszel": "Beszel"}


def endpoint_url(value, provider="Komari"):
    if not isinstance(value, str) or len(value) > 400:
        raise ValueError(f"请输入有效的 {provider} 地址。")
    value = value.strip()
    if not value or any(character.isspace() or not character.isprintable() for character in value):
        raise ValueError(f"请输入有效的 {provider} 地址。")
    try:
        url = urlsplit(value)
        host = url.hostname
        port = url.port
        path = url.path.rstrip("/")
        if provider == "Komari" and path.endswith("/api/rpc2"):
            path = path.removesuffix("/api/rpc2")
        if (not host or url.username is not None or url.password is not None or "?" in value or "#" in value
                or url.scheme not in ("https", "http") or not re.fullmatch(r"(?:/[A-Za-z0-9._~-]+)*", path)
                or any(part in (".", "..") for part in path.split("/")) or port == 0):
            raise ValueError
        try:
            address = ip_address(host)
            if "%" in host:
                raise ValueError
            host = "[" + str(address) + "]" if address.version == 6 else str(address)
            local = address.is_loopback
        except ValueError:
            host = host.encode("idna").decode("ascii")
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
                raise ValueError
            local = host == "localhost"
    except (ValueError, UnicodeError):
        raise ValueError(f"请输入有效的 {provider} 地址，且地址内不要包含账号、令牌或查询参数。") from None
    default_port = 443 if url.scheme == "https" else 80
    authority = host if port is None or port == default_port else f"{host}:{port}"
    endpoint = urlunsplit((url.scheme, authority, path, "", ""))
    if provider == "Beszel":
        if not beszel.secure_endpoint(endpoint):
            raise ValueError("Beszel 地址须使用 HTTPS。本机回环 IP 可使用 HTTP。")
    elif url.scheme != "https" and not local:
        raise ValueError("Komari 地址须使用 HTTPS。本机回环地址可使用 HTTP。")
    return endpoint


def valid_token(token):
    if token is not None and (not isinstance(token, str) or not re.fullmatch(r"[\x21-\x7e]{1,512}", token)):
        raise ValueError("Komari 令牌格式无效。")
    return token


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_rpc(endpoint, token, method, params=None):
    if method not in METHODS:
        raise ValueError("Komari 接口仅支持读取监控数据。")
    if token and not endpoint.startswith("https://"):
        raise ValueError("发送 Komari 令牌需要 HTTPS 地址。")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode("utf-8")
    request = Request(endpoint + "/api/rpc2", data=payload, headers=headers)
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=TIMEOUT) as response:
            raw = response.read(MAX_BYTES + 1)
    except HTTPError as error:
        if 300 <= error.code < 400:
            raise ValueError("Komari 返回了重定向，请填写最终的 HTTPS 地址。") from None
        if error.code in (401, 403):
            raise ValueError("Komari 拒绝访问，请检查站点权限和 API 令牌。") from None
        raise ValueError(f"Komari 接口返回 HTTP {error.code}。") from None
    except (URLError, OSError, HTTPException, ValueError):
        raise ValueError("无法连接 Komari，请检查地址、网络和 TLS 证书。") from None
    if len(raw) > MAX_BYTES:
        raise ValueError("Komari 返回的数据超过读取限制。")
    try:
        result = json.loads(raw)
    except (UnicodeError, RecursionError, ValueError):
        raise ValueError("Komari 返回的接口格式无效。") from None
    if not isinstance(result, dict) or result.get("jsonrpc") != "2.0" or result.get("id") != 1:
        raise ValueError("Komari 返回的接口格式无效。")
    if "error" in result:
        raise ValueError("Komari 拒绝读取监控数据，请检查接口版本、站点权限和令牌。")
    if "result" not in result:
        raise ValueError("Komari 返回的接口格式无效。")
    return result["result"]


def normalized_uuid(value):
    try:
        return str(UUID(value)) if isinstance(value, str) and len(value) == 36 else None
    except ValueError:
        return None


def clean_label(value, fallback=""):
    if not isinstance(value, str):
        return fallback
    return "".join(char for char in value[:160] if char.isprintable()).strip() or fallback


def node_list(result):
    if not isinstance(result, (dict, list)):
        raise ValueError("Komari 返回的节点列表格式无效。")
    pairs = result.items() if isinstance(result, dict) else ((None, node) for node in result)
    nodes = {}
    for key, node in pairs:
        if not isinstance(node, dict):
            continue
        uuid = normalized_uuid(node.get("uuid", key))
        if uuid and len(nodes) < MAX_NODES:
            nodes[uuid] = {"uuid": uuid, "name": clean_label(node.get("name"), uuid),
                           "group": clean_label(node.get("group"))}
    return sorted(nodes.values(), key=lambda node: (node["group"], node["name"], node["uuid"]))


def number(value, maximum=(1 << 53) - 1):
    return value if type(value) in (int, float) and 0 <= value <= maximum and isfinite(value) else None


def date_stamp(value):
    if not isinstance(value, str) or len(value) > 45:
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if timestamp.tzinfo is not None and timestamp.year >= 2000:
            return timestamp.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (ValueError, OverflowError):
        pass
    return None


def summarize_status(record):
    if not isinstance(record, dict):
        return {}
    online = record.get("online")
    return {
        "online": online if type(online) is bool else None,
        "cpu_pct": number(record.get("cpu"), 100),
        "memory_used": number(record.get("ram")), "memory_total": number(record.get("ram_total")),
        "disk_used": number(record.get("disk")), "disk_total": number(record.get("disk_total")),
        "rx_bps": number(record.get("net_in")), "tx_bps": number(record.get("net_out")),
        "checked_at": date_stamp(record.get("time")),
    }


def load_records(raw, uuid):
    if not isinstance(raw, dict):
        return []
    records = raw.get("records")
    if isinstance(records, dict):
        records = records.get(uuid)
    if not isinstance(records, list):
        return []
    output = []
    for row in records[:MAX_HISTORY]:
        if not isinstance(row, dict) or ("client" in row and normalized_uuid(row["client"]) != uuid):
            continue
        when = date_stamp(row.get("time"))
        if not when:
            continue
        point = summarize_status(row)
        output.append({"time": when, "cpu_pct": point["cpu_pct"], "memory_used": point["memory_used"],
                       "memory_total": point["memory_total"], "disk_used": point["disk_used"],
                       "disk_total": point["disk_total"]})
    return sorted(output, key=lambda row: row["time"])


def ping_records(raw, uuid):
    if not isinstance(raw, dict) or not isinstance(raw.get("records"), list):
        return []
    tasks = raw.get("tasks")
    tasks = {task["id"]: task for task in tasks if isinstance(task, dict) and type(task.get("id")) is int} if isinstance(tasks, list) else {}
    series = {}
    for row in raw["records"][:MAX_HISTORY]:
        if not isinstance(row, dict) or ("client" in row and normalized_uuid(row["client"]) != uuid):
            continue
        task_id, when = row.get("task_id"), date_stamp(row.get("time"))
        if type(task_id) is not int or task_id <= 0 or not when:
            continue
        task = tasks.get(task_id, {})
        if task_id not in series:
            name = clean_label(task.get("name"), f"任务 {task_id}")
            kind = clean_label(task.get("type")).upper()
            series[task_id] = {"id": task_id, "carrier": str(task_id),
                               "label": f"{name} · {kind}" if kind else name,
                               "interval_seconds": number(task.get("interval"), 86400), "points": []}
        series[task_id]["points"].append({"checked_at": when, "latency_ms": number(row.get("value"))})
    return list(series.values())


def beszel_nodes(rows):
    nodes = {}
    for row in rows:
        uuid = beszel.record_id(row.get("id"))
        if uuid:
            nodes[uuid] = {"uuid": uuid, "name": clean_label(row.get("name"), uuid), "group": ""}
    return sorted(nodes.values(), key=lambda node: (node["name"], node["uuid"]))


def beszel_status(row):
    info = row.get("info")
    info = info if isinstance(info, dict) else {}
    status = row.get("status")
    return {
        "online": True if status == "up" else False if status == "down" else None,
        "cpu_pct": number(info.get("cpu"), 100),
        "memory_pct": number(info.get("mp"), 100),
        "disk_pct": number(info.get("dp"), 100),
        "checked_at": date_stamp(row.get("updated")),
    }


def beszel_load(rows, uuid):
    def gibibytes(value):
        value = number(value, ((1 << 53) - 1) / (1 << 30))
        return round(value * (1 << 30)) if value is not None else None

    result = {}
    for row in rows:
        stats = row.get("stats")
        stamp = date_stamp(row.get("created"))
        if row.get("system") != uuid or not stamp or not isinstance(stats, dict):
            continue
        memory = stats.get("mem")
        if isinstance(memory, list) and len(memory) >= 2:
            memory_total, memory_used = number(memory[0]), number(memory[1])
        else:
            memory_total, memory_used = gibibytes(stats.get("m")), gibibytes(stats.get("mu"))
        result[stamp] = {
            "time": stamp, "cpu_pct": number(stats.get("cpu"), 100),
            "memory_pct": number(stats.get("mp"), 100),
            "memory_used": memory_used, "memory_total": memory_total,
            "disk_pct": number(stats.get("dp"), 100),
            "disk_used": gibibytes(stats.get("du")), "disk_total": gibibytes(stats.get("d")),
        }
    return [result[stamp] for stamp in sorted(result)]


def discard_token(credential):
    if credential:
        try:
            delete_password(credential)
        except CredentialError:
            pass


class _ProviderMonitor:
    def __init__(self, db, lock, provider):
        self.db = db
        self.lock = lock
        self.provider = provider
        self.name = PROVIDERS[provider]
        self.settings_table = f"{provider}_settings"
        self.bindings_table = f"{provider}_bindings"
        self.other_bindings_table = "komari_bindings" if provider == "beszel" else "beszel_bindings"
        self.beszel = beszel.BeszelSession() if provider == "beszel" else None
        self.worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"vps-{provider}")
        self.pending = None
        self.next_refresh = 0
        self.cache_config = None
        self.cached_status = {}
        self.stale = False
        self.closed = False
        with lock, db:
            db.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.settings_table} (
                    id INTEGER PRIMARY KEY CHECK(id=1), endpoint TEXT NOT NULL, credential TEXT
                )
            """)
            db.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.bindings_table} (
                    host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
                    endpoint TEXT NOT NULL, node_uuid TEXT NOT NULL, name TEXT NOT NULL
                )
            """)

    def _config(self):
        return self.db.execute(f"SELECT endpoint, credential FROM {self.settings_table} WHERE id=1").fetchone()

    def _bindings(self, endpoint):
        rows = self.db.execute(f"SELECT host_id, node_uuid, name FROM {self.bindings_table} WHERE endpoint=?", (endpoint,))
        return {host: {"uuid": uuid, "name": name} for host, uuid, name in rows}

    def _read_token(self, credential):
        if not credential:
            if self.beszel:
                raise ValueError("请输入 Beszel 账号和密码。")
            return None
        try:
            token = read_password(credential)
            if not token:
                raise CredentialError
            if self.beszel:
                return beszel.validate_credentials(json.loads(token))
            return valid_token(token)
        except (CredentialError, RecursionError, ValueError):
            raise ValueError(f"无法读取本机保存的 {self.name} 凭据，请重新输入。") from None

    def _draft_token(self, body, envelope):
        if "token_box" not in body:
            return None
        context = {"host": body["endpoint"], "username": "", "port": None, "auth_mode": self.provider,
                   "known_hosts": "", "password_box": body["token_box"]}
        try:
            if self.beszel:
                return beszel.validate_credentials(envelope.decrypt_json(context, self.provider))
            return valid_token(envelope.decrypt(context, "komari"))
        except ValueError:
            raise ValueError(f"无法读取加密的 {self.name} 凭据，请重新输入。") from None

    def _config_view(self, config):
        if not config:
            return {"provider": self.provider, "endpoint": "", "token_saved": False, "bindings": {}}
        endpoint, credential = config
        return {"provider": self.provider, "endpoint": endpoint, "token_saved": bool(credential),
                "bindings": self._bindings(endpoint)}

    def _beszel_read(self, config, operation, *args):
        return self.beszel.read(tuple(config), lambda: self._read_token(config[1]), operation, *args)

    def _refresh(self, config, uuids):
        if self.beszel:
            requested = set(uuids)
            rows = self._beszel_read(config, beszel.systems, uuids)
            statuses = {row["id"]: beszel_status(row) for row in rows
                        if beszel.record_id(row.get("id")) in requested}
            return {uuid: statuses.get(uuid, {}) for uuid in uuids}
        result = read_rpc(config[0], self._read_token(config[1]), "common:getNodesLatestStatus", {"uuids": uuids})
        if not isinstance(result, dict):
            raise ValueError("Komari 返回的节点状态格式无效。")
        return {uuid: summarize_status(result.get(uuid)) for uuid in uuids}

    def snapshot(self):
        with self.lock:
            config = self._config()
            if self.cache_config != config:
                self.cache_config = config
                self.cached_status = {}
                self.next_refresh = 0
                self.stale = False
            if self.pending is not None and self.pending[1].done():
                requested, future = self.pending
                self.pending = None
                if requested == config:
                    try:
                        self.cached_status.update(future.result())
                        self.stale = False
                    except ValueError:
                        self.stale = True
            if not config:
                return {}
            bindings = self._bindings(config[0])
            uuids = sorted({binding["uuid"] for binding in bindings.values()})
            now = monotonic()
            if uuids and not self.closed and self.pending is None and now >= self.next_refresh:
                self.next_refresh = now + REFRESH_INTERVAL
                self.pending = (config, self.worker.submit(self._refresh, config, uuids))
            return {host: {**binding, **self.cached_status.get(binding["uuid"], {}), "stale": self.stale,
                           "provider": self.provider}
                    for host, binding in bindings.items()}

    def request(self, body, envelope):
        actions = {
            "state": (set(), set()),
            "test": ({"endpoint"}, {"token_box", "forget_token"}),
            "save": ({"endpoint"}, {"token_box", "forget_token"}),
            "bind": ({"host_id", "node_uuid"}, set()),
            "history": ({"host_id"}, set()),
        }
        action = body.get("action")
        if not isinstance(action, str) or action not in actions:
            raise ValueError(f"{self.name} 操作无效。")
        required, optional = actions[action]
        fields = body.keys() - {"action"}
        if not required <= fields <= required | optional:
            raise ValueError(f"{self.name} 请求参数无效。")
        with self.lock:
            config = self._config()
            if action == "state":
                return self._config_view(config)
        if action in ("test", "save"):
            return self._configure(action, body, envelope, config)
        if not config:
            raise ValueError(f"请先保存 {self.name} 地址。")
        host = body["host_id"]
        if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,80}", host):
            raise ValueError("请选择 VPS 设备。")
        if action == "bind":
            return self._bind(config, host, body["node_uuid"])
        return self._history(config, host)

    def _configure(self, action, body, envelope, config):
        endpoint = endpoint_url(body["endpoint"], self.name)
        forget = body.get("forget_token", False)
        if type(forget) is not bool or (forget and "token_box" in body):
            raise ValueError(f"{self.name} 凭据选项无效。")
        token = self._draft_token(body, envelope)
        credential = config[1] if config and config[0] == endpoint and not forget else None
        if self.beszel:
            if token:
                nodes = beszel_nodes(beszel.systems(endpoint, beszel.authenticate(endpoint, token)))
            elif forget and action == "save":
                nodes = []
            else:
                nodes = beszel_nodes(self._beszel_read((endpoint, credential), beszel.systems))
        else:
            nodes = node_list(read_rpc(endpoint, token or self._read_token(credential), "common:getNodes"))
        if action == "test":
            return {"provider": self.provider, "endpoint": endpoint, "nodes": nodes}
        if token:
            value = json.dumps(token, ensure_ascii=False, separators=(",", ":")) if self.beszel else token
            try:
                new_credential = save_password(value)
            except (CredentialError, ValueError):
                raise ValueError(f"无法将 {self.name} 凭据保存到 Windows 凭据管理器。") from None
        else:
            new_credential = credential
        try:
            with self.lock, self.db:
                self.db.execute("BEGIN IMMEDIATE")
                if self._config() != config:
                    raise ValueError(f"{self.name} 设置已在另一面板修改，请重新打开设置。")
                self.db.execute(f"""
                    INSERT INTO {self.settings_table} (id, endpoint, credential) VALUES (1, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET endpoint=excluded.endpoint, credential=excluded.credential
                """, (endpoint, new_credential))
                result = self._config_view((endpoint, new_credential))
        except Exception:
            if token:
                discard_token(new_credential)
            raise
        if config and config[1] != new_credential:
            discard_token(config[1])
        return {**result, "nodes": nodes}

    def _bind(self, config, host, target):
        node = None
        if target is not None:
            uuid = beszel.record_id(target) if self.beszel else normalized_uuid(target)
            if uuid is None:
                raise ValueError(f"请选择有效的 {self.name} 节点。")
            if self.beszel:
                rows = self._beszel_read(config, beszel.systems, [uuid])
                result = next((row for row in rows if row.get("id") == uuid), None)
            else:
                result = read_rpc(config[0], self._read_token(config[1]), "common:getNodes", {"uuid": uuid})
                if not isinstance(result, dict) or normalized_uuid(result.get("uuid")) != uuid:
                    result = None
            if result is None:
                raise ValueError(f"无法读取所选的 {self.name} 节点。")
            node = (uuid, clean_label(result.get("name"), uuid))
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if self._config() != config:
                raise ValueError(f"{self.name} 设置已变更，请重新打开面板。")
            if not self.db.execute("SELECT 1 FROM hosts WHERE id=?", (host,)).fetchone():
                raise KeyError(host)
            if node:
                self.db.execute(f"""
                    INSERT INTO {self.bindings_table} (host_id, endpoint, node_uuid, name) VALUES (?, ?, ?, ?)
                    ON CONFLICT(host_id) DO UPDATE SET endpoint=excluded.endpoint, node_uuid=excluded.node_uuid, name=excluded.name
                """, (host, config[0], *node))
                self.db.execute(f"DELETE FROM {self.other_bindings_table} WHERE host_id=?", (host,))
            else:
                self.db.execute(f"DELETE FROM {self.bindings_table} WHERE host_id=?", (host,))
            self.next_refresh = 0
            return self._config_view(config)

    def _history(self, config, host):
        with self.lock:
            binding = self._bindings(config[0]).get(host)
        if not binding:
            raise ValueError(f"请先为这台 VPS 绑定 {self.name} 节点。")
        uuid = binding["uuid"]
        result = {**binding, "provider": self.provider, "load": [], "ping": [], "errors": {}}
        if self.beszel:
            try:
                raw = self._beszel_read(config, beszel.history, uuid)
                result["load"] = beszel_load(raw, uuid)
            except ValueError as error:
                result["errors"]["load"] = str(error)
            return result
        token = self._read_token(config[1])
        for kind, hours, decoder in (("load", 24, load_records), ("ping", 1, ping_records)):
            try:
                raw = read_rpc(config[0], token, "common:getRecords", {
                    "type": kind, "uuid": uuid, "hours": hours, "maxCount": MAX_HISTORY,
                })
                result[kind] = decoder(raw, uuid)
            except ValueError as error:
                result["errors"][kind] = str(error)
        return result

    def shutdown(self):
        with self.lock:
            self.closed = True
        self.worker.shutdown(wait=False, cancel_futures=True)


class KomariMonitor:
    """Keep the dashboard's existing monitor interface and Komari defaults."""

    def __init__(self, db, lock):
        self.providers = {provider: _ProviderMonitor(db, lock, provider) for provider in PROVIDERS}

    def snapshot(self):
        snapshots = {}
        for monitor in self.providers.values():
            snapshots.update(monitor.snapshot())
        return snapshots

    def request(self, body, envelope):
        provider = body.get("provider", "komari")
        if not isinstance(provider, str) or provider not in self.providers:
            raise ValueError("请选择有效的监控服务。")
        return self.providers[provider].request({key: value for key, value in body.items() if key != "provider"}, envelope)

    def shutdown(self):
        for monitor in self.providers.values():
            monitor.shutdown()
