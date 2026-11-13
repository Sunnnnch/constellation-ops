"""Run local ICMP, TCP and HTTP probes attached to saved VPS devices."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPException
from ipaddress import ip_address
from pathlib import Path
from threading import Timer
from time import monotonic, time
from urllib.parse import quote, urlsplit
from uuid import uuid4
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys

from dashboard_history import utc_string
from dashboard_password_ssh import remaining, resolve, stop_socket


TIMEOUT = 5
MAX_WORKERS = 4
MAX_PER_HOST = 8
MAX_PROBES = 100
MAX_HISTORY = 96
MAX_TARGET_LENGTH = 512
MIN_INTERVAL = 30
MAX_INTERVAL = 3600
SOURCE = "local"
KINDS = {"icmp", "tcp", "http"}
HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
PING_TIME = re.compile(rb"([=<])\s*(\d+(?:[.,]\d+)?)\s*ms\b", re.IGNORECASE)


def normalize_hostname(value):
    value = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    if "%" in value:
        raise ValueError("请输入不带接口标识的 IP 地址，或填写域名。")
    try:
        return str(ip_address(value))
    except ValueError:
        pass
    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("探测目标的域名无效。") from None
    labels = ascii_host.removesuffix(".").split(".")
    if len(ascii_host) > 253 or any(not HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("请输入有效的域名或 IP 地址。")
    return ascii_host.lower()


def http_target(value):
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise ValueError("HTTP 探测地址无效。") from None
    if (parts.scheme not in ("http", "https") or not parts.hostname or "@" in parts.netloc
            or "#" in value or "\\" in value or port == 0):
        raise ValueError("请输入 HTTP 或 HTTPS 地址，地址中不能含登录凭据或片段。")
    hostname = normalize_hostname(parts.hostname)
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        authority += f":{port}"
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="/?%:@!$&'()*+,;=-._~")
    return parts.scheme, hostname, port, authority, path + (f"?{query}" if query else "")


def validate_config(config):
    if not isinstance(config, dict) or set(config) - {"name", "type", "target", "port", "interval_seconds", "enabled"}:
        raise ValueError("网络探针配置无效。")
    name = config.get("name")
    kind = config.get("type")
    target = config.get("target")
    port = config.get("port")
    interval = config.get("interval_seconds", 60)
    enabled = config.get("enabled", True)
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or not name.isprintable():
        raise ValueError("请输入 1–80 个字符的探针名称。")
    if not isinstance(kind, str) or kind not in KINDS:
        raise ValueError("请选择 ICMP、TCP 或 HTTP(S) 探针。")
    if (not isinstance(target, str) or not 1 <= len(target.strip()) <= MAX_TARGET_LENGTH
            or any(char.isspace() or not char.isprintable() for char in target.strip())):
        raise ValueError("探测地址无效。")
    target = target.strip()
    if kind == "http":
        scheme, _, _, authority, request = http_target(target)
        target = f"{scheme}://{authority}{request}"
        if len(target) > MAX_TARGET_LENGTH:
            raise ValueError("HTTP 探测地址过长。")
    else:
        target = normalize_hostname(target)
    if kind == "tcp":
        port = 80 if port is None else port
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("TCP 端口应在 1–65535 之间。")
    else:
        port = None
    if type(interval) is not int or not MIN_INTERVAL <= interval <= MAX_INTERVAL:
        raise ValueError(f"探测间隔应在 {MIN_INTERVAL}–{MAX_INTERVAL} 秒之间。")
    if type(enabled) is not bool:
        raise ValueError("探针启用状态无效。")
    return {"name": name.strip(), "type": kind, "target": target, "port": port,
            "interval_seconds": interval, "enabled": enabled}


def connect(hostname, port, deadline):
    last_error = OSError("No usable addresses")
    for family, kind, protocol, _, address in resolve(hostname, port, deadline):
        try:
            connection = socket.socket(family, kind, protocol)
        except OSError as error:
            last_error = error
            continue
        started = monotonic()
        try:
            connection.settimeout(remaining(deadline))
            connection.connect(address)
            return connection, round((monotonic() - started) * 1000, 2)
        except OSError as error:
            last_error = error
            connection.close()
    raise last_error


def probe_result(status, message, latency=None, http_status=None):
    return {"ok": status == "ok", "status": status, "latency_ms": latency,
            "checked_at": utc_string(datetime.now(timezone.utc)), "message": message, "http_status": http_status}


def probe_http(target, deadline):
    scheme, host, port, authority, request = http_target(target)
    port = port or (443 if scheme == "https" else 80)
    started = monotonic()
    connection, _ = connect(host, port, deadline)
    with closing(HTTPConnection(host, port)) as client:
        client.sock = connection
        if scheme == "https":
            context = ssl.create_default_context()
            connection.settimeout(remaining(deadline))
            client.sock = context.wrap_socket(connection, server_hostname=host.removesuffix("."))
        client.sock.settimeout(remaining(deadline))
        # Stop the header read at the total deadline even if the server drips bytes.
        watchdog = Timer(remaining(deadline), stop_socket, args=(client.sock,))
        watchdog.daemon = True
        watchdog.start()
        try:
            client.request("GET", request, headers={"Host": authority, "Connection": "close",
                                                   "User-Agent": "VPS-Ops-Probe"})
            with client.getresponse() as response:
                code = response.status
                elapsed = round((monotonic() - started) * 1000, 2)
        finally:
            watchdog.cancel()
    status = "ok" if 200 <= code < 400 else "http_error"
    return probe_result(status, f"HTTP {code}", elapsed, code)


def probe_icmp(target, deadline):
    addresses = resolve(target, 0, deadline)
    if not addresses:
        raise socket.gaierror
    # Prefer IPv4 for a dual-stack hostname, and keep the family of literal addresses.
    address = next((item for item in addresses if item[0] == socket.AF_INET), addresses[0])
    family, _, _, _, endpoint = address
    if os.name == "nt":
        binary = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "PING.EXE"
        executable = str(binary) if binary.is_file() else None
        options = ["-n", "1", "-w", str(max(1, int(remaining(deadline) * 1000))),
                   "-6" if family == socket.AF_INET6 else "-4"]
    else:
        executable = shutil.which("ping6" if sys.platform in ("darwin", "freebsd") and family == socket.AF_INET6 else "ping")
        options = ["-n", "-c", "1"]
        if sys.platform.startswith("linux") and family == socket.AF_INET6:
            options.append("-6")
    if not executable:
        return probe_result("unavailable", "本机缺少系统 ping 程序。")
    result = subprocess.run(
        [executable, *options, endpoint[0]], stdin=subprocess.DEVNULL, capture_output=True, timeout=remaining(deadline),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    # Windows can return exit code 0 for an ICMP destination-unreachable reply.
    match = PING_TIME.search(result.stdout)
    if match is None:
        if result.returncode == 2 or result.stderr:
            return probe_result("unavailable", "系统 ping 无法运行，请检查本机 ICMP 权限。")
        return probe_result("unreachable", "未收到 ICMP 回显应答。")
    latency = float(match[2].replace(b",", b"."))
    message = f"往返时间 < {latency:g} ms" if match[1] == b"<" else "收到 ICMP 回显应答。"
    return probe_result("ok", message, latency)


def execute_probe(config):
    deadline = monotonic() + TIMEOUT
    try:
        if config["type"] == "icmp":
            return probe_icmp(config["target"], deadline)
        if config["type"] == "http":
            return probe_http(config["target"], deadline)
        connection, elapsed = connect(config["target"], config["port"], deadline)
        connection.close()
        return probe_result("ok", "TCP 端口可连接。", elapsed)
    except socket.gaierror:
        return probe_result("dns_error", "无法解析探测目标。")
    except ConnectionRefusedError:
        return probe_result("refused", "目标拒绝连接。")
    except (TimeoutError, subprocess.TimeoutExpired):
        return probe_result("timeout", "探测超时。")
    except ssl.SSLError:
        return probe_result("tls_error", "TLS 握手或证书验证失败。")
    except HTTPException:
        if monotonic() >= deadline:
            return probe_result("timeout", "探测超时。")
        return probe_result("http_error", "目标未返回有效的 HTTP 响应。")
    except OSError:
        if monotonic() >= deadline:
            return probe_result("timeout", "探测超时。")
        return probe_result("unreachable", "目标不可达，或连接已断开。")


class ProbeStore:
    """Persist per-device probe definitions and bounded recent observations."""

    def __init__(self, database, lock):
        self.db = database
        self.lock = lock
        self.workers = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="vps-network-probe")
        self.pending = set()
        self.closed = False
        with self.lock, self.db:
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS network_probes (
                    id TEXT PRIMARY KEY, host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                    revision TEXT NOT NULL, config TEXT NOT NULL, enabled INTEGER NOT NULL,
                    due REAL NOT NULL DEFAULT 0, lease TEXT, lease_until REAL NOT NULL DEFAULT 0
                )
            """)
            self.db.execute("CREATE INDEX IF NOT EXISTS network_probes_host ON network_probes(host_id)")
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS network_probe_results (
                    id INTEGER PRIMARY KEY, probe_id TEXT NOT NULL REFERENCES network_probes(id) ON DELETE CASCADE,
                    data TEXT NOT NULL
                )
            """)
            self.db.execute("CREATE INDEX IF NOT EXISTS network_probe_results_probe ON network_probe_results(probe_id, id)")

    def require_host(self, host_id):
        if not isinstance(host_id, str) or not self.db.execute("SELECT 1 FROM hosts WHERE id=?", (host_id,)).fetchone():
            raise KeyError(host_id)

    def list(self, host_id):
        with self.lock:
            self.require_host(host_id)
            rows = self.db.execute("""
                SELECT probe.id, probe.config, probe.lease_until,
                       (SELECT data FROM network_probe_results WHERE probe_id=probe.id ORDER BY id DESC LIMIT 1)
                FROM network_probes AS probe WHERE probe.host_id=? ORDER BY probe.rowid
            """, (host_id,))
            now = time()
            return {"source": SOURCE, "probes": [
                {"id": probe_id, **json.loads(config), "latest": json.loads(latest) if latest else None,
                 "running": lease_until > now}
                for probe_id, config, lease_until, latest in rows
            ]}

    def save(self, host_id, config, probe_id=None):
        config = validate_config(config)
        data = json.dumps(config, ensure_ascii=False)
        revision = uuid4().hex
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self.require_host(host_id)
            if probe_id is None:
                count = self.db.execute("SELECT count(*) FROM network_probes WHERE host_id=?", (host_id,)).fetchone()[0]
                if count >= MAX_PER_HOST:
                    raise ValueError(f"每台设备最多可配置 {MAX_PER_HOST} 个网络探针。")
                if self.db.execute("SELECT count(*) FROM network_probes").fetchone()[0] >= MAX_PROBES:
                    raise ValueError(f"面板最多可配置 {MAX_PROBES} 个网络探针。")
                probe_id = uuid4().hex
                self.db.execute("INSERT INTO network_probes (id,host_id,revision,config,enabled) VALUES (?,?,?,?,?)",
                                (probe_id, host_id, revision, data, config["enabled"]))
            else:
                previous = self.db.execute("SELECT config FROM network_probes WHERE host_id=? AND id=?",
                                           (host_id, probe_id)).fetchone()
                if previous is None:
                    raise KeyError(probe_id)
                previous = json.loads(previous[0])
                self.db.execute("""
                    UPDATE network_probes SET revision=?,config=?,enabled=?,due=0,lease=NULL,lease_until=0
                    WHERE host_id=? AND id=?
                """, (revision, data, config["enabled"], host_id, probe_id))
                if any(previous[key] != config[key] for key in ("type", "target", "port")):
                    self.db.execute("DELETE FROM network_probe_results WHERE probe_id=?", (probe_id,))
        return {"id": probe_id}

    def delete(self, host_id, probe_id):
        with self.lock, self.db:
            deleted = self.db.execute("DELETE FROM network_probes WHERE host_id=? AND id=?", (host_id, probe_id))
            if not deleted.rowcount:
                raise KeyError(probe_id)
        return {}

    def history(self, host_id, probe_id):
        with self.lock:
            if not self.db.execute("SELECT 1 FROM network_probes WHERE host_id=? AND id=?", (host_id, probe_id)).fetchone():
                raise KeyError(probe_id)
            rows = self.db.execute("SELECT data FROM network_probe_results WHERE probe_id=? ORDER BY id", (probe_id,))
            return {"source": SOURCE, "points": [json.loads(row[0]) for row in rows]}

    def run(self, host_id, probe_id):
        with self.lock:
            row = self.db.execute("SELECT id,revision,config FROM network_probes WHERE host_id=? AND id=?",
                                  (host_id, probe_id)).fetchone()
            if row is None:
                raise KeyError(probe_id)
            return {"queued": self.queue(row, force=True)}

    def refresh(self, host_id=None):
        with self.lock:
            if self.closed or len(self.pending) >= MAX_WORKERS:
                return
            now = time()
            rows = self.db.execute("""
                SELECT id,revision,config FROM network_probes
                WHERE enabled=1 AND due<=? AND lease_until<=? AND (? IS NULL OR host_id=?)
                ORDER BY due,id
            """, (now, now, host_id, host_id)).fetchall()
            for row in rows:
                if len(self.pending) >= MAX_WORKERS:
                    break
                self.queue(row)

    def queue(self, row, *, force=False):
        probe_id, revision, data = row
        if self.closed or probe_id in self.pending or len(self.pending) >= MAX_WORKERS:
            return False
        config = json.loads(data)
        now = time()
        lease = uuid4().hex
        with self.db:
            claimed = self.db.execute("""
                UPDATE network_probes SET due=?,lease=?,lease_until=?
                WHERE id=? AND revision=? AND lease_until<=? AND (? OR (enabled=1 AND due<=?))
            """, (now + config["interval_seconds"], lease, now + TIMEOUT * 3,
                  probe_id, revision, now, force, now))
        if not claimed.rowcount:
            return False
        self.pending.add(probe_id)
        self.workers.submit(self.record, probe_id, revision, lease, config)
        return True

    def record(self, probe_id, revision, lease, config):
        try:
            result = execute_probe(config)
        except Exception:
            result = probe_result("unavailable", "本机未能完成网络探测。")
        with self.lock:
            try:
                with self.db:
                    released = self.db.execute("""
                        UPDATE network_probes SET lease=NULL,lease_until=0
                        WHERE id=? AND revision=? AND lease=?
                    """, (probe_id, revision, lease))
                    if not released.rowcount:
                        return
                    self.db.execute("INSERT INTO network_probe_results (probe_id,data) VALUES (?,?)",
                                    (probe_id, json.dumps(result, ensure_ascii=False)))
                    self.db.execute("""
                        DELETE FROM network_probe_results WHERE probe_id=? AND id IN
                        (SELECT id FROM network_probe_results WHERE probe_id=? ORDER BY id DESC LIMIT -1 OFFSET ?)
                    """, (probe_id, probe_id, MAX_HISTORY))
            finally:
                self.pending.discard(probe_id)

    def shutdown(self):
        with self.lock:
            self.closed = True
        self.workers.shutdown(wait=True)
