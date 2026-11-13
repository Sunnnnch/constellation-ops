#!/usr/bin/env python3
"""Run the Constellation Ops dashboard on the local loopback interface."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
from threading import Event, RLock, Thread, Timer
from time import monotonic
from uuid import uuid4
import webbrowser

from dashboard_credentials import CredentialError, available as credential_storage_available
from dashboard_credentials import delete_password, read_password, save_password
from dashboard_history import MISSING_IDENTITY, ProbeHistory, demo_history, demo_latency_histories
from dashboard_inventory_transfer import export_inventory, import_inventory, preview_inventory
from dashboard_metrics import collect, empty_sample
from dashboard_password_crypto import PasswordEnvelope
from dashboard_password_ssh import password_diagnostic
from dashboard_password_terminal import open_password_terminal
from dashboard_probes import ProbeStore
from dashboard_terminal_sessions import TerminalSessions
from dashboard_file_jobs import FileJobs
from dashboard_files import remote_path
from dashboard_geo import DeviceGeo
from dashboard_komari import KomariMonitor
from dashboard_sync import DashboardSync
from dashboard_tunnels import TunnelManager
from dashboard_outbound_store import OutboundChecks, demo_ping_histories
from dashboard_outbound_probes import PACKETS, PACKET_OPTIONS
from dashboard_ssh import (
    AUTH_DEFAULTS, PASSWORD_ONLY, clean_text, open_terminal, test_connection, validate_connection,
)


STATIC = Path(__file__).with_name("dashboard_static")
BRAND_ICON = Path(__file__).resolve().parents[3] / "assets" / "vps-ops.png"
BRAND_ICON_URL = "/vps-ops.png"
MAX_BODY = 12_288
MAX_HOSTS = 100
MAX_TRANSFER_BODY = 512 * 1024
HISTORY_ROUTE = re.compile(r"/api/hosts/([a-zA-Z0-9-]{1,80})/history")
TERMINAL_ROUTE = re.compile(r"/api/terminal/(open|exchange|close)")
PANEL_ASSETS = {
    "/vendor/xterm.js": ("vendor/xterm.js", "text/javascript; charset=utf-8"),
    "/vendor/xterm-fit.js": ("vendor/xterm-fit.js", "text/javascript; charset=utf-8"),
    "/vendor/xterm.css": ("vendor/xterm.css", "text/css; charset=utf-8"),
    "/probes.js": ("probes.js", "text/javascript; charset=utf-8"),
    "/outbound-probes.js": ("outbound-probes.js", "text/javascript; charset=utf-8"),
    "/outbound-bulk.js": ("outbound-bulk.js", "text/javascript; charset=utf-8"),
    "/files.js": ("files.js", "text/javascript; charset=utf-8"),
    "/latency-chart.js": ("latency-chart.js", "text/javascript; charset=utf-8"),
    "/komari.js": ("komari.js", "text/javascript; charset=utf-8"),
    "/webdav.js": ("webdav.js", "text/javascript; charset=utf-8"),
    "/tunnels.js": ("tunnels.js", "text/javascript; charset=utf-8"),
    "/tunnels.css": ("tunnels.css", "text/css; charset=utf-8"),
    "/flags.css": ("flags.css", "text/css; charset=utf-8"),
}


def pending_sample():
    return {**empty_sample(), "checked_at": None}


def default_data_dir():
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "VPS Ops"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "vps-ops"


def validate_host(body):
    def clean(key, maximum, default=""):
        return clean_text(body, key, maximum, default)

    name = clean("name", 80)
    if not name:
        raise ValueError("请输入显示名称。")
    connection = validate_connection(body)
    limit = body.get("traffic_limit_gb")
    if limit is not None and (type(limit) not in (int, float) or not 0 < limit <= 1e9):
        raise ValueError("流量配额须为大于 0 的 GB 数值。")
    expires = clean("expires_on", 10)
    if expires:
        try:
            if date.fromisoformat(expires).isoformat() != expires:
                raise ValueError
        except ValueError as error:
            raise ValueError("到期日格式应为 YYYY-MM-DD。") from error
    return {
        "name": name, **connection,
        "group": clean("group", 48), "note": clean("note", 300),
        "traffic_limit_gb": limit, "expires_on": expires,
    }


class Inventory:
    def __init__(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(directory / "hosts.sqlite3", check_same_thread=False)
        self.db.execute("PRAGMA foreign_keys=ON")
        with self.db:
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS hosts (id TEXT PRIMARY KEY, revision TEXT NOT NULL, data TEXT NOT NULL)"
            )
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_preferences (
                    name TEXT PRIMARY KEY, value TEXT NOT NULL
                )
            """)

    def entries(self):
        rows = self.db.execute("SELECT id, revision, data FROM hosts ORDER BY rowid")
        return {host_id: (revision, json.loads(data)) for host_id, revision, data in rows}

    def metric_display(self):
        row = self.db.execute("SELECT value FROM dashboard_preferences WHERE name='metric_display'").fetchone()
        return "text" if row and row[0] == "text" else "gauges"

    def set_metric_display(self, mode):
        if mode not in ("gauges", "text"):
            raise ValueError("请选择仪表盘或文字显示。")
        with self.db:
            self.db.execute("""
                INSERT INTO dashboard_preferences(name, value) VALUES ('metric_display', ?)
                ON CONFLICT(name) DO UPDATE SET value=excluded.value
            """, (mode,))

    def save(self, host_id, data, *, create, expected_revision=None):
        revision = uuid4().hex
        with self.db:
            if create:
                # The count and insert share one transaction, including across separate panel processes.
                self.db.execute("BEGIN IMMEDIATE")
                if self.db.execute("SELECT count(*) FROM hosts").fetchone()[0] >= MAX_HOSTS:
                    raise ValueError(f"最多添加 {MAX_HOSTS} 台主机。")
                self.db.execute("INSERT INTO hosts VALUES (?, ?, ?)", (host_id, revision, json.dumps(data)))
            else:
                result = self.db.execute(
                    "UPDATE hosts SET revision=?, data=? WHERE id=? AND revision=?",
                    (revision, json.dumps(data), host_id, expected_revision),
                )
                if not result.rowcount:
                    raise ValueError("设备已在另一个面板中修改，请刷新后重试。")

    def remove(self, host_id):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("SELECT data FROM hosts WHERE id=?", (host_id,)).fetchone()
            if row is None:
                raise KeyError(host_id)
            self.db.execute("DELETE FROM hosts WHERE id=?", (host_id,))
            return json.loads(row[0])


def password_target(host):
    user, separator, hostname = host["host"].rpartition("@")
    return (hostname.lower(), user if separator else host.get("username", ""),
            host.get("port") or 22, host.get("known_hosts", ""))


def discard_credential(credential_id):
    if credential_id:
        try:
            delete_password(credential_id)
        except CredentialError:
            print("Constellation Ops: could not remove an unused Credential Manager entry.", file=sys.stderr)


def demo_inventory():
    gib = 1024**3
    day = datetime.now().date()
    examples = (
        ("GPU 实验节点", "gpu-lab.example", "GPU 计算", "online", 17.4, 15, 58, 18, 80, 154, 30, 18),
        ("应用服务", "app-edge.example", "应用服务", "online", 72.6, 4.9, 8, 37, 64, 81, 21, 46),
        ("备份节点", "backup.example", "存储备份", "unreachable", None, None, None, None, None, None, None, 7),
        ("研究工作站", "research.example", "GPU 计算", "auth_required", None, None, None, None, None, None, None, 92),
    )
    demo_cpus = {
        "gpu-lab.example": ("Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz", 16, 16),
        "app-edge.example": ("AMD EPYC 7B13", 8, 4),
    }
    hosts, samples = [], {}
    for index, (name, host, group, status, cpu, used, mem, disk, size, rx, tx, days) in enumerate(examples):
        host_id = f"demo-{index}"
        hosts.append({
            **AUTH_DEFAULTS, "id": host_id, "name": name, "host": host, "group": group, "port": None,
            "known_hosts": "", "note": "示例设备", "traffic_limit_gb": 500,
            "expires_on": (day + timedelta(days=days)).isoformat(),
        })
        if status == "online":
            cpu_model, cpu_logical_count, cpu_available_count = demo_cpus[host]
            gpu = [{"name": "Tesla T4", "used_mib": 6144, "total_mib": 15360,
                    "utilization_pct": 27, "temperature_c": 41}] if index == 0 else []
            samples[host_id] = {
                **empty_sample("online"), "hostname": host.split(".")[0], "uptime_seconds": 612942 + index * 136800,
                "latency_ms": 133 + index * 31, "cpu_pct": cpu, "memory_used": int(used * gib),
                "cpu_model": cpu_model, "cpu_logical_count": cpu_logical_count,
                "cpu_available_count": cpu_available_count,
                "memory_total": mem * gib, "disk_used": disk * gib, "disk_total": size * gib,
                "rx_bytes": rx * gib, "tx_bytes": tx * gib, "rx_bps": 184320 + index * 57344,
                "tx_bps": 37120 + index * 36352, "gpus": gpu,
            }
        else:
            reason = "SSH 连接超时" if status == "unreachable" else "请先在终端验证 SSH 主机指纹并配置密钥"
            samples[host_id] = empty_sample(status, reason)
    return hosts, samples


class Dashboard:
    def __init__(self, directory, interval, demo):
        self.inventory = Inventory(directory)
        self.history = ProbeHistory(self.inventory.db)
        self.password_envelope = PasswordEnvelope()
        self.interval = interval
        self.demo = demo
        self.demo_hosts, self.demo_samples = demo_inventory()
        self.lock = RLock()
        self.probes = ProbeStore(self.inventory.db, self.lock)
        self.outbound_checks = OutboundChecks(self.inventory.db, self.lock)
        self.komari = KomariMonitor(self.inventory.db, self.lock)
        self.sync = DashboardSync(self.inventory, self.lock, directory, validate_host, MAX_HOSTS, lambda: self.demo)
        self.tunnels = TunnelManager(
            self.inventory.db, self.lock, self.inventory.entries,
            self._saved_probe_credentials, self.password_envelope, is_demo=lambda: self.demo,
        )
        self.terminals = TerminalSessions()
        self.files = FileJobs()
        self.geo = DeviceGeo()
        self.stop = Event()
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="vps-probe")
        self.pending = {}
        self.latest = {}
        self.scheduler = Thread(target=self._poll, name="vps-poller", daemon=True)
        self.outbound_scheduler = Thread(target=self._poll_outbound_schedules, name="vps-outbound-poller", daemon=True)
        self.sync_scheduler = Thread(target=self._poll_sync, name="vps-webdav-sync", daemon=True)
        self.outbound_scheduler.start()
        self.sync_scheduler.start()
        if not self.demo:
            self.tunnels.enable_autostart()

    def _poll_sync(self):
        while not self.stop.wait(3):
            try:
                self.sync.tick()
            except sqlite3.Error:
                print("Constellation Ops: could not check automatic WebDAV sync.", file=sys.stderr)

    def _poll(self):
        next_ssh = 0
        while not self.stop.is_set():
            now = monotonic()
            if now >= next_ssh:
                self.refresh()
                next_ssh = now + self.interval
            self.refresh_network_probes()
            self.stop.wait(min(5, max(0, next_ssh - monotonic())))

    def refresh_network_probes(self):
        with self.lock:
            if not self.demo and not self.stop.is_set():
                self.probes.refresh()

    def _poll_outbound_schedules(self):
        while not self.stop.wait(2):
            with self.lock:
                if self.demo:
                    continue
                try:
                    self.outbound_checks.refresh_schedules(self.inventory.entries, self._scheduled_probe_credentials)
                except sqlite3.Error:
                    print("Constellation Ops: could not check scheduled outbound probes.", file=sys.stderr)

    def _saved_probe_credentials(self, host):
        if host.get("auth_mode") != "password":
            return None, None
        credential = host.get("credential_id")
        fingerprint = host.get("credential_fingerprint")
        if not credential or not fingerprint:
            return None, None
        return read_password(credential), fingerprint

    def _scheduled_probe_credentials(self, host):
        try:
            password, fingerprint = self._saved_probe_credentials(host)
        except CredentialError:
            raise ValueError("无法读取本机保存的 SSH 密码，请在设备设置中重新保存。") from None
        if host.get("auth_mode") == "password" and password is None:
            raise ValueError("定时测速需要保存此设备的 SSH 密码。")
        if host.get("auth_mode") == "key" and not host.get("identity_file"):
            raise ValueError(MISSING_IDENTITY)
        return password, fingerprint

    def _probe(self, host_id, revision, host):
        try:
            with self.lock:
                current = self.inventory.entries().get(host_id)
                if self.demo or self.stop.is_set() or current is None or current[0] != revision:
                    return
            try:
                credential_id = host.get("credential_id")
                if credential_id and host.get("auth_mode") == "password":
                    password = read_password(credential_id)
                    if password is None:
                        sample = empty_sample("auth_required", "找不到本机保存的密码，请重新输入并保存。")
                        sample["password_failure"] = True
                    else:
                        sample = collect(host, password=password)
                else:
                    sample = collect(host)
            except CredentialError as error:
                sample = empty_sample("auth_required", str(error))
                sample["password_failure"] = True
            except Exception:
                sample = empty_sample(error="采集失败，请检查本机 SSH 客户端。")
            now = monotonic()
            with self.lock:
                current = self.inventory.entries().get(host_id)
                if current is None or current[0] != revision:
                    return
                previous = self.latest.get(host_id)
                if previous and previous[0] == revision and sample["status"] == previous[1]["status"] == "online":
                    elapsed = now - previous[2]
                    uptime = sample["uptime_seconds"]
                    old_uptime = previous[1]["uptime_seconds"]
                    restarted = uptime is not None and old_uptime is not None and uptime < old_uptime
                    for direction in ("rx", "tx"):
                        value = sample.get(f"{direction}_bytes")
                        old = previous[1].get(f"{direction}_bytes")
                        if not restarted and elapsed > 0 and value is not None and old is not None and value >= old:
                            sample[f"{direction}_bps"] = (value - old) / elapsed
                self.latest[host_id] = (revision, sample, now)
                try:
                    self.history.record(host_id, revision, host, sample)
                except sqlite3.Error:
                    print("Constellation Ops: could not save a probe history point.", file=sys.stderr)
        finally:
            with self.lock:
                self.pending.pop(host_id, None)
                current = self.inventory.entries().get(host_id)
                if current is not None and current[0] != revision:
                    self.refresh(host_id)

    def refresh(self, only=None):
        with self.lock:
            if self.demo or self.stop.is_set():
                return
            entries = self.inventory.entries()
            if only is not None and only not in entries:
                raise KeyError(only)
            for host_id, (revision, host) in entries.items():
                mode = host.get("auth_mode")
                if (mode == "password" and not host.get("credential_id")) or (mode == "key" and not host.get("identity_file")):
                    continue
                current = self.latest.get(host_id)
                if mode == "password" and only is None and current and current[0] == revision and current[1].get("password_failure"):
                    continue
                if (only is None or host_id == only) and host_id not in self.pending:
                    self.pending[host_id] = revision
                    self.pool.submit(self._probe, host_id, revision, host)

    def state(self):
        with self.lock:
            base = {"demo": self.demo, "interval_seconds": self.interval,
                    "metric_display": self.inventory.metric_display(),
                    "webdav_folder": "" if self.demo else self.sync.folder(),
                    "webdav_dedicated_folder": None if self.demo else self.sync.dedicated_folder(),
                    "webdav_auto": {"mode": "off", "available": False} if self.demo else self.sync.auto_state(),
                    "komari": {} if self.demo else self.komari.snapshot(),
                    "password_storage_available": credential_storage_available(),
                    "password_public_key": self.password_envelope.public_key,
                    "password_terminal_available": os.name == "nt" and self.password_envelope.public_key is not None,
                    "embedded_terminal_modes": self.terminals.modes}
            if self.demo:
                return {**base, "hosts": self.demo_hosts, "samples": self.demo_samples, "refreshing": [],
                        "latency_history": demo_latency_histories(self.demo_samples),
                        "ping_history": demo_ping_histories(self.demo_samples)}
            entries = self.inventory.entries()
            hosts, samples = [], {}
            for host_id, (revision, host) in entries.items():
                public_host = {key: value for key, value in host.items() if key not in ("credential_id", "credential_fingerprint")}
                hosts.append({**AUTH_DEFAULTS, "id": host_id, **public_host,
                              "password_saved": bool(host.get("credential_id")), "country_code": self.geo.country(host)})
                current = self.latest.get(host_id)
                if host.get("auth_mode") == "password" and not host.get("credential_id"):
                    samples[host_id] = {**empty_sample("password_required", PASSWORD_ONLY), "checked_at": None}
                elif host.get("auth_mode") == "key" and not host.get("identity_file"):
                    samples[host_id] = {**empty_sample("auth_required", MISSING_IDENTITY), "checked_at": None}
                else:
                    samples[host_id] = current[1] if current and current[0] == revision else pending_sample()
            try:
                latency_history = self.history.recent_latencies(entries)
            except sqlite3.Error:
                latency_history = {}
                print("Constellation Ops: could not read recent probe history.", file=sys.stderr)
            try:
                ping_history = self.outbound_checks.recent_pings(entries)
            except sqlite3.Error:
                ping_history = {}
                print("Constellation Ops: could not read recent outbound Ping history.", file=sys.stderr)
            return {
                **base, "hosts": hosts, "samples": samples, "latency_history": latency_history, "ping_history": ping_history,
                "refreshing": [host_id for host_id, rev in self.pending.items()
                               if host_id in entries and entries[host_id][0] == rev],
            }

    def set_metric_display(self, mode):
        with self.lock:
            self.inventory.set_metric_display(mode)
        return {"metric_display": mode}

    def set_demo(self, enabled):
        with self.lock:
            self.demo = enabled
            if not enabled:
                self.tunnels.enable_autostart()

    def integration_request(self, name, body):
        if self.demo:
            raise ValueError("请先退出演示模式。")
        integration = self.sync if name == "webdav" else self.komari
        return integration.request(body, self.password_envelope)

    def tunnel_request(self, body):
        if self.demo:
            raise ValueError("请先退出演示模式，再管理 SSH 隧道。")
        if self.stop.is_set():
            raise ValueError("星图正在关闭。")
        return self.tunnels.request(body)

    def change(self, method, host_id, body):
        with self.lock:
            if self.demo:
                raise ValueError("请先退出演示模式，再管理真实主机。")
            if method == "DELETE":
                removed = self.inventory.remove(host_id)
                self.latest.pop(host_id, None)
                discard_credential(removed.get("credential_id"))
                return
            revision, previous = self.inventory.entries()[host_id] if method == "PUT" else (None, {})
        host = validate_host(body)
        previous_id = previous.get("credential_id")
        new_id = None
        if host["auth_mode"] == "password":
            remember = body.get("remember_password", False)
            clear = body.get("clear_password", False)
            if type(remember) is not bool or type(clear) is not bool or (remember and clear):
                raise ValueError("密码保存设置无效。")
            same_target = previous.get("auth_mode") == "password" and password_target(previous) == password_target(host)
            if remember and "password_box" in body:
                if not credential_storage_available():
                    raise ValueError("当前系统无法保存 SSH 密码。")
                password = self.password_envelope.decrypt(body, "save")
                result = password_diagnostic(host, password)
                if not result["ok"]:
                    raise ValueError(result["message"])
                new_id = save_password(password)
                host.update(credential_id=new_id, credential_fingerprint=result["fingerprint"])
            elif previous_id and same_target and not clear:
                host.update(credential_id=previous_id, credential_fingerprint=previous["credential_fingerprint"])
            elif remember:
                raise ValueError("请输入新连接的 SSH 密码，或取消记住密码。")
        host_id = host_id or uuid4().hex
        with self.lock:
            try:
                if self.demo:
                    raise ValueError("请先退出演示模式，再管理真实主机。")
                self.inventory.save(host_id, host, create=method == "POST", expected_revision=revision)
            except (ValueError, sqlite3.Error):
                discard_credential(new_id)
                raise
            if previous_id != host.get("credential_id"):
                discard_credential(previous_id)
            self.latest.pop(host_id, None)
            self.refresh(host_id)

    def test_ssh(self, draft):
        host = validate_connection(draft)
        if host["auth_mode"] != "password":
            return test_connection(host)
        password, fingerprint = self.connection_password(host, draft, "test")
        if password is None:
            return test_connection(host)
        return password_diagnostic(host, password, expected_fingerprint=fingerprint)

    def connection_password(self, host, draft, action):
        if "password_box" in draft:
            return self.password_envelope.decrypt(draft, action), None
        host_id = draft.get("credential_id")
        if host_id is None:
            return None, None
        if not isinstance(host_id, str) or not 1 <= len(host_id) <= 80:
            raise ValueError("设备编号无效。")
        with self.lock:
            _, saved = self.inventory.entries()[host_id]
            if saved.get("auth_mode") != "password" or password_target(saved) != password_target(host):
                raise ValueError("连接资料已变更，请重新输入密码。")
            credential = saved.get("credential_id")
            password = read_password(credential) if credential else None
        if password is None:
            raise ValueError("找不到本机保存的密码，请重新输入。")
        return password, saved["credential_fingerprint"]

    def host_history(self, host_id):
        with self.lock:
            if self.demo:
                return {"points": demo_history(self.demo_samples[host_id])}
            _, host = self.inventory.entries()[host_id]
            return {"points": self.history.points(host_id, host)}

    def transfer_inventory(self, action, payload=None):
        with self.lock:
            if self.demo:
                raise ValueError("请先退出演示模式，再迁移设备清单。")
            if action == "export":
                return export_inventory(self.inventory)
            handler = preview_inventory if action == "preview" else import_inventory
            return handler(self.inventory, payload, validator=validate_host, max_hosts=MAX_HOSTS)

    def open_ssh(self, draft):
        host = validate_connection(draft)
        manual = draft.get("manual", False)
        verify_host = draft.get("verify_host", False)
        if type(manual) is not bool or type(verify_host) is not bool:
            raise ValueError("终端连接参数无效。")
        if verify_host:
            if host["auth_mode"] != "password":
                raise ValueError("此指纹确认入口用于密码设备。")
            return open_terminal(host, verify_host=True)
        if host["auth_mode"] != "password" or manual:
            return open_terminal(host)
        password, fingerprint = self.connection_password(host, draft, "terminal")
        if password is None:
            return open_terminal(host)
        return open_password_terminal(host, password, expected_fingerprint=fingerprint)

    def terminal_request(self, action, body):
        fields = {
            "open": ({"host", "cols", "rows"}, set()),
            "exchange": ({"id", "offset"}, {"input_data", "cols", "rows"}),
            "close": ({"id"}, set()),
        }
        required, optional = fields[action]
        if not required <= body.keys() <= required | optional:
            raise ValueError("终端请求参数无效。")
        if action == "close":
            return self.terminals.close(body["id"])
        if action == "exchange":
            return self.terminals.exchange(body["id"], body["offset"], input_data=body.get("input_data"),
                                           cols=body.get("cols"), rows=body.get("rows"))
        with self.lock:
            if self.demo:
                raise ValueError("请先退出演示模式，再连接真实设备。")
        draft = body["host"]
        host = validate_connection(draft)
        password = fingerprint = None
        if host["auth_mode"] == "password":
            password, fingerprint = self.connection_password(host, draft, "terminal")
            if password is None:
                raise ValueError("请输入 SSH 密码，或先为此设备记住密码。")
        return self.terminals.open(host, password, expected_fingerprint=fingerprint, cols=body["cols"], rows=body["rows"])

    def probe_request(self, body):
        action = body.get("action")
        fields = {"list": set(), "save": {"config"}, "delete": {"id"}, "history": {"id"}, "run": {"id"}}
        if not isinstance(action, str) or action not in fields:
            raise ValueError("探针操作无效。")
        required = {"action", "host_id"} | fields[action]
        if not required <= body.keys() <= required | ({"id"} if action == "save" else set()):
            raise ValueError("探针请求参数无效。")
        host_id, probe_id = body["host_id"], body.get("id")
        if not isinstance(host_id, str) or not 1 <= len(host_id) <= 80 or (
            "id" in body and (not isinstance(probe_id, str) or not 1 <= len(probe_id) <= 80)
        ):
            raise ValueError("设备或探针编号无效。")
        with self.lock:
            if self.demo:
                raise ValueError("请先退出演示模式，再管理探针。")
            if action == "list":
                return self.probes.list(host_id)
            if action == "save":
                return self.probes.save(host_id, body["config"], probe_id)
            handler = {"delete": self.probes.delete, "history": self.probes.history, "run": self.probes.run}[action]
            return handler(host_id, probe_id)

    def outbound_probe_request(self, body):
        action = body.get("action")
        fields = {
            "state": ({"host_id"}, {"region_id", "region_ids"}),
            "run": ({"host_id", "region_id"}, {"password_box"}),
            "run_batch": ({"host_id", "region_ids"}, {"password_box", "packets"}),
            "selection_save": ({"host_id", "region_ids"}, set()),
            "selection_options": (set(), set()),
            "selection_bulk_save": ({"host_ids", "region_ids"}, set()),
            "region_save": ({"host_id", "name", "targets"}, {"region_id"}),
            "region_delete": ({"host_id", "region_id"}, set()),
            "schedule_save": ({"host_id", "enabled", "interval_seconds", "packets"}, {"region_ids"}),
            "history": ({"host_id", "region_id"}, set()),
        }
        if not isinstance(action, str) or action not in fields:
            raise ValueError("地区出网测速请求无效。")
        required, optional = fields[action]
        required = {"action"} | required
        if not required <= body.keys() <= required | optional:
            raise ValueError("地区出网测速请求无效。")
        host_id = body.get("host_id")
        if "host_id" in body and (not isinstance(host_id, str) or not 1 <= len(host_id) <= 80):
            raise ValueError("设备编号无效。")
        region_id = body.get("region_id")
        if "region_id" in body and (not isinstance(region_id, str) or not 1 <= len(region_id) <= 80):
            raise ValueError("地区编号无效。")
        region_ids = body.get("region_ids")
        if "region_ids" in body and not isinstance(region_ids, list):
            raise ValueError("请选择有效的测速地区。")
        packets = body.get("packets", PACKETS)
        if action in ("run", "run_batch") and (type(packets) is not int or packets not in PACKET_OPTIONS):
            raise ValueError("请选择 5 包快测或 20 包复测。")
        with self.lock:
            if self.demo or self.stop.is_set():
                raise ValueError("请在真实设备详情中打开服务器出网检测。")
            if action == "selection_options":
                return self.outbound_checks.selection_options()
            if action == "selection_bulk_save":
                updated_count = self.outbound_checks.save_selection(body["host_ids"], region_ids)
                return {"updated_count": updated_count}
            revision, host = self.inventory.entries()[host_id]
            if action == "history":
                return self.outbound_checks.history(host_id, host, region_id)
            if action == "schedule_save":
                if type(body["enabled"]) is not bool:
                    raise ValueError("请选择是否开启定时测速。")
                if body["enabled"]:
                    self._scheduled_probe_credentials(host)
                self.outbound_checks.save_schedule(host_id, body["enabled"], body["interval_seconds"], packets)
            elif action == "selection_save":
                self.outbound_checks.save_selection([host_id], region_ids)
            elif action == "region_save":
                region_id = self.outbound_checks.save_region(body["name"], body["targets"], region_id)
            elif action == "region_delete":
                self.outbound_checks.delete_region(region_id)
                region_id = None
            current = self.outbound_checks.state(host_id, host, region_id, region_ids=region_ids)
            password = fingerprint = None
            credential_error = None
            password_mode = host.get("auth_mode") == "password"
            if password_mode:
                try:
                    password, fingerprint = self._saved_probe_credentials(host)
                except CredentialError:
                    credential_error = "无法读取本机保存的 SSH 密码，请输入本次连接密码。"
            password_required = password_mode and password is None
            if action in ("run", "run_batch"):
                if "password_box" in body:
                    if not password_mode:
                        raise ValueError("此设备未配置密码认证。")
                    draft = {"host": "outbound-probes", "username": host_id, "auth_mode": "password",
                             "password_box": body["password_box"]}
                    password = self.password_envelope.decrypt(draft, "outbound-probes")
                    fingerprint = host.get("credential_fingerprint")
                if password_mode and password is None:
                    raise ValueError(credential_error or "请输入本次连接的 SSH 密码。")
                if host.get("auth_mode") == "key" and not host.get("identity_file"):
                    raise ValueError(MISSING_IDENTITY)
                targets = region_ids if action == "run_batch" else [current["region_id"]]
                self.outbound_checks.run_batch(host_id, revision, host, password, fingerprint, targets, packets=packets)
                current = self.outbound_checks.state(host_id, host, region_id, region_ids=region_ids)
            return {**current, "password_required": password_required}

    def file_request(self, body):
        action = body.get("action")
        fields = {"state": (set(), set()), "list": (set(), {"path", "password_box"}),
                  "upload": ({"path"}, {"password_box"}), "download": ({"path"}, {"password_box"}),
                  "poll": ({"ticket"}, set())}
        if not isinstance(action, str) or action not in fields:
            raise ValueError("文件操作无效。")
        required, optional = fields[action]
        required = {"action", "host_id"} | required
        if not required <= body.keys() <= required | optional:
            raise ValueError("文件操作参数无效。")
        host_id = body["host_id"]
        if not isinstance(host_id, str) or not 1 <= len(host_id) <= 80:
            raise ValueError("设备编号无效。")
        path = body.get("path")
        if "path" in body:
            path = remote_path(path)
        with self.lock:
            if self.demo or self.stop.is_set():
                raise ValueError("请选择已添加的 VPS 使用文件管理。")
            revision, host = self.inventory.entries()[host_id]
            if action == "poll":
                ticket = body["ticket"]
                if not isinstance(ticket, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32}", ticket):
                    raise ValueError("文件操作编号无效。")
                return self.files.poll(host_id, ticket)
            password_mode = host.get("auth_mode") == "password"
            password = fingerprint = None
            if "password_box" in body:
                if not password_mode:
                    raise ValueError("此设备未配置密码认证。")
                draft = {"host": "file-manager", "username": host_id, "auth_mode": "password",
                         "password_box": body["password_box"]}
                password = self.password_envelope.decrypt(draft, "files")
                fingerprint = host.get("credential_fingerprint")
            elif password_mode:
                try:
                    password, fingerprint = self._saved_probe_credentials(host)
                except CredentialError:
                    pass
            password_required = password_mode and password is None
            if action == "state":
                return {"password_required": password_required}
            if password_required:
                raise ValueError("请输入此设备的 SSH 密码。")
            if host.get("auth_mode") == "key" and not host.get("identity_file"):
                raise ValueError(MISSING_IDENTITY)

            def check_revision():
                with self.lock:
                    entry = self.inventory.entries().get(host_id)
                    if self.stop.is_set() or self.demo or entry is None or entry[0] != revision:
                        raise ValueError("设备连接配置已变更，请重新打开文件管理。")

            return self.files.submit(host_id, action, host, password, fingerprint, path, check_revision)

    def shutdown(self):
        self.stop.set()
        self.tunnels.shutdown()
        self.outbound_scheduler.join()
        self.sync_scheduler.join()
        if self.scheduler.ident is not None:
            self.scheduler.join()
        self.terminals.shutdown()
        self.probes.shutdown()
        self.outbound_checks.shutdown()
        self.sync.shutdown()
        self.komari.shutdown()
        self.files.shutdown()
        self.geo.shutdown()
        self.pool.shutdown(wait=True, cancel_futures=True)
        self.inventory.db.close()


class LocalServer(ThreadingHTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(8)
        return connection, address


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send_content(self, status, kind, content):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; "
                         "style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; "
                         "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(content)

    def respond(self, status, payload):
        self.send_content(status, "application/json; charset=utf-8",
                          json.dumps(payload, ensure_ascii=False, allow_nan=False).encode())

    def valid_host(self):
        if self.headers.get_all("Host") != [self.server.authority]:
            self.respond(403, {"error": "请使用面板提供的 127.0.0.1 地址。"})
            return False
        return True

    def do_GET(self):
        if not self.valid_host():
            return
        if self.path == "/api/state":
            self.respond(200, self.server.dashboard.state())
            return
        if self.path == BRAND_ICON_URL:
            self.send_content(200, "image/png", BRAND_ICON.read_bytes())
            return
        history = HISTORY_ROUTE.fullmatch(self.path)
        if history:
            try:
                result = self.server.dashboard.host_history(history[1])
            except KeyError:
                self.respond(404, {"error": "主机不存在。"})
            except sqlite3.Error:
                self.respond(503, {"error": "无法读取巡检历史。"})
            else:
                self.respond(200, result)
            return
        asset = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/style.css": ("style.css", "text/css; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            **PANEL_ASSETS,
        }.get(self.path)
        if asset is None:
            self.respond(404, {"error": "页面不存在。"})
            return
        filename, kind = asset
        content = (STATIC / filename).read_bytes()
        if self.path == "/":
            content = content.replace(b"__VPS_CSRF_TOKEN__", self.server.csrf.encode())
        self.send_content(200, kind, content)

    def parse_body(self):
        lengths = self.headers.get_all("Content-Length", [])
        if self.command == "DELETE" and not lengths and not self.headers.get("Transfer-Encoding"):
            return {}
        if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isdigit():
            raise ValueError("请求长度无效。")
        length = int(lengths[0])
        transfer = self.command == "POST" and self.path in ("/api/inventory/preview", "/api/inventory/import")
        maximum = MAX_TRANSFER_BODY if transfer else 2 * MAX_BODY if self.path == "/api/files" else MAX_BODY
        if length > maximum:
            raise ValueError("请求过大。")
        if length == 0 and self.command == "DELETE":
            return {}
        if self.headers.get_content_type() != "application/json":
            raise ValueError("请求必须使用 JSON。")
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, RecursionError) as error:
            raise ValueError("JSON 格式无效。") from error
        if not isinstance(body, dict):
            raise ValueError("请求必须是 JSON 对象。")
        return body

    def mutate(self):
        if not self.valid_host():
            return
        token = self.headers.get("X-VPS-CSRF", "").encode("utf-8")
        if self.headers.get_all("Origin") != [f"http://{self.server.authority}"] or not secrets.compare_digest(token, self.server.csrf.encode()):
            self.respond(403, {"error": "页面验证失败，请刷新面板。"})
            return
        panel = self.server.dashboard
        try:
            body = self.parse_body()
            terminal = TERMINAL_ROUTE.fullmatch(self.path) if self.command == "POST" else None
            if terminal:
                self.respond(200, panel.terminal_request(terminal[1], body))
                return
            if self.command == "POST" and self.path == "/api/probes":
                self.respond(200, panel.probe_request(body))
                return
            if self.command == "POST" and self.path == "/api/outbound-probes":
                self.respond(200, panel.outbound_probe_request(body))
                return
            if self.command == "POST" and self.path == "/api/files":
                self.respond(200, panel.file_request(body))
                return
            if self.command == "POST" and self.path in ("/api/webdav", "/api/komari"):
                self.respond(200, panel.integration_request(self.path.rsplit("/", 1)[1], body))
                return
            if self.command == "POST" and self.path == "/api/tunnels":
                self.respond(200, panel.tunnel_request(body))
                return
            if self.command == "POST" and self.path == "/api/metric-display":
                self.respond(200, panel.set_metric_display(body.get("mode")))
                return
            if self.command == "POST" and self.path in (
                "/api/inventory/export", "/api/inventory/preview", "/api/inventory/import",
            ):
                action = self.path.rsplit("/", 1)[1]
                self.respond(200, panel.transfer_inventory(action, body.get("inventory")))
                return
            if self.command == "POST" and self.path == "/api/hosts":
                panel.change(self.command, None, body)
            elif self.command in ("PUT", "DELETE") and self.path.startswith("/api/hosts/"):
                panel.change(self.command, self.path.removeprefix("/api/hosts/"), body)
            elif self.command == "POST" and self.path == "/api/refresh":
                host_id = body.get("id")
                if host_id is not None and not isinstance(host_id, str):
                    raise ValueError("主机编号无效。")
                panel.refresh(host_id)
            elif self.command == "POST" and self.path == "/api/demo":
                enabled = body.get("enabled")
                if type(enabled) is not bool:
                    raise ValueError("演示模式参数无效。")
                panel.set_demo(enabled)
            elif self.command == "POST" and self.path == "/api/ssh/test":
                self.respond(200, panel.test_ssh(body))
                return
            elif self.command == "POST" and self.path == "/api/ssh/terminal":
                self.respond(200, panel.open_ssh(body))
                return
            elif self.command == "POST" and self.path == "/api/ssh/key-file":
                from dashboard_native import choose_key_file

                self.respond(200, choose_key_file())
                return
            else:
                self.respond(404, {"error": "操作不存在。"})
                return
        except ValueError as error:
            self.respond(400, {"error": str(error)})
            return
        except KeyError:
            self.respond(404, {"error": "主机不存在。"})
            return
        except CredentialError as error:
            self.respond(503, {"error": str(error)})
            return
        except sqlite3.Error:
            self.respond(503, {"error": "无法写入主机列表，请检查本机存储。"})
            return
        except OSError:
            self.respond(503, {"error": "无法打开本机文件选择器。"})
            return
        self.respond(200, panel.state())

    do_POST = do_PUT = do_DELETE = mutate


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--port", type=int, default=8765, help="本机 HTTP 端口，0 为自动分配")
    cli.add_argument("--interval", type=int, default=60, help="自动巡检间隔，单位秒")
    cli.add_argument("--data-dir", type=Path, default=default_data_dir(), help="本机主机列表目录")
    cli.add_argument("--demo", action="store_true", help="打开演示数据")
    cli.add_argument("--open", action="store_true", help="打开默认浏览器")
    args = cli.parse_args()
    if not 0 <= args.port <= 65535 or not 15 <= args.interval <= 3600:
        cli.error("端口须为 0–65535，间隔须为 15–3600 秒。")
    try:
        server = LocalServer(("127.0.0.1", args.port), Handler)
    except OSError:
        cli.exit(1, f"无法监听 127.0.0.1:{args.port}，请关闭已有面板或指定 --port 0。\n")
    with server:
        try:
            panel = Dashboard(args.data_dir.expanduser(), args.interval, args.demo)
        except (OSError, sqlite3.Error) as error:
            cli.exit(1, f"无法打开本机主机列表：{error}\n")
        server.dashboard = panel
        server.authority = f"127.0.0.1:{server.server_port}"
        server.csrf = secrets.token_urlsafe(32)
        url = f"http://{server.authority}/"
        print(url, flush=True)
        panel.scheduler.start()
        if args.open:
            opener = Timer(0.2, webbrowser.open, args=(url,))
            opener.daemon = True
            opener.start()
        try:
            server.serve_forever(poll_interval=0.3)
        except KeyboardInterrupt:
            pass
        finally:
            panel.shutdown()


if __name__ == "__main__":
    main()
