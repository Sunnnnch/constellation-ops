"""Persist VPS tunnel profiles and supervise this panel's local listeners."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import re
import sqlite3
from threading import Event, Thread
import time
from uuid import uuid4

from dashboard_credentials import CredentialError
from dashboard_history import MISSING_IDENTITY
from dashboard_tunnel_runtime import TunnelError, open_tunnel, port_available, remote_address


_PROFILE_FIELDS = ("id", "host_id", "name", "local_port", "remote_host", "remote_port")
_AUTOMATION_FIELDS = ("auto_start", "auto_reconnect")
_PROFILE_COLUMNS = (*_PROFILE_FIELDS, *_AUTOMATION_FIELDS, "stopped_at")
_PROFILE_SELECT = """
    SELECT profile.id, host_id, name, local_port, remote_host, remote_port,
           coalesce(auto_start, 0), coalesce(auto_reconnect, 0), coalesce(stopped_at, 0)
    FROM dashboard_tunnel_profiles AS profile
    LEFT JOIN dashboard_tunnel_automation AS automation ON automation.tunnel_id=profile.id
"""
_CONNECTION_FIELDS = ("host", "username", "port", "auth_mode", "identity_file", "known_hosts",
                      "credential_id", "credential_fingerprint")
_LEASE_SECONDS = 15
_HEARTBEAT_SECONDS = 2
_RETRY_DELAYS = (2, 4, 8, 16, 30)


def _port(value, label):
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value):
        value = int(value)
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError(f"{label}必须在 1 至 65535 之间。")
    return value


def _connection(host):
    return tuple(host.get(field) for field in _CONNECTION_FIELDS)


def _connection_revision(host_id, revision):
    return f"{host_id}:{revision}"


def _automation_settings(body, fallback):
    values = tuple(body.get(key, bool(fallback.get(key))) for key in _AUTOMATION_FIELDS)
    if any(type(value) is not bool for value in values):
        raise ValueError("隧道自动化设置必须为开启或关闭。")
    return values


@dataclass
class _Session:
    host_id: str
    connection: tuple
    automatic: bool = False
    cancelled: Event = field(default_factory=Event)
    status: str = "starting"
    runtime: object = None
    has_connected: bool = False
    retry_at: float | None = None
    attempts: int = 0
    message: str = ""
    closing: bool = False


class TunnelManager:
    def __init__(self, db, lock, entries, saved_credentials, password_envelope, *, is_demo=lambda: False):
        self.db = db
        self.lock = lock
        self.entries = entries
        self.saved_credentials = saved_credentials
        self.password_envelope = password_envelope
        self.is_demo = is_demo
        self.owner = uuid4().hex
        self.opened_at = time.time()
        self.autostart = None
        self.sessions = {}
        self.errors = {}
        self.password_needed = set()
        self.closed = Event()
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_tunnel_profiles (
                    id TEXT PRIMARY KEY, host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                    name TEXT NOT NULL, local_port INTEGER NOT NULL,
                    remote_host TEXT NOT NULL, remote_port INTEGER NOT NULL
                )
            """)
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_tunnel_automation (
                    tunnel_id TEXT PRIMARY KEY REFERENCES dashboard_tunnel_profiles(id) ON DELETE CASCADE,
                    auto_start INTEGER NOT NULL DEFAULT 0, auto_reconnect INTEGER NOT NULL DEFAULT 0,
                    stopped_at REAL NOT NULL DEFAULT 0
                )
            """)
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_tunnel_leases (
                    tunnel_id TEXT PRIMARY KEY,
                    local_port INTEGER NOT NULL UNIQUE, owner TEXT NOT NULL, expires REAL NOT NULL,
                    stop_requested INTEGER NOT NULL DEFAULT 0
                )
            """)
        self.workers = ThreadPoolExecutor(max_workers=4, thread_name_prefix="vps-tunnel")
        self.closers = ThreadPoolExecutor(max_workers=2, thread_name_prefix="vps-tunnel-close")
        self.monitor = Thread(target=self._monitor, name="vps-tunnel-monitor", daemon=True)
        self.monitor.start()

    def enable_autostart(self):
        with self.lock:
            if self.autostart is None and not self.closed.is_set() and not self.is_demo():
                now = time.time()
                self.autostart = dict(self.db.execute("""
                    SELECT settings.tunnel_id, lease.expires FROM dashboard_tunnel_automation AS settings
                    LEFT JOIN dashboard_tunnel_leases AS lease ON lease.tunnel_id=settings.tunnel_id AND lease.expires > ?
                    WHERE settings.auto_start=1 ORDER BY settings.rowid
                """, (now,)))

    def request(self, body):
        if not isinstance(body, dict):
            raise ValueError("隧道请求格式无效。")
        with self.lock:
            if self.closed.is_set():
                raise ValueError("隧道管理正在关闭。")
            action = body.get("action")
            if action == "check":
                port = _port(body.get("local_port"), "本机端口")
                return {"local_port": port, "port_state": self._port_state(port, self._leases())}
            if action in ("create", "update"):
                self._save(body, create=action == "create")
            elif action == "automation":
                self._set_automation(body)
            elif action == "delete":
                self._delete(body.get("id"))
            elif action == "start":
                self._start(body)
            elif action == "stop":
                self._stop(body.get("id"))
            elif action != "state":
                raise ValueError("未知的隧道操作。")
            return self._state()

    def _leases(self):
        return {port: (tunnel_id, stop_requested) for port, tunnel_id, stop_requested in self.db.execute(
            "SELECT local_port, tunnel_id, stop_requested FROM dashboard_tunnel_leases WHERE expires > ?",
            (time.time(),)
        )}

    @staticmethod
    def _port_state(port, leases):
        if port in leases:
            return "tunnel"
        return "available" if port_available(port) else "occupied"

    def _state(self):
        entries = self.entries()
        leases = self._leases()
        ports = {}
        tunnels = []
        for profile in self._profiles("ORDER BY profile.rowid"):
            tunnel = {key: profile[key] for key in _PROFILE_FIELDS}
            tunnel.update({key: bool(profile[key]) for key in _AUTOMATION_FIELDS})
            tunnel_id, host_id, port = profile["id"], profile["host_id"], profile["local_port"]
            entry = entries.get(host_id)
            if entry is None:
                continue
            revision, host = entry
            password_mode = host.get("auth_mode") == "password"
            session = self.sessions.get(tunnel_id)
            lease = leases.get(port)
            status, message = "stopped", ""
            if lease and lease[0] == tunnel_id and lease[1]:
                status = "stopping"
            elif session:
                status, message = session.status, session.message
            elif lease and lease[0] == tunnel_id:
                status, message = "other_panel", "隧道从另一个面板启动。"
            elif tunnel_id in self.errors:
                status, message = "error", self.errors[tunnel_id]
            if port not in ports:
                ports[port] = self._port_state(port, leases)
            tunnel.update(status=status, message=message, port_state=ports[port],
                          can_stop=status in ("starting", "running", "reconnecting", "other_panel"),
                          password_required=password_mode and (
                              tunnel_id in self.password_needed or not host.get("credential_id")
                              or not host.get("credential_fingerprint")
                          ))
            if password_mode:
                tunnel["connection_revision"] = _connection_revision(host_id, revision)
            tunnels.append(tunnel)
        return {"tunnels": tunnels}

    def _profiles(self, where="", params=()):
        return [dict(zip(_PROFILE_COLUMNS, row)) for row in self.db.execute(
            f"{_PROFILE_SELECT} {where}", params
        )]

    def _profile(self, tunnel_id):
        if not isinstance(tunnel_id, str) or not re.fullmatch(r"[a-f0-9]{32}", tunnel_id):
            raise ValueError("隧道编号无效。")
        rows = self._profiles("WHERE profile.id=?", (tunnel_id,))
        if not rows:
            raise ValueError("未找到该隧道，请刷新面板。")
        return rows[0]

    def _require_stopped(self, tunnel_id):
        lease = self.db.execute(
            "SELECT 1 FROM dashboard_tunnel_leases WHERE tunnel_id=? AND expires > ?", (tunnel_id, time.time())
        ).fetchone()
        if tunnel_id in self.sessions or lease:
            raise ValueError("请先停止此隧道。")

    def _save(self, body, *, create):
        host_id = body.get("host_id")
        if not isinstance(host_id, str):
            raise ValueError("请选择要绑定的 VPS。")
        name = body.get("name")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or not name.strip().isprintable():
            raise ValueError("请输入 1 至 80 个字符的隧道名称。")
        remote_host = body.get("remote_host")
        remote_host = remote_address(remote_host.strip() if isinstance(remote_host, str) else remote_host)
        profile = (host_id, name.strip(), _port(body.get("local_port"), "本机端口"),
                   remote_host, _port(body.get("remote_port"), "远端端口"))
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if host_id not in self.entries():
                raise ValueError("请选择要绑定的 VPS。")
            if create:
                tunnel_id = uuid4().hex
                self.db.execute("INSERT INTO dashboard_tunnel_profiles VALUES (?, ?, ?, ?, ?, ?)",
                                (tunnel_id, *profile))
                settings = _automation_settings(body, {})
            else:
                existing = self._profile(body.get("id"))
                tunnel_id = existing["id"]
                self._require_stopped(tunnel_id)
                settings = _automation_settings(body, existing)
                self.db.execute("""UPDATE dashboard_tunnel_profiles
                    SET host_id=?, name=?, local_port=?, remote_host=?, remote_port=? WHERE id=?
                """, (*profile, tunnel_id))
            self._write_automation(tunnel_id, settings)
        if not create:
            self._clear_result(tunnel_id)

    def _write_automation(self, tunnel_id, settings):
        self.db.execute("""
            INSERT INTO dashboard_tunnel_automation (tunnel_id, auto_start, auto_reconnect) VALUES (?, ?, ?)
            ON CONFLICT(tunnel_id) DO UPDATE SET auto_start=excluded.auto_start, auto_reconnect=excluded.auto_reconnect
        """, (tunnel_id, *settings))

    def _set_automation(self, body):
        if not any(key in body for key in _AUTOMATION_FIELDS):
            raise ValueError("请选择要更新的隧道自动化设置。")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            profile = self._profile(body.get("id"))
            tunnel_id = profile["id"]
            auto_start, auto_reconnect = _automation_settings(body, profile)
            self._write_automation(tunnel_id, (auto_start, auto_reconnect))
        session = self.sessions.get(tunnel_id)
        if session:
            profile.update(auto_start=auto_start, auto_reconnect=auto_reconnect)
            if not self._opening_allowed(profile, session):
                self._cancel(tunnel_id, session)

    def _delete(self, tunnel_id):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._profile(tunnel_id)
            self._require_stopped(tunnel_id)
            self.db.execute("DELETE FROM dashboard_tunnel_profiles WHERE id=?", (tunnel_id,))
        self._clear_result(tunnel_id)

    def _clear_result(self, tunnel_id):
        self.errors.pop(tunnel_id, None)
        self.password_needed.discard(tunnel_id)

    def _credentials(self, host, body, tunnel_id, revision):
        if "password_box" in body:
            if host.get("auth_mode") != "password":
                raise ValueError("此设备未配置密码认证。")
            draft = {"host": "tunnels", "username": tunnel_id, "auth_mode": "password",
                     "known_hosts": revision, "password_box": body["password_box"]}
            return self.password_envelope.decrypt(draft, "tunnel-start"), host.get("credential_fingerprint")
        try:
            return self.saved_credentials(host)
        except CredentialError:
            return None, None

    def _start(self, body, *, automatic=False):
        profile = self._profile(body.get("id"))
        tunnel_id, host_id, local_port = (profile[key] for key in ("id", "host_id", "local_port"))
        if tunnel_id in self.sessions or (automatic and self._skip_autostart(profile)):
            return
        entry = self.entries().get(host_id)
        if entry is None:
            raise ValueError("此隧道绑定的 VPS 已删除。")
        revision, host = entry
        if host.get("auth_mode") == "key" and not host.get("identity_file"):
            raise ValueError(MISSING_IDENTITY)
        password, fingerprint = self._credentials(host, body, tunnel_id, _connection_revision(host_id, revision))
        if host.get("auth_mode") == "password" and (not password or (automatic and not fingerprint)):
            self.password_needed.add(tunnel_id)
            self.errors[tunnel_id] = ("自动启动需要设备中已保存并验证的 SSH 密码。"
                                      if automatic else "请输入此设备的 SSH 密码。")
            return
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            current = self._profile(tunnel_id)
            if automatic and self._skip_autostart(current):
                return
            if automatic and self._autostart_peer(tunnel_id):
                return tunnel_id in self.autostart
            if any(profile[key] != current[key] for key in _PROFILE_FIELDS) or entry != self.entries().get(host_id):
                raise ValueError("隧道或设备已在另一个面板中修改，请重试。")
            self.db.execute("DELETE FROM dashboard_tunnel_leases WHERE expires <= ?", (time.time(),))
            self._require_stopped(tunnel_id)
            if self._port_state(local_port, self._leases()) != "available":
                raise ValueError(f"本机端口 {local_port} 已占用，请停止占用它的隧道或更换端口。")
            self.db.execute("""
                INSERT INTO dashboard_tunnel_leases (tunnel_id, local_port, owner, expires) VALUES (?, ?, ?, ?)
            """, (tunnel_id, local_port, self.owner, time.time() + _LEASE_SECONDS))
            if not automatic:
                self.db.execute("UPDATE dashboard_tunnel_automation SET stopped_at=0 WHERE tunnel_id=?", (tunnel_id,))
        self._clear_result(tunnel_id)
        session = _Session(host_id, _connection(host), automatic=automatic)
        self.sessions[tunnel_id] = session
        if self.autostart is not None:
            self.autostart.pop(tunnel_id, None)
        self.workers.submit(self._open, profile, session, host, password, fingerprint)

    def _skip_autostart(self, profile):
        return self.is_demo() or not profile["auto_start"] or profile["stopped_at"] >= self.opened_at

    def _autostart_peer(self, tunnel_id):
        row = self.db.execute(
            "SELECT expires, stop_requested FROM dashboard_tunnel_leases WHERE tunnel_id=? AND expires > ?",
            (tunnel_id, time.time()),
        ).fetchone()
        if row is None:
            return False
        expires, stop_requested = row
        observed_expiry = self.autostart.get(tunnel_id)
        if stop_requested or (observed_expiry is not None and expires > observed_expiry):
            self.autostart.pop(tunnel_id, None)
        else:
            # A live peer renews the lease. A crashed panel's lease expires and can be replaced.
            self.autostart[tunnel_id] = expires
        return True

    def _open(self, profile, session, host, password, fingerprint):
        tunnel_id, local_port, remote_host, remote_port = (
            profile[key] for key in ("id", "local_port", "remote_host", "remote_port")
        )
        with self.lock:
            if not self._can_publish(tunnel_id, session):
                self._finish(tunnel_id)
                return
        try:
            runtime = open_tunnel(host, local_port, remote_host, remote_port, password=password,
                                  expected_fingerprint=fingerprint, cancelled=session.cancelled)
        except TunnelError as exc:
            with self.lock:
                try:
                    if exc.retryable and self._schedule_retry(tunnel_id, session, str(exc)):
                        return
                except sqlite3.OperationalError:
                    pass
                self._finish(tunnel_id, str(exc))
            return
        except Exception:
            self._finish(tunnel_id, "无法启动 SSH 隧道。")
            return
        with self.lock:
            if self._can_publish(tunnel_id, session):
                session.runtime = runtime
                session.status = "running"
                session.has_connected = True
                session.retry_at = None
                session.attempts = 0
                session.message = ""
                return
        self._close(tunnel_id, runtime)

    def _can_publish(self, tunnel_id, session):
        if session.cancelled.is_set():
            return False
        try:
            profiles = self._profiles("WHERE profile.id=?", (tunnel_id,))
            entry = self.entries().get(session.host_id)
            lease = self.db.execute("""
                SELECT stop_requested FROM dashboard_tunnel_leases WHERE tunnel_id=? AND owner=?
            """, (tunnel_id, self.owner)).fetchone()
        except sqlite3.OperationalError:
            return False
        return (bool(profiles) and entry is not None and session.connection == _connection(entry[1])
                and lease == (0,) and self._opening_allowed(profiles[0], session))

    def _opening_allowed(self, profile, session):
        if session.status == "reconnecting" and (self.is_demo() or not profile["auto_reconnect"]):
            return False
        if session.automatic and not session.has_connected and session.status in ("starting", "reconnecting"):
            return not self.is_demo() and bool(profile["auto_start"])
        return True

    def _schedule_retry(self, tunnel_id, session, error):
        if (session.cancelled.is_set() or self.is_demo() or not (session.has_connected or session.automatic)):
            return False
        profiles = self._profiles("WHERE profile.id=?", (tunnel_id,))
        if not profiles:
            return False
        profile = profiles[0]
        if not profile["auto_reconnect"] or (not session.has_connected and not profile["auto_start"]):
            return False
        delay = _RETRY_DELAYS[session.attempts]
        session.attempts = min(session.attempts + 1, len(_RETRY_DELAYS) - 1)
        session.status = "reconnecting"
        session.retry_at = time.monotonic() + delay
        session.message = f"{error} 约 {delay} 秒后重连。"
        return True

    def _stop(self, tunnel_id):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._profile(tunnel_id)
            self.db.execute("""
                INSERT INTO dashboard_tunnel_automation (tunnel_id, stopped_at) VALUES (?, ?)
                ON CONFLICT(tunnel_id) DO UPDATE SET stopped_at=excluded.stopped_at
            """, (tunnel_id, time.time()))
            self.db.execute("""
                UPDATE dashboard_tunnel_leases SET stop_requested=1 WHERE tunnel_id=? AND expires > ?
            """, (tunnel_id, time.time()))
        if tunnel_id in self.sessions:
            self._cancel(tunnel_id, self.sessions[tunnel_id])
        else:
            self._clear_result(tunnel_id)

    def _cancel(self, tunnel_id, session):
        if not session.cancelled.is_set():
            session.cancelled.set()
            session.status = "stopping"
            session.message = ""
            if session.runtime is not None:
                self.closers.submit(self._close, tunnel_id, session.runtime)
            elif session.retry_at is not None and not session.closing:
                self._finish(tunnel_id)

    def _close(self, tunnel_id, runtime):
        try:
            runtime.close()
        finally:
            self._finish(tunnel_id)

    def _close_for_retry(self, tunnel_id, session, runtime):
        try:
            runtime.close()
        finally:
            with self.lock:
                session.closing = False
                if session.cancelled.is_set():
                    self._finish(tunnel_id)

    def _finish(self, tunnel_id, error=None):
        with self.lock:
            session = self.sessions.pop(tunnel_id)
            if error and not session.cancelled.is_set():
                self.errors[tunnel_id] = error
            try:
                with self.db:
                    self.db.execute("DELETE FROM dashboard_tunnel_leases WHERE tunnel_id=? AND owner=?",
                                    (tunnel_id, self.owner))
            except sqlite3.OperationalError:
                # An interrupted database writer may delay release until this lease expires.
                pass

    def _monitor(self):
        while not self.closed.wait(_HEARTBEAT_SECONDS):
            try:
                self._refresh_leases()
            except sqlite3.OperationalError:
                continue

    def _refresh_leases(self):
        with self.lock:
            if self.closed.is_set():
                return
            if not self.is_demo():
                self._start_pending_profiles()
            if not self.sessions:
                return
            entries = self.entries()
            profiles = {profile["id"]: profile for profile in self._profiles()}
            with self.db:
                self.db.execute("UPDATE dashboard_tunnel_leases SET expires=? WHERE owner=?",
                                (time.time() + _LEASE_SECONDS, self.owner))
                owned = dict(self.db.execute(
                    "SELECT tunnel_id, stop_requested FROM dashboard_tunnel_leases WHERE owner=?", (self.owner,)
                ))
            for tunnel_id, session in list(self.sessions.items()):
                entry = entries.get(session.host_id)
                profile = profiles.get(tunnel_id)
                if (owned.get(tunnel_id, True) or profile is None or entry is None
                        or session.connection != _connection(entry[1])):
                    self._cancel(tunnel_id, session)
                elif session.status == "running" and not session.runtime.alive():
                    error = session.runtime.error() or "SSH 隧道已断开。"
                    if self._schedule_retry(tunnel_id, session, error):
                        runtime, session.runtime = session.runtime, None
                        session.closing = True
                        self.closers.submit(self._close_for_retry, tunnel_id, session, runtime)
                    else:
                        self.errors[tunnel_id] = error
                        self._cancel(tunnel_id, session)
                elif not self._opening_allowed(profile, session):
                    self._cancel(tunnel_id, session)
                elif session.status == "reconnecting" and session.retry_at is not None and not session.closing:
                    if time.monotonic() >= session.retry_at:
                        self._retry(profile, session, entry[1])

    def _start_pending_profiles(self):
        for tunnel_id in list(self.autostart or ()):
            profiles = self._profiles("WHERE profile.id=?", (tunnel_id,))
            if profiles and not self._skip_autostart(profiles[0]):
                if self._autostart_peer(tunnel_id):
                    continue
                try:
                    if self._start({"id": tunnel_id}, automatic=True):
                        continue
                except ValueError as exc:
                    self.errors[tunnel_id] = str(exc)
            self.autostart.pop(tunnel_id, None)

    def _retry(self, profile, session, host):
        tunnel_id = profile["id"]
        password, fingerprint = self._credentials(host, {}, tunnel_id, None)
        if host.get("auth_mode") == "password" and (not password or not fingerprint):
            self.password_needed.add(tunnel_id)
            self._finish(tunnel_id, "自动重连需要设备中已保存并验证的 SSH 密码。")
            return
        session.retry_at = None
        session.message = "正在重新连接 SSH 隧道。"
        self.workers.submit(self._open, profile, session, host, password, fingerprint)

    def shutdown(self):
        with self.lock:
            if self.closed.is_set():
                return
            self.closed.set()
            for tunnel_id, session in list(self.sessions.items()):
                self._cancel(tunnel_id, session)
        self.monitor.join()
        self.workers.shutdown(wait=True)
        self.closers.shutdown(wait=True)
