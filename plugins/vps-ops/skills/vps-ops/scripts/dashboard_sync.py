"""Merge portable VPS configuration and selected private keys into encrypted WebDAV backups."""

from base64 import b64decode, b64encode
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
from tempfile import mkstemp
from threading import Lock, Timer
from time import monotonic, time
from uuid import uuid4

from dashboard_history import connection_identity
from dashboard_credentials import CredentialError, available as vault_available, delete_password, read_password, save_password
from dashboard_inventory_transfer import PORTABLE_DEFAULTS, target
from dashboard_outbound_regions import MAX_CUSTOM_REGIONS, PRESETS, region_label, validate_region_targets
from dashboard_outbound_schedule import schedule_time, validate_schedule
from dashboard_ssh import clean_text, identity_file
from dashboard_webdav import WebDAV, WebDAVConflict, decrypt_archive, encrypt_archive


PROFILE_FIELDS = (*PORTABLE_DEFAULTS, "note")
ID = re.compile(r"[0-9a-f]{32}")
PRIVATE_KEY = re.compile(
    rb"-----BEGIN (OPENSSH PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|DSA PRIVATE KEY|"
    rb"PRIVATE KEY|ENCRYPTED PRIVATE KEY)-----\r?\n[A-Za-z0-9+/=\r\n: ,.-]+"
    rb"-----END \1-----\r?\n?\Z"
)
MAX_KEY_BYTES = 65536
TICKET_SECONDS = 600
AUTO_INTERVALS = (5, 15, 30, 60)
AUTO_LEASE_SECONDS = 180


def digest(data):
    return sha256(data).hexdigest()


def local_digest(snapshot):
    canonical = {**snapshot, "devices": sorted(snapshot["devices"], key=lambda row: row["id"]),
                 "regions": sorted(snapshot["regions"], key=lambda row: row["id"])}
    return digest(json.dumps(canonical, ensure_ascii=False, sort_keys=True).encode("utf-8"))


def archive_ids(snapshot, field):
    return {entry["id"] for entry in snapshot[field]}


def discard_secret(reference):
    if reference:
        try:
            delete_password(reference)
        except CredentialError:
            pass


def encode_key(path):
    try:
        with identity_file(path).open("rb") as stream:
            data = stream.read(MAX_KEY_BYTES + 1)
    except OSError:
        raise ValueError("无法读取所选 SSH 私钥，请检查文件权限。") from None
    if len(data) > MAX_KEY_BYTES or not PRIVATE_KEY.fullmatch(data):
        raise ValueError("所选文件不是支持的 SSH 私钥，或超过 64 KiB。")
    return b64encode(data).decode("ascii")


def decode_key(value):
    if not isinstance(value, str) or len(value) > ((MAX_KEY_BYTES + 2) // 3) * 4:
        raise ValueError("备份内的 SSH 私钥大小或格式无效。")
    try:
        data = b64decode(value, validate=True)
    except ValueError:
        raise ValueError("备份内的 SSH 私钥格式无效。") from None
    if len(data) > MAX_KEY_BYTES or not PRIVATE_KEY.fullmatch(data):
        raise ValueError("备份内的 SSH 私钥格式无效。")
    return data


def private_file(directory, data):
    directory = directory.resolve()
    keys = directory / "sync-keys"
    keys.mkdir(mode=0o700, exist_ok=True)
    if keys.resolve() != keys or (os.name != "nt" and keys.stat().st_mode & 0o077):
        raise ValueError("本机同步密钥目录的访问权限不安全。")
    fd, name = mkstemp(prefix="id_", dir=keys)
    path = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            if os.name == "nt":
                windows = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32"
                options = {"capture_output": True, "timeout": 5, "creationflags": subprocess.CREATE_NO_WINDOW}
                user = subprocess.run([str(windows / "whoami.exe"), "/user", "/fo", "csv", "/nh"], **options)
                sid = re.search(rb'"(S-1-[0-9-]+)"', user.stdout)
                if user.returncode or not sid:
                    raise ValueError("无法识别当前 Windows 用户，私钥未导入。")
                result = subprocess.run([str(windows / "icacls.exe"), str(path), "/inheritance:r",
                                         "/grant:r", "*" + sid[1].decode("ascii") + ":(F)"], **options)
                if result.returncode:
                    raise ValueError("无法限制本机私钥的访问权限，私钥未导入。")
            else:
                os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
        identity_file(str(path))
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def profile(host):
    defaults = {**PORTABLE_DEFAULTS, "note": ""}
    return {field: host.get(field, default) for field, default in defaults.items()}


def validate_archive(raw, validator, max_hosts):
    if (set(raw) != {"version", "devices", "regions", "metric_display"} or type(raw["version"]) is not int
            or raw["version"] != 1 or not isinstance(raw["devices"], list) or len(raw["devices"]) > max_hosts
            or not isinstance(raw["regions"], list) or len(raw["regions"]) > MAX_CUSTOM_REGIONS
            or raw["metric_display"] not in ("gauges", "text")):
        raise ValueError("同步文件结构或版本无效。")
    regions = {}
    preset_ids = {region[0] for region in PRESETS}
    for region in raw["regions"]:
        if not isinstance(region, dict) or set(region) != {"id", "name", "targets"}:
            raise ValueError("同步文件内的测速地区无效。")
        region_id = region["id"]
        if not isinstance(region_id, str) or not ID.fullmatch(region_id) or region_id in regions:
            raise ValueError("同步文件内的测速地区编号无效。")
        name = region_label(region["name"], "地区名称")
        targets = region["targets"]
        if (not isinstance(targets, list) or not all(isinstance(row, list) and len(row) == 3
                and isinstance(row[0], str) and ID.fullmatch(row[0]) for row in targets)
                or len({row[0] for row in targets}) != len(targets)):
            raise ValueError("同步文件内的测速目标无效。")
        checked = validate_region_targets([{"carrier": label, "target": ip} for _, label, ip in targets])
        regions[region_id] = {"id": region_id, "name": name, "targets": [
            [old[0], item[1], item[2]] for old, item in zip(targets, checked)
        ]}
    devices = {}
    for entry in raw["devices"]:
        required = {"id", "profile", "regions", "schedule"}
        if not isinstance(entry, dict) or not required <= entry.keys() <= required | {"key"}:
            raise ValueError("同步文件内的设备记录无效。")
        key = entry["id"]
        host = entry["profile"]
        if (not isinstance(key, str) or not ID.fullmatch(key) or key in devices
                or not isinstance(host, dict) or set(host) != set(PROFILE_FIELDS)):
            raise ValueError("同步文件内的设备编号或字段无效。")
        if host["auth_mode"] == "key":
            validated = validator({**host, "auth_mode": "alias"})
            if not validated["username"] and "@" not in validated["host"]:
                raise ValueError("私钥设备需要 SSH 用户名。")
            validated["auth_mode"] = "key"
        else:
            validated = validator(host)
        choices = entry["regions"]
        schedule = entry["schedule"]
        if (not isinstance(choices, list) or len(choices) > 8
                or any(not isinstance(item, str) or item not in preset_ids | regions.keys() for item in choices)
                or len(set(choices)) != len(choices) or not isinstance(schedule, dict)
                or set(schedule) != {"interval_seconds", "packets"}):
            raise ValueError("同步文件内的测速设置无效。")
        validate_schedule(False, schedule["interval_seconds"], schedule["packets"])
        device = {**entry, "profile": profile(validated)}
        if "key" in device:
            if validated["auth_mode"] != "key":
                raise ValueError("同步文件内的私钥与认证方式不一致。")
            decode_key(device["key"])
        devices[key] = device
    return {"version": 1, "devices": list(devices.values()), "regions": list(regions.values()),
            "metric_display": raw["metric_display"]}


class DashboardSync:
    def __init__(self, inventory, lock, directory, validator, max_hosts, unavailable):
        self.inventory = inventory
        self.db = inventory.db
        self.lock = lock
        self.directory = directory
        self.validator = validator
        self.max_hosts = max_hosts
        self.unavailable = unavailable
        self.operations = Lock()
        self.pending = {}
        self.expiry = None
        with self.db:
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_sync_ids (
                    host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
                    sync_id TEXT NOT NULL UNIQUE
                )
            """)
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_webdav_auto (
                    id INTEGER PRIMARY KEY CHECK(id=1), config TEXT NOT NULL, credential TEXT NOT NULL,
                    due REAL NOT NULL, last REAL, message TEXT NOT NULL DEFAULT '',
                    kind TEXT NOT NULL DEFAULT '', lease TEXT, lease_until REAL,
                    local_digest TEXT, remote_digest TEXT
                )
            """)

    def snapshot(self, key_ids=()):
        entries = self.inventory.entries()
        mapping = dict(self.db.execute("SELECT host_id,sync_id FROM dashboard_sync_ids"))
        selections = {}
        for host_id, region_id in self.db.execute(
                "SELECT host_id,region_id FROM outbound_region_selections ORDER BY position"):
            selections.setdefault(host_id, []).append(region_id)
        schedules = {host_id: {"interval_seconds": interval, "packets": packets}
                     for host_id, interval, packets in self.db.execute(
                         "SELECT host_id,interval_seconds,packets FROM outbound_schedules")}
        devices = {}
        for host_id, (_, host) in entries.items():
            saved = {"id": mapping.get(host_id, host_id), "profile": profile(host),
                     "regions": selections.get(host_id, []),
                     "schedule": schedules.get(host_id, {"interval_seconds": 900, "packets": 5})}
            if host_id in key_ids:
                if host.get("auth_mode") != "key" or not host.get("identity_file"):
                    raise ValueError("所选设备的本机私钥不可用，请重新勾选。")
                saved["key"] = encode_key(host["identity_file"])
            devices[host_id] = saved
        if set(key_ids) - devices.keys():
            raise ValueError("所选设备已不存在，请重新勾选。")
        regions = [{"id": region_id, "name": name, "targets": json.loads(targets)}
                   for region_id, name, targets in self.db.execute("SELECT id,name,targets FROM outbound_regions")]
        return {"version": 1, "devices": list(devices.values()), "regions": regions,
                "metric_display": self.inventory.metric_display()}, devices, entries

    def plan(self, remote):
        local, devices, entries = self.snapshot()
        ids = {device["id"]: key for key, device in devices.items()}
        targets = {}
        for key, device in devices.items():
            targets.setdefault(target(device["profile"]), []).append(key)
        paired = set()
        new_targets = set()
        changes = []
        summary = dict(added=0, updated=0, unchanged=0, keys=0, skipped_keys=0, settings=0, conflicts=[])
        for incoming in remote["devices"]:
            name = incoming["profile"]["name"]
            host_id = ids.get(incoming["id"])
            if host_id is None:
                matches = targets.get(target(incoming["profile"]), ())
                if len(matches) > 1:
                    raise ValueError("本机有多个连接匹配「" + name + "」。请先整理设备清单。")
                if matches:
                    host_id = matches[0]
            if host_id in paired:
                raise ValueError("备份内有多个设备匹配同一本机连接，请先整理备份。")
            if host_id is not None:
                paired.add(host_id)
            else:
                destination = target(incoming["profile"])
                if destination in new_targets:
                    raise ValueError("备份内有重复的 SSH 连接，请先整理备份。")
                new_targets.add(destination)
            current = devices.get(host_id)
            existing = entries[host_id][1] if host_id else {}
            differed = current is not None and any(current[field] != incoming[field]
                                                    for field in ("profile", "regions", "schedule"))
            restore_key = False
            key_matches = False
            if "key" in incoming:
                key_path = existing.get("identity_file")
                if not key_path:
                    restore_key = True
                else:
                    try:
                        key_matches = encode_key(key_path) == incoming["key"]
                    except ValueError:
                        pass
                    if not key_matches:
                        differed = restore_key = True
                    else:
                        summary["skipped_keys"] += 1
            if differed:
                summary["conflicts"].append(name)
            category = "added" if current is None else "updated" if (
                differed or restore_key or current["id"] != incoming["id"]
            ) else "unchanged"
            summary[category] += 1
            summary["keys"] += restore_key
            changes.append((host_id, existing, incoming, differed, restore_key, key_matches))
        if len(entries) + summary["added"] > self.max_hosts:
            raise ValueError("应用后会超过设备数量上限。")
        local_regions = {region["id"]: region for region in local["regions"]}
        for region in remote["regions"]:
            old = local_regions.get(region["id"])
            if old != region:
                summary["settings"] += 1
            if old and old != region:
                summary["conflicts"].append("测速地区 · " + region["name"])
        if len(local_regions.keys() | {row["id"] for row in remote["regions"]}) > MAX_CUSTOM_REGIONS:
            raise ValueError("应用后会超过自定义测速地区上限。")
        if local["metric_display"] != remote["metric_display"]:
            summary["settings"] += 1
            summary["conflicts"].append("指标显示")
        return local, entries, changes, local_regions, summary

    @staticmethod
    def check_destinations(entries, changes, resolution):
        destinations = {key: target(host) for key, (_, host) in entries.items()}
        changed = set()
        for host_id, existing, incoming, differed, _, _ in changes:
            if host_id and differed and resolution == "local":
                continue
            destination = target(incoming["profile"])
            if not existing or destination != target(existing):
                key = host_id or "new:" + incoming["id"]
                changed.add(key)
                destinations[key] = destination
        used = {}
        for key, destination in destinations.items():
            previous = used.setdefault(destination, key)
            if previous != key and (previous in changed or key in changed):
                raise ValueError("同步后有两台设备使用相同的 SSH 连接。请保留本机版本或先整理设备清单。")

    def apply(self, remote, before, resolution, *, expected_auto=None):
        created = []
        try:
            with self.lock, self.db:
                self.db.execute("BEGIN IMMEDIATE")
                if expected_auto is not None:
                    keys, expected_digest = expected_auto
                    if local_digest(self._auto_snapshot(keys)) != expected_digest:
                        raise WebDAVConflict("本机设置已变更，请手动预览。")
                local, entries, changes, local_regions, summary = self.plan(remote)
                if local != before[0] or entries != before[1] or summary != before[2]:
                    raise ValueError("本机设置已变化，请重新预览后再应用。")
                self.check_destinations(entries, changes, resolution)
                if resolution == "local":
                    summary["unchanged"] += sum(differed for _, _, _, differed, _, _ in changes)
                    summary["updated"] -= sum(differed for _, _, _, differed, _, _ in changes)
                    summary["keys"] = sum(restore_key and not differed for _, _, _, differed, restore_key, _ in changes)
                    summary["settings"] = sum(region["id"] not in local_regions for region in remote["regions"])
                for region in remote["regions"]:
                    if resolution == "remote" or region["id"] not in local_regions:
                        self.db.execute("""
                            INSERT INTO outbound_regions VALUES (?, ?, ?)
                            ON CONFLICT(id) DO UPDATE SET name=excluded.name,targets=excluded.targets
                        """, (region["id"], region["name"], json.dumps(region["targets"])))
                if resolution == "remote":
                    self.db.execute("""
                        INSERT INTO dashboard_preferences VALUES ('metric_display', ?)
                        ON CONFLICT(name) DO UPDATE SET value=excluded.value
                    """, (remote["metric_display"],))
                for host_id, existing, incoming, differed, restore_key, key_matches in changes:
                    if host_id and differed and resolution == "local":
                        self.bind(host_id, incoming["id"])
                        continue
                    new = host_id is None
                    host_id = host_id or uuid4().hex
                    host = {**incoming["profile"], "known_hosts": "", "identity_file": ""}
                    same_target = bool(existing) and connection_identity(existing) == connection_identity(host)
                    same_auth = existing.get("auth_mode") == host["auth_mode"]
                    if same_target:
                        host["known_hosts"] = existing.get("known_hosts", "")
                    if same_target and same_auth:
                        for field in ("identity_file", "credential_id", "credential_fingerprint"):
                            if field in existing:
                                host[field] = existing[field]
                    if key_matches:
                        host["identity_file"] = existing["identity_file"]
                    if restore_key:
                        key = private_file(self.directory, decode_key(incoming["key"]))
                        created.append(key)
                        host["identity_file"] = str(key)
                    data = json.dumps(host, allow_nan=False)
                    if new:
                        self.db.execute("INSERT INTO hosts VALUES (?, ?, ?)", (host_id, uuid4().hex, data))
                    elif host != existing:
                        self.db.execute("UPDATE hosts SET revision=?,data=? WHERE id=?", (uuid4().hex, data, host_id))
                    self.bind(host_id, incoming["id"])
                    self.db.execute("DELETE FROM outbound_region_selections WHERE host_id=?", (host_id,))
                    self.db.executemany("INSERT INTO outbound_region_selections VALUES (?, ?, ?)",
                                        ((host_id, key, index) for index, key in enumerate(incoming["regions"])))
                    self.db.execute("""
                        INSERT INTO outbound_schedules(host_id,enabled,interval_seconds,packets) VALUES (?,0,?,?)
                        ON CONFLICT(host_id) DO UPDATE SET interval_seconds=excluded.interval_seconds,
                            packets=excluded.packets
                    """, (host_id, incoming["schedule"]["interval_seconds"], incoming["schedule"]["packets"]))
        except (OSError, sqlite3.Error, subprocess.SubprocessError):
            for path in created:
                path.unlink(missing_ok=True)
            raise ValueError("无法在本机保存同步设置或私钥。") from None
        except BaseException:
            for path in created:
                path.unlink(missing_ok=True)
            raise
        return summary

    def bind(self, host_id, sync_id):
        self.db.execute("""
            INSERT INTO dashboard_sync_ids VALUES (?, ?)
            ON CONFLICT(host_id) DO UPDATE SET sync_id=excluded.sync_id
        """, (host_id, sync_id))

    def _clear_pending(self, ticket):
        with self.operations:
            self.pending.pop(ticket, None)

    def remember_folder(self, url, dedicated=False):
        try:
            with self.lock, self.db:
                self.db.executemany("""
                    INSERT INTO dashboard_preferences(name,value) VALUES (?,?)
                    ON CONFLICT(name) DO UPDATE SET value=excluded.value
                """, (("webdav_folder", url), ("webdav_dedicated_folder", str(int(dedicated)))))
        except sqlite3.Error:
            pass

    def folder(self):
        row = self.db.execute("SELECT value FROM dashboard_preferences WHERE name='webdav_folder'").fetchone()
        return row[0] if row else ""

    def dedicated_folder(self):
        row = self.db.execute("SELECT value FROM dashboard_preferences WHERE name='webdav_dedicated_folder'").fetchone()
        return row[0] == "1" if row else None

    def auto_state(self):
        row = self.db.execute("""
            SELECT config,due,last,message,kind,lease_until FROM dashboard_webdav_auto WHERE id=1
        """).fetchone()
        if not row:
            return {"mode": "off", "available": vault_available()}
        raw, due, last, message, kind, lease_until = row
        settings = json.loads(raw)
        return {"mode": settings["mode"], "interval_minutes": settings["interval_minutes"], "url": settings["url"],
                "dedicated_folder": settings["dedicated_folder"], "key_ids": list(settings["keys"]),
                "next_at": schedule_time(due) if kind != "conflict" else None, "last_at": schedule_time(last),
                "message": message, "kind": "running" if lease_until and lease_until > time() else kind,
                "running": bool(lease_until and lease_until > time()),
                "available": vault_available()}

    def _assert_auto_idle(self):
        if self.db.execute("SELECT 1 FROM dashboard_webdav_auto WHERE id=1 AND lease_until>?", (time(),)).fetchone():
            raise ValueError("正在自动同步，请等本轮完成后再操作。")

    def _auto_control(self, action):
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._assert_auto_idle()
            if action == "auto_run":
                changed = self.db.execute("""
                    UPDATE dashboard_webdav_auto SET due=?,kind='',message='已安排立即同步。' WHERE id=1
                """, (time(),))
                if not changed.rowcount:
                    raise ValueError("请先保存自动同步设置。")
                return self.auto_state()
            old = self.db.execute("SELECT credential FROM dashboard_webdav_auto WHERE id=1").fetchone()
            self.db.execute("DELETE FROM dashboard_webdav_auto WHERE id=1")
        discard_secret(old[0] if old else None)
        return self.auto_state()

    def _save_auto(self, body, url, dedicated, secret, dav):
        mode = body.get("mode")
        interval = body.get("interval_minutes")
        if mode not in ("upload", "sync") or type(interval) is not int or interval not in AUTO_INTERVALS:
            raise ValueError("自动同步模式或间隔无效。")
        if not vault_available():
            raise ValueError("自动同步需要 Windows 凭据管理器。")
        if len(secret["passphrase"]) < 12 or len(secret["passphrase"]) > 512:
            raise ValueError("同步密码须为 12 至 512 个字符。")
        key_ids = self._key_ids(body)
        with self.lock:
            self._assert_auto_idle()
            _, devices, _ = self.snapshot(key_ids)
        stored = dav.download()
        if stored:
            validate_archive(decrypt_archive(stored[0], secret["passphrase"]), self.validator, self.max_hosts)
        else:
            dav.test()
        keys = {host: digest(decode_key(devices[host]["key"])) for host in key_ids}
        settings = {"mode": mode, "interval_minutes": interval, "url": url, "dedicated_folder": dedicated, "keys": keys}
        new = save_password(json.dumps(secret, ensure_ascii=False))
        try:
            with self.lock, self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self._assert_auto_idle()
                old = self.db.execute("""
                    SELECT config,credential,local_digest,remote_digest FROM dashboard_webdav_auto WHERE id=1
                """).fetchone()
                baselines = (None, None)
                if old:
                    prior = json.loads(old[0])
                    if prior["url"] == url and prior["dedicated_folder"] == dedicated and prior["keys"] == keys:
                        baselines = old[2:]
                self.db.execute("""
                    INSERT OR REPLACE INTO dashboard_webdav_auto
                        (id,config,credential,due,message,local_digest,remote_digest)
                    VALUES (1,?,?,?,'已安排首次自动同步。',?,?)
                """, (json.dumps(settings), new, time(), *baselines))
        except BaseException:
            discard_secret(new)
            raise
        discard_secret(old[1] if old else None)
        self.remember_folder(url, dedicated)
        with self.lock:
            return self.auto_state()

    def tick(self):
        if self.unavailable() or not self.operations.acquire(blocking=False):
            return
        try:
            with self.lock, self.db:
                now = time()
                self.db.execute("BEGIN IMMEDIATE")
                row = self.db.execute("""
                    SELECT config,credential,local_digest,remote_digest FROM dashboard_webdav_auto
                    WHERE id=1 AND kind<>'conflict' AND due<=? AND (lease_until IS NULL OR lease_until<=?)
                """, (now, now)).fetchone()
                if not row:
                    return
                settings = json.loads(row[0])
                lease = uuid4().hex
                due = now + settings["interval_minutes"] * 60
                self.db.execute("""
                    UPDATE dashboard_webdav_auto SET lease=?,lease_until=?,due=? WHERE id=1
                """, (lease, now + AUTO_LEASE_SECONDS, due))
            local, remote = row[2:]
            try:
                local, remote, message = self._automatic_round(settings, row[1], local, remote)
                kind = "success"
            except WebDAVConflict as error:
                kind, message = "conflict", str(error)
            except CredentialError:
                kind, message = "conflict", "自动同步凭据不可用，请重新输入并保存设置。"
            except ValueError as error:
                kind, message = "error", str(error)
            except (OSError, sqlite3.Error):
                kind, message = "error", "自动同步未完成，请检查本机存储。"
            with self.lock, self.db:
                self.db.execute("""
                    UPDATE dashboard_webdav_auto SET last=?,message=?,kind=?,local_digest=?,remote_digest=?,
                        lease=NULL,lease_until=NULL WHERE id=1 AND lease=?
                """, (time(), message, kind, local, remote, lease))
        finally:
            self.operations.release()

    def _auto_snapshot(self, key_consent):
        try:
            with self.lock:
                snapshot, devices, _ = self.snapshot(key_consent)
        except ValueError as error:
            raise WebDAVConflict("所选 SSH 私钥不可用，请检查后重新保存自动同步设置。") from error
        for host, expected in key_consent.items():
            if digest(decode_key(devices[host]["key"])) != expected:
                raise WebDAVConflict("所选 SSH 私钥已变更，请检查后重新保存自动同步设置。")
        return snapshot

    def _automatic_round(self, settings, credential, prior_local, prior_remote):
        saved = read_password(credential)
        if not saved:
            raise CredentialError("Missing sync credential")
        secret = json.loads(saved)
        dav = WebDAV(settings["url"], secret["username"], secret["password"],
                     dedicated_folder=settings["dedicated_folder"])
        passphrase = secret["passphrase"]
        keys = settings["keys"]
        snapshot = self._auto_snapshot(keys)
        current_local = local_digest(snapshot)
        stored = dav.download()
        if stored is None:
            if prior_remote is not None:
                raise WebDAVConflict("云端同步文件已被移除，请手动确认后重新上传。")
            encrypted = self._write_snapshot(dav, snapshot, passphrase, None)
            return current_local, digest(encrypted), "已自动加密上传。"
        encrypted, _ = stored
        current_remote = digest(encrypted)
        if prior_remote == current_remote and prior_local == current_local:
            return current_local, current_remote, "两端暂无新变更。"
        remote = validate_archive(decrypt_archive(encrypted, passphrase), self.validator, self.max_hosts)
        if prior_remote == current_remote:
            self.merge_for_upload(snapshot, remote)
            encrypted = self._write_snapshot(dav, snapshot, passphrase, stored)
            return current_local, digest(encrypted), "已自动加密上传。"
        with self.lock:
            snapshot = self._auto_snapshot(keys)
            current_local = local_digest(snapshot)
            local, entries, changes, _, plan = self.plan(remote)
            if prior_remote is None:
                if not any(plan[field] for field in ("added", "updated", "settings", "keys")) and all(
                    archive_ids(snapshot, field) == archive_ids(remote, field) for field in ("devices", "regions")
                ):
                    return current_local, current_remote, "两端设置已对齐。"
                raise WebDAVConflict("首次同步发现两端设置不同，请下载并预览后手动应用或上传。")
            if settings["mode"] != "sync" or current_local != prior_local:
                raise WebDAVConflict("云端已变更，请下载并预览后手动处理。")
            if any(archive_ids(local, field) - archive_ids(remote, field) for field in ("devices", "regions")):
                raise WebDAVConflict("云端少了设备或测速地区，请手动确认。")
            if any(restore_key for _, _, _, _, restore_key, _ in changes):
                raise WebDAVConflict("云端私钥变更，请手动预览并确认。")
            try:
                self.apply(remote, (local, entries, plan), "remote", expected_auto=(keys, current_local))
            except ValueError as error:
                raise WebDAVConflict("无法自动应用云端变更，请手动预览。 " + str(error)) from None
            return local_digest(self._auto_snapshot(keys)), current_remote, "已自动下载并应用云端变更。"

    def _key_ids(self, body):
        ids = body.get("key_ids", [])
        if (not isinstance(ids, list) or len(ids) > self.max_hosts
                or any(not isinstance(key, str) or not ID.fullmatch(key) for key in ids)
                or len(set(ids)) != len(ids)):
            raise ValueError("私钥选择无效。")
        return ids

    @staticmethod
    def merge_for_upload(snapshot, remote):
        remote_devices = {device["id"]: device for device in remote["devices"]}
        snapshot["regions"] = list({
            **{region["id"]: region for region in remote["regions"]},
            **{region["id"]: region for region in snapshot["regions"]},
        }.values())
        device_ids = set()
        for entry in snapshot["devices"]:
            device_ids.add(entry["id"])
            prior = remote_devices.get(entry["id"])
            if (prior and "key" in prior and "key" not in entry and entry["profile"]["auth_mode"] == "key"
                    and connection_identity(prior["profile"]) == connection_identity(entry["profile"])):
                entry["key"] = prior["key"]
        if remote_devices.keys() - device_ids:
            raise WebDAVConflict("云端有本机未导入的设备。请先从云端预览并恢复设备。")

    def _write_snapshot(self, dav, snapshot, passphrase, stored):
        checked = validate_archive(snapshot, self.validator, self.max_hosts)
        encrypted = encrypt_archive(checked, passphrase)
        dav.upload(encrypted, stored[1] if stored else None, create=stored is None)
        return encrypted

    def _matching_auto(self, url, dedicated):
        row = self.db.execute("SELECT config FROM dashboard_webdav_auto WHERE id=1").fetchone()
        if row:
            config = json.loads(row[0])
            if config["url"] == url and config["dedicated_folder"] == dedicated:
                return row[0], config
        return None

    def _auto_baseline(self, url, dedicated, *, applied_remote=None):
        matched = self._matching_auto(url, dedicated)
        if not matched:
            return None
        raw, config = matched
        try:
            snapshot = self._auto_snapshot(config["keys"])
        except WebDAVConflict:
            return None
        has_local_additions = applied_remote is not None and any(
            archive_ids(snapshot, field) - archive_ids(applied_remote, field) for field in ("devices", "regions")
        )
        return raw, config, None if has_local_additions else local_digest(snapshot)

    def _update_auto_baseline(self, baseline, encrypted_digest):
        if not baseline:
            return
        raw, config, checked = baseline
        with self.lock, self.db:
            self.db.execute("""
                UPDATE dashboard_webdav_auto
                SET local_digest=?,remote_digest=?,due=?,kind='success',message='已按手动同步结果继续自动同步。'
                WHERE id=1 AND config=? AND (lease_until IS NULL OR lease_until<=?)
            """, (checked, encrypted_digest, time() + config["interval_minutes"] * 60, raw, time()))

    def shutdown(self):
        with self.operations:
            if self.expiry:
                self.expiry.cancel()
            self.pending.clear()

    def request(self, body, envelope):
        action = body.get("action")
        if action not in ("test", "preview", "apply", "upload", "auto_save", "auto_run", "auto_disable"):
            raise ValueError("WebDAV 操作无效。")
        if not self.operations.acquire(blocking=False):
            raise ValueError("已有同步操作正在运行，请稍后重试。")
        try:
            return self._request(action, body, envelope)
        finally:
            self.operations.release()

    def _request(self, action, body, envelope):
        if self.unavailable():
            raise ValueError("请先退出演示模式。")
        if action in ("auto_run", "auto_disable"):
            if set(body) != {"action"}:
                raise ValueError("自动同步操作参数无效。")
            return self._auto_control(action)
        ticket = body.get("ticket")
        previous = self.pending.get(ticket) if isinstance(ticket, str) else None
        if previous and previous["expires"] <= monotonic():
            previous = None
        if action == "apply":
            resolution = body.get("resolution", "local")
            if (set(body) - {"action", "ticket", "resolution"} or not previous
                    or previous["applied"] or resolution not in ("local", "remote")):
                raise ValueError("请重新预览并选择应用方式。")
            with self.lock:
                self._assert_auto_idle()
                result = self.apply(previous["remote"], previous["local"], resolution)
                baseline = self._auto_baseline(
                    previous["url"], previous["dedicated"], applied_remote=previous["remote"],
                ) if resolution == "remote" else None
            self._update_auto_baseline(baseline, previous["digest"])
            previous.pop("remote")
            previous.pop("local")
            previous["applied"] = True
            return {**result, "conflicts": []}

        fields = {"action", "url", "password_box"}
        optional = {"dedicated_folder"}
        if action == "auto_save":
            fields |= {"mode", "interval_minutes"}
            optional.add("key_ids")
        if action == "upload":
            optional |= {"key_ids", "ticket"}
        if not fields <= body.keys() <= fields | optional:
            raise ValueError("WebDAV 操作参数无效。")
        url = clean_text(body, "url", 1200)
        dedicated = body.get("dedicated_folder", False)
        secret = envelope.decrypt_json({"host": "webdav", "username": body["url"], "port": None,
                                        "auth_mode": "password", "known_hosts": "",
                                        "password_box": body["password_box"]}, "webdav-" + action)
        if set(secret) != {"username", "password", "passphrase"} or not all(isinstance(x, str) for x in secret.values()):
            raise ValueError("加密的同步凭据格式无效。")
        dav = WebDAV(url, secret["username"], secret["password"], dedicated_folder=dedicated)
        if action == "test":
            result = dav.test()
            self.remember_folder(url, dedicated)
            return result
        if action == "auto_save":
            return self._save_auto(body, url, dedicated, secret, dav)
        passphrase = secret["passphrase"]
        stored = dav.download()
        if action == "preview":
            if stored is None:
                raise ValueError("这个文件夹还没有同步备份，可以先上传。")
            encrypted, etag = stored
            remote = validate_archive(decrypt_archive(encrypted, passphrase), self.validator, self.max_hosts)
            with self.lock:
                local, entries, _, _, result = self.plan(remote)
            new_ticket = uuid4().hex
            if self.expiry:
                self.expiry.cancel()
            self.pending = {new_ticket: {"url": url, "dedicated": dedicated, "etag": etag, "digest": digest(encrypted),
                                         "remote": remote, "local": (local, entries, result),
                                         "applied": not any(result[k] for k in ("added", "updated", "keys", "settings")),
                                         "expires": monotonic() + TICKET_SECONDS}}
            if self.pending[new_ticket]["applied"]:
                self.pending[new_ticket].pop("remote")
                self.pending[new_ticket].pop("local")
            self.expiry = Timer(TICKET_SECONDS, self._clear_pending, args=(new_ticket,))
            self.expiry.daemon = True
            self.expiry.start()
            self.remember_folder(url, dedicated)
            return {**result, "ticket": new_ticket}

        key_ids = self._key_ids(body)
        remote = None
        if stored is not None:
            encrypted, etag = stored
            if (not previous or previous["url"] != url or previous["dedicated"] != dedicated or not previous["applied"]
                    or previous["digest"] != digest(encrypted) or previous["etag"] != etag):
                raise WebDAVConflict("云端已有同步文件或内容已更新。请重新预览并应用后再上传。")
            remote = validate_archive(decrypt_archive(encrypted, passphrase), self.validator, self.max_hosts)
        with self.lock:
            self._assert_auto_idle()
            snapshot, _, _ = self.snapshot(key_ids)
            baseline = self._auto_baseline(url, dedicated)
        if remote is not None:
            self.merge_for_upload(snapshot, remote)
        encrypted = self._write_snapshot(dav, snapshot, passphrase, stored)
        self.pending.clear()
        self.remember_folder(url, dedicated)
        self._update_auto_baseline(baseline, digest(encrypted))
        return {"devices": len(snapshot["devices"]), "keys": sum("key" in entry for entry in snapshot["devices"])}
