"""Save device region selections and track server-originated checks."""

from concurrent.futures import ThreadPoolExecutor
import json
from math import isfinite
from time import time
from uuid import uuid4

from dashboard_history import connection_identity
from dashboard_outbound_probes import PACKETS, PACKET_OPTIONS, outbound_unavailable, run_outbound_probe_batch
from dashboard_outbound_regions import (
    DEFAULT_REGION_ID, MAX_CUSTOM_REGIONS, PRESETS, region_label, region_targets, region_view, validate_region_targets,
)
from dashboard_outbound_schedule import OutboundSchedule, PING_TREND_SECONDS, schedule_time


MAX_CONCURRENT = 4
LEASE_SECONDS = 150
MAX_SELECTED_REGIONS = 8
MAX_SELECTED_HOSTS = 100


def validate_ids(values, maximum, message):
    if (not isinstance(values, list) or not 1 <= len(values) <= maximum
            or any(not isinstance(value, str) or not 1 <= len(value) <= 80 for value in values)
            or len(set(values)) != len(values)):
        raise ValueError(message)


def region_result(region, row, now):
    result = json.loads(row[2]) if row and row[2] else {}
    previous = {item["id"]: item for item in result.get("rows", [])}
    rows = []
    for target in region["targets"]:
        measured = previous.get(target["id"])
        if measured and measured["target"] == target["target"]:
            rows.append({**measured, **target})
        else:
            rows.append({**target, "sent": None, "received": None, "loss_percent": None,
                         "latency_ms": None, "status": None})
    running = bool(row and row[0] and row[1] > now)
    error = "上一次检测已中断，请重新开始。" if row and row[0] and not running else result.get("error")
    return {"checked_at": result.get("checked_at"), "error": error, "rows": rows, "running": running,
            "region_id": region["id"]}


def ping_series(region, interval_seconds):
    labels = [target["carrier"] for target in region["targets"]]
    return [{
        "id": region["id"] + ":" + target["id"],
        "label": f'{region["name"]} · {carrier}' + (f' · {target["target"]}' if labels.count(carrier) > 1 else ""),
        "carrier": carrier,
        "interval_seconds": interval_seconds,
        "points": [],
    } for target, carrier in zip(region["targets"], labels)]


def demo_ping_histories(samples):
    region = region_view(*PRESETS[0])
    minute = 60
    now = int(time()) // minute * minute
    output = {}
    for host_index, (host_id, sample) in enumerate(samples.items()):
        if sample["status"] != "online":
            output[host_id] = {"scheduled": False, "series": []}
            continue
        series = ping_series(region, minute)
        for line_index, line in enumerate(series):
            for index in range(PING_TREND_SECONDS // minute):
                checked_at = schedule_time(now - PING_TREND_SECONDS + (index + 1) * minute)
                value = 105 + 25 * host_index + 38 * line_index + (index * (line_index + 3)) % 19
                line["points"].append({"checked_at": checked_at,
                                       "latency_ms": None if 30 + line_index <= index < 33 + line_index else value})
        output[host_id] = {"scheduled": True, "series": series}
    return output


class OutboundChecks:
    def __init__(self, db, lock):
        self.db = db
        self.lock = lock
        self.closed = False
        self.pool = ThreadPoolExecutor(max_workers=MAX_CONCURRENT, thread_name_prefix="vps-outbound-check")
        with lock, db:
            db.execute("BEGIN IMMEDIATE")
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            db.execute("""
                CREATE TABLE IF NOT EXISTS outbound_regions (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, targets TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS outbound_region_checks (
                    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                    region_id TEXT NOT NULL, connection TEXT NOT NULL, lease TEXT,
                    lease_until REAL NOT NULL, result TEXT,
                    PRIMARY KEY(host_id, region_id)
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS outbound_region_selections (
                    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                    region_id TEXT NOT NULL, position INTEGER NOT NULL,
                    PRIMARY KEY(host_id, region_id)
                )
            """)
            if "outbound_region_checks" not in tables and "outbound_checks" in tables:
                db.execute("""
                    INSERT INTO outbound_region_checks (host_id, region_id, connection, lease_until, result)
                    SELECT checks.host_id, ?, checks.connection, 0, checks.result
                    FROM outbound_checks AS checks JOIN hosts ON hosts.id=checks.host_id
                    WHERE checks.result IS NOT NULL
                """, (DEFAULT_REGION_ID,))
            self.schedules = OutboundSchedule(db)

    def _regions(self):
        regions = [region_view(*preset) for preset in PRESETS]
        for region_id, name, targets in self.db.execute("SELECT id,name,targets FROM outbound_regions ORDER BY rowid"):
            regions.append(region_view(region_id, name, json.loads(targets), custom=True))
        return regions

    def _region(self, region_id, regions):
        if region_id is None:
            region_id = DEFAULT_REGION_ID
        for region in regions:
            if region["id"] == region_id:
                return region
        raise ValueError("这个测速地区已不存在，请重新选择地区。")

    def _selected_regions(self, host_id, regions):
        available = {region["id"] for region in regions}
        rows = self.db.execute("""
            SELECT region_id FROM outbound_region_selections WHERE host_id=? ORDER BY position
        """, (host_id,))
        return [region_id for (region_id,) in rows if region_id in available] or [DEFAULT_REGION_ID]

    def _validate_regions(self, region_ids, regions):
        validate_ids(region_ids, MAX_SELECTED_REGIONS, f"请选择 1 至 {MAX_SELECTED_REGIONS} 个不同的测速地区。")
        return [self._region(region_id, regions) for region_id in region_ids]

    def selection_options(self):
        with self.lock:
            return {"regions": self._regions(), "max_selected_regions": MAX_SELECTED_REGIONS}

    def save_selection(self, host_ids, region_ids):
        validate_ids(host_ids, MAX_SELECTED_HOSTS, f"请选择 1 至 {MAX_SELECTED_HOSTS} 台不同的设备。")
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._validate_regions(region_ids, self._regions())
            placeholders = ",".join("?" for _ in host_ids)
            available = {host_id for (host_id,) in self.db.execute(
                f"SELECT id FROM hosts WHERE id IN ({placeholders})", host_ids,
            )}
            if set(host_ids) != available:
                raise ValueError("部分所选设备已不存在，请重新选择设备。")
            self.db.execute(f"DELETE FROM outbound_region_selections WHERE host_id IN ({placeholders})", host_ids)
            self.db.executemany("INSERT INTO outbound_region_selections VALUES (?, ?, ?)",
                                ((host_id, region_id, position) for host_id in host_ids
                                 for position, region_id in enumerate(region_ids)))
        return len(host_ids)

    def state(self, host_id, host, region_id=None, *, region_ids=None):
        with self.lock:
            regions = self._regions()
            selected = self._selected_regions(host_id, regions)
            showing = self._validate_regions(selected if region_ids is None else region_ids, regions)
            focus = self._region(region_id, regions) if region_id is not None else showing[0]
            if focus not in showing:
                showing.append(focus)
            connection = connection_identity(host)
            checks = self.db.execute("""
                SELECT region_id, connection, lease, lease_until, result FROM outbound_region_checks WHERE host_id=?
            """, (host_id,)).fetchall()
            schedule = self.schedules.state(host_id)
        now = time()
        results = {key: (lease, lease_until, result) for key, identity, lease, lease_until, result in checks
                   if identity == connection}
        active = [key for key, _, lease, lease_until, _ in checks if lease and lease_until > now]
        region_results = {region["id"]: region_result(region, results.get(region["id"]), now) for region in showing}
        return {**region_results[focus["id"]], "regions": regions, "selected_region_ids": selected,
                "region_results": list(region_results.values()), "batch_running": bool(active),
                "active_region_ids": active, "max_selected_regions": MAX_SELECTED_REGIONS, "schedule": schedule}

    def schedule_state(self, host_id):
        with self.lock:
            return self.schedules.state(host_id)

    def save_schedule(self, host_id, enabled, interval_seconds, packets):
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self.schedules.save(host_id, enabled, interval_seconds, packets, time())
        return self.schedule_state(host_id)

    def history(self, host_id, host, region_id):
        with self.lock:
            region = self._region(region_id, self._regions())
            return self.schedules.history(host_id, connection_identity(host), region)

    def recent_pings(self, entries):
        histories = {host_id: {"scheduled": False, "series": []} for host_id in entries}
        if not entries:
            return histories
        connections = {host_id: connection_identity(host) for host_id, (_, host) in entries.items()}
        with self.lock:
            regions = {region["id"]: region for region in self._regions()}
            rows = self.schedules.recent(connections, regions, time())
            series_by_region = {}
            for host_id, region_id, checked_at, raw, enabled, interval in rows:
                history = histories[host_id]
                history["scheduled"] = bool(enabled)
                region = regions[region_id]
                key = (host_id, region_id)
                if key not in series_by_region:
                    series = ping_series(region, interval if enabled else None)
                    series_by_region[key] = series
                    history["series"].extend(series)
                if checked_at is None:
                    continue
                try:
                    result = json.loads(raw)
                    measured = {(row["id"], row["target"]): row for row in result.get("rows", [])}
                except (AttributeError, KeyError, TypeError, ValueError):
                    measured = {}
                for target, series in zip(region["targets"], series_by_region[key]):
                    row = measured.get((target["id"], target["target"]), {})
                    value = row.get("latency_ms")
                    if (row.get("status") not in ("success", "partial")
                            or type(value) not in (int, float) or not isfinite(value) or value < 0):
                        value = None
                    series["points"].append({"checked_at": checked_at, "latency_ms": value})
        return histories

    def refresh_schedules(self, entries, credentials):
        now = time()
        with self.lock:
            if self.closed:
                return
            due = self.schedules.due_hosts(now, MAX_CONCURRENT)
            if not due:
                return
            inventory = entries() if callable(entries) else entries
        for host_id, due_at in due:
            entry = inventory.get(host_id)
            if entry is None:
                continue
            revision, host = entry
            try:
                password, fingerprint = credentials(host)
            except ValueError as error:
                with self.lock, self.db:
                    self.schedules.fail_to_start(host_id, revision, due_at, time(), str(error))
                continue
            self._queue_batch(host_id, revision, host, password, fingerprint, None, None, scheduled=True)

    def _reject_active_region(self, region_id):
        if self.db.execute("SELECT 1 FROM outbound_region_checks WHERE region_id=? AND lease_until>? LIMIT 1",
                           (region_id, time())).fetchone():
            raise ValueError("这个地区正在测速，请等本轮结束后再修改。")

    def save_region(self, name, targets, region_id=None):
        name = region_label(name, "地区名称")
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            regions = self._regions()
            if any(item["name"].casefold() == name.casefold() and item["id"] != region_id for item in regions):
                raise ValueError("已有同名测速地区，请填写另一个名称。")
            if region_id is None:
                if sum(item["custom"] for item in regions) >= MAX_CUSTOM_REGIONS:
                    raise ValueError(f"最多可添加 {MAX_CUSTOM_REGIONS} 个自定义地区。")
                validated = validate_region_targets(targets)
                region_id = uuid4().hex
                self.db.execute("INSERT INTO outbound_regions VALUES (?, ?, ?)",
                                (region_id, name, json.dumps(validated, ensure_ascii=False)))
            else:
                region = self._region(region_id, regions)
                if not region["custom"]:
                    raise ValueError("内置地区无法修改，请添加自定义地区。")
                self._reject_active_region(region_id)
                previous = region_targets(region)
                validated = validate_region_targets(targets, previous)
                if {ip for _, _, ip in previous} != {ip for _, _, ip in validated}:
                    self.db.execute("DELETE FROM outbound_region_checks WHERE region_id=?", (region_id,))
                    self.schedules.clear_history(region_id)
                self.db.execute("UPDATE outbound_regions SET name=?, targets=? WHERE id=?",
                                (name, json.dumps(validated, ensure_ascii=False), region_id))
        return region_id

    def delete_region(self, region_id):
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            region = self._region(region_id, self._regions())
            if not region["custom"]:
                raise ValueError("内置地区无法删除。")
            self._reject_active_region(region_id)
            self.db.execute("DELETE FROM outbound_region_checks WHERE region_id=?", (region_id,))
            self.db.execute("DELETE FROM outbound_region_selections WHERE region_id=?", (region_id,))
            self.schedules.clear_history(region_id)
            self.db.execute("DELETE FROM outbound_regions WHERE id=?", (region_id,))
        return DEFAULT_REGION_ID

    def run(self, host_id, revision, host, password, fingerprint, region_id=None):
        region_ids = [DEFAULT_REGION_ID if region_id is None else region_id]
        self.run_batch(host_id, revision, host, password, fingerprint, region_ids)

    def run_batch(self, host_id, revision, host, password, fingerprint, region_ids, *, packets=PACKETS):
        if type(packets) is not int or packets not in PACKET_OPTIONS:
            raise ValueError("请选择每个地址发送 5 或 20 个探测包。")
        self._queue_batch(host_id, revision, host, password, fingerprint, region_ids, packets)

    def _queue_batch(self, host_id, revision, host, password, fingerprint, region_ids, packets, *, scheduled=False):
        connection = connection_identity(host)
        lease = uuid4().hex
        with self.lock:
            if self.closed:
                if scheduled:
                    return
                raise ValueError("面板正在关闭，请重新打开后检测。")
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                current = self.db.execute("SELECT revision FROM hosts WHERE id=?", (host_id,)).fetchone()
                if scheduled and (current is None or current[0] != revision):
                    return
                if current is None:
                    raise KeyError(host_id)
                if current[0] != revision:
                    raise ValueError("设备连接配置已变更，请重新打开详情后检测。")
                now = time()
                available = self._regions()
                if scheduled:
                    settings = self.schedules.due_settings(host_id, now)
                    if settings is None:
                        return
                    interval, packets = settings
                    region_ids = self._selected_regions(host_id, available)
                regions = self._validate_regions(region_ids, available)
                pending = self.db.execute("""
                    SELECT region_id, connection FROM outbound_region_checks WHERE host_id=? AND lease_until>?
                """, (host_id, now)).fetchall()
                if pending:
                    if scheduled or set(pending) == {(region_id, connection) for region_id in region_ids}:
                        return
                    raise ValueError("这台设备正在进行出网检测，请等本轮结束后再检测。")
                count = self.db.execute("SELECT count(DISTINCT lease) FROM outbound_region_checks WHERE lease_until>?",
                                        (now,)).fetchone()[0]
                if count >= MAX_CONCURRENT:
                    if scheduled:
                        return
                    raise ValueError("正在进行的出网检测过多，请稍后再试。")
                self.db.executemany("""
                    INSERT INTO outbound_region_checks (host_id, region_id, connection, lease, lease_until)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(host_id, region_id) DO UPDATE SET connection=excluded.connection,
                        lease=excluded.lease, lease_until=excluded.lease_until,
                        result=CASE WHEN connection=excluded.connection THEN result ELSE NULL END
                """, ((host_id, region_id, connection, lease, now + LEASE_SECONDS) for region_id in region_ids))
                if scheduled:
                    self.schedules.begin(host_id, lease, now + interval)
            targets = {region["id"]: region_targets(region) for region in regions}
            self.pool.submit(self._measure, host_id, lease, connection, host, password, fingerprint, targets, packets, scheduled)

    def _measure(self, host_id, lease, connection, host, password, fingerprint, targets, packets, scheduled):
        try:
            results = run_outbound_probe_batch(host, password, expected_fingerprint=fingerprint,
                                               regions=targets, packets=packets)
        except Exception:
            results = {}
        source = "scheduled" if scheduled else "manual"
        error = None
        with self.lock, self.db:
            for region_id, configured_targets in targets.items():
                result = results.get(region_id)
                if result is None:
                    result = outbound_unavailable("服务器出网检测未能完成，请检查 SSH 连接后重试。", targets=configured_targets)
                data = json.dumps(result, ensure_ascii=False, allow_nan=False)
                saved = self.db.execute("""
                    UPDATE outbound_region_checks SET lease=NULL, lease_until=0, result=?
                    WHERE host_id=? AND region_id=? AND lease=?
                """, (data, host_id, region_id, lease))
                if saved.rowcount:
                    self.schedules.record(host_id, region_id, connection, source, data, checked_at=result["checked_at"])
                    error = error or result.get("error")
            if scheduled:
                self.schedules.complete(host_id, lease, time(), error)

    def shutdown(self):
        with self.lock:
            self.closed = True
        self.pool.shutdown(wait=True)
