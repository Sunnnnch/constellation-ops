"""Persistent cadence and bounded history for outbound ICMP measurements."""

from datetime import datetime, timezone
import json

from dashboard_history import utc_string
from dashboard_outbound_probes import MAX_SCHEDULE_PACKETS, MIN_SCHEDULE_PACKETS, PACKETS
from dashboard_outbound_regions import DEFAULT_REGION_ID


DEFAULT_INTERVAL_SECONDS = 900
MIN_INTERVAL_SECONDS = 30
MAX_INTERVAL_SECONDS = 86400
HISTORY_LIMIT = 240
VISIBLE_POINTS = 120
PING_TREND_SECONDS = 60 * 60


def schedule_time(timestamp):
    return None if timestamp is None else utc_string(datetime.fromtimestamp(timestamp, timezone.utc))


def validate_schedule(enabled, interval_seconds, packets):
    if type(enabled) is not bool:
        raise ValueError("请选择是否启用定时测速。")
    if type(interval_seconds) is not int or not MIN_INTERVAL_SECONDS <= interval_seconds <= MAX_INTERVAL_SECONDS:
        raise ValueError(f"测速间隔须为 {MIN_INTERVAL_SECONDS} 至 {MAX_INTERVAL_SECONDS} 秒的整数。")
    if type(packets) is not int or not MIN_SCHEDULE_PACKETS <= packets <= MAX_SCHEDULE_PACKETS:
        raise ValueError(f"每个目标的包数须为 {MIN_SCHEDULE_PACKETS} 至 {MAX_SCHEDULE_PACKETS} 的整数。")


class OutboundSchedule:
    def __init__(self, db):
        self.db = db
        db.execute("""
            CREATE TABLE IF NOT EXISTS outbound_schedules (
                host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
                enabled INTEGER NOT NULL, interval_seconds INTEGER NOT NULL, packets INTEGER NOT NULL,
                due REAL, completed REAL, error TEXT, lease TEXT
            )
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS outbound_schedules_due ON outbound_schedules(due) WHERE enabled=1
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS outbound_region_history (
                id INTEGER PRIMARY KEY,
                host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                region_id TEXT NOT NULL, connection TEXT NOT NULL, source TEXT NOT NULL,
                result TEXT NOT NULL, checked_at TEXT
            )
        """)
        columns = {column[1] for column in db.execute("PRAGMA table_info(outbound_region_history)")}
        if "checked_at" not in columns:
            db.execute("ALTER TABLE outbound_region_history ADD COLUMN checked_at TEXT")
            db.execute("""
                UPDATE outbound_region_history
                SET checked_at=CASE WHEN json_valid(result) THEN json_extract(result, '$.checked_at') END
            """)
        # An older Codex panel can still write to the same local history during an upgrade.
        db.execute("""
            CREATE TRIGGER IF NOT EXISTS outbound_region_history_legacy_time
            AFTER INSERT ON outbound_region_history FOR EACH ROW
            WHEN NEW.checked_at IS NULL AND json_valid(NEW.result)
            BEGIN
                UPDATE outbound_region_history SET checked_at=json_extract(NEW.result, '$.checked_at') WHERE id=NEW.id;
            END
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS outbound_region_history_lookup ON outbound_region_history(host_id, region_id, id DESC)
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS outbound_region_history_recent
            ON outbound_region_history(host_id, region_id, connection, checked_at)
        """)

    def state(self, host_id):
        row = self.db.execute("""
            SELECT enabled, interval_seconds, packets, due, completed, error FROM outbound_schedules WHERE host_id=?
        """, (host_id,)).fetchone()
        enabled, interval, packets, due, completed, error = row or (False, DEFAULT_INTERVAL_SECONDS, PACKETS, None, None, None)
        return {"enabled": bool(enabled), "interval_seconds": interval, "packets": packets,
                "next_at": schedule_time(due), "last_at": schedule_time(completed), "error": error}

    def save(self, host_id, enabled, interval_seconds, packets, now):
        validate_schedule(enabled, interval_seconds, packets)
        if not self.db.execute("SELECT 1 FROM hosts WHERE id=?", (host_id,)).fetchone():
            raise KeyError(host_id)
        self.db.execute("""
            INSERT INTO outbound_schedules (host_id, enabled, interval_seconds, packets, due) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(host_id) DO UPDATE SET enabled=excluded.enabled, interval_seconds=excluded.interval_seconds,
                packets=excluded.packets, due=excluded.due, error=NULL
            WHERE enabled<>excluded.enabled OR interval_seconds<>excluded.interval_seconds OR packets<>excluded.packets
        """, (host_id, int(enabled), interval_seconds, packets, now if enabled else None))

    def due_hosts(self, now, limit):
        return self.db.execute("""
            SELECT host_id, due FROM outbound_schedules AS schedule
            WHERE enabled=1 AND due<=? AND NOT EXISTS (
                SELECT 1 FROM outbound_region_checks WHERE host_id=schedule.host_id AND lease_until>?
            ) ORDER BY due, host_id LIMIT ?
        """, (now, now, limit)).fetchall()

    def due_settings(self, host_id, now):
        return self.db.execute("""
            SELECT interval_seconds, packets FROM outbound_schedules WHERE host_id=? AND enabled=1 AND due<=?
        """, (host_id, now)).fetchone()

    def begin(self, host_id, lease, next_at):
        self.db.execute("UPDATE outbound_schedules SET due=?, lease=? WHERE host_id=?", (next_at, lease, host_id))

    def fail_to_start(self, host_id, revision, due, now, error):
        self.db.execute("""
            UPDATE outbound_schedules SET due=?+interval_seconds, error=?
            WHERE host_id=? AND enabled=1 AND due=? AND EXISTS (SELECT 1 FROM hosts WHERE id=? AND revision=?)
        """, (now, error, host_id, due, host_id, revision))

    def complete(self, host_id, lease, now, error):
        self.db.execute("""
            UPDATE outbound_schedules SET lease=NULL, completed=?, error=? WHERE host_id=? AND lease=?
        """, (now, error, host_id, lease))

    def record(self, host_id, region_id, connection, source, data, *, checked_at):
        self.db.execute("""
            INSERT INTO outbound_region_history (host_id, region_id, connection, source, result, checked_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (host_id, region_id, connection, source, data, checked_at))
        self.db.execute("""
            DELETE FROM outbound_region_history WHERE host_id=? AND region_id=? AND id<(
                SELECT id FROM outbound_region_history WHERE host_id=? AND region_id=? ORDER BY id DESC LIMIT 1 OFFSET ?
            )
        """, (host_id, region_id, host_id, region_id, HISTORY_LIMIT - 1))

    def recent(self, connections, regions, now):
        if not connections:
            return ()
        hosts_sql = ", ".join("(?, ?)" for _ in connections)
        regions_sql = ", ".join("(?)" for _ in regions)
        hosts = [value for target in connections.items() for value in target]
        return self.db.execute(f"""
            WITH targets_hosts(host_id, connection) AS (VALUES {hosts_sql}),
            valid_regions(region_id) AS (VALUES {regions_sql}),
            selections AS (
                SELECT host_id, region_id, connection, position
                FROM targets_hosts
                JOIN outbound_region_selections USING (host_id)
                JOIN valid_regions USING (region_id)
            ),
            targets AS (
                SELECT host_id, region_id, connection, position FROM selections
                UNION ALL
                SELECT host_id, ?, connection, 0 FROM targets_hosts AS host
                WHERE NOT EXISTS (SELECT 1 FROM selections WHERE selections.host_id=host.host_id)
            ),
            ranked AS (
                SELECT targets.host_id, targets.region_id, targets.position, history.checked_at, history.result,
                       schedule.enabled, schedule.interval_seconds,
                       row_number() OVER (
                           PARTITION BY targets.host_id, targets.region_id, substr(history.checked_at, 1, 16)
                           ORDER BY history.checked_at DESC, history.id DESC
                       ) AS minute_rank
                FROM targets
                LEFT JOIN outbound_region_history AS history
                    ON history.host_id=targets.host_id AND history.region_id=targets.region_id
                    AND history.connection=targets.connection AND history.checked_at BETWEEN ? AND ?
                LEFT JOIN outbound_schedules AS schedule ON schedule.host_id=targets.host_id
                WHERE schedule.enabled=1 OR history.checked_at IS NOT NULL
            )
            SELECT host_id, region_id, checked_at, result, enabled, interval_seconds
            FROM ranked WHERE minute_rank=1 ORDER BY host_id, position, checked_at
        """, (*hosts, *regions, DEFAULT_REGION_ID, schedule_time(now - PING_TREND_SECONDS), schedule_time(now)))

    def clear_history(self, region_id):
        self.db.execute("DELETE FROM outbound_region_history WHERE region_id=?", (region_id,))

    def history(self, host_id, connection, region):
        region_id = region["id"]
        stored = self.db.execute("""
            SELECT source, result FROM outbound_region_history WHERE host_id=? AND region_id=? AND connection=? ORDER BY id DESC
        """, (host_id, region_id, connection)).fetchall()
        summary = {item["id"]: {**item, "sent": 0, "received": 0, "samples": 0, "loss_percent": None}
                   for item in region["targets"]}
        points = []
        for index, (source, raw) in enumerate(stored):
            point = json.loads(raw)
            for row in point.get("rows", []):
                target = summary.get(row["id"])
                sent, received = row.get("sent"), row.get("received")
                if (target is None or target["target"] != row["target"] or type(sent) is not int
                        or type(received) is not int or not 0 <= received <= sent or sent == 0):
                    continue
                target["sent"] += sent
                target["received"] += received
                target["samples"] += 1
            if index < VISIBLE_POINTS:
                points.append({**point, "source": source})
        for target in summary.values():
            sent = target["sent"]
            if sent:
                target["loss_percent"] = round((sent - target["received"]) * 100 / sent, 2)
        points.reverse()
        return {"region_id": region_id, "points": points, "summary": list(summary.values()),
                "total_points": len(stored), "history_limit": HISTORY_LIMIT}
