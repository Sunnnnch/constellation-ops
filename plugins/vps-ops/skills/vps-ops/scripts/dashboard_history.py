"""Keep bounded, local histories of completed SSH probes."""

from datetime import datetime, timedelta, timezone
import json
from time import monotonic


WINDOW = 24 * 60 * 60
RECENT_MINUTES = 60
MISSING_IDENTITY = "此设备需要重新选择本机 SSH 私钥。"


def connection_identity(host):
    prefix, separator, hostname = host["host"].rpartition("@")
    alias = host.get("auth_mode", "alias") == "alias"
    port = host.get("port") if alias else host.get("port") or 22
    return json.dumps([alias, hostname.lower().rstrip("."),
                       prefix if separator else host.get("username", ""), port])


def memory_percentage(sample):
    used, total = sample.get("memory_used"), sample.get("memory_total")
    return round(100 * used / total, 2) if used is not None and total and 0 <= used <= total else None


class ProbeHistory:
    def __init__(self, db):
        self.db = db
        self.next_prune = 0
        with db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS probe_history (
                    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                    connection TEXT NOT NULL,
                    minute INTEGER NOT NULL,
                    checked_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    cpu_pct REAL,
                    memory_pct REAL,
                    latency_ms REAL,
                    PRIMARY KEY (host_id, connection, minute)
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS probe_history_expiry ON probe_history(checked_at)")
        self.prune()

    def prune(self):
        if monotonic() < self.next_prune:
            return
        with self.db:
            self.db.execute("DELETE FROM probe_history WHERE checked_at < ?", (history_cutoff(),))
        self.next_prune = monotonic() + 3600

    def record(self, host_id, revision, host, sample):
        self.prune()
        checked_at = sample["checked_at"]
        minute = int(datetime.fromisoformat(checked_at.replace("Z", "+00:00")).timestamp()) // 60
        with self.db:
            self.db.execute("""
                INSERT INTO probe_history (host_id, connection, minute, checked_at, status, cpu_pct, memory_pct, latency_ms)
                SELECT id, ?, ?, ?, ?, ?, ?, ? FROM hosts WHERE id = ? AND revision = ?
                ON CONFLICT (host_id, connection, minute) DO UPDATE SET
                    checked_at = excluded.checked_at,
                    status = excluded.status,
                    cpu_pct = excluded.cpu_pct,
                    memory_pct = excluded.memory_pct,
                    latency_ms = excluded.latency_ms
                WHERE excluded.checked_at >= probe_history.checked_at
            """, (connection_identity(host), minute, checked_at, sample["status"], sample.get("cpu_pct"),
                  memory_percentage(sample), sample.get("latency_ms"), host_id, revision))

    def points(self, host_id, host):
        now = datetime.now(timezone.utc)
        rows = self.db.execute("""
            SELECT checked_at, status, cpu_pct, memory_pct, latency_ms FROM probe_history
            WHERE host_id = ? AND connection = ? AND checked_at BETWEEN ? AND ?
            ORDER BY minute
        """, (host_id, connection_identity(host), history_cutoff(now), utc_string(now)))
        columns = ("checked_at", "status", "cpu_pct", "memory_pct", "latency_ms")
        return [dict(zip(columns, row)) for row in rows]

    def recent_latencies(self, entries):
        histories = {host_id: [] for host_id in entries}
        if not entries:
            return histories
        now = datetime.now(timezone.utc)
        start = now - timedelta(minutes=RECENT_MINUTES)
        targets = ", ".join("(?, ?)" for _ in entries)
        parameters = [
            value
            for host_id, (_, host) in entries.items()
            for value in (host_id, connection_identity(host))
        ]
        rows = self.db.execute(f"""
            WITH targets(host_id, connection) AS (VALUES {targets})
            SELECT history.host_id, history.checked_at,
                   CASE WHEN history.status = 'online' THEN history.latency_ms END
            FROM targets
            JOIN probe_history AS history USING (host_id, connection)
            WHERE history.minute BETWEEN ? AND ? AND history.checked_at BETWEEN ? AND ?
            ORDER BY history.host_id, history.minute
        """, (*parameters, int(start.timestamp()) // 60, int(now.timestamp()) // 60,
              utc_string(start), utc_string(now)))
        for host_id, checked_at, latency_ms in rows:
            histories[host_id].append({"checked_at": checked_at, "latency_ms": latency_ms})
        return histories


def utc_string(when):
    return when.isoformat(timespec="seconds").replace("+00:00", "Z")


def history_cutoff(now=None):
    now = now or datetime.now(timezone.utc)
    return utc_string(now - timedelta(seconds=WINDOW))


def demo_history(sample, *, minutes=1440, now=None):
    now = now or datetime.now(timezone.utc)
    points = []
    offsets = (-3, 2, 0, 5, 1, -2, 2, 6, 3, 1, -1, 2)
    for index in range(1440 - minutes, 1440):
        checked_at = utc_string(now - timedelta(minutes=1439 - index))
        online = sample["status"] == "online" and not 552 <= index < 625
        offset = offsets[index % len(offsets)] if index < 1439 else 0
        points.append({
            "checked_at": checked_at,
            "status": "online" if online else "unreachable",
            "cpu_pct": max(0, min(100, sample["cpu_pct"] + offset)) if online else None,
            "memory_pct": max(0, min(100, memory_percentage(sample) + offset / 2)) if online else None,
            "latency_ms": max(0, sample["latency_ms"] + offset * 5) if online else None,
        })
    return points


def demo_latency_histories(samples):
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    return {
        host_id: [{"checked_at": point["checked_at"], "latency_ms": point["latency_ms"]}
                  for point in demo_history(sample, minutes=RECENT_MINUTES, now=now)]
        for host_id, sample in samples.items()
    }
