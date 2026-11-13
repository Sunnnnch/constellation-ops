"""Collect a bounded Linux resource snapshot using a verified OpenSSH host."""

from __future__ import annotations

from datetime import datetime, timezone
import math
import os
import subprocess
import tempfile
import time

from dashboard_password_ssh import PasswordSSHError, password_command
from dashboard_ssh import PASSWORD_ONLY, command_for, failure, ssh_environment, validate_connection


TIMEOUT = 14
MAX_PAYLOAD = 16_384
MAX_SAFE_INTEGER = (1 << 53) - 1
FRAME_START = "VPS_OPS_METRICS_1_BEGIN"
FRAME_END = "VPS_OPS_METRICS_1_END"

PROBE = r"""export LC_ALL=C
read -r started ignored < /proc/uptime || started=
printf 'VPS_OPS_METRICS_1_BEGIN\n'
host_name=$(hostname 2>/dev/null | head -n 1 | cut -c 1-253)
printf 'hostname\t%s\n' "$host_name"
printf 'uptime\t%s\n' "$started"

cgroup=$(awk -F: '$1 == "0" && $2 == "" {print $3; exit}' /proc/self/cgroup 2>/dev/null)
cgroup_dir="/sys/fs/cgroup${cgroup%/}"
if [ -n "$cgroup" ] && [ ! -d "$cgroup_dir" ]; then
    mount_root=$(awk '$5 == "/sys/fs/cgroup" && / - cgroup2 / {print $4; exit}' /proc/self/mountinfo)
    case "$cgroup" in
        "$mount_root") cgroup_dir=/sys/fs/cgroup ;;
        "$mount_root"/*) cgroup_dir="/sys/fs/cgroup${cgroup#"$mount_root"}" ;;
    esac
fi

cpu_ticks() {
    awk '$1 == "cpu" {
        total = 0
        for (i = 2; i <= NF && i <= 9; i++) total += $i
        printf "%.0f %.0f\n", total, $5 + $6
        exit
    }' /proc/stat
}

cgroup_ticks() {
    if [ -n "$cgroup" ] && [ -r "$cgroup_dir/cpu.stat" ]; then
        awk '$1 == "usage_usec" {print $2; exit}' "$cgroup_dir/cpu.stat"
    fi
}

set -- $(cpu_ticks)
total_before=${1:-0}
idle_before=${2:-0}
usage_before=$(cgroup_ticks)
read -r cpu_started ignored < /proc/uptime || cpu_started=
sleep 1
set -- $(cpu_ticks)
total_after=${1:-0}
idle_after=${2:-0}
usage_after=$(cgroup_ticks)
read -r cpu_ended ignored < /proc/uptime || cpu_ended=

quota=
period=
if [ -n "$cgroup" ] && [ -r "$cgroup_dir/cpu.max" ]; then
    read -r quota period < "$cgroup_dir/cpu.max"
fi
awk -v total_before="$total_before" -v idle_before="$idle_before" \
    -v total_after="$total_after" -v idle_after="$idle_after" \
    -v quota="$quota" -v period="$period" -v usage_before="$usage_before" \
    -v usage_after="$usage_after" -v started="$cpu_started" -v ended="$cpu_ended" '
    BEGIN {
        elapsed = ended - started
        total = total_after - total_before
        if (quota ~ /^[0-9]+$/ && quota > 0 && period > 0 && elapsed > 0 &&
            usage_before ~ /^[0-9]+$/ && usage_after ~ /^[0-9]+$/ &&
            usage_after >= usage_before)
            pct = 100 * (usage_after - usage_before) / (elapsed * 1000000 * quota / period)
        else if (total > 0)
            pct = 100 * (total - (idle_after - idle_before)) / total
        else
            exit
        printf "cpu\t%.2f\n", pct < 0 ? 0 : (pct > 100 ? 100 : pct)
    }'

read_cpu_model() {
    awk 'index($0, ":") {
        key = $0
        sub(/:.*/, "", key)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
        key = tolower(key)
        if (key != "model name" && key != "cpu model" && key != "uarch") next

        sub(/^[^:]*:[[:space:]]*/, "")
        if (!NF) next
        if (key == "model name") {model = $0; exit}
        if (!(key in alternate)) alternate[key] = $0
    }
    END {
        if (length(model)) print model
        else if ("cpu model" in alternate) print alternate["cpu model"]
        else if ("uarch" in alternate) print alternate["uarch"]
    }' "$@"
}

cpu_model=$(read_cpu_model /proc/cpuinfo 2>/dev/null)
if [ -z "$cpu_model" ] && command -v lscpu >/dev/null 2>&1; then
    cpu_model=$(lscpu 2>/dev/null | read_cpu_model)
fi
if [ -z "$cpu_model" ]; then
    cpu_model=$(awk '
        /^Processor[[:space:]]*:/ {
            sub(/^[^:]*:[[:space:]]*/, "")
            if (NF) {processor = $0; exit}
        }
        /^CPU implementer[[:space:]]*:/ && $NF ~ /^0x[[:xdigit:]]+$/ && !implementer {
            implementer = $NF
        }
        /^CPU part[[:space:]]*:/ && $NF ~ /^0x[[:xdigit:]]+$/ && !part {part = $NF}
        END {
            if (processor) print processor
            else if (implementer && part) printf "ARM (implementer %s, part %s)\n", implementer, part
        }' /proc/cpuinfo 2>/dev/null)
fi
if [ -n "$cpu_model" ]; then
    printf 'cpu_model\t%.160s\n' "$cpu_model"
fi
awk '
    $1 ~ /^cpu[0-9]+$/ {count++}
    END {if (count) printf "cpu_logical_count\t%d\n", count}
' /proc/stat 2>/dev/null
awk '
    $1 == "Cpus_allowed_list:" && NF == 2 && length($2) <= 4096 {
        printf "cpu_allowed_list\t%s\n", $2
        exit
    }
' /proc/self/status 2>/dev/null

memory_limit=
memory_current=
inactive_file=
if [ -n "$cgroup" ] && [ -r "$cgroup_dir/memory.max" ] && [ -r "$cgroup_dir/memory.current" ]; then
    read -r memory_limit < "$cgroup_dir/memory.max"
    read -r memory_current < "$cgroup_dir/memory.current"
    if [ -r "$cgroup_dir/memory.stat" ]; then
        inactive_file=$(awk '$1 == "inactive_file" {print $2; exit}' "$cgroup_dir/memory.stat")
    fi
fi
awk -v limit="$memory_limit" -v current="$memory_current" -v cache="$inactive_file" '
    $1 == "MemTotal:" {total = $2 * 1024}
    $1 == "MemAvailable:" {available = $2 * 1024; have_available = 1}
    $1 == "MemFree:" || $1 == "Buffers:" || $1 == "Cached:" || $1 == "SReclaimable:" {
        fallback += $2 * 1024
    }
    $1 == "Shmem:" {fallback -= $2 * 1024}
    END {
        if (total <= 0) exit
        if (limit ~ /^[0-9]+$/ && limit > 0 && limit <= total && current ~ /^[0-9]+$/) {
            total = limit
            used = current - cache
        } else {
            used = total - (have_available ? available : fallback)
        }
        printf "memory\t%.0f\t%.0f\n", used < 0 ? 0 : (used > total ? total : used), total
    }' /proc/meminfo

df -Pk / 2>/dev/null | awk 'NR == 2 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
    printf "disk\t%.0f\t%.0f\n", $3 * 1024, $2 * 1024
}'

ipv4_uplinks=$(awk 'NR > 1 && $2 == "00000000" && $1 != "lo" {print $1}' /proc/net/route 2>/dev/null)
ipv6_uplinks=$(awk '$1 ~ /^0+$/ && $2 == "00" && $10 != "lo" {print $10}' /proc/net/ipv6_route 2>/dev/null)
awk -v uplinks="$ipv4_uplinks $ipv6_uplinks" '
    BEGIN {
        n = split(uplinks, interfaces, /[[:space:]]+/)
        for (i = 1; i <= n; i++) {
            if (interfaces[i] != "") {selected[interfaces[i]] = 1; have_selection = 1}
        }
    }
    NR > 2 {
        iface = $1
        sub(/:$/, "", iface)
        if (iface == "lo") next
        if (have_selection && !selected[iface]) next
        if (!have_selection && iface ~ /^(veth|docker|br-|virbr|cni|flannel)/) next
        rx += $2
        tx += $10
        found = 1
    }
    END {
        if (found) printf "network\t%.0f\t%.0f\n", rx, tx
    }' /proc/net/dev 2>/dev/null

if command -v nvidia-smi >/dev/null 2>&1; then
    nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu,temperature.gpu \
        --format=csv,noheader,nounits 2>/dev/null | head -n 16 |
        while IFS= read -r row; do printf 'gpu\t%.512s\n' "$row"; done
fi

read -r finished ignored < /proc/uptime || finished=
awk -v started="$started" -v finished="$finished" 'BEGIN {
    if (started != "" && finished != "" && finished >= started)
        printf "probe_seconds\t%.2f\n", finished - started
}'
printf 'VPS_OPS_METRICS_1_END\n'
"""


def empty_sample(status: str = "unknown", error: str | None = None) -> dict:
    return {
        "status": status,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "latency_ms": None,
        "error": error,
        "hostname": None,
        "uptime_seconds": None,
        "cpu_pct": None,
        "cpu_model": None,
        "cpu_logical_count": None,
        "cpu_available_count": None,
        "memory_used": None,
        "memory_total": None,
        "disk_used": None,
        "disk_total": None,
        "rx_bytes": None,
        "tx_bytes": None,
        "rx_bps": None,
        "tx_bps": None,
        "gpus": [],
    }


def bounded_number(value: str, maximum: float) -> float | None:
    try:
        number = float(value)
    except ValueError:
        return None
    return number if math.isfinite(number) and 0 <= number <= maximum else None


def counter(value: str) -> int | None:
    if not value.isascii() or not value.isdecimal() or len(value) > 20:
        return None
    number = int(value)
    # The dashboard client consumes JSON numbers as IEEE-754 doubles.
    return number if number <= MAX_SAFE_INTEGER else None


def cpu_list_count(value: str) -> int | None:
    """Count the ordered, disjoint CPU IDs and ranges in a Linux affinity list."""
    if not value or len(value) > 4096:
        return None
    count = 0
    previous = -1
    for part in value.split(","):
        first, dash, last = part.partition("-")
        start = counter(first)
        end = counter(last) if dash else start
        if start is None or end is None or start <= previous or end < start:
            return None
        count += end - start + 1
        previous = end
    return count if count <= MAX_SAFE_INTEGER else None


def label(value: str, maximum: int) -> str:
    return "".join(char for char in value if char.isprintable()).strip()[:maximum]


def parse_sample(payload: bytes, elapsed_seconds: float) -> dict:
    if len(payload) > MAX_PAYLOAD:
        return empty_sample(error="服务器返回的巡检数据过长。")
    lines = payload.decode("utf-8", errors="replace").splitlines()
    if lines.count(FRAME_START) != 1 or lines.count(FRAME_END) != 1:
        return empty_sample(error="SSH 已连接，但未收到 Linux 巡检数据。")
    start, end = lines.index(FRAME_START), lines.index(FRAME_END)
    if end <= start:
        return empty_sample(error="服务器返回的巡检数据不完整。")

    sample = empty_sample("online")
    seen = set()
    byte_fields = {
        "memory": ("memory_used", "memory_total"),
        "disk": ("disk_used", "disk_total"),
        "network": ("rx_bytes", "tx_bytes"),
    }
    for line in lines[start + 1:end]:
        field, separator, data = line.partition("\t")
        if not separator:
            continue
        if field == "gpu":
            parts = [part.strip() for part in data.rsplit(",", 4)]
            if len(parts) == 5 and len(sample["gpus"]) < 16:
                name = label(parts[0], 120)
                if name:
                    sample["gpus"].append({
                        "name": name,
                        "used_mib": bounded_number(parts[1], 1 << 30),
                        "total_mib": bounded_number(parts[2], 1 << 30),
                        "utilization_pct": bounded_number(parts[3], 100),
                        "temperature_c": bounded_number(parts[4], 200),
                    })
            continue
        if field in seen:
            continue
        seen.add(field)
        if field == "hostname":
            sample["hostname"] = label(data, 253) or None
        elif field == "uptime":
            sample["uptime_seconds"] = bounded_number(data, 1 << 40)
        elif field == "cpu":
            sample["cpu_pct"] = bounded_number(data, 100)
        elif field == "cpu_model":
            sample["cpu_model"] = label(data.replace("\t", " "), 160) or None
        elif field == "cpu_logical_count":
            sample["cpu_logical_count"] = counter(data) or None
        elif field == "cpu_allowed_list":
            sample["cpu_available_count"] = cpu_list_count(data)
        elif field == "probe_seconds":
            remote_elapsed = bounded_number(data, TIMEOUT)
            if remote_elapsed is not None:
                sample["latency_ms"] = max(0, round((elapsed_seconds - remote_elapsed) * 1000))
        elif field in byte_fields:
            parts = data.split("\t")
            if len(parts) == 2:
                first, second = byte_fields[field]
                sample[first], sample[second] = map(counter, parts)
    return sample


def ssh_error(returncode: int, stderr: bytes) -> dict:
    diagnostic = failure(returncode, stderr, "alias")
    status = diagnostic["status"]
    if status in ("host_key_changed", "host_key_unknown", "authentication_failed", "key_unavailable"):
        return empty_sample("auth_required", diagnostic["message"])
    if status == "command_failed":
        return empty_sample(error="服务器未能运行 Linux 巡检命令。")
    return empty_sample("unreachable", diagnostic["message"])


def collect(host: dict, *, password: str | None = None) -> dict:
    """Return one read-only sample; SSH errors are mapped to safe UI messages."""
    if host.get("auth_mode") == "password":
        if password is None:
            return empty_sample("password_required", PASSWORD_ONLY)
        try:
            output, elapsed = password_command(
                validate_connection(host), password, "sh -s", PROBE.encode("ascii"), timeout=TIMEOUT,
                max_output=MAX_PAYLOAD, expected_fingerprint=host["credential_fingerprint"],
            )
        except PasswordSSHError as error:
            diagnostic = error.diagnostic
            status = diagnostic["status"]
            if status in ("host_key_changed", "host_key_unknown", "host_key_revoked", "authentication_failed"):
                return {**empty_sample("auth_required", diagnostic["message"]), "password_failure": True}
            if status in ("command_failed", "dependency_unavailable", "configuration_error"):
                return empty_sample(error=diagnostic["message"])
            return empty_sample("unreachable", diagnostic["message"])
        except (KeyError, TypeError, ValueError, OSError):
            return empty_sample("auth_required", "密码连接配置无效，请重新编辑设备。")
        return parse_sample(output, elapsed)
    try:
        command = [*command_for(validate_connection(host)), "sh -s"]
    except (TypeError, ValueError, OSError) as error:
        return empty_sample(error=f"SSH 配置无效或本机未安装 OpenSSH。{error}" if isinstance(error, ValueError)
                            else "SSH 配置无效或本机未安装 OpenSSH。")

    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            started = time.monotonic()
            result = subprocess.run(
                command, input=PROBE.encode("ascii"), stdout=stdout, stderr=stderr, timeout=TIMEOUT,
                env=ssh_environment(),
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            elapsed = time.monotonic() - started
            if result.returncode:
                stderr.seek(0)
                return ssh_error(result.returncode, stderr.read(4096))
            stdout.seek(0)
            return parse_sample(stdout.read(MAX_PAYLOAD + 1), elapsed)
    except subprocess.TimeoutExpired:
        return empty_sample("unreachable", "SSH 巡检超时，请检查网络或服务器状态。")
    except OSError:
        return empty_sample(error="本机无法运行 SSH 巡检，请检查 OpenSSH 和运行权限。")
