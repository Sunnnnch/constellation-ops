"""Run regional ICMP checks from the selected Linux VPS over verified SSH."""

from datetime import datetime, timezone
from ipaddress import ip_address
from math import ceil
import os
import re
from shlex import quote
import subprocess
import tempfile

from dashboard_history import utc_string
from dashboard_outbound_regions import DEFAULT_TARGETS
from dashboard_password_ssh import PasswordSSHError, password_command
from dashboard_ssh import command_for, failure, ssh_environment, validate_connection


PACKETS = 5
RETEST_PACKETS = 20
PACKET_OPTIONS = (PACKETS, RETEST_PACKETS)
MIN_SCHEDULE_PACKETS = 1
MAX_SCHEDULE_PACKETS = RETEST_PACKETS
PARALLEL_TARGETS = 12
MAX_OUTPUT = 48 * 1024
MARKER = b"vps-ops-ping\t"
COUNTS = re.compile(rb"(?:^|\t)(\d{1,3}) packets? transmitted,\s*(\d{1,3})(?: packets?)? received\b")
LATENCY = re.compile(rb"(?:^|\t)(?:rtt|round-trip) [^\t=]+ = [0-9.]+/([0-9]{1,6}(?:\.[0-9]{1,8})?)/[0-9.]+")
SCRIPT_START = """LC_ALL=C
export LC_ALL
packets=$1
probe() {
    id=$1
    target=$2
    set -- ping
    case "$target" in
        *:*)
            if command -v ping6 >/dev/null 2>&1; then
                set -- ping6
            else
                set -- ping -6
            fi
            ;;
    esac
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'vps-ops-ping\\t%s\\t127\\t\\n' "$id"
        return
    fi
    report=$("$@" -n -q -c "$packets" -W 2 "$target" 2>&1)
    code=$?
    printf 'vps-ops-ping\\t%s\\t%s\\t%s\\n' "$id" "$code" "$(printf '%s' "$report" | tr '\\n' '\\t')"
}
"""


def build_script(targets, packets=PACKETS):
    if type(packets) is not int or not MIN_SCHEDULE_PACKETS <= packets <= MAX_SCHEDULE_PACKETS:
        raise ValueError("每个测试目标可发 1 至 20 个 Ping 包。")
    lines = [f"set -- {packets}\n", SCRIPT_START]
    for start in range(0, len(targets), PARALLEL_TARGETS):
        lines.extend(f"probe {quote(node_id)} {quote(str(ip_address(target)))} &\n"
                     for node_id, _, target in targets[start:start + PARALLEL_TARGETS])
        lines.append("wait\n")
    return "".join(lines).encode("ascii")


def unavailable_row(node_id, carrier, target, message):
    return {"id": node_id, "carrier": carrier, "target": target, "sent": None, "received": None,
            "loss_percent": None, "latency_ms": None, "status": "unavailable", "message": message}


def outbound_unavailable(message, targets=DEFAULT_TARGETS):
    return {"checked_at": utc_string(datetime.now(timezone.utc)), "error": message,
            "rows": [unavailable_row(*target, message) for target in targets]}


def parse_output(output, targets=DEFAULT_TARGETS, packets=PACKETS):
    if len(output) > MAX_OUTPUT:
        return outbound_unavailable("服务器返回的 Ping 结果过长。", targets)
    reports = {}
    for line in output.splitlines():
        if line.startswith(MARKER):
            fields = line[len(MARKER):].split(b"\t", 2)
            if len(fields) == 3:
                node_id, code, report = fields
                reports[node_id] = (code, report)
    if not reports:
        return outbound_unavailable("SSH 已连接，但服务器没有返回 Ping 结果。", targets)

    rows = []
    for node_id, carrier, target in targets:
        code, report = reports.get(node_id.encode(), (b"", b""))
        counts = COUNTS.search(report) if code in (b"0", b"1") else None
        if counts:
            sent, received = (int(value) for value in counts.groups())
            if 0 <= received <= sent <= packets and sent > 0:
                latency = LATENCY.search(report) if received else None
                status = "success" if received == sent else "partial" if received else "no_reply"
                rows.append({"id": node_id, "carrier": carrier, "target": target, "sent": sent, "received": received,
                             "loss_percent": round((sent - received) / sent * 100, 2),
                             "latency_ms": float(latency[1]) if latency else None, "status": status})
                continue

        if code == b"127":
            message = "服务器未安装 Ping。"
        elif b"operation not permitted" in report.lower() or b"permission denied" in report.lower():
            message = "当前 SSH 用户没有发送 ICMP 的权限。"
        else:
            message = "服务器未能完成这条线路的 Ping。"
        rows.append(unavailable_row(node_id, carrier, target, message))
    return {"checked_at": utc_string(datetime.now(timezone.utc)), "rows": rows}


def _execute(host, password, expected_fingerprint, targets, packets):
    timeout = 14 + ceil(len(targets) / PARALLEL_TARGETS) * (packets + 4)
    try:
        payload = build_script(targets, packets)
        connection = validate_connection(host)
        mode = connection["auth_mode"]
        if mode == "password":
            if password is None:
                return None, "请先在设备设置中保存 SSH 密码，再运行服务器出网检测。"
            output, _ = password_command(
                connection, password, "sh -s", payload, timeout=timeout, max_output=MAX_OUTPUT,
                expected_fingerprint=expected_fingerprint or host.get("credential_fingerprint"),
            )
        else:
            command = [*command_for(connection), "sh -s"]
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                result = subprocess.run(
                    command, input=payload, stdout=stdout, stderr=stderr, timeout=timeout, env=ssh_environment(),
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                if result.returncode:
                    stderr.seek(0)
                    return None, failure(result.returncode, stderr.read(8192), mode)["message"]
                stdout.seek(0)
                output = stdout.read(MAX_OUTPUT + 1)
    except PasswordSSHError as error:
        return None, error.diagnostic["message"]
    except (subprocess.TimeoutExpired, TimeoutError):
        return None, "SSH 或远程 Ping 超时，请检查设备连接后重试。"
    except (OSError, ValueError):
        return None, "无法运行服务器出网检测，请检查设备的 SSH 配置。"
    return output, None


def run_outbound_probe_batch(host, password=None, *, expected_fingerprint=None, regions, packets=PACKETS):
    """Use one verified SSH command for all selected regions."""
    ids_by_address = {}
    for targets in regions.values():
        for _, _, address in targets:
            ids_by_address.setdefault(address, str(len(ids_by_address)))
    targets = tuple((key, "", address) for address, key in ids_by_address.items())
    output, error = _execute(host, password, expected_fingerprint, targets, packets)
    if error is not None:
        return {region_id: outbound_unavailable(error, targets) for region_id, targets in regions.items()}
    result = parse_output(output, targets, packets)
    measured = {row["target"]: row for row in result["rows"]}
    return {
        region_id: {**result, "rows": [{**measured[address], "id": key, "carrier": label} for key, label, address in targets]}
        for region_id, targets in regions.items()
    }
