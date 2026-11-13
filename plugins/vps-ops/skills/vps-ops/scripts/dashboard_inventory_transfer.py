"""Transfer portable device profiles between local Constellation Ops inventories."""

from __future__ import annotations

import json
from uuid import uuid4


VERSION = 1
PORTABLE_DEFAULTS = {
    "name": "",
    "host": "",
    "username": "",
    "port": None,
    "group": "",
    "auth_mode": "alias",
    "traffic_limit_gb": None,
    "expires_on": "",
}


def export_inventory(inventory):
    hosts = [
        {field: host.get(field, default) for field, default in PORTABLE_DEFAULTS.items()}
        for _, host in inventory.entries().values()
    ]
    return {"inventory": {"version": VERSION, "hosts": hosts}}


def validated_hosts(payload, validator, max_hosts):
    if not isinstance(payload, dict) or payload.keys() != {"version", "hosts"}:
        raise ValueError("设备清单须包含 version 和 hosts。")
    if type(payload["version"]) is not int or payload["version"] != VERSION:
        raise ValueError("设备清单版本不受支持。")
    rows = payload["hosts"]
    if not isinstance(rows, list) or len(rows) > max_hosts:
        raise ValueError(f"设备清单须为数组，且最多包含 {max_hosts} 台设备。")
    hosts = []
    for number, row in enumerate(rows, 1):
        if not isinstance(row, dict) or not row.keys() <= PORTABLE_DEFAULTS.keys():
            raise ValueError(f"第 {number} 台设备包含不支持的字段。")
        try:
            draft = {**PORTABLE_DEFAULTS, **row}
            if draft["auth_mode"] == "key":
                # Portable profiles never carry a local key path. Keep key mode after
                # validating all fields that ordinary device creation also accepts.
                host = validator({**draft, "auth_mode": "alias"})
                if not (host["username"] or "@" in host["host"]):
                    raise ValueError("请输入远程 SSH 用户名。")
                host["auth_mode"] = "key"
            else:
                host = validator(draft)
        except ValueError as error:
            raise ValueError(f"第 {number} 台设备无效。{error}") from error
        hosts.append(host)
    return hosts


def target(host):
    embedded_user, separator, hostname = host["host"].partition("@")
    if not separator:
        hostname = embedded_user
        embedded_user = ""
    return (hostname.lower().removesuffix("."), host.get("username") or embedded_user, host.get("port") or 22)


def plan(inventory, hosts, max_hosts):
    entries = inventory.entries()
    targets = {target(host) for _, host in entries.values()}
    added = []
    for host in hosts:
        connection = target(host)
        if connection not in targets:
            targets.add(connection)
            added.append(host)
    if len(entries) + len(added) > max_hosts:
        raise ValueError(f"导入后将超过 {max_hosts} 台设备的上限。")
    return added, {"added": len(added), "skipped": len(hosts) - len(added)}


def preview_inventory(inventory, payload, *, validator, max_hosts):
    hosts = validated_hosts(payload, validator, max_hosts)
    _, result = plan(inventory, hosts, max_hosts)
    return result


def import_inventory(inventory, payload, *, validator, max_hosts):
    hosts = validated_hosts(payload, validator, max_hosts)
    with inventory.db:
        # Hold the write reservation while checking capacity and duplicates, including
        # when the browser and native app use separate database connections.
        inventory.db.execute("BEGIN IMMEDIATE")
        added, result = plan(inventory, hosts, max_hosts)
        inventory.db.executemany(
            "INSERT INTO hosts VALUES (?, ?, ?)",
            ((uuid4().hex, uuid4().hex, json.dumps(host)) for host in added),
        )
    return result
