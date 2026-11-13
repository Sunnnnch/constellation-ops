"""Preset targets and validation for server-originated regional Ping."""

from ipaddress import ip_address
from uuid import uuid4


DEFAULT_REGION_ID = "cn-default"
MAX_CUSTOM_REGIONS = 50
MAX_TARGETS = 6
MAX_LABEL = 60
DEFAULT_TARGETS = (
    ("telecom", "电信", "219.141.140.10"),
    ("unicom", "联通", "210.22.97.1"),
    ("mobile", "移动", "221.179.155.161"),
)
PRESETS = (
    (DEFAULT_REGION_ID, "中国", DEFAULT_TARGETS),
    ("cn-anhui", "安徽（合肥）", (
        ("telecom", "电信", "61.132.163.68"),
        ("unicom", "联通", "218.104.78.2"),
        ("mobile", "移动", "211.138.180.2"),
    )),
    ("cn-shanghai", "上海", (
        ("telecom", "电信", "202.96.209.133"),
        ("unicom", "联通", "210.22.97.1"),
        ("mobile", "移动", "211.136.112.200"),
    )),
    ("uk-london", "英国（伦敦）", (
        ("edis", "EDIS", "46.17.63.250"),
        ("psychz", "Psychz", "108.181.67.248"),
        ("speedypage", "SpeedyPage", "45.139.227.46"),
    )),
    ("us-new-york", "美国（纽约）", (("edis", "EDIS", "158.255.213.100"),)),
    ("jp-tokyo", "日本（东京）", (("edis", "EDIS", "194.68.27.10"),)),
    ("sg-singapore", "新加坡", (("edis", "EDIS", "194.68.26.10"),)),
)


def region_view(region_id, name, targets, *, custom=False):
    return {"id": region_id, "name": name, "custom": custom,
            "targets": [{"id": key, "carrier": label, "target": ip} for key, label, ip in targets]}


def region_targets(region):
    return tuple((target["id"], target["carrier"], target["target"]) for target in region["targets"])


def region_label(value, field):
    value = value.strip() if isinstance(value, str) else ""
    if not 1 <= len(value) <= MAX_LABEL or not value.isprintable():
        raise ValueError(f"请输入 1 至 {MAX_LABEL} 个可显示字符作为{field}。")
    return value


def normalize_target(value):
    if not isinstance(value, str):
        raise ValueError("请输入有效的 IPv4 或 IPv6 地址。")
    value = value.strip()
    if not 1 <= len(value) <= 45 or "%" in value:
        raise ValueError("请输入有效的 IPv4 或 IPv6 地址。")
    try:
        address = ip_address(value)
    except ValueError:
        raise ValueError("请输入有效的 IPv4 或 IPv6 地址。") from None
    address = getattr(address, "ipv4_mapped", None) or address
    if (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified
            or str(address) == "255.255.255.255"):
        raise ValueError("请输入从 VPS 可访问的单播地址。")
    return str(address)


def validate_region_targets(targets, previous=()):
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
        raise ValueError(f"每个自定义地区可添加 1 至 {MAX_TARGETS} 个测试地址。")
    keys = {ip: key for key, _, ip in previous}
    validated = []
    seen = set()
    for row in targets:
        if not isinstance(row, dict) or set(row) != {"carrier", "target"}:
            raise ValueError("测速目标格式无效。")
        label = region_label(row["carrier"], "目标名称")
        target = normalize_target(row["target"])
        if target in seen:
            raise ValueError("同一个地区的测试 IP 不能重复。")
        seen.add(target)
        key = keys.get(target) or uuid4().hex
        validated.append((key, label, target))
    return tuple(validated)
