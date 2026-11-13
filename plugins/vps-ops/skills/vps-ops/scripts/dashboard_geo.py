"""Offline country lookup for the device list."""

from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from gzip import open as open_gzip
from ipaddress import ip_address
import os
from pathlib import Path
import socket
from struct import Struct
import subprocess
from threading import Lock
from time import monotonic

from dashboard_password_ssh import resolve
from dashboard_ssh import command_for, ssh_environment, validate_connection


DATABASE_PATH = Path(__file__).with_name("country_ranges.gz")
HEADER = Struct("!4sII")
COUNTRY_FORMAT = b"VGC1"
MAX_DATABASE_BYTES = 32 * 1024 * 1024
MAX_CACHE_ENTRIES = 512
MAX_PENDING_LOOKUPS = 128
KNOWN_TTL = 15 * 60
UNKNOWN_TTL = 2 * 60
DESTINATION_FIELDS = ("auth_mode", "host", "username", "port", "known_hosts")


class CountryRanges:
    def __init__(self, path):
        with open_gzip(path, "rb") as file:
            self.data = file.read(MAX_DATABASE_BYTES + 1)
        if not HEADER.size <= len(self.data) <= MAX_DATABASE_BYTES:
            raise ValueError("Unexpected country database size.")
        version, self.ipv4_count, self.ipv6_count = HEADER.unpack_from(self.data)
        self.ipv6_offset = HEADER.size + 10 * self.ipv4_count
        if version != COUNTRY_FORMAT or len(self.data) != self.ipv6_offset + 34 * self.ipv6_count:
            raise ValueError("Unexpected country database format.")

    def lookup(self, ip):
        address = ip.packed
        width = len(address)
        offset, count = (
            (HEADER.size, self.ipv4_count) if width == 4 else (self.ipv6_offset, self.ipv6_count)
        )
        record_size = 2 * width + 2
        start, end = 0, count
        while start < end:
            middle = (start + end) // 2
            index = offset + middle * record_size
            if address < self.data[index:index + width]:
                end = middle
            elif address > self.data[index + width:index + 2 * width]:
                start = middle + 1
            else:
                return self.data[index + 2 * width:index + record_size].decode("ascii")
        return None


@lru_cache(maxsize=1)
def country_database():
    return CountryRanges(DATABASE_PATH)


def country_for_ip(value):
    try:
        address = ip_address(value)
    except ValueError:
        return None
    address = getattr(address, "ipv4_mapped", None) or address
    if not address.is_global or address.is_multicast:
        return None
    try:
        return country_database().lookup(address)
    except (OSError, EOFError, ValueError):
        return None


def effective_destination(host):
    hostname = host["host"].rsplit("@", 1)[-1]
    port = host.get("port") or 22
    if host.get("auth_mode", "alias") != "alias":
        return hostname, port, "any"

    try:
        command = command_for(validate_connection(host))
        result = subprocess.run(
            [*command[:-1], "-G", command[-1]], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, env=ssh_environment(), timeout=4,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return hostname, port, "any"
    if result.returncode:
        return hostname, port, "any"
    settings = {}
    for line in result.stdout.decode("utf-8", errors="replace").splitlines():
        key, _, value = line.partition(" ")
        if key in ("hostname", "port", "addressfamily"):
            settings[key] = value
    return settings.get("hostname", hostname), int(settings.get("port", port)), settings.get("addressfamily", "any")


def lookup_device_country(host):
    try:
        hostname, port, family = effective_destination(host)
        try:
            ip_address(hostname)
        except ValueError:
            pass
        else:
            return country_for_ip(hostname)
        families = {"inet": socket.AF_INET, "inet6": socket.AF_INET6}
        requested_family = families.get(family)
        for candidate_family, _, _, _, address in resolve(hostname, port, monotonic() + 4):
            if requested_family is not None and candidate_family != requested_family:
                continue
            # The first address in the system resolver's connection order represents this endpoint.
            return country_for_ip(address[0])
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


class DeviceGeo:
    def __init__(self):
        self._lock = Lock()
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="vps-geo")
        self._cache = OrderedDict()
        self._pending = set()
        self._closed = False

    def country(self, host):
        """Return an available country code and queue any lookup outside the request."""
        destination = {field: host[field] for field in DESTINATION_FIELDS if field in host}
        key = tuple(destination.get(field) for field in DESTINATION_FIELDS)
        with self._lock:
            current = self._cache.get(key)
            if current is not None:
                self._cache.move_to_end(key)
            if (
                not self._closed and key not in self._pending and len(self._pending) < MAX_PENDING_LOOKUPS
                and (current is None or current[0] <= monotonic())
            ):
                self._pending.add(key)
                self._pool.submit(self._lookup, key, destination)
            return current[1] if current is not None else None

    def _lookup(self, key, host):
        code = None
        try:
            code = lookup_device_country(host)
        finally:
            with self._lock:
                self._pending.discard(key)
                self._cache[key] = (monotonic() + (KNOWN_TTL if code else UNKNOWN_TTL), code)
                self._cache.move_to_end(key)
                if len(self._cache) > MAX_CACHE_ENTRIES:
                    self._cache.popitem(last=False)

    def shutdown(self):
        with self._lock:
            self._closed = True
        self._pool.shutdown(wait=False, cancel_futures=True)
