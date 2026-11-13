"""Authenticate to a verified SSH host using a password from the local panel."""

from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from contextlib import contextmanager
from hashlib import sha256
import logging
import errno
import os
from pathlib import Path
from queue import Empty, Queue
import re
import socket
import subprocess
from threading import BoundedSemaphore, Thread, Timer
from time import monotonic, sleep

import vps_ops
from dashboard_password_crypto import prepare_password_dependencies


TEST_TIMEOUT = 10
PASSWORD_PROMPT = re.compile(r"(?:password(?: for [A-Za-z0-9_.@-]+)?|密码)[:：]?", re.IGNORECASE)
DNS_SLOTS = BoundedSemaphore(8)
TRANSPORT_LOG_NAME = "vps_ops.password_transport"
TRANSPORT_LOG = logging.getLogger(TRANSPORT_LOG_NAME)
TRANSPORT_LOG.addHandler(logging.NullHandler())
TRANSPORT_LOG.propagate = False
DISABLED_ALGORITHMS = {
    "ciphers": ["aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"],
    "macs": ["hmac-md5", "hmac-md5-96", "hmac-sha1-96"],
}


class PasswordSSHError(Exception):
    def __init__(self, status, message, *, fingerprint=None):
        super().__init__(message)
        self.diagnostic = {"ok": False, "status": status, "message": message, "latency_ms": None}
        if fingerprint is not None:
            self.diagnostic["fingerprint"] = fingerprint


def remaining(deadline):
    time_left = deadline - monotonic()
    if time_left <= 0:
        raise TimeoutError
    return time_left


def known_hosts_files(host):
    if host.get("known_hosts"):
        return [Path(host["known_hosts"])]
    user_directory = Path.home() / ".ssh"
    system_directory = (
        Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ssh"
        if os.name == "nt"
        else Path("/etc/ssh")
    )
    return [
        user_directory / "known_hosts",
        user_directory / "known_hosts2",
        system_directory / "ssh_known_hosts",
        system_directory / "ssh_known_hosts2",
    ]


def lookup_host_keys(host, hostname, port, deadline):
    """Use OpenSSH's own hostname-pattern and hashed-host matching."""
    host_entry = hostname if port == 22 else f"[{hostname}]:{port}"
    known = {}
    revoked = set()
    try:
        keygen = vps_ops.executable("ssh-keygen")
        for path in known_hosts_files(host):
            if not path.exists():
                continue
            if not path.is_file():
                raise OSError
            result = subprocess.run(
                [keygen, "-F", host_entry, "-f", str(path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=remaining(deadline),
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if result.returncode not in (0, 1) or result.stderr:
                raise OSError
            for line in result.stdout.splitlines():
                fields = line.split()
                if not fields or fields[0].startswith(b"#"):
                    continue
                marker = fields.pop(0) if fields[0].startswith(b"@") else b""
                if len(fields) < 3 or marker not in (b"", b"@revoked"):
                    continue
                _, key_type, data = fields[:3]
                blob = b64decode(data, validate=True)
                if marker == b"@revoked":
                    revoked.add(blob)
                else:
                    known.setdefault(key_type.decode("ascii"), set()).add(blob)
    except (subprocess.TimeoutExpired, TimeoutError):
        raise TimeoutError from None
    except (OSError, UnicodeError, Base64Error, ValueError):
        raise PasswordSSHError("configuration_error", "无法读取本机 SSH 主机指纹记录。请检查 OpenSSH 和 known_hosts。") from None
    return known, revoked


def resolve(hostname, port, deadline):
    # DNS calls have no timeout argument in Python. Cap concurrent lookups and
    # let a stuck system resolver finish without blocking the panel.
    if not DNS_SLOTS.acquire(blocking=False):
        raise TimeoutError
    result = Queue(maxsize=1)

    def lookup():
        try:
            result.put(socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM))
        except OSError as error:
            result.put(error)
        finally:
            DNS_SLOTS.release()

    try:
        Thread(target=lookup, name="vps-ssh-dns", daemon=True).start()
    except RuntimeError:
        DNS_SLOTS.release()
        raise
    try:
        addresses = result.get(timeout=remaining(deadline))
    except Empty:
        raise TimeoutError from None
    if isinstance(addresses, OSError):
        raise addresses
    return addresses


def connect(hostname, port, deadline):
    last_error = OSError("no addresses returned")
    for family, kind, protocol, _, address in resolve(hostname, port, deadline):
        connection = socket.socket(family, kind, protocol)
        try:
            connection.settimeout(remaining(deadline))
            connection.connect(address)
            return connection
        except OSError as error:
            last_error = error
            connection.close()
    raise last_error


def stop_socket(connection):
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    connection.close()


def key_fingerprint(blob):
    return "SHA256:" + b64encode(sha256(blob).digest()).decode("ascii").rstrip("=")


def prefer_known_algorithms(options, known, expected_fingerprint):
    rsa_types = {"rsa-sha2-512", "rsa-sha2-256"}
    pinned_types = {
        key_type for key_type, blobs in known.items()
        if expected_fingerprint and any(key_fingerprint(blob) == expected_fingerprint for blob in blobs)
    }

    def priority(name):
        key_type = "ssh-rsa" if name in rsa_types else name
        return (key_type not in pinned_types, key_type not in known)

    options.key_types = tuple(sorted(options.key_types, key=priority))


def verify_host_key(key, known, revoked, certificate, expected_fingerprint):
    blob = key.asbytes()
    fingerprint = key_fingerprint(blob)
    if blob in revoked:
        raise PasswordSSHError("host_key_changed", "这把 SSH 主机密钥已被标记为撤销。请从服务商控制台核对。",
                               fingerprint=fingerprint)
    if not certificate and blob in known.get(key.get_name(), ()):
        if expected_fingerprint and fingerprint != expected_fingerprint:
            raise PasswordSSHError("host_key_changed", "SSH 主机指纹与保存密码时验证的指纹不同。请核对并重新设置密码。",
                                   fingerprint=fingerprint)
        return fingerprint
    if known:
        raise PasswordSSHError("host_key_changed", "SSH 主机指纹与本机记录不符。请从服务商控制台独立核对。",
                               fingerprint=fingerprint)
    raise PasswordSSHError("host_key_unknown", "SSH 主机指纹尚未确认。请打开 SSH 终端，核对服务商指纹后确认。",
                           fingerprint=fingerprint)


def authenticate(transport, paramiko, username, password, deadline):
    transport.auth_timeout = remaining(deadline)
    try:
        transport.auth_password(username, password, fallback=False)
    except paramiko.BadAuthenticationType as error:
        if "keyboard-interactive" not in error.allowed_types:
            raise PasswordSSHError("authentication_failed", "服务器未启用密码登录。请检查 SSH 配置或使用终端。") from None
        answered = False

        def answer(_title, _instructions, prompts):
            nonlocal answered
            if not prompts:
                return []
            if len(prompts) != 1 or answered or prompts[0][1] or not PASSWORD_PROMPT.fullmatch(prompts[0][0].strip()):
                raise PasswordSSHError("authentication_failed", "服务器需要其他交互验证。请在 SSH 终端登录。")
            answered = True
            return [password]

        transport.auth_timeout = remaining(deadline)
        transport.auth_interactive(username, answer)
    if not transport.is_authenticated():
        raise PasswordSSHError("authentication_failed", "服务器需要其他交互验证。请在 SSH 终端登录。")


@contextmanager
def password_session(host, password, deadline, expected_fingerprint, *, persistent=False):
    try:
        prepare_password_dependencies()
        import paramiko
    except (ImportError, OSError):
        raise PasswordSSHError("dependency_unavailable", "本机缺少密码登录组件 Paramiko。请按插件说明安装。") from None
    embedded, separator, hostname = host["host"].rpartition("@")
    hostname = hostname.lower()
    username = host.get("username") or (embedded if separator else "")
    port = host.get("port") or 22
    stage = "connect"
    try:
        known, revoked = lookup_host_keys(host, hostname, port, deadline)
        with connect(hostname, port, deadline) as connection:
            # Channel exec waits for the server's request acknowledgement.
            # Closing the socket also releases that wait at the deadline.
            watchdog = Timer(remaining(deadline), stop_socket, args=(connection,))
            watchdog.daemon = True
            watchdog.start()
            try:
                with paramiko.Transport(connection, disabled_algorithms=DISABLED_ALGORITHMS) as transport:
                    transport.set_log_channel(TRANSPORT_LOG_NAME)
                    transport.banner_timeout = remaining(deadline)
                    prefer_known_algorithms(transport.get_security_options(), known, expected_fingerprint)
                    transport.start_client(timeout=remaining(deadline))
                    key = transport.get_remote_server_key()
                    fingerprint = verify_host_key(
                        key, known, revoked, "-cert-" in transport.host_key_type, expected_fingerprint,
                    )
                    stage = "authenticate"
                    authenticate(transport, paramiko, username, password, deadline)
                    if persistent:
                        watchdog.cancel()
                    stage = "command"
                    yield transport, fingerprint
            finally:
                watchdog.cancel()
    except PasswordSSHError:
        raise
    except (socket.gaierror, ConnectionRefusedError) as error:
        if isinstance(error, socket.gaierror):
            raise PasswordSSHError("dns_failed", "无法解析 SSH 主机名，请检查设备地址。") from None
        raise PasswordSSHError("port_refused", "SSH 端口拒绝连接，请检查端口和服务。") from None
    except (OSError, EOFError, paramiko.SSHException) as error:
        if isinstance(error, TimeoutError) or monotonic() >= deadline or "timeout" in str(error).lower():
            raise PasswordSSHError("timeout", "SSH 连接超时，请检查网络、端口和服务器。") from None
        if isinstance(error, paramiko.AuthenticationException):
            raise PasswordSSHError("authentication_failed", "SSH 密码认证失败，请检查用户名、密码和服务器设置。") from None
        if isinstance(error, OSError) and error.errno in (errno.EACCES, errno.ENETUNREACH, errno.EHOSTUNREACH):
            raise PasswordSSHError("unreachable", "本机无法到达 SSH 主机，请检查网络和防火墙。") from None
        if stage == "command":
            raise PasswordSSHError("command_failed", "SSH 已登录，但服务器未能执行巡检命令。") from None
        raise PasswordSSHError("connection_failed", "SSH 连接未能完成，请检查网络和服务器 SSH 设置。") from None


def password_diagnostic(host, password, *, expected_fingerprint=None):
    started = monotonic()
    try:
        with password_session(host, password, started + TEST_TIMEOUT, expected_fingerprint) as (_, fingerprint):
            latency = round((monotonic() - started) * 1000)
    except PasswordSSHError as error:
        return error.diagnostic
    return {
        "ok": True, "status": "connected", "message": "SSH 密码认证成功。",
        "latency_ms": latency, "fingerprint": fingerprint,
    }


def password_command(host, password, command, payload, *, timeout, max_output, expected_fingerprint=None):
    started = monotonic()
    deadline = started + timeout
    with password_session(host, password, deadline, expected_fingerprint) as (transport, _):
        with transport.open_session(timeout=remaining(deadline)) as channel:
            channel.settimeout(remaining(deadline))
            channel.exec_command(command)
            channel.sendall(payload)
            channel.shutdown_write()
            output = bytearray()
            while True:
                remaining(deadline)
                if channel.recv_ready():
                    output.extend(channel.recv(min(32768, max_output + 1 - len(output))))
                    if len(output) > max_output:
                        raise PasswordSSHError("command_failed", "服务器返回的巡检数据过长。")
                elif channel.recv_stderr_ready():
                    channel.recv_stderr(32768)
                elif channel.closed:
                    break
                else:
                    sleep(0.02)
            if channel.recv_exit_status() != 0:
                raise PasswordSSHError("command_failed", "SSH 已登录，但服务器未能执行巡检命令。")
    return bytes(output), monotonic() - started
