"""Validate dashboard SSH settings and run OpenSSH diagnostics or a local terminal."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
from time import monotonic

import vps_ops


AUTH_DEFAULTS = {"username": "", "auth_mode": "alias", "identity_file": ""}
PASSWORD_PROMPT = "服务器提供密码认证。请在本机 SSH 终端输入密码完成登录。"
PASSWORD_ONLY = "此设备尚未记住 SSH 密码。可在编辑设备中输入密码并保存，以启用自动巡检。"
USERNAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
TEST_TIMEOUT = 10
EARLY_EXIT_SECONDS = 5


def clean_text(body, key, maximum, default=""):
    value = body.get(key, default)
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError(f"{key} 必须是 {maximum} 字符以内的文本。")
    if any(not char.isprintable() for char in value):
        raise ValueError(f"{key} 包含控制字符。")
    return value.strip()


def is_local(path):
    # Reject UNC, Windows device paths and alternate data streams.
    return not path.as_posix().startswith("//") and (
        os.name != "nt" or (len(path.drive) == 2 and path.drive[1] == ":" and ":" not in str(path)[2:])
    )


def local_file(value):
    source = Path(value).expanduser()
    if not source.is_absolute() or not is_local(source):
        raise ValueError
    path = source.resolve(strict=True)
    if not is_local(path) or not path.is_file() or any(
        not char.isprintable() or char in '"%$' for char in str(path)
    ):
        raise ValueError
    return path


def identity_file(value):
    try:
        return local_file(value)
    except (OSError, RuntimeError, ValueError) as error:
        raise ValueError("请选择本机存在的 SSH 私钥文件，路径须为本地绝对路径。") from error


def validate_connection(body):
    if not isinstance(body, dict):
        raise ValueError("SSH 配置必须是 JSON 对象。")
    host = clean_text(body, "host", 320)
    username = clean_text(body, "username", 64)
    try:
        vps_ops.destination(host)
        if username:
            vps_ops.matching(USERNAME, username, "Invalid SSH username.")
    except argparse.ArgumentTypeError as error:
        raise ValueError("请输入有效的 SSH 主机和用户名。主机可使用别名、域名、IPv4 或 user@hostname。") from error
    if username and "@" in host and username != host.split("@", 1)[0]:
        raise ValueError("用户名与主机地址中填写的用户名不同。")
    mode = body.get("auth_mode", "alias")
    if mode not in ("alias", "key", "password"):
        raise ValueError("SSH 认证方式无效。")
    if mode != "alias" and not (username or "@" in host):
        raise ValueError("请输入远程 SSH 用户名。")
    port = body.get("port")
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("SSH 端口须为 1–65535。")
    known_hosts = clean_text(body, "known_hosts", 512)
    if known_hosts:
        try:
            known_hosts = str(vps_ops.known_hosts_file(known_hosts) if mode == "alias" else local_file(known_hosts))
        except (argparse.ArgumentTypeError, OSError, RuntimeError, ValueError) as error:
            raise ValueError("请选择本机已验证且存在的 known_hosts 文件。") from error
    key = clean_text(body, "identity_file", 1024)
    return {
        "host": host, "username": username, "port": port, "known_hosts": known_hosts,
        "auth_mode": mode, "identity_file": str(identity_file(key)) if mode == "key" else "",
    }


def command_for(host, *, interactive=False, log_level="ERROR"):
    options = argparse.Namespace(
        interactive=interactive, ssh_config=None,
        known_hosts=Path(host["known_hosts"]) if host["known_hosts"] else None,
        port=host["port"],
    )
    command = vps_ops.client_args(options, confirm_host=interactive)
    # Block unattended DNS-based trust and preserve the local fingerprint prompt.
    command.extend([
        "-o", "VerifyHostKeyDNS=no", "-o", "NoHostAuthenticationForLocalhost=no",
        "-o", "SessionType=default", "-o", "StdinNull=no",
    ])
    mode = host["auth_mode"]
    if mode != "alias":
        command.extend(["-F", "none"])
    if mode == "key":
        command.extend([
            "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey",
            "-i", host["identity_file"],
        ])
    elif mode == "password":
        command.extend([
            "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive",
        ])
    target = host["host"]
    if host["username"] and "@" not in target:
        target = f"{host['username']}@{target}"
    if interactive:
        command.extend(["-o", "EscapeChar=none", "-tt"])
    else:
        command.extend(["-T", "-o", f"LogLevel={log_level}"])
    return [*command, target]


def diagnostic(status, message, *, latency_ms=None):
    return {"ok": status == "connected", "status": status, "message": message, "latency_ms": latency_ms}


def failure(returncode, stderr, mode):
    error = stderr.decode("utf-8", errors="replace").lower()
    if any(marker in error for marker in ("remote host identification has changed", "offending", "host key has changed")):
        return diagnostic("host_key_changed", "SSH 主机指纹已变更。请从服务商控制台独立核对新指纹，确认后再更新 known_hosts。")
    if "host key verification failed" in error or "host key is known" in error:
        return diagnostic("host_key_unknown", "SSH 主机指纹尚未确认。请打开终端，对照服务商提供的指纹后确认。")
    if any(marker in error for marker in (
        "bad permissions", "unprotected private key file", "error in libcrypto", "invalid format", "not accessible:",
    )):
        return diagnostic("key_unavailable", "OpenSSH 无法使用所选私钥，请检查文件、格式和访问权限。")
    if re.search(r"connect to host [^\r\n]+: (permission denied|operation not permitted)", error):
        return diagnostic("unreachable", "本机拒绝建立 SSH 网络连接，请检查网络访问权限或防火墙。")
    if "permission denied" in error or "no supported authentication methods" in error:
        # OpenSSH prints the methods offered by the server at the end of this line.
        offered = re.search(r"permission denied \(([a-z0-9,\-]+)\)\.", error)
        methods = set(offered[1].split(",")) if offered else set()
        if mode == "password" and methods.intersection({"password", "keyboard-interactive"}):
            return diagnostic("password_required", PASSWORD_PROMPT)
        if mode == "password":
            return diagnostic("authentication_failed", "服务器未提供可用的密码认证，请检查 SSH 账号和服务端认证设置。")
        return diagnostic("authentication_failed", "SSH 认证失败，请核对用户名、密钥授权和 ssh-agent 状态。")
    if "could not resolve hostname" in error or "name or service not known" in error:
        return diagnostic("dns_failed", "无法解析 SSH 主机名，请检查地址或 SSH 别名。")
    if "connection refused" in error:
        return diagnostic("port_refused", "SSH 端口拒绝连接，请检查端口号和远程 SSH 服务。")
    if "timed out" in error:
        return diagnostic("timeout", "SSH 连接超时，请检查网络、端口和服务端防火墙。")
    if "no route to host" in error or "network is unreachable" in error:
        return diagnostic("unreachable", "本机无法到达 SSH 主机，请检查网络路由。")
    if returncode != 255:
        return diagnostic("command_failed", "SSH 已到达远端，远端未能完成诊断命令。")
    return diagnostic("connection_failed", "SSH 连接失败，请检查服务器状态和本机 OpenSSH 配置。")


def ssh_environment():
    return {**os.environ, "SSH_ASKPASS_REQUIRE": "never", "LC_ALL": "C"}


def test_connection(host):
    host = validate_connection(host)
    try:
        # Windows OpenSSH can report refused connections only in its verbose diagnostics.
        command = command_for(host, log_level="DEBUG1")
    except (OSError, ValueError):
        return diagnostic("configuration_error", "本机无法启动 OpenSSH，请检查安装和配置。")
    try:
        with tempfile.TemporaryFile() as stderr:
            started = monotonic()
            result = subprocess.run(
                [*command, "exit"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr,
                timeout=TEST_TIMEOUT, env=ssh_environment(),
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if result.returncode:
                stderr.seek(0)
                return failure(result.returncode, stderr.read(8192), host["auth_mode"])
            elapsed_ms = round((monotonic() - started) * 1000)
            return diagnostic("connected", "SSH 连接及认证成功。", latency_ms=elapsed_ms)
    except subprocess.TimeoutExpired:
        return diagnostic("timeout", "SSH 诊断超时，请检查网络、端口和服务器状态。")
    except OSError:
        return diagnostic("configuration_error", "本机无法运行 SSH，请检查 OpenSSH 和运行权限。")


def fingerprint_command(host):
    command = command_for(host, interactive=True)
    return [command[0], "-o", "PreferredAuthentications=none", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no", *command[1:], "exit"]


def open_terminal(host, *, verify_host=False):
    host = validate_connection(host)
    try:
        command = fingerprint_command(host) if verify_host else command_for(host, interactive=True)
        if os.name != "nt":
            return {"ok": True, "status": "manual_terminal", "message": "请在本机终端运行此命令。",
                    "command": shlex.join(command)}
        # The child owns its console and keeps errors visible. No shell interprets its arguments.
        subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--verify-host" if verify_host else "--terminal", json.dumps(host)],
            creationflags=subprocess.CREATE_NEW_CONSOLE, close_fds=True, env=ssh_environment(),
        )
    except (OSError, ValueError):
        return diagnostic("configuration_error", "无法启动本机 SSH 终端，请检查 OpenSSH 和运行权限。")
    message = ("请在终端核对并确认指纹，然后回到面板连接。" if verify_host else
               "已打开本机 SSH 终端。请在那里确认指纹或输入密码。")
    return {"ok": True, "status": "launched", "message": message}


def terminal_main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("--terminal", "--verify-host"):
        return 2
    verify_host = sys.argv[1] == "--verify-host"
    exit_code = 1
    try:
        host = validate_connection(json.loads(sys.argv[2]))
        command = fingerprint_command(host) if verify_host else command_for(host, interactive=True)
        print("首次连接时，请先通过服务商控制台独立核对终端显示的 SSH 指纹。", flush=True)
        if verify_host:
            print("此窗口只用于核对指纹。确认后请回面板连接。", flush=True)
        started = monotonic()
        result = subprocess.run(command, env=ssh_environment())
        exit_code = result.returncode
        if exit_code == 0 and not verify_host and monotonic() - started >= EARLY_EXIT_SECONDS:
            return 0
        if verify_host:
            print("如已确认并保存指纹，请回到星图再点连接。")
        else:
            print(f"SSH 已退出（代码 {exit_code}）。")
    except (OSError, ValueError):
        print("无法启动本机 OpenSSH，请检查设备配置和 OpenSSH 安装。")
    except KeyboardInterrupt:
        return 130
    try:
        input("按 Enter 键关闭窗口。")
    except (EOFError, KeyboardInterrupt):
        pass
    return exit_code


if __name__ == "__main__":
    raise SystemExit(terminal_main())
