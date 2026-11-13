#!/usr/bin/env python3
"""Run bounded VPS operations through the local OpenSSH client."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile


HOST_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}"
DESTINATION = re.compile(rf"(?:[A-Za-z0-9_][A-Za-z0-9_.-]{{0,63}}@)?{HOST_NAME}")
UNIT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]{0,254}")
OUTPUT_LIMIT = 65_536
SSH_OPTIONS = (
    "UpdateHostKeys=no",
    "ConnectTimeout=8",
    "ConnectionAttempts=1",
    "ServerAliveInterval=15",
    "ServerAliveCountMax=3",
    "ControlMaster=no",
    "ControlPath=none",
    "ForkAfterAuthentication=no",
    "ForwardAgent=no",
    "ForwardX11=no",
    "PermitLocalCommand=no",
    "RemoteCommand=none",
    "Tunnel=no",
)

STATUS_COMMAND = """export LC_ALL=C
printf 'Host: '; hostname
printf 'Kernel: '; uname -srm
printf 'Time (UTC): '; date -u '+%Y-%m-%d %H:%M:%S'
printf 'Uptime: '; uptime
if command -v nproc >/dev/null 2>&1; then printf 'Visible logical CPUs: '; nproc; fi
printf '\\nMemory\\n'
if command -v free >/dev/null 2>&1; then free -h; else printf 'free unavailable\\n'; fi
if [ -r /sys/fs/cgroup/cgroup.controllers ]; then
    cgroup=$(awk -F: '$1 == "0" && $2 == "" { print $3; exit }' /proc/self/cgroup)
    for field in cpu.max memory.max memory.current; do
        path="/sys/fs/cgroup${cgroup%/}/$field"
        if [ -r "$path" ]; then printf 'cgroup %s: ' "$field"; cat "$path"; fi
    done
fi
printf '\\nFilesystems\\n'
df -h /
if command -v mountpoint >/dev/null 2>&1; then
    for mount in /workspace /data /root/rivermind-data; do
        if mountpoint -q "$mount"; then df -h "$mount"; fi
    done
fi
printf '\\nNVIDIA GPUs\\n'
if command -v nvidia-smi >/dev/null 2>&1; then
    nvidia-smi --query-gpu=index,name,memory.used,memory.total,utilization.gpu,temperature.gpu --format=csv,noheader | head -n 32
else
    printf 'nvidia-smi unavailable\\n'
fi
printf '\\nRunning Docker containers (up to 12)\\n'
if command -v docker >/dev/null 2>&1; then
    docker ps --format '{{.Names}}: {{.Status}}' | head -n 12
else
    printf 'docker unavailable\\n'
fi"""


def matching(pattern: re.Pattern[str], value: str, message: str) -> str:
    if not pattern.fullmatch(value):
        raise argparse.ArgumentTypeError(message)
    return value


def destination(value: str) -> str:
    return matching(DESTINATION, value, "Use [user@]hostname, IPv4 or an SSH alias.")


def forward_host(value: str) -> str:
    return matching(re.compile(HOST_NAME), value, "Use a remote hostname or IPv4 address.")


def service_unit(value: str) -> str:
    return matching(UNIT, value, "Use one exact systemd unit name, without options or glob patterns.")


def bounded_integer(value: str, maximum: int) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Use an integer.") from exc
    if not 1 <= number <= maximum:
        raise argparse.ArgumentTypeError(f"Use a value between 1 and {maximum}.")
    return number


def port(value: str) -> int:
    return bounded_integer(value, 65535)


def remote_file(value: str) -> str:
    if (
        not value.startswith("/")
        or value.endswith("/")
        or value.startswith("//")
        or any(part in {"", ".", ".."} for part in value.split("/")[1:])
        or any(not char.isprintable() or char in "\\*?[]{}" for char in value)
    ):
        raise argparse.ArgumentTypeError("Use an absolute POSIX file path without glob, traversal or control characters.")
    return value


def existing_file(value: str) -> Path:
    path = Path(value).expanduser().absolute()
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"File not found: {path}")
    return path


def known_hosts_file(value: str) -> Path:
    path = existing_file(value)
    if any(not char.isprintable() or char in '"%$' for char in str(path)):
        raise argparse.ArgumentTypeError("The known-hosts path contains OpenSSH expansion or quoting characters.")
    return path


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--ssh-config", type=existing_file, metavar="PATH", help="Use this trusted SSH client configuration.")
    cli.add_argument("--known-hosts", type=known_hosts_file, metavar="PATH", help="Use this existing host key file.")
    cli.add_argument("--port", type=port, metavar="N", help="Override the SSH server port.")
    cli.add_argument("--interactive", action="store_true", help="Let OpenSSH prompt for authentication in your terminal.")
    commands = cli.add_subparsers(dest="command", required=True)

    for name, purpose in (
        ("resolve", "Show selected effective OpenSSH settings without connecting."),
        ("status", "Read host, disk, memory, GPU and Docker status."),
        ("logs", "Read recent journal entries for one systemd unit."),
        ("upload", "Upload one file via SFTP. Existing remote files can be overwritten."),
        ("download", "Download one file via SFTP into a new local file."),
        ("tunnel", "Open one foreground SSH tunnel bound to 127.0.0.1."),
    ):
        command = commands.add_parser(name, help=purpose, description=purpose)
        command.add_argument("host", type=destination)
        if name == "logs":
            command.add_argument("unit", type=service_unit)
            command.add_argument("--lines", type=lambda value: bounded_integer(value, 500), default=50, metavar="N")
        elif name == "upload":
            command.add_argument("local", type=existing_file)
            command.add_argument("remote", type=remote_file)
        elif name == "download":
            command.add_argument("remote", type=remote_file)
            command.add_argument("local", type=Path)
        elif name == "tunnel":
            command.add_argument("local_port", type=port)
            command.add_argument("remote_host", type=forward_host)
            command.add_argument("remote_port", type=port)
    return cli


def executable(name: str) -> str:
    if os.name == "nt":
        name += ".exe"
        system_client = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "OpenSSH" / name
        if system_client.is_file():
            return str(system_client)
    path = os.pathsep.join(item for item in os.get_exec_path() if os.path.isabs(item))
    client = shutil.which(name, path=path)
    if not client or not os.path.isabs(client):
        raise ValueError(f"{name} was not found. Install OpenSSH and put it on your PATH.")
    return client


def client_args(
    args: argparse.Namespace, client: str = "ssh", *, forwards: bool = False, confirm_host: bool = False,
) -> list[str]:
    command = [executable(client)]
    options = [
        f"StrictHostKeyChecking={'ask' if confirm_host else 'yes'}",
        *SSH_OPTIONS, f"BatchMode={'no' if args.interactive else 'yes'}",
    ]
    if args.interactive:
        options.append("NumberOfPasswordPrompts=1")
    options.append(f"ClearAllForwardings={'no' if forwards else 'yes'}")
    if args.ssh_config:
        command.extend(["-F", str(args.ssh_config)])
    if args.port:
        command.extend(["-P" if client == "scp" else "-p", str(args.port)])
    if args.known_hosts:
        options.extend([f'UserKnownHostsFile="{args.known_hosts.as_posix()}"', "GlobalKnownHostsFile=none"])
    for option in options:
        command.extend(["-o", option])
    return command


def display_output(data: bytes) -> None:
    # Remote output may contain terminal escapes or directions embedded in logs.
    shown = data[:OUTPUT_LIMIT].decode("utf-8", errors="replace").replace("\r\n", "\n")
    print("".join(char for char in shown if char.isprintable() or char in "\n\t"), end="")
    if len(data) > OUTPUT_LIMIT:
        print(f"\n[Output truncated at {OUTPUT_LIMIT} bytes.]")


def ssh_config(args: argparse.Namespace) -> dict[str, str]:
    command = [*client_args(args, forwards=True), "-G", "-T", args.host]
    response = subprocess.run(command, stdout=subprocess.PIPE, check=True, timeout=12)
    settings = {}
    for line in response.stdout.decode("utf-8", errors="replace").splitlines():
        key, separator, value = line.partition(" ")
        if separator:
            settings[key.lower()] = value
    return settings


def resolve(args: argparse.Namespace) -> int:
    settings = ssh_config(args)
    for key in ("host", "hostname", "user", "port", "stricthostkeychecking", "batchmode"):
        if key in settings:
            display_output(f"{key}: {settings[key]}\n".encode())
    if any(settings.get(key, "none").lower() != "none" for key in ("proxycommand", "proxyjump")):
        print("jump/proxy: configured")
    return 0


def inspect(args: argparse.Namespace) -> int:
    if args.command == "status":
        remote_command = STATUS_COMMAND
    else:
        unit = shlex.quote(f"--unit={args.unit}")
        remote_command = f"journalctl --no-pager --output=short-iso --lines={args.lines} {unit}"
    command = [*client_args(args), "-T", args.host, remote_command]
    with tempfile.TemporaryFile() as output:
        response = subprocess.run(command, stdout=output, timeout=40)
        output.seek(0)
        display_output(output.read(OUTPUT_LIMIT + 1))
    return response.returncode


def transfer(args: argparse.Namespace) -> int:
    # -s explicitly selects SFTP in OpenSSH scp. Do not enable the legacy protocol.
    command = [*client_args(args, "scp"), "-s", "--"]
    remote = f"{args.host}:{args.remote}"
    if args.command == "upload":
        print("SCP can overwrite an existing remote file. A remote directory receives the local basename.", file=sys.stderr)
        return subprocess.run([*command, str(args.local), remote]).returncode

    target = args.local.expanduser().absolute()
    if os.path.lexists(target):
        raise ValueError(f"Local destination already exists: {target}")
    if not target.parent.is_dir():
        raise ValueError(f"Local destination directory does not exist: {target.parent}")
    with tempfile.TemporaryDirectory(prefix=".vps-ops-", dir=target.parent) as staging:
        temporary = Path(staging) / "payload"
        response = subprocess.run([*command, remote, str(temporary)])
        if response.returncode:
            return response.returncode
        # Windows rename refuses existing destinations. On POSIX, link has that guarantee.
        if os.name == "nt":
            temporary.rename(target)
        else:
            os.link(temporary, target)
    print(f"Downloaded {target}")
    return 0


def tunnel(args: argparse.Namespace) -> int:
    settings = ssh_config(args)
    for option in ("localforward", "remoteforward", "dynamicforward"):
        if option in settings:
            raise ValueError("The SSH configuration already defines forwards. Use an SSH alias without existing forwards.")
    forwarding = f"127.0.0.1:{args.local_port}:{args.remote_host}:{args.remote_port}"
    command = [
        *client_args(args, forwards=True), "-o", "GatewayPorts=no",
        "-o", "ExitOnForwardFailure=yes", "-N", "-T", "-e", "none", "-L", forwarding, args.host,
    ]
    print(f"Starting tunnel {forwarding}. Press Ctrl+C to close it.", file=sys.stderr, flush=True)
    if os.name != "nt":
        # Replace the wrapper so stopping its PID stops the tunnel on Unix.
        os.execv(command[0], command)
    with subprocess.Popen(command) as process:
        try:
            return process.wait()
        except KeyboardInterrupt:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait()
            return 130


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "resolve":
            return resolve(args)
        if args.command in {"status", "logs"}:
            return inspect(args)
        if args.command in {"upload", "download"}:
            return transfer(args)
        return tunnel(args)
    except subprocess.TimeoutExpired as error:
        print(f"OpenSSH did not finish within {error.timeout} seconds.", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        return error.returncode
    except (OSError, ValueError) as error:
        print(f"vps-ops: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
