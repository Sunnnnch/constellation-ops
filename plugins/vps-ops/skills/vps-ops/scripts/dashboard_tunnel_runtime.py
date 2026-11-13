"""Own the SSH transports and loopback listeners for dashboard tunnels."""

from collections import deque
from contextlib import suppress
from ipaddress import IPv6Address
import os
import re
import signal
import socket
import subprocess
from threading import BoundedSemaphore, Event, Lock, Thread, Timer, current_thread
from time import monotonic

from dashboard_password_ssh import PasswordSSHError, password_session
from dashboard_ssh import command_for, failure, ssh_environment


LOOPBACK = "127.0.0.1"
START_TIMEOUT = 14
CHANNEL_TIMEOUT = 5
KEEPALIVE_INTERVAL = 15
KEEPALIVE_TIMEOUT = 30
HOST_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}")
INHERITED_FORWARDS = {b"localforward", b"remoteforward", b"dynamicforward"}
RETRYABLE_SSH_FAILURES = {"dns_failed", "port_refused", "timeout", "unreachable", "connection_failed"}


class TunnelError(ValueError):
    """A failure with a message safe to show in the dashboard."""

    def __init__(self, message, *, retryable=False):
        super().__init__(message)
        self.retryable = retryable


def loopback_socket(local_port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if os.name == "nt":
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LOOPBACK, local_port))
    except OSError:
        listener.close()
        raise
    return listener


def port_available(local_port):
    try:
        with loopback_socket(local_port):
            return True
    except OSError:
        return False


def remote_address(value):
    if not isinstance(value, str):
        raise TunnelError("请输入有效的目标主机名或 IP 地址。")
    if HOST_NAME.fullmatch(value):
        return value
    address = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        normalized = IPv6Address(address)
        if normalized.scope_id and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", normalized.scope_id):
            raise ValueError
        return str(normalized)
    except ValueError:
        raise TunnelError("请输入有效的目标主机名或 IP 地址。") from None


def openssh_command(host):
    command = command_for(host, log_level="DEBUG1")
    command[command.index("ClearAllForwardings=yes")] = "ClearAllForwardings=no"
    command[command.index("SessionType=default")] = "SessionType=none"
    command[-1:-1] = [
        "-N", "-e", "none", "-o", "GatewayPorts=no", "-o", "ControlPersist=no",
        "-o", "ExitOnForwardFailure=yes",
    ]
    return command


def process_options():
    options = {"stdin": subprocess.DEVNULL, "env": ssh_environment()}
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW
    else:
        options["start_new_session"] = True
    return options


def check_cancelled(cancelled):
    if cancelled.is_set():
        raise TunnelError("隧道启动已取消。")


def check_openssh_config(command, deadline, cancelled):
    # ClearAllForwardings also clears the explicit -L, so inspect the resolved
    # configuration first. A dedicated SSH alias can omit inherited forwards.
    with subprocess.Popen(
        [*command[:-1], "-G", command[-1]],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, **process_options(),
    ) as process:
        try:
            while True:
                check_cancelled(cancelled)
                if monotonic() >= deadline:
                    raise TunnelError("读取本机 OpenSSH 配置超时。")
                try:
                    output, _ = process.communicate(timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    continue
        finally:
            if process.poll() is None:
                stop_process(process)
    if process.returncode:
        raise TunnelError("无法读取本机 OpenSSH 配置，请检查 SSH 配置和别名。")
    for line in output.splitlines():
        if line.split(b" ", 1)[0].lower() in INHERITED_FORWARDS:
            raise TunnelError("该 SSH 别名已有端口转发。请选择未配置转发的别名或使用独立设备连接。")


def stop_process(process):
    if process.poll() is None:
        with suppress(OSError):
            if os.name == "nt":
                process.terminate()
            else:
                os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=0.4)
        except subprocess.TimeoutExpired:
            with suppress(OSError):
                if os.name == "nt":
                    process.kill()
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            with suppress(subprocess.TimeoutExpired):
                process.wait(timeout=0.4)


def windows_job(process):
    """Keep the OpenSSH process tree tied to the dashboard process on Windows."""
    import ctypes
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("per_process_time", ctypes.c_int64), ("per_job_time", ctypes.c_int64),
            ("flags", wintypes.DWORD), ("min_working_set", ctypes.c_size_t),
            ("max_working_set", ctypes.c_size_t), ("active_processes", wintypes.DWORD),
            ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD),
        ]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("basic", BasicLimits), ("io", ctypes.c_uint64 * 6),
            ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
            ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
    kernel.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel.CreateJobObjectW(None, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = ExtendedLimits()
    limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):  # Extended limits
        error = ctypes.WinError(ctypes.get_last_error())
        kernel.CloseHandle(handle)
        raise error
    if not kernel.AssignProcessToJobObject(handle, int(process._handle)):
        error = ctypes.WinError(ctypes.get_last_error())
        kernel.CloseHandle(handle)
        raise error
    return lambda: kernel.CloseHandle(handle)


class OpenSSHTunnel:
    def __init__(self, process, mode, local_port, close_job):
        self.process = process
        self.close_job = close_job
        self.mode = mode
        self.local_port = local_port
        self.ready = Event()
        self.finished = Event()
        self.log = deque(maxlen=40)
        self.reader = Thread(target=self.read_stderr, daemon=True)
        self.reader.start()

    def read_stderr(self):
        listener = f"debug1: Local forwarding listening on {LOOPBACK} port {self.local_port}.".encode("ascii")
        listener_requested = False
        try:
            with self.process.stderr as stderr:
                for line in iter(lambda: stderr.readline(4096), b""):
                    self.log.append(line)
                    if line.strip() == listener:
                        listener_requested = True
                    if listener_requested and line.strip() == b"debug1: Entering interactive session.":
                        self.ready.set()
        except (OSError, ValueError):
            pass
        finally:
            self.finished.set()

    def wait_until_ready(self, deadline, cancelled):
        while monotonic() < deadline:
            check_cancelled(cancelled)
            if self.process.poll() is not None:
                self.finished.wait(0.15)
                raise self.exit_error()
            if self.ready.is_set() and not port_available(self.local_port):
                return self
            cancelled.wait(0.05)
        raise TunnelError("SSH 隧道启动超时，请检查 VPS 地址、端口和网络连接。", retryable=True)

    def alive(self):
        return self.process.poll() is None

    def close(self):
        close_job, self.close_job = self.close_job, None
        if close_job is not None:
            close_job()
        stop_process(self.process)
        self.reader.join(timeout=0.2)

    def error(self):
        if self.alive():
            return None
        return str(self.exit_error())

    def exit_error(self):
        code = self.process.poll()
        if code == 0:
            return TunnelError("SSH 隧道已断开。", retryable=True)
        logs = b"".join(self.log.copy())
        normalized = logs.lower()
        if b"address already in use" in normalized:
            return TunnelError("本机端口已被占用。")
        if b"could not request local forwarding" in normalized:
            return TunnelError("无法监听本机端口，请检查端口占用及本机权限。")
        if any(marker in normalized for marker in (
            b"no matching", b"bad configuration option", b"bad owner or permissions",
            b"unknown option", b"bad local forwarding specification",
        )):
            return TunnelError("OpenSSH 配置与此连接不兼容，请检查客户端和 VPS 的 SSH 设置。")
        if self.ready.is_set():
            return TunnelError("SSH 隧道已断开，请检查 VPS 状态和网络连接。", retryable=True)
        diagnostic = failure(code, logs, self.mode)
        return TunnelError(diagnostic["message"], retryable=diagnostic["status"] in RETRYABLE_SSH_FAILURES)


def open_openssh(host, local_port, remote_host, remote_port, cancelled):
    deadline = monotonic() + START_TIMEOUT
    try:
        command = openssh_command(host)
        check_openssh_config(command, deadline, cancelled)
        check_cancelled(cancelled)
        if not port_available(local_port):
            raise TunnelError("本机端口已被占用。")
        address = f"[{remote_host}]" if ":" in remote_host else remote_host
        forwarding = f"{LOOPBACK}:{local_port}:{address}:{remote_port}"
        process = subprocess.Popen(
            [*command[:-1], "-L", forwarding, command[-1]],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **process_options(),
        )
    except TunnelError:
        raise
    except (OSError, ValueError):
        raise TunnelError("本机无法启动 OpenSSH，请检查安装和配置。") from None
    close_job = None
    try:
        if os.name == "nt":
            close_job = windows_job(process)
        tunnel = OpenSSHTunnel(process, host["auth_mode"], local_port, close_job)
    except OSError:
        if close_job is not None:
            close_job()
        stop_process(process)
        raise TunnelError("Windows 无法托管 OpenSSH 隧道进程。") from None
    except BaseException:
        if close_job is not None:
            close_job()
        stop_process(process)
        raise
    try:
        return tunnel.wait_until_ready(deadline, cancelled)
    except BaseException:
        tunnel.close()
        raise


def copy_stream(source, destination, finish_write, closed, ssh_error):
    try:
        while not closed.is_set():
            try:
                data = source.recv(65536)
            except socket.timeout:
                continue
            if not data:
                finish_write()
                return
            pending = memoryview(data)
            while pending and not closed.is_set():
                try:
                    sent = destination.send(pending)
                except socket.timeout:
                    continue
                if not sent:
                    raise OSError
                pending = pending[sent:]
    except (OSError, EOFError, ssh_error):
        closed.set()


class PasswordTunnel:
    def __init__(self, listener, session, transport, target, ssh_error):
        self.listener = listener
        self.session = session
        self.transport = transport
        self.target = target
        self.ssh_error = ssh_error
        self.stopped = Event()
        self.unresponsive = Event()
        self.lock = Lock()
        self.clients = set()
        self.slots = BoundedSemaphore(16)
        self.worker = Thread(target=self.accept, daemon=True)
        self.keepalive = Thread(target=self.check_keepalive, daemon=True)

    def start(self):
        self.worker.start()
        self.keepalive.start()

    def check_keepalive(self):
        # A refusal still proves the server replied. Paramiko's standard
        # keepalive requests no reply, so it cannot detect a silent failure.
        while not self.stopped.wait(KEEPALIVE_INTERVAL) and self.transport.is_active():
            replied = Event()
            watchdog = Timer(KEEPALIVE_TIMEOUT, self.keepalive_timed_out, args=(replied,))
            watchdog.daemon = True
            watchdog.start()
            try:
                self.transport.global_request("keepalive@openssh.com")
            except (OSError, EOFError, self.ssh_error):
                self.close()
                return
            finally:
                replied.set()
                watchdog.cancel()

    def keepalive_timed_out(self, replied):
        if not replied.is_set() and not self.stopped.is_set() and self.transport.is_active():
            self.unresponsive.set()
            self.close()

    def accept(self):
        try:
            while not self.stopped.is_set() and self.transport.is_active():
                try:
                    client, peer = self.listener.accept()
                except socket.timeout:
                    continue
                if not self.slots.acquire(blocking=False):
                    client.close()
                    continue
                with self.lock:
                    if self.stopped.is_set():
                        client.close()
                        self.slots.release()
                        return
                    self.clients.add(client)
                try:
                    Thread(target=self.forward, args=(client, peer), daemon=True).start()
                except RuntimeError:
                    client.close()
                    with self.lock:
                        self.clients.discard(client)
                    self.slots.release()
        except OSError:
            pass
        finally:
            self.close()

    def forward(self, client, peer):
        try:
            client.settimeout(0.25)
            with self.transport.open_channel("direct-tcpip", self.target, peer, timeout=CHANNEL_TIMEOUT) as channel:
                channel.settimeout(0.25)
                finished = Event()
                outbound = Thread(
                    target=copy_stream,
                    args=(client, channel, channel.shutdown_write, finished, self.ssh_error),
                    daemon=True,
                )
                outbound.start()
                try:
                    copy_stream(channel, client, lambda: client.shutdown(socket.SHUT_WR), finished, self.ssh_error)
                    while (outbound.is_alive() and not channel.closed and not self.stopped.is_set()
                           and not finished.wait(0.1)):
                        pass
                finally:
                    finished.set()
                    outbound.join(timeout=0.35)
        except (OSError, EOFError, self.ssh_error, RuntimeError):
            # The server may refuse this particular channel while SSH stays up.
            pass
        finally:
            client.close()
            with self.lock:
                self.clients.discard(client)
            self.slots.release()

    def alive(self):
        return not self.stopped.is_set() and self.worker.is_alive() and self.transport.is_active()

    def close(self):
        with self.lock:
            if self.stopped.is_set():
                return
            self.stopped.set()
            self.listener.close()
            clients = list(self.clients)
        for client in clients:
            with suppress(OSError):
                client.shutdown(socket.SHUT_RDWR)
            client.close()
        with suppress(OSError, PasswordSSHError):
            self.session.__exit__(None, None, None)
        if self.keepalive.ident is not None and current_thread() is not self.keepalive:
            self.keepalive.join(timeout=0.3)

    def error(self):
        if self.unresponsive.is_set():
            return "SSH 服务器未响应保活请求，连接已断开。"
        if not self.alive():
            return "SSH 隧道已断开，请检查 VPS 状态和网络连接。"
        return None


def open_password(host, local_port, remote_host, remote_port, password, expected_fingerprint, cancelled):
    if not password:
        raise TunnelError("请输入设备的 SSH 密码，或先在设备设置中保存密码。")
    try:
        listener = loopback_socket(local_port)
    except OSError:
        raise TunnelError("无法监听本机端口，请检查端口占用及本机权限。") from None
    try:
        check_cancelled(cancelled)
        session = password_session(host, password, monotonic() + START_TIMEOUT, expected_fingerprint, persistent=True)
        transport, _ = session.__enter__()
    except PasswordSSHError as error:
        listener.close()
        raise TunnelError(str(error), retryable=error.diagnostic["status"] in RETRYABLE_SSH_FAILURES) from None
    except BaseException:
        listener.close()
        raise
    from paramiko import SSHException

    tunnel = PasswordTunnel(listener, session, transport, (remote_host, remote_port), SSHException)
    try:
        check_cancelled(cancelled)
        listener.settimeout(0.25)
        try:
            listener.listen(16)
        except OSError:
            raise TunnelError("无法监听本机端口，请检查端口占用及本机权限。") from None
        tunnel.start()
        return tunnel
    except BaseException:
        tunnel.close()
        raise


def open_tunnel(host, local_port, remote_host, remote_port, *, password=None, expected_fingerprint=None, cancelled=None):
    if any(type(port) is not int or not 1 <= port <= 65535 for port in (local_port, remote_port)):
        raise TunnelError("端口须为 1–65535。")
    address = remote_address(remote_host)
    cancelled = cancelled if cancelled is not None else Event()
    check_cancelled(cancelled)
    if host["auth_mode"] == "password":
        return open_password(host, local_port, address, remote_port, password, expected_fingerprint, cancelled)
    return open_openssh(host, local_port, address, remote_port, cancelled)
