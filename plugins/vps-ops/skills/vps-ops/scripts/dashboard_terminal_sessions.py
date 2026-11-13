"""Bounded interactive SSH sessions for the local dashboard."""

from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from contextlib import ExitStack
import os
from secrets import token_urlsafe
from threading import Condition, Event, Lock, Thread, Timer
from time import monotonic

from dashboard_credentials import validate_password
from dashboard_password_ssh import PasswordSSHError, password_session, remaining, stop_socket
from dashboard_password_terminal import CONNECT_TIMEOUT
from dashboard_ssh import command_for, diagnostic, ssh_environment, validate_connection


MAX_SESSIONS = 8
MAX_INPUT = 4096
MAX_PENDING_INPUT = 8 * MAX_INPUT
OUTPUT_PAGE = 16 * 1024
OUTPUT_CAPACITY = 256 * 1024
IDLE_TIMEOUT = 5 * 60
CLOSED_TIMEOUT = 60
POLL_INTERVAL = 0.035


def terminal_size(cols, rows):
    if type(cols) is not int or type(rows) is not int or not (1 <= cols <= 500 and 1 <= rows <= 200):
        raise ValueError("SSH 终端尺寸无效。")
    return cols, rows


def terminal_input(input_data):
    if input_data is None:
        return b""
    if not isinstance(input_data, str) or len(input_data) > 4 * ((MAX_INPUT + 2) // 3):
        raise ValueError("SSH 终端单次输入过长。")
    try:
        decoded = b64decode(input_data, validate=True)
    except (ValueError, Base64Error):
        raise ValueError("SSH 终端输入编码无效。") from None
    if len(decoded) > MAX_INPUT:
        raise ValueError("SSH 终端单次输入过长。")
    return decoded


class PasswordTerminal:
    def __init__(self, host, password, fingerprint, size):
        deadline = monotonic() + CONNECT_TIMEOUT
        with ExitStack() as resources:
            transport, _ = resources.enter_context(
                password_session(host, password, deadline, fingerprint, persistent=True),
            )
            timer = Timer(remaining(deadline), stop_socket, args=(transport.sock,))
            timer.daemon = True
            timer.start()
            try:
                channel = resources.enter_context(transport.open_session(timeout=remaining(deadline)))
                channel.set_combine_stderr(True)
                channel.settimeout(2)
                channel.get_pty(term="xterm-256color", width=size[0], height=size[1])
                channel.invoke_shell()
            finally:
                timer.cancel()
            self.transport = transport
            self.channel = channel
            self.resources = resources.pop_all()

    def read(self):
        if self.channel.recv_ready():
            return self.channel.recv(OUTPUT_PAGE)
        return b"" if self.channel.closed else None

    def write(self, data):
        self.channel.sendall(data)

    def resize(self, size):
        self.channel.resize_pty(width=size[0], height=size[1])

    def exit_code(self):
        if self.channel.exit_status_ready():
            code = self.channel.recv_exit_status()
            return None if code == -1 else code
        return None

    def close(self):
        stop_socket(self.transport.sock)
        self.resources.close()


class TerminalSession:
    def __init__(self, adapter, size):
        self.id = token_urlsafe(24)
        self.adapter = adapter
        self.changed = Condition()
        self.closed = Event()
        self.finished = Event()
        self.stop = False
        self.offset = 0
        self.output = bytearray()
        self.pending = bytearray()
        self.size = size
        self.pending_size = None
        self.last_seen = monotonic()
        self.closed_at = None
        self.exit_code = None
        self.error = None
        self.reader = Thread(target=self._read_output, name="vps-ssh-output", daemon=True)
        self.writer = Thread(target=self._write_input, name="vps-ssh-input", daemon=True)

    def start(self):
        self.writer.start()
        try:
            self.reader.start()
        except RuntimeError:
            self.request_close()
            self.writer.join()
            raise

    def exchange(self, offset, data, size):
        with self.changed:
            if type(offset) is not int or not 0 <= offset <= self.offset:
                raise ValueError("SSH 终端输出位置无效。")
            if not self.stop:
                if len(self.pending) + len(data) > MAX_PENDING_INPUT:
                    raise ValueError("SSH 终端输入队列已满，请稍后继续。")
                self.pending.extend(data)
                if size is not None and size != self.size:
                    self.pending_size = self.size = size
                if data or self.pending_size is not None:
                    self.changed.notify()
            self.last_seen = monotonic()
            start = self.offset - len(self.output)
            lost = offset < start
            index = max(offset, start) - start
            output = self.output[index:index + OUTPUT_PAGE]
            next_offset = start + index + len(output)
            ended = self.closed_at is not None and next_offset == self.offset
            return {
                "id": self.id,
                "offset": next_offset,
                "data": b64encode(output).decode("ascii"),
                "lost": lost,
                "status": "closed" if ended else "open",
                "exit_code": self.exit_code if ended else None,
                "error": self.error if ended else None,
            }

    def expired(self, now):
        with self.changed:
            if self.closed_at is not None:
                return now - self.closed_at >= CLOSED_TIMEOUT
            return now - self.last_seen >= IDLE_TIMEOUT

    def request_close(self):
        with self.changed:
            self.stop = True
            self.closed.set()
            self.changed.notify_all()

    def _read_output(self):
        error = None
        exit_code = None
        try:
            while not self.closed.is_set():
                data = self.adapter.read()
                if data is None:
                    self.closed.wait(POLL_INTERVAL)
                elif not data:
                    exit_code = self.adapter.exit_code()
                    break
                else:
                    with self.changed:
                        self.output.extend(data)
                        self.offset += len(data)
                        excess = len(self.output) - OUTPUT_CAPACITY
                        if excess > 0:
                            del self.output[:excess]
        except Exception:
            if not self.closed.is_set():
                error = "读取 SSH 终端输出失败，连接已关闭。"
        finally:
            self.request_close()
            with self.changed:
                self.closed_at = monotonic()
                self.exit_code = exit_code
                self.error = self.error or error
            try:
                self.adapter.close()
            except OSError:
                pass
            finally:
                self.writer.join()
                self.finished.set()

    def _write_input(self):
        try:
            while True:
                with self.changed:
                    self.changed.wait_for(lambda: self.stop or self.pending or self.pending_size)
                    if self.stop:
                        return
                    size, self.pending_size = self.pending_size, None
                    data = bytes(self.pending)
                    self.pending.clear()
                if size is not None:
                    self.adapter.resize(size)
                if data:
                    self.adapter.write(data)
        except Exception:
            with self.changed:
                if not self.stop:
                    self.error = "向 SSH 终端发送输入失败，连接已关闭。"
            self.request_close()


class TerminalSessions:
    def __init__(self):
        self._sessions = {}
        self._closing = {}
        self._lock = Lock()
        self._opening = 0
        self._shutdown = Event()
        self._sweeper = None

    @property
    def modes(self):
        modes = ["password"]
        if os.name == "nt":
            from dashboard_conpty import conpty_available

            if conpty_available():
                modes.extend(("alias", "key"))
        return modes

    def open(self, host, password=None, *, expected_fingerprint=None, cols=80, rows=24):
        host = validate_connection(host)
        mode = host["auth_mode"]
        size = terminal_size(cols, rows)
        if mode not in self.modes:
            return diagnostic("terminal_unavailable", "此系统的 SSH 配置或私钥模式请使用本机终端。")
        if mode == "password" and not password:
            return diagnostic("password_required", "请在编辑设备中保存 SSH 密码后再连接。")
        with self._lock:
            self._prune()
            if self._shutdown.is_set():
                return diagnostic("terminal_unavailable", "SSH 终端服务已停止。")
            if len(self._sessions) + len(self._closing) + self._opening >= MAX_SESSIONS:
                return diagnostic("terminal_limit", "SSH 终端标签已达上限，请关闭不使用的标签后再连接。")
            self._opening += 1
        adapter = None
        try:
            if mode == "password":
                adapter = PasswordTerminal(host, validate_password(password), expected_fingerprint, size)
            else:
                from dashboard_conpty import WindowsTerminal

                command = command_for(host, interactive=True)
                # OpenSSH keeps the first value for these settings.
                command[1:1] = [
                    "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                    "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "PermitLocalCommand=no",
                ]
                adapter = WindowsTerminal(command, {**ssh_environment(), "TERM": "xterm-256color"}, size)
            session = TerminalSession(adapter, size)
            with self._lock:
                if self._shutdown.is_set():
                    return diagnostic("terminal_unavailable", "SSH 终端服务已停止。")
                if self._sweeper is None:
                    self._sweeper = Thread(target=self._sweep, name="vps-ssh-terminal-cleanup", daemon=True)
                    self._sweeper.start()
                session.start()
                self._sessions[session.id] = session
                adapter = None
            return {
                "ok": True, "id": session.id, "offset": 0, "data": "",
                "lost": False, "status": "open", "exit_code": None, "error": None,
            }
        except PasswordSSHError as error:
            if error.diagnostic["status"] == "command_failed":
                return diagnostic("terminal_failed", "SSH 已登录，但服务器未能启动交互终端。")
            return error.diagnostic
        except (OSError, RuntimeError, ValueError):
            return diagnostic("terminal_failed", "无法打开 SSH 终端，请检查设备配置和本机 SSH 组件。")
        finally:
            try:
                if adapter is not None:
                    adapter.close()
            finally:
                with self._lock:
                    self._opening -= 1

    def exchange(self, session_id, offset, *, input_data=None, cols=None, rows=None):
        size = None if cols is None and rows is None else terminal_size(cols, rows)
        data = terminal_input(input_data)
        if not isinstance(session_id, str):
            raise ValueError("SSH 终端会话无效。")
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise ValueError("SSH 终端会话已关闭或过期。")
        return session.exchange(offset, data, size)

    def close(self, session_id):
        if not isinstance(session_id, str):
            raise ValueError("SSH 终端会话无效。")
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is not None:
                self._closing[session.id] = session
                session.request_close()
        return {"ok": True}

    def shutdown(self):
        self._shutdown.set()
        with self._lock:
            sessions = [*self._sessions.values(), *self._closing.values()]
            self._sessions.clear()
            self._closing.clear()
        for session in sessions:
            session.request_close()
        deadline = monotonic() + 2
        for session in sessions:
            session.finished.wait(max(0, deadline - monotonic()))

    def _sweep(self):
        while not self._shutdown.wait(10):
            with self._lock:
                self._prune()

    def _prune(self):
        now = monotonic()
        for session_id, session in list(self._sessions.items()):
            if session.expired(now):
                del self._sessions[session_id]
                self._closing[session_id] = session
                session.request_close()
        for session_id, session in list(self._closing.items()):
            if session.finished.is_set():
                del self._closing[session_id]