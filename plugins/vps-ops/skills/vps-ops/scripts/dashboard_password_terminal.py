"""Open a verified password-authenticated SSH shell in a local Windows console."""

from codecs import getincrementaldecoder
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
from queue import Empty, Queue
import subprocess
import sys
from threading import Event, Thread, Timer
from time import monotonic

from dashboard_credentials import validate_password
from dashboard_password_ssh import PasswordSSHError, password_session, remaining, stop_socket
from dashboard_ssh import EARLY_EXIT_SECONDS, diagnostic, validate_connection


CONNECT_TIMEOUT = 12
MAX_BOOTSTRAP = 16 * 1024
MAX_RESULT = 4096
CONSOLE_READ_WRITE = 0x80000000 | 0x40000000
CONSOLE_SHARED = 3
OPEN_EXISTING = 3
INITIAL_TERMINAL_SIZE = (80, 24)
INVALID_HANDLE = ctypes.c_void_p(-1).value
PROCESSED_INPUT, LINE_INPUT, ECHO_INPUT, QUICK_EDIT = 0x1, 0x2, 0x4, 0x40
MOUSE_INPUT = 0x10
EXTENDED_FLAGS, VT_INPUT = 0x80, 0x200
PROCESSED_OUTPUT, VT_OUTPUT, NO_AUTO_RETURN = 0x1, 0x4, 0x8


class ConsolePosition(ctypes.Structure):
    _fields_ = [("x", wintypes.SHORT), ("y", wintypes.SHORT)]


class ConsoleRect(ctypes.Structure):
    _fields_ = [(name, wintypes.SHORT) for name in ("left", "top", "right", "bottom")]


class ConsoleBufferInfo(ctypes.Structure):
    _fields_ = [
        ("size", ConsolePosition), ("cursor", ConsolePosition), ("attributes", wintypes.WORD),
        ("window", ConsoleRect), ("maximum_size", ConsolePosition),
    ]


class WindowsConsole:
    def __init__(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        specs = {
            "AllocConsole": ((), wintypes.BOOL),
            "CreateFileW": ((wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                              wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE), wintypes.HANDLE),
            "CloseHandle": ((wintypes.HANDLE,), wintypes.BOOL),
            "GetConsoleMode": ((wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)), wintypes.BOOL),
            "SetConsoleMode": ((wintypes.HANDLE, wintypes.DWORD), wintypes.BOOL),
            "SetConsoleTitleW": ((wintypes.LPCWSTR,), wintypes.BOOL),
            "GetConsoleScreenBufferInfo": ((wintypes.HANDLE, ctypes.POINTER(ConsoleBufferInfo)), wintypes.BOOL),
            "ReadConsoleW": ((wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                               ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID), wintypes.BOOL),
            "WriteConsoleW": ((wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID), wintypes.BOOL),
        }
        for name, (argument_types, result_type) in specs.items():
            function = getattr(kernel, name)
            function.argtypes = argument_types
            function.restype = result_type
        self.kernel = kernel
        self.input = None
        self.output = None

    def __enter__(self):
        if not self.kernel.AllocConsole():
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            self.input = self.open_handle("CONIN$")
            self.output = self.open_handle("CONOUT$")
        except OSError:
            self.__exit__(None, None, None)
            raise
        self.kernel.SetConsoleTitleW("星图 SSH")
        return self

    def __exit__(self, *_):
        for handle in (self.input, self.output):
            if handle is not None:
                self.kernel.CloseHandle(handle)

    def open_handle(self, name):
        handle = self.kernel.CreateFileW(name, CONSOLE_READ_WRITE, CONSOLE_SHARED, None, OPEN_EXISTING, 0, None)
        if handle == INVALID_HANDLE or handle is None:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def mode(self, handle):
        mode = wintypes.DWORD()
        if not self.kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            raise ctypes.WinError(ctypes.get_last_error())
        return mode.value

    @contextmanager
    def virtual_terminal(self):
        input_mode, output_mode = self.mode(self.input), self.mode(self.output)
        # ConPTY automatically requests mouse-motion reports when Quick Edit
        # is disabled while ENABLE_MOUSE_INPUT is still set.
        raw_input = input_mode & ~(PROCESSED_INPUT | LINE_INPUT | ECHO_INPUT | QUICK_EDIT | MOUSE_INPUT)
        vt_output = output_mode | PROCESSED_OUTPUT | VT_OUTPUT
        try:
            if not self.kernel.SetConsoleMode(self.input, raw_input | EXTENDED_FLAGS | VT_INPUT):
                raise ctypes.WinError(ctypes.get_last_error())
            if not (self.kernel.SetConsoleMode(self.output, vt_output | NO_AUTO_RETURN)
                    or self.kernel.SetConsoleMode(self.output, vt_output)):
                raise ctypes.WinError(ctypes.get_last_error())
            yield
        finally:
            self.kernel.SetConsoleMode(self.input, input_mode | EXTENDED_FLAGS)
            self.kernel.SetConsoleMode(self.output, output_mode)

    def size(self):
        buffer = ConsoleBufferInfo()
        if not self.kernel.GetConsoleScreenBufferInfo(self.output, ctypes.byref(buffer)):
            return 80, 24
        window = buffer.window
        return max(1, window.right - window.left + 1), max(1, window.bottom - window.top + 1)

    def read(self):
        buffer = ctypes.create_string_buffer(4096)
        length = wintypes.DWORD()
        if not self.kernel.ReadConsoleW(self.input, buffer, len(buffer) // 2, ctypes.byref(length), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.raw[:length.value * 2]

    def write(self, value):
        encoded = value.encode("utf-16-le", "replace")
        # Use bounded writes and retain the original UTF-16 code units for WriteConsoleW.
        units_written = 0
        length = len(encoded) // 2
        buffer = ctypes.create_string_buffer(encoded)
        while units_written < length:
            written = wintypes.DWORD()
            if not self.kernel.WriteConsoleW(self.output, ctypes.byref(buffer, units_written * 2),
                                             length - units_written, ctypes.byref(written), None) or not written.value:
                raise OSError("Could not write to Windows console.")
            units_written += written.value


def exchange_bootstrap(process, payload, replies):
    try:
        with process.stdin:
            process.stdin.write(payload)
        with process.stdout:
            reply = json.loads(process.stdout.readline(MAX_RESULT + 1))
        if isinstance(reply, dict) and type(reply.get("ok")) is bool and isinstance(reply.get("status"), str):
            replies.put(reply)
            return
    except (OSError, ValueError, RecursionError):
        pass
    replies.put(diagnostic("configuration_error", "未能打开本机 SSH 终端。"))


def stop_process(process):
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        Thread(target=process.wait, daemon=True).start()


def open_password_terminal(host, password, *, expected_fingerprint=None):
    if os.name != "nt":
        return diagnostic("terminal_unavailable", "此系统请通过本机 SSH 终端交互登录。")
    host = validate_connection(host)
    validate_password(password)
    if host["auth_mode"] != "password":
        return diagnostic("configuration_error", "设备没有使用 SSH 密码认证。")
    bootstrap = json.dumps({"host": host, "password": password, "fingerprint": expected_fingerprint},
                           ensure_ascii=False).encode("utf-8")
    try:
        process = subprocess.Popen(
            [sys.executable, "-E", "-s", "-B", str(Path(__file__).resolve())],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            close_fds=True, creationflags=subprocess.DETACHED_PROCESS,
        )
    except OSError:
        return diagnostic("configuration_error", "无法启动本机 SSH 终端。")
    replies = Queue(maxsize=1)
    Thread(target=exchange_bootstrap, args=(process, bootstrap, replies), daemon=True).start()
    try:
        result = replies.get(timeout=CONNECT_TIMEOUT + 2)
    except Empty:
        stop_process(process)
        return diagnostic("timeout", "打开 SSH 终端超时，请重试。")
    if result["ok"]:
        Thread(target=process.wait, daemon=True).start()
    else:
        stop_process(process)
    return result


def send_console_input(console, channel, stopped, input_errors):
    decode = getincrementaldecoder("utf-16-le")("replace")
    try:
        while not stopped.is_set():
            chunk = console.read()
            if not chunk:
                stopped.wait(0.05)
                continue
            if not stopped.is_set():
                # VT input with ENABLE_PROCESSED_INPUT disabled delivers Ctrl+C as byte 0x03.
                channel.sendall(decode.decode(chunk).encode("utf-8"))
    except (OSError, EOFError):
        if not stopped.is_set():
            input_errors.append("本机终端输入已中断，或 SSH 连接已断开。")
    finally:
        stopped.set()


def relay(console, channel, size):
    stopped = Event()
    input_errors = []
    decode = getincrementaldecoder("utf-8")("replace")
    keyboard = Thread(target=send_console_input, args=(console, channel, stopped, input_errors), daemon=True)
    keyboard.start()
    next_resize = monotonic() + 0.25
    try:
        while True:
            if channel.recv_ready():
                console.write(decode.decode(channel.recv(16384)))
            elif stopped.is_set() or channel.closed or not channel.get_transport().is_active():
                break
            else:
                stopped.wait(0.025)
            now = monotonic()
            if now >= next_resize:
                updated_size = console.size()
                if updated_size != size and not channel.closed:
                    channel.resize_pty(width=updated_size[0], height=updated_size[1])
                    size = updated_size
                next_resize = now + 0.25
        console.write(decode.decode(b"", final=True))
        return input_errors[0] if input_errors else None
    finally:
        stopped.set()


def emit(result):
    sys.stdout.buffer.write(json.dumps(result, ensure_ascii=True).encode("ascii") + b"\n")
    sys.stdout.buffer.flush()


def start_shell(channel):
    from paramiko import SSHException

    try:
        width, height = INITIAL_TERMINAL_SIZE
        channel.get_pty(term="xterm-256color", width=width, height=height)
    except SSHException as error:
        if not channel.get_transport().is_active():
            raise
        raise PasswordSSHError("pty_failed", "服务器未接受交互终端（PTY）请求。请检查 SSH 服务是否允许分配终端。") from error
    try:
        channel.invoke_shell()
    except SSHException as error:
        if not channel.get_transport().is_active():
            raise
        raise PasswordSSHError("shell_failed", "服务器未接受交互 Shell 请求。请检查此 SSH 账号的登录 Shell 和服务端策略。") from error


def show_session_exit(console, reason):
    console.write(f"\r\n[星图] {reason}\r\n关闭此窗口即可返回设备面板。\r\n")
    # Closing the window ends this console process. A second read would compete
    # with the relay thread's outstanding Windows console read.
    Event().wait()


def main():
    acknowledged = False
    try:
        with sys.stdin.buffer as pipe:
            raw = pipe.read(MAX_BOOTSTRAP + 1)
        if len(raw) > MAX_BOOTSTRAP:
            raise ValueError
        bootstrap = json.loads(raw)
        del raw
        host = validate_connection(bootstrap["host"])
        password = validate_password(bootstrap.pop("password"))
        deadline = monotonic() + CONNECT_TIMEOUT
        session = password_session(host, password, deadline, bootstrap.get("fingerprint"), persistent=True)
        del password, bootstrap
        with session as (transport, fingerprint):
            from paramiko import SSHException

            watchdog = Timer(remaining(deadline), stop_socket, args=(transport.sock,))
            watchdog.daemon = True
            watchdog.start()
            try:
                with transport.open_session(timeout=remaining(deadline)) as channel:
                    channel.set_combine_stderr(True)
                    start_shell(channel)
                    with WindowsConsole() as console:
                        with console.virtual_terminal():
                            watchdog.cancel()
                            channel.settimeout(10)
                            emit({"ok": True, "status": "launched", "message": "已登录并打开本机 SSH 终端。",
                                  "fingerprint": fingerprint, "latency_ms": None})
                            acknowledged = True
                            opened = monotonic()
                            try:
                                reason = relay(console, channel, INITIAL_TERMINAL_SIZE)
                            except (OSError, EOFError, SSHException):
                                reason = "本机终端无法继续读取会话，或 SSH 连接已断开。"
                        exit_code = channel.recv_exit_status() if channel.exit_status_ready() else -1
                        channel.close()
                        transport.close()
                        if reason or exit_code != 0 or monotonic() - opened < EARLY_EXIT_SECONDS:
                            if reason is None:
                                reason = ("SSH 会话断开，服务器未返回退出状态。" if exit_code == -1 else
                                          f"远端 Shell 已退出（退出码 {exit_code}）。")
                            show_session_exit(console, reason)
            except OSError:
                if not acknowledged:
                    emit(diagnostic("configuration_error", "无法打开本机 SSH 终端。"))
                return 1
            finally:
                watchdog.cancel()
    except PasswordSSHError as error:
        if not acknowledged:
            emit(error.diagnostic)
        return 1
    except (KeyError, TypeError, ValueError, OSError, RecursionError):
        if not acknowledged:
            emit(diagnostic("configuration_error", "无法打开本机 SSH 终端。"))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
