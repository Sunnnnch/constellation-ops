"""Run OpenSSH in a hidden Windows pseudoconsole using the native ConPTY API."""

import ctypes as c
from ctypes import wintypes as w
from functools import lru_cache
import os
from subprocess import list2cmdline
from threading import Lock
from time import monotonic


PSEUDOCONSOLE_ATTRIBUTE = 0x00020016
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
STARTF_USESTDHANDLES = 0x00000100
INVALID_HANDLE = c.c_void_p(-1).value
WAIT_OBJECT_0 = 0
PIPE_CLOSED = (109, 232, 233)
EXIT_DRAIN_SECONDS = 0.15


class Coord(c.Structure):
    _fields_ = [("x", w.SHORT), ("y", w.SHORT)]


class StartupInfo(c.Structure):
    _fields_ = [
        ("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR), ("title", w.LPWSTR),
        ("x", w.DWORD), ("y", w.DWORD), ("width", w.DWORD), ("height", w.DWORD),
        ("xchars", w.DWORD), ("ychars", w.DWORD), ("fill", w.DWORD), ("flags", w.DWORD),
        ("show", w.WORD), ("reserved_size", w.WORD), ("reserved_data", c.POINTER(w.BYTE)),
        ("stdin", w.HANDLE), ("stdout", w.HANDLE), ("stderr", w.HANDLE),
    ]


class StartupInfoEx(c.Structure):
    _fields_ = [("startup", StartupInfo), ("attributes", w.LPVOID)]


class ProcessInfo(c.Structure):
    _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]


@lru_cache(maxsize=1)
def api():
    kernel = c.WinDLL("kernel32", use_last_error=True)
    dword_ptr = c.POINTER(w.DWORD)
    size_ptr = c.POINTER(c.c_size_t)
    signatures = {
        "CreatePseudoConsole": ((Coord, w.HANDLE, w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)), c.c_long),
        "ResizePseudoConsole": ((w.HANDLE, Coord), c.c_long),
        "ClosePseudoConsole": ((w.HANDLE,), None),
        "InitializeProcThreadAttributeList": ((w.LPVOID, w.DWORD, w.DWORD, size_ptr), w.BOOL),
        "UpdateProcThreadAttribute": ((w.LPVOID, w.DWORD, c.c_size_t, w.LPVOID, c.c_size_t,
                                       w.LPVOID, size_ptr), w.BOOL),
        "DeleteProcThreadAttributeList": ((w.LPVOID,), None),
        "CreateProcessW": ((w.LPCWSTR, w.LPWSTR, w.LPVOID, w.LPVOID, w.BOOL, w.DWORD,
                            w.LPVOID, w.LPCWSTR, c.POINTER(StartupInfoEx), c.POINTER(ProcessInfo)), w.BOOL),
        "CloseHandle": ((w.HANDLE,), w.BOOL),
        "PeekNamedPipe": ((w.HANDLE, w.LPVOID, w.DWORD, dword_ptr, dword_ptr, dword_ptr), w.BOOL),
        "WaitForSingleObject": ((w.HANDLE, w.DWORD), w.DWORD),
        "GetExitCodeProcess": ((w.HANDLE, dword_ptr), w.BOOL),
        "TerminateProcess": ((w.HANDLE, w.UINT), w.BOOL),
    }
    for name, (argtypes, restype) in signatures.items():
        function = getattr(kernel, name)
        function.argtypes = argtypes
        function.restype = restype
    return kernel


def conpty_available():
    if os.name != "nt":
        return False
    try:
        api()
    except (AttributeError, OSError):
        return False
    return True


def check(result):
    if not result:
        raise c.WinError(c.get_last_error())


def check_hresult(result):
    if result < 0:
        raise OSError(f"ConPTY HRESULT 0x{result & 0xFFFFFFFF:08X}")


def start_process(kernel, console, command, env):
    size = c.c_size_t()
    kernel.InitializeProcThreadAttributeList(None, 1, 0, c.byref(size))
    attributes = c.create_string_buffer(size.value)
    check(kernel.InitializeProcThreadAttributeList(attributes, 1, 0, c.byref(size)))
    try:
        check(kernel.UpdateProcThreadAttribute(
            attributes, 0, PSEUDOCONSOLE_ATTRIBUTE, console, c.sizeof(w.HANDLE), None, None,
        ))
        startup = StartupInfoEx()
        startup.startup.cb = c.sizeof(startup)
        # Ensure a parent with redirected stdin/stdout (for example MCP stdio)
        # cannot pass those streams to the attached console application.
        startup.startup.flags = STARTF_USESTDHANDLES
        startup.startup.stdin = startup.startup.stdout = startup.startup.stderr = INVALID_HANDLE
        startup.attributes = c.cast(attributes, w.LPVOID)
        process = ProcessInfo()
        environment = "\0".join(f"{key}={value}" for key, value in sorted(env.items(), key=lambda item: item[0].upper()))
        command_line = c.create_unicode_buffer(list2cmdline(command))
        check(kernel.CreateProcessW(
            command[0], command_line, None, None, False, EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            c.create_unicode_buffer(environment + "\0"), None, c.byref(startup), c.byref(process),
        ))
        kernel.CloseHandle(process.thread)
        return process.process
    finally:
        kernel.DeleteProcThreadAttributeList(attributes)


class WindowsTerminal:
    def __init__(self, command, env, size):
        from msvcrt import get_osfhandle, setmode

        self.kernel = api()
        self.console = w.HANDLE()
        self.process = None
        self.input_fd = self.output_fd = None
        self.output_handle = None
        self.exit_at = None
        self._resize_lock = Lock()
        self._write_lock = Lock()
        input_peer = output_peer = None
        try:
            input_peer, self.input_fd = os.pipe()
            self.output_fd, output_peer = os.pipe()
            setmode(self.input_fd, os.O_BINARY)
            setmode(self.output_fd, os.O_BINARY)
            self.output_handle = get_osfhandle(self.output_fd)
            check_hresult(self.kernel.CreatePseudoConsole(
                Coord(*size), get_osfhandle(input_peer), get_osfhandle(output_peer), 0, c.byref(self.console),
            ))
            self.process = start_process(self.kernel, self.console, command, env)
        except BaseException:
            self.close()
            raise
        finally:
            for fd in (input_peer, output_peer):
                if fd is not None:
                    os.close(fd)

    def read(self):
        available = w.DWORD()
        if not self.kernel.PeekNamedPipe(self.output_handle, None, 0, None, c.byref(available), None):
            error = c.get_last_error()
            if error in PIPE_CLOSED:
                return b""
            raise c.WinError(error)
        if available.value:
            return os.read(self.output_fd, min(16 * 1024, available.value))
        if self.kernel.WaitForSingleObject(self.process, 0) == WAIT_OBJECT_0:
            if self.exit_at is None:
                self.exit_at = monotonic()
            elif monotonic() - self.exit_at >= EXIT_DRAIN_SECONDS:
                return b""
        return None

    def write(self, data):
        # On Windows a blocking pipe write may wait for ConPTY to consume data.
        # Only the input worker calls this method.
        with self._write_lock:
            view = memoryview(data)
            while self.input_fd is not None and view:
                written = os.write(self.input_fd, view)
                if not written:
                    raise OSError("ConPTY write failed")
                view = view[written:]

    def resize(self, size):
        with self._resize_lock:
            if self.console and self.kernel.WaitForSingleObject(self.process, 0) != WAIT_OBJECT_0:
                check_hresult(self.kernel.ResizePseudoConsole(self.console, Coord(*size)))

    def exit_code(self):
        code = w.DWORD()
        if self.process and self.kernel.WaitForSingleObject(self.process, 0) == WAIT_OBJECT_0:
            check(self.kernel.GetExitCodeProcess(self.process, c.byref(code)))
            return code.value
        return None

    def close(self):
        if self.process and self.kernel.WaitForSingleObject(self.process, 0) != WAIT_OBJECT_0:
            self.kernel.TerminateProcess(self.process, 1)
        # Close the output reader before releasing ConPTY. On older Windows,
        # ClosePseudoConsole can otherwise wait for a final frame to be read.
        if self.output_fd is not None:
            os.close(self.output_fd)
            self.output_fd = None
        with self._resize_lock:
            if self.console:
                self.kernel.ClosePseudoConsole(self.console)
                self.console = w.HANDLE()
            if self.process:
                self.kernel.CloseHandle(self.process)
                self.process = None
        with self._write_lock:
            if self.input_fd is not None:
                os.close(self.input_fd)
                self.input_fd = None