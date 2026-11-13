"""Open native file pickers without reading the selected file."""

from pathlib import Path
import json
import os
from secrets import token_urlsafe
import subprocess
import sys
from threading import Timer
from time import monotonic


PICKER_TIMEOUT = 90
PICKER_UNAVAILABLE = "无法打开系统文件选择器，请手动填写本机私钥路径。"
PICKER_EXPIRED = "文件选择已超时，可以重试或手动填写私钥路径。"


def picker_command(mode="key", suggested=""):
    return [sys.executable, "-I", "-B", str(Path(__file__).resolve()), mode, suggested]


def picker_options():
    return {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "creationflags": subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    }


def picker_result(returncode, output):
    if returncode == 124:
        raise ValueError(PICKER_EXPIRED)
    if returncode != 0:
        raise ValueError(PICKER_UNAVAILABLE)
    try:
        path = json.loads(output)
    except (ValueError, RecursionError) as error:
        raise ValueError(PICKER_UNAVAILABLE) from error
    if path is not None and (not isinstance(path, str) or not Path(path).is_absolute()):
        raise ValueError(PICKER_UNAVAILABLE)
    return {"path": path}


def choose_key_file():
    """Wait for a selection in the threaded browser server."""
    try:
        result = subprocess.run(picker_command(), **picker_options(), timeout=PICKER_TIMEOUT)
    except subprocess.TimeoutExpired as error:
        raise ValueError(PICKER_EXPIRED) from error
    except OSError as error:
        raise ValueError(PICKER_UNAVAILABLE) from error
    return picker_result(result.returncode, result.stdout)


def choose_transfer_file(mode, suggested=""):
    if mode not in ("upload", "download"):
        raise ValueError("文件传输操作无效。")
    try:
        result = subprocess.run(picker_command(mode, suggested), **picker_options(), timeout=PICKER_TIMEOUT)
        return picker_result(result.returncode, result.stdout)["path"]
    except subprocess.TimeoutExpired:
        raise ValueError("文件选择已超时，请重新选择。") from None
    except (OSError, ValueError):
        raise ValueError("无法完成系统文件选择，请重试。") from None


class KeyFilePicker:
    """Keep the serial MCP connection available while the dialog is open."""

    def __init__(self):
        self.process = None
        self.token = None
        self.completed = {}

    def collect(self):
        now = monotonic()
        self.completed = {ticket: result for ticket, result in self.completed.items() if result[0] > now}
        if self.process is not None and self.process.poll() is not None:
            output, _ = self.process.communicate()
            self.completed[self.token] = (now + PICKER_TIMEOUT, self.process.returncode, output)
            self.process = None
            self.token = None

    def start(self):
        self.collect()
        if self.process is not None:
            raise ValueError("文件选择器已打开，请先完成或取消选择。")
        try:
            self.process = subprocess.Popen(picker_command(), **picker_options())
        except OSError as error:
            raise ValueError(PICKER_UNAVAILABLE) from error
        self.token = token_urlsafe(18)
        return {"ticket": self.token}

    def poll(self, ticket):
        self.collect()
        if ticket == self.token:
            return {"pending": True}
        result = self.completed.pop(ticket, None)
        if result is None:
            raise ValueError("文件选择已结束，请重新打开选择器。")
        _, returncode, output = result
        return picker_result(returncode, output)

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                try:
                    self.process.kill()
                except ProcessLookupError:
                    pass
            self.process.communicate()
            self.process = None
            self.token = None
        self.completed.clear()


def native_dialog(mode, suggested):
    import tkinter
    from tkinter import filedialog

    window = tkinter.Tk()
    try:
        window.withdraw()
        window.attributes("-topmost", True)
        home = Path.home()
        if mode == "key":
            directory = home / ".ssh"
            path = filedialog.askopenfilename(parent=window, title="星图 · 选择本机 SSH 私钥",
                                              initialdir=directory if directory.is_dir() else home)
        elif mode == "upload":
            path = filedialog.askopenfilename(parent=window, title="星图 · 选择要上传的文件", initialdir=home)
        else:
            directory = home / "Downloads"
            path = filedialog.asksaveasfilename(parent=window, title="星图 · 选择下载保存位置",
                                                initialdir=directory if directory.is_dir() else home,
                                                initialfile=suggested, confirmoverwrite=False)
        if len(path) > 512:
            return 1
        print(json.dumps(path or None, ensure_ascii=True))
    finally:
        window.destroy()
    return 0


if __name__ == "__main__":
    mode, suggested = sys.argv[1:] if len(sys.argv) == 3 else ("key", "")
    if mode not in ("key", "upload", "download"):
        sys.exit(1)
    timer = Timer(PICKER_TIMEOUT, os._exit, args=(124,))
    timer.daemon = True
    timer.start()
    try:
        sys.exit(native_dialog(mode, suggested))
    finally:
        timer.cancel()
