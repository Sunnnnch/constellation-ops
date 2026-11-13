"""Browse and transfer files through the device's verified SFTP session."""

from contextlib import contextmanager, suppress
from datetime import datetime, timezone
import errno
import os
from pathlib import Path, PurePosixPath
import posixpath
import stat
import subprocess
import tempfile
from threading import Lock, Thread, Timer
from time import monotonic
from uuid import uuid4

from dashboard_password_crypto import prepare_password_dependencies
from dashboard_password_ssh import PasswordSSHError, password_session, remaining
from dashboard_ssh import command_for, failure, is_local, ssh_environment, validate_connection


BROWSE_TIMEOUT = 20
TRANSFER_TIMEOUT = 300
MAX_ENTRIES = 500
MAX_LIST_PATH_BYTES = 64 * 1024
MAX_FILE_BYTES = 1024 ** 3
BLOCK_BYTES = 32768
TRANSFER_WINDOW = 32


class FileOperationError(ValueError):
    """An operation failed with a message safe to show in the panel."""


class OpenSSHPipes:
    """Paramiko's SFTP packet client can read and write an OpenSSH subsystem."""

    def __init__(self, process):
        self.process = process
        self.write_lock = Lock()

    def send(self, data):
        with self.write_lock:
            count = self.process.stdin.write(data)
            self.process.stdin.flush()
            return count

    def recv(self, size):
        return self.process.stdout.read1(size)

    def get_name(self):
        return "OpenSSH SFTP"

    def recv_ready(self):
        # Uploads explicitly drain the response queue after each transfer window.
        return False

    def close(self):
        with self.write_lock:
            with suppress(OSError):
                self.process.stdin.close()


def capture_stderr(source, tail):
    try:
        for data in iter(lambda: source.read1(4096), b""):
            tail.extend(data[:8192 - len(tail)])
    except (OSError, ValueError):
        pass


def stop_process(process):
    if process.poll() is None:
        with suppress(OSError):
            process.kill()


def read_blocks(remote, size):
    offset = 0
    while offset < size:
        end = min(offset + BLOCK_BYTES * TRANSFER_WINDOW, size)
        requests = [(start, min(BLOCK_BYTES, end - start)) for start in range(offset, end, BLOCK_BYTES)]
        for block, (_, length) in zip(remote.readv(requests), requests, strict=True):
            if len(block) != length:
                raise FileOperationError("传输期间 VPS 文件已变更，请重试。")
            yield block
        offset = end


def sftp_error(error, deadline):
    if monotonic() >= deadline or isinstance(error, TimeoutError):
        return FileOperationError("文件操作超时，请检查 SSH 连接后重试。")
    code = getattr(error, "errno", None)
    if code == errno.ENOENT:
        return FileOperationError("路径已不存在，请刷新目录后重试。")
    if code in (errno.EACCES, errno.EPERM):
        return FileOperationError("无法访问此路径，请检查本机或 VPS 上的权限。")
    if code == errno.ENOSPC:
        return FileOperationError("存储空间不足，无法完成传输。")
    return FileOperationError("SFTP 操作失败，请检查 SSH 连接、路径和权限。")


@contextmanager
def openssh_session(host, paramiko, deadline):
    command = command_for(host)
    command[command.index("SessionType=default")] = "SessionType=subsystem"
    command.append("sftp")
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=ssh_environment(), creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    errors = bytearray()
    drain = Thread(target=capture_stderr, args=(process.stderr, errors), daemon=True)
    drain.start()
    watchdog = Timer(max(0, deadline - monotonic()), stop_process, args=(process,))
    watchdog.daemon = True
    watchdog.start()
    try:
        with paramiko.SFTPClient(OpenSSHPipes(process)) as client:
            yield client
    except (EOFError, paramiko.SSHException) as error:
        if monotonic() >= deadline:
            raise sftp_error(error, deadline) from None
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.3)
        if process.returncode:
            drain.join(timeout=0.2)
            diagnostic = failure(process.returncode, bytes(errors), host["auth_mode"])
            if diagnostic["status"] not in ("command_failed", "connection_failed"):
                raise FileOperationError(diagnostic["message"]) from None
            if b"subsystem request failed" in bytes(errors).lower():
                raise FileOperationError("VPS 的 SSH 服务未启用 SFTP。") from None
        raise sftp_error(error, deadline) from None
    finally:
        watchdog.cancel()
        stop_process(process)
        process.wait()
        drain.join(timeout=0.3)
        for stream in (process.stdin, process.stdout, process.stderr):
            with suppress(OSError):
                stream.close()


@contextmanager
def file_session(host, password, expected_fingerprint, timeout):
    prepare_password_dependencies()
    try:
        import paramiko
        from paramiko.sftp import SFTPError
    except (ImportError, OSError):
        raise FileOperationError("文件管理需要本机 Paramiko 组件，请按星图安装说明补齐依赖。") from None

    host = validate_connection(host)
    deadline = monotonic() + timeout
    try:
        if host["auth_mode"] == "password":
            if not password:
                raise FileOperationError("请输入该设备的 SSH 密码，或在设备设置中保存密码。")
            with password_session(host, password, deadline, expected_fingerprint) as (transport, _):
                try:
                    with transport.open_session(timeout=remaining(deadline)) as channel:
                        channel.settimeout(min(20, remaining(deadline)))
                        channel.invoke_subsystem("sftp")
                        with paramiko.SFTPClient(channel) as client:
                            yield client
                except (OSError, EOFError, SFTPError, paramiko.SSHException, UnicodeError) as error:
                    raise sftp_error(error, deadline) from None
        else:
            with openssh_session(host, paramiko, deadline) as client:
                yield client
    except PasswordSSHError as error:
        raise FileOperationError(error.diagnostic["message"]) from None
    except (OSError, EOFError, SFTPError, paramiko.SSHException, UnicodeError) as error:
        raise sftp_error(error, deadline) from None


def remote_path(path):
    if (not isinstance(path, str) or not path.startswith("/") or len(path) > 4096
            or any(not char.isprintable() for char in path)):
        raise FileOperationError("请输入 VPS 上的绝对路径。")
    return path


def remote_directory(client, path):
    return remote_path(client.normalize("." if path in (None, "") else remote_path(path)))


def file_kind(mode):
    if mode is None:
        return "other"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def timestamp(value):
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat() if value is not None else None
    except (OSError, OverflowError, ValueError):
        return None


def list_files(host, password=None, expected_fingerprint=None, path=None):
    entries = []
    path_bytes = 0
    truncated = False
    with file_session(host, password, expected_fingerprint, BROWSE_TIMEOUT) as client:
        directory = remote_directory(client, path)
        for info in client.listdir_iter(directory, read_aheads=1):
            name = info.filename
            if name in ("", ".", "..") or "/" in name or any(not char.isprintable() for char in name):
                continue
            path = posixpath.join(directory, name)
            if len(path) > 4096:
                continue
            path_bytes += len(name.encode("utf-8")) + len(path.encode("utf-8"))
            if len(entries) == MAX_ENTRIES or path_bytes > MAX_LIST_PATH_BYTES:
                truncated = True
                break
            kind = file_kind(info.st_mode)
            entries.append({"name": name, "path": path, "kind": kind,
                            "size": info.st_size if kind == "file" else None, "modified_at": timestamp(info.st_mtime)})
    entries.sort(key=lambda item: (item["kind"] != "directory", item["name"].casefold(), item["name"]))
    parent = posixpath.dirname(directory.rstrip("/")) or "/"
    return {"path": directory, "parent": None if directory == "/" else parent, "entries": entries,
            "truncated": truncated}


def checked_local_path(value):
    path = Path(value)
    if not path.is_absolute() or not is_local(path):
        raise FileOperationError("请选择本机上的文件路径。")
    return path


def check_size(size):
    if not isinstance(size, int) or not 0 <= size <= MAX_FILE_BYTES:
        raise FileOperationError("单个文件最多可传输 1 GiB。")


def require_remote_new(client, path):
    try:
        client.lstat(path)
    except FileNotFoundError:
        return
    raise FileOperationError("VPS 上已有同名文件，请选择其他目录或重命名本机文件。")


def upload_file(host, password, expected_fingerprint, local_path, remote_directory_path):
    source = checked_local_path(local_path)
    if not source.name or any(not char.isprintable() for char in source.name):
        raise FileOperationError("请选择文件名有效的本机文件。")
    try:
        resolved = checked_local_path(source.resolve(strict=True))
        if not resolved.is_file():
            raise FileOperationError("请选择普通文件进行上传。")
        with resolved.open("rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise FileOperationError("请选择普通文件进行上传。")
            size = metadata.st_size
            check_size(size)
            with file_session(host, password, expected_fingerprint, TRANSFER_TIMEOUT) as client:
                directory = remote_directory(client, remote_directory_path)
                destination = posixpath.join(directory, source.name)
                require_remote_new(client, destination)
                temporary = posixpath.join(directory, f".vps-ops-upload-{uuid4().hex}.part")
                remote = client.open(temporary, "wx", bufsize=0)
                published = False
                try:
                    with remote:
                        transferred = 0
                        while transferred < size:
                            data = stream.read(min(BLOCK_BYTES, size - transferred))
                            if not data:
                                raise FileOperationError("传输期间本机文件已变更，请重新选择文件。")
                            transferred += len(data)
                            block_number = (transferred + BLOCK_BYTES - 1) // BLOCK_BYTES
                            # Bound outstanding requests and collect every write status before publishing.
                            remote.set_pipelined(block_number % TRANSFER_WINDOW != 0 and transferred < size)
                            remote.write(data)
                    if stream.read(1) or os.fstat(stream.fileno()).st_mtime_ns != metadata.st_mtime_ns:
                        raise FileOperationError("传输期间本机文件已变更，请重新选择文件。")
                    if client.stat(temporary).st_size != size:
                        raise FileOperationError("VPS 收到的文件大小与本机文件不一致，请重试。")
                    try:
                        client.rename(temporary, destination)
                    except OSError:
                        require_remote_new(client, destination)
                        raise
                    published = True
                finally:
                    if not published:
                        with suppress(OSError, EOFError):
                            client.remove(temporary)
    except OSError as error:
        raise sftp_error(error, float("inf")) from None
    return {"name": source.name, "path": destination, "size": size}


def publish_local(temporary, destination):
    if os.name == "nt":
        temporary.rename(destination)
    else:
        os.link(temporary, destination)


def download_file(host, password, expected_fingerprint, source_path, local_path):
    source = remote_path(source_path)
    destination = checked_local_path(local_path)
    deadline = monotonic() + TRANSFER_TIMEOUT
    try:
        parent = checked_local_path(destination.parent.resolve(strict=True))
        destination = parent / destination.name
        if os.path.lexists(destination):
            raise FileExistsError
        with file_session(host, password, expected_fingerprint, TRANSFER_TIMEOUT) as client:
            if file_kind(client.lstat(source).st_mode) != "file":
                raise FileOperationError("请选择 VPS 上的普通文件进行下载。")
            descriptor, name = tempfile.mkstemp(dir=parent, prefix=".vps-ops-download-", suffix=".part")
            temporary = Path(name)
            try:
                with os.fdopen(descriptor, "wb") as stream, client.open(source, "rb") as remote:
                    metadata = remote.stat()
                    size = metadata.st_size
                    check_size(size)
                    for block in read_blocks(remote, size):
                        stream.write(block)
                    final = remote.stat()
                    if final.st_size != size or final.st_mtime != metadata.st_mtime:
                        raise FileOperationError("传输期间 VPS 文件已变更，请重试。")
                if monotonic() >= deadline:
                    raise FileOperationError("文件操作超时，请检查 SSH 连接后重试。")
                try:
                    publish_local(temporary, destination)
                except FileExistsError:
                    raise FileOperationError("本机已有同名文件，请选择新的保存位置或文件名。") from None
            finally:
                temporary.unlink(missing_ok=True)
    except FileExistsError:
        raise FileOperationError("本机已有同名文件，请选择新的保存位置或文件名。") from None
    except OSError as error:
        raise sftp_error(error, float("inf")) from None
    return {"name": PurePosixPath(source).name, "path": str(destination), "size": size}
