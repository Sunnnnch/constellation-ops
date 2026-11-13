"""Run native-picker and SFTP jobs without blocking the dashboard bridge."""

from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import PurePosixPath
import re
from secrets import token_urlsafe
from threading import Lock
from time import monotonic
from typing import NamedTuple

from dashboard_files import download_file, list_files, upload_file
from dashboard_native import choose_transfer_file


def suggested_name(path):
    basename = PurePosixPath(path).name
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f\x7f]', "_", basename).strip(" .")
    if re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", cleaned, re.IGNORECASE):
        cleaned = "_" + cleaned
    return cleaned[:180] or "download"


class Job(NamedTuple):
    host_id: str
    action: str
    expires: float | None
    future: Future
    stage: str


class FileJobs:
    def __init__(self):
        self.lock = Lock()
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="vps-files")
        self.jobs = {}
        self.closed = False

    def _prune(self):
        now = monotonic()
        self.jobs = {ticket: job for ticket, job in self.jobs.items() if job.expires is None or job.expires > now}

    def submit(self, host_id, action, host, password, fingerprint, path, check_revision):
        with self.lock:
            self._prune()
            if self.closed:
                raise ValueError("文件管理正在关闭，请重新打开面板。")
            active = [job for job in self.jobs.values() if not job.future.done()]
            if len(active) >= 4 or len(self.jobs) >= 64:
                raise ValueError("正在处理的文件操作过多，请稍后再试。")
            if any(job.host_id == host_id for job in active):
                raise ValueError("这台设备正在处理文件，请等待当前操作完成。")
            if action != "list" and any(job.action != "list" for job in active):
                raise ValueError("已有文件传输或文件选择窗口，请先完成它。")
            ticket = token_urlsafe(24)
            future = self.pool.submit(self._run, ticket, action, host, password, fingerprint, path, check_revision)
            self.jobs[ticket] = Job(host_id, action, None, future, "list" if action == "list" else "picker")
        future.add_done_callback(lambda _: self._expire(ticket))
        return {"ticket": ticket}

    def _expire(self, ticket):
        with self.lock:
            self.jobs[ticket] = self.jobs[ticket]._replace(expires=monotonic() + 120)

    def _run(self, ticket, action, host, password, fingerprint, path, check_revision):
        try:
            if action == "list":
                check_revision()
                return list_files(host, password, fingerprint, path)
            local = choose_transfer_file(action, suggested_name(path) if action == "download" else "")
            if local is None:
                return {"cancelled": True}
            with self.lock:
                self.jobs[ticket] = self.jobs[ticket]._replace(stage="transfer")
            check_revision()
            if action == "upload":
                return upload_file(host, password, fingerprint, local, path)
            return download_file(host, password, fingerprint, path, local)
        except ValueError:
            raise
        except Exception:
            raise ValueError("文件操作未能完成，请检查 SSH 连接及读写权限。") from None

    def poll(self, host_id, ticket):
        with self.lock:
            self._prune()
            job = self.jobs.get(ticket)
            if job is None or job.host_id != host_id:
                raise ValueError("文件操作已结束或已过期，请重新打开文件管理。")
            future = job.future
        if not future.done():
            return {"pending": True, "stage": job.stage}
        return {"pending": False, "result": future.result()}

    def shutdown(self):
        with self.lock:
            self.closed = True
        self.pool.shutdown(wait=True, cancel_futures=True)
