"""Process attribution and safe suspend. Attribution is a HEURISTIC: file-system events do
not carry the writer's PID, so we look for processes whose command line or open files
point into the watched folder."""
from __future__ import annotations

import os
import time
from typing import Optional

import psutil

PROTECTED = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "winlogon.exe", "explorer.exe", "svchost.exe", "init", "systemd", "sshd", "dwm.exe",
}


def _clean(p: str) -> str:
    return os.path.normpath(os.path.abspath(p)).replace("/", "\\").lower() if p else ""


def touches_root(proc: psutil.Process, root: str, cmd: Optional[str] = None) -> bool:
    root_clean = _clean(root)
    root_base = os.path.basename(root).lower()
    try:
        if cmd is None:
            cmd = " ".join(proc.cmdline())
        cmd_clean = cmd.replace("/", "\\").lower()
        if root_clean in cmd_clean or (root_base and root_base in cmd_clean):
            return True
        try:
            cwd_clean = _clean(proc.cwd())
            if cwd_clean and (cwd_clean.startswith(root_clean) or root_clean.startswith(cwd_clean)):
                return True
        except (psutil.Error, OSError):
            pass
        return False
    except (psutil.Error, OSError):
        return False


def attribute_process(root: str, exclude: tuple[int, ...] = ()) -> Optional[tuple[int, str]]:
    skip = set(exclude) | {os.getpid()}
    best: Optional[tuple[int, str, float]] = None
    root_clean = _clean(root)
    root_base = os.path.basename(root).lower()

    # Fast batch query using process_iter
    for p in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
        try:
            pid = p.info["pid"]
            name = (p.info["name"] or "").lower()
            if pid in skip or name in PROTECTED:
                continue
            cmd = " ".join(p.info["cmdline"] or [])
            cmd_clean = cmd.replace("/", "\\").lower()
            matched = (root_clean in cmd_clean) or (root_base and root_base in cmd_clean)
            if not matched:
                try:
                    cwd_clean = _clean(p.cwd())
                    if cwd_clean and (cwd_clean.startswith(root_clean) or root_clean.startswith(cwd_clean)):
                        matched = True
                except (psutil.Error, OSError):
                    pass
            if matched:
                ctime = p.info.get("create_time") or 0.0
                if best is None or ctime > best[2]:
                    best = (pid, p.info["name"] or name, ctime)
        except (psutil.Error, OSError):
            continue

    return (best[0], best[1]) if best else None


def validate_suspend(pid: int, expected_name: str, root: str, allowed: bool) -> tuple[bool, str]:
    """Policy checks run immediately before containment."""
    if not allowed:
        return False, "process suspension is disabled (set SENTINEL_ALLOW_SUSPEND=1)"
    if pid == os.getpid():
        return False, "refusing to suspend the Sentinel agent itself"
    try:
        p = psutil.Process(pid)
        name = p.name()
    except psutil.Error:
        return False, f"process {pid} no longer exists"
    if name.lower() in PROTECTED:
        return False, f"{name} is a protected system process"
    if name != expected_name:
        return False, f"pid {pid} is now {name}, expected {expected_name} (possible PID reuse)"
    if not touches_root(p, root):
        return False, f"{name} no longer references the watched folder"
    return True, "ok"


def suspend(pid: int) -> tuple[bool, str]:
    try:
        p = psutil.Process(pid)
        p.suspend()
        for _ in range(20):  # the OS applies the stop asynchronously; recheck for up to 2s
            if p.status() == psutil.STATUS_STOPPED:
                return True, "suspended"
            time.sleep(0.1)
        return False, f"suspend sent but status is still {p.status()}"
    except psutil.AccessDenied:
        return False, "access denied (run the agent as Administrator)"
    except psutil.Error as e:
        return False, f"suspend failed: {e}"


def resume(pid: int) -> None:
    try:
        psutil.Process(pid).resume()
    except psutil.Error:
        pass
