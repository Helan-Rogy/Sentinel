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


def touches_root(proc: psutil.Process, root: str) -> bool:
    root_n = os.path.normcase(os.path.abspath(root))
    try:
        cmd = os.path.normcase(" ".join(proc.cmdline()))
        if root_n in cmd:
            return True
        return any(os.path.normcase(f.path).startswith(root_n) for f in proc.open_files())
    except (psutil.Error, OSError):
        return False


def attribute_process(root: str, exclude: tuple[int, ...] = ()) -> Optional[tuple[int, str]]:
    skip = set(exclude) | {os.getpid()}
    best: Optional[psutil.Process] = None
    for p in psutil.process_iter(["pid", "name"]):
        if p.info["pid"] in skip or (p.info["name"] or "").lower() in PROTECTED:
            continue
        if touches_root(p, root):
            try:
                if best is None or p.create_time() > best.create_time():
                    best = p
            except psutil.Error:
                continue
    return (best.pid, best.name()) if best else None


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
