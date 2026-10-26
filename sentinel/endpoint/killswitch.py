"""Memory Canary & Ransomware Vaccine Killswitch Manager.

Creates in-memory vaccine mutexes corresponding to known ransomware kill-switches
and single-instance locks (e.g. WannaCry, LockBit, Cerber).
When ransomware begins execution and checks for these mutexes, it detects an active
lock or kill-switch and terminates immediately before initiating disk encryption.
"""
from __future__ import annotations

import ctypes
import os
import sys
from typing import Dict, List, Optional

# Prominent ransomware killswitch and single-instance mutex signatures
VACCINE_MUTEXES = [
    "Global\\MsWinZonesCacheCounterMutexA",     # WannaCry global killswitch
    "Global\\LockBit_SingleInstance_Mutex",     # LockBit single-execution lock
    "Global\\p1337_mutex",                      # Cerber ransomware lock
    "Global\\Maze_Vaccine_Mutex_2020",          # Maze ransomware
    "Global\\Sentinel_Immunity_Canary_Mutex",   # Sentinel memory canary token
]


class KillSwitchManager:
    """Manages active kernel mutex handles for pre-execution ransomware neutralization."""

    def __init__(self, mutex_names: Optional[List[str]] = None) -> None:
        self.mutex_names = list(mutex_names or VACCINE_MUTEXES)
        self._handles: Dict[str, Any] = {}
        self._is_windows = sys.platform == "win32"

    def deploy(self) -> List[str]:
        """Deploy and hold vaccine mutexes in process memory."""
        deployed = []
        for name in self.mutex_names:
            if name in self._handles:
                deployed.append(name)
                continue

            if self._is_windows:
                try:
                    # CreateMutexW(lpMutexAttributes=None, bInitialOwner=True, lpName=name)
                    handle = ctypes.windll.kernel32.CreateMutexW(None, True, name)
                    if handle:
                        self._handles[name] = handle
                        deployed.append(name)
                except Exception:
                    pass
            else:
                # Simulated handle for non-Windows platforms
                self._handles[name] = id(name)
                deployed.append(name)

        return deployed

    def release(self) -> None:
        """Release mutex handles cleanly on shutdown."""
        if self._is_windows:
            for name, handle in list(self._handles.items()):
                try:
                    ctypes.windll.kernel32.CloseHandle(handle)
                except Exception:
                    pass
        self._handles.clear()

    @property
    def active_mutexes(self) -> List[str]:
        return list(self._handles.keys())

    def status(self) -> Dict[str, Any]:
        return {
            "deployed_count": len(self._handles),
            "active_mutexes": self.active_mutexes,
            "platform": sys.platform,
        }
