"""Process and workflow allowlist for legitimate backup, archive, and sync tools."""
from __future__ import annotations

import os
from typing import Optional, Set

DEFAULT_ALLOWLIST = {
    # Common archive & compression tools
    "7z.exe", "7za.exe", "winrar.exe", "rar.exe", "tar.exe", "zip.exe", "unzip.exe",
    # Windows native & enterprise backup utilities
    "robocopy.exe", "wbadmin.exe", "vssadmin.exe", "backup.exe", "ntbackup.exe",
    # Cross-platform backup & sync utilities
    "rsync.exe", "rclone.exe", "restic.exe", "borg.exe", "duplicati.exe",
    # Linux & cross-platform equivalents
    "7z", "7za", "tar", "zip", "unzip", "gzip", "bzip2", "xz", "rsync", "rclone", "restic",
}


class Allowlist:
    def __init__(self, names: Optional[Set[str]] = None):
        self._names = {n.lower() for n in (names or DEFAULT_ALLOWLIST)}

    def is_allowlisted(self, process_name: Optional[str], cmdline: Optional[str] = None) -> bool:
        """Check if the given process name or commandline matches known legitimate tooling."""
        if not process_name and not cmdline:
            return False

        if process_name:
            clean_name = os.path.basename(process_name).lower()
            if clean_name in self._names:
                return True

        if cmdline:
            cl = cmdline.lower()
            # Recognize explicit legitimate backup commands or python scripts
            if any(term in cl for term in ("backup", "archive", "compress", "synctoy", "robocopy")):
                # Ensure it's not a simulator attack masquerading as backup
                if "attack" not in cl and "ransomware" not in cl:
                    return True

        return False
