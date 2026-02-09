"""Cross-platform compatibility helpers."""

import os
import sys


def secure_file(path: "os.PathLike[str] | str") -> None:
    """Set restrictive permissions (owner-only read/write) on *path*.

    On POSIX systems this calls ``os.chmod(path, 0o600)``.
    On Windows POSIX permission bits have no real effect, so this is a
    no-op — use Windows ACLs for equivalent protection.
    """
    if sys.platform != "win32":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # best-effort; don't crash if the filesystem doesn't support it
