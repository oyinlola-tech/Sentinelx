"""Hand the generated first-administrator password to the operator without logging it.

Anything written to standard output or standard error ends up in a log: ``docker logs``,
the systemd journal, a CI transcript or a log shipper. So the generated password is
never printed. It is written to a file only this account can read, the console shows
where that file is, and the file is removed once the administrator has replaced the
password.

The default location is a private directory in this account's temporary directory. In
the Docker Compose stack that is the API container's ``/tmp``, a memory-backed tmpfs, so
the password never reaches a disk or a volume.
"""

from __future__ import annotations

import contextlib
import os
import stat
import sys
import tempfile
from pathlib import Path

from sentinelx.telemetry.logging import get_logger

__all__ = [
    "BootstrapSecretError",
    "default_password_file",
    "remove_password_file",
    "write_password_file",
]

log = get_logger(__name__)

PLATFORM: str = sys.platform
FILE_NAME = "initial-admin-password"


class BootstrapSecretError(OSError):
    """The password file could not be written safely."""


def default_password_file() -> Path:
    """``<temp>/sentinelx-<uid>/initial-admin-password``, one directory per account."""
    owner = str(os.geteuid()) if hasattr(os, "geteuid") else os.environ.get("USERNAME", "user")
    return Path(tempfile.gettempdir()) / f"sentinelx-{owner}" / FILE_NAME


def _private_directory(directory: Path) -> None:
    """Create ``directory`` for this account alone, or refuse one others could tamper with."""
    with contextlib.suppress(FileExistsError):
        directory.mkdir(mode=0o700, parents=True)
    info = directory.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise BootstrapSecretError(f"{directory} is not a plain directory")
    if PLATFORM != "win32":  # Windows temp directories are already per user (ACLs)
        if info.st_uid != os.geteuid():
            raise BootstrapSecretError(f"{directory} belongs to another account")
        if info.st_mode & 0o077:
            raise BootstrapSecretError(
                f"{directory} is accessible to other accounts (mode {stat.S_IMODE(info.st_mode):o})"
            )


def write_password_file(path: Path, password: str) -> Path:
    """Write ``password`` to ``path`` readable by this account only.

    An existing file is replaced, never followed: a symlink planted at ``path`` is
    removed rather than written through.

    Raises:
        BootstrapSecretError: the directory or file cannot be made private.
    """
    path = path.expanduser()
    try:
        _private_directory(path.parent)
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
    except BootstrapSecretError:
        raise
    except OSError as exc:
        raise BootstrapSecretError(f"cannot create {path}: {exc.strerror or exc}") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(password + "\n")
    return path


def remove_password_file(path: Path) -> bool:
    """Delete the password file if it exists. Returns whether one was removed."""
    try:
        path.expanduser().unlink()
    except FileNotFoundError:
        return False
    except OSError as exc:
        log.warning("bootstrap_password_file_not_removed", path=str(path), error=str(exc))
        return False
    log.info("bootstrap_password_file_removed", path=str(path))
    return True
