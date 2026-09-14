"""Firewall adapter interface and a safe command runner.

The response engine never talks to a firewall directly; it calls a
:class:`FirewallAdapter`.  That keeps nftables/iptables specifics in one place and
lets tests substitute an in-memory firewall that records what *would* have
happened.

Command execution rules, enforced by :class:`CommandRunner`:

* argv lists only - there is no code path that invokes a shell;
* the binary is resolved to an absolute path once, at construction;
* every argument is a ``str`` produced by this package from validated values,
  never raw user input (addresses are re-serialised from :mod:`ipaddress` objects);
* every call has a timeout and its outcome is logged.
"""

from __future__ import annotations

import abc
import asyncio
import contextlib
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sentinelx.common.errors import FirewallError
from sentinelx.common.netutils import IPNetworkT
from sentinelx.telemetry.logging import get_logger
from sentinelx.telemetry.metrics import metrics

__all__ = ["BlockEntry", "CommandResult", "CommandRunner", "FirewallAdapter"]

log = get_logger(__name__)

PLATFORM: str = sys.platform


@dataclass(frozen=True, slots=True)
class BlockEntry:
    """One active block."""

    network: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    comment: str = ""
    rate_limited: bool = False

    @property
    def temporary(self) -> bool:
        return self.expires_at is not None

    def remaining_seconds(self) -> float | None:
        if self.expires_at is None:
            return None
        return max(0.0, (self.expires_at - datetime.now(UTC)).total_seconds())

    def as_dict(self) -> dict[str, object]:
        return {
            "network": self.network,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "temporary": self.temporary,
            "remaining_seconds": self.remaining_seconds(),
            "comment": self.comment,
            "rate_limited": self.rate_limited,
        }


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def display(self) -> str:
        """Command for logs and audit. Safe: every token was generated internally."""
        return " ".join(self.argv)


class CommandRunner:
    """Runs one firewall binary with argv lists and a timeout.

    Args:
        binary: executable name, resolved with :func:`shutil.which`.
        timeout: seconds before the process is killed.
        use_sudo: prefix ``sudo -n`` (non-interactive). For deployments that grant
            the service a narrow sudoers rule rather than CAP_NET_ADMIN.

    Raises:
        FirewallError: at construction if the binary is not installed.
    """

    def __init__(self, binary: str, *, timeout: float = 10.0, use_sudo: bool = False) -> None:
        resolved = shutil.which(binary)
        if resolved is None:
            raise FirewallError(f"{binary} is not installed or not on PATH")
        self.binary = resolved
        self.timeout = timeout
        self._prefix: tuple[str, ...] = ()
        if use_sudo:
            sudo = shutil.which("sudo")
            if sudo is None:
                raise FirewallError("use_sudo requested but sudo is not installed")
            self._prefix = (sudo, "-n")

    async def run(self, *args: str, check: bool = True) -> CommandResult:
        for arg in args:
            if not isinstance(arg, str):  # defensive: catches programming errors early
                raise TypeError(f"firewall argument must be str, got {type(arg).__name__}")
            if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in arg):
                raise FirewallError("refusing firewall argument containing control characters")
        argv = (*self._prefix, self.binary, *args)
        started = time.perf_counter()
        if PLATFORM == "win32":
            # asyncio subprocesses need the Proactor event loop on Windows, and uvicorn
            # uses the selector loop in some modes; a worker thread works with both.
            returncode, stdout, stderr = await self._run_in_thread(argv)
        else:
            returncode, stdout, stderr = await self._run_async(argv)

        result = CommandResult(
            argv=argv,
            returncode=returncode,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            duration=time.perf_counter() - started,
        )
        log.debug(
            "firewall_command",
            command=result.display,
            returncode=result.returncode,
            duration=round(result.duration, 4),
        )
        if check and not result.ok:
            raise FirewallError(
                f"firewall command failed ({result.returncode}): {result.stderr.strip() or result.stdout.strip()}",
                command=result.display,
                stderr=result.stderr,
            )
        return result

    async def _run_async(self, argv: tuple[str, ...]) -> tuple[int, bytes, bytes]:
        try:
            process = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
        except OSError as exc:
            raise FirewallError(
                f"could not execute firewall command: {exc}", command=" ".join(argv)
            ) from exc
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
        except (TimeoutError, asyncio.CancelledError) as exc:
            # Never leave a firewall command running unattended.
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await process.wait()
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise FirewallError(
                f"firewall command timed out after {self.timeout}s", command=" ".join(argv)
            ) from None
        return (process.returncode if process.returncode is not None else -1), stdout, stderr

    async def _run_in_thread(self, argv: tuple[str, ...]) -> tuple[int, bytes, bytes]:
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        def run() -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                argv,
                capture_output=True,
                timeout=self.timeout,
                check=False,
                creationflags=creation_flags,
            )

        try:
            completed = await asyncio.to_thread(run)
        except subprocess.TimeoutExpired:
            raise FirewallError(
                f"firewall command timed out after {self.timeout}s", command=" ".join(argv)
            ) from None
        except OSError as exc:
            raise FirewallError(
                f"could not execute firewall command: {exc}", command=" ".join(argv)
            ) from exc
        return completed.returncode, completed.stdout, completed.stderr


class FirewallAdapter(abc.ABC):
    """Operations the response engine needs from a firewall.

    Adapters receive networks that have **already passed the safety guard**.  They
    must still never build commands from anything but ``ipaddress`` objects.
    """

    backend: str = "abstract"

    @abc.abstractmethod
    async def setup(self) -> None:
        """Create the tables/chains/sets this adapter owns. Idempotent."""

    @abc.abstractmethod
    async def block(
        self, network: IPNetworkT, *, duration: int | None = None, comment: str = ""
    ) -> BlockEntry:
        """Drop traffic from ``network``; auto-expire after ``duration`` seconds if given."""

    @abc.abstractmethod
    async def unblock(self, network: IPNetworkT) -> bool:
        """Remove a block. Returns False if it was not present."""

    @abc.abstractmethod
    async def rate_limit(
        self, network: IPNetworkT, *, packets_per_second: int, duration: int | None = None
    ) -> BlockEntry:
        """Limit packets from ``network`` to a rate."""

    @abc.abstractmethod
    async def list_blocked(self) -> list[BlockEntry]:
        """Blocks currently in force, as reported by the firewall itself."""

    @abc.abstractmethod
    async def teardown(self) -> None:
        """Remove everything this adapter created (its own table or chain, nothing else)."""

    async def block_ip(self, network: IPNetworkT, comment: str = "") -> BlockEntry:
        return await self.block(network, comment=comment)

    async def unblock_ip(self, network: IPNetworkT) -> bool:
        return await self.unblock(network)

    async def add_temporary_block(
        self, network: IPNetworkT, duration: int, comment: str = ""
    ) -> BlockEntry:
        if duration <= 0:
            raise ValueError(f"temporary block duration must be positive, got {duration}")
        return await self.block(network, duration=duration, comment=comment)

    async def remove_rule(self, network: IPNetworkT) -> bool:
        return await self.unblock(network)

    async def health(self) -> dict[str, object]:
        return {"backend": self.backend, "ok": True}

    @staticmethod
    def _record(operation: str, backend: str, ok: bool) -> None:
        metrics.firewall_actions.labels(
            backend=backend, operation=operation, result="ok" if ok else "error"
        ).inc()
