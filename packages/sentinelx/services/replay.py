"""PCAP replay (the PCAP Lab).

A replay runs in its **own** pipeline instance, never the live one:

* its sliding windows, baselines and incidents cannot mix with live traffic state;
* its response engine is forced into dry run with an in-memory firewall, so
  replaying a capture can show what *would* have been blocked but can never block
  anything, whatever the live response mode is;
* its detections and incidents are tagged with the replay id, which keeps them out
  of the live dashboards while remaining queryable in the lab.

Uploaded files are stored under ``PCAP_DIRECTORY/uploads`` with a random name; the
original name is kept only as metadata.  Paths supplied by clients are resolved and
must stay inside ``PCAP_DIRECTORY``.
"""

from __future__ import annotations

import asyncio
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelx.capture.pcap import PcapFileCapture, pcap_metadata
from sentinelx.common.enums import ResponseMode
from sentinelx.common.errors import PcapError
from sentinelx.common.models import new_id
from sentinelx.config.settings import Settings
from sentinelx.events.bus import EventBus, EventType
from sentinelx.events.serialize import detection_to_dict, incident_to_dict
from sentinelx.firewall import MemoryFirewall
from sentinelx.pipeline import Pipeline
from sentinelx.response.engine import decision_payload
from sentinelx.services.rules import RuleService
from sentinelx.storage.audit import AuditService
from sentinelx.storage.database import Database
from sentinelx.storage.models import ReplayRecord
from sentinelx.storage.repositories import ReplayRepository
from sentinelx.telemetry.logging import get_logger

__all__ = ["ReplayService"]

log = get_logger(__name__)

_PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
)
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class ReplayService:
    def __init__(
        self,
        settings: Settings,
        database: Database,
        bus: EventBus,
        rules: RuleService,
        audit: AuditService,
    ) -> None:
        self.settings = settings
        self.database = database
        self.bus = bus
        self.rules = rules
        self.audit = audit
        self.directory = Path(settings.capture.pcap_directory).resolve()
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._pipelines: dict[str, Pipeline] = {}
        self.max_concurrent = 2

    # ------------------------------------------------------------------ files

    def resolve(self, relative: str) -> Path:
        """Resolve a client-supplied path strictly inside the PCAP directory.

        Raises:
            PcapError: for traversal attempts, absolute paths, or missing files.
        """
        candidate = (self.directory / relative).resolve()
        if self.directory != candidate and self.directory not in candidate.parents:
            raise PcapError("path is outside the PCAP directory")
        if not candidate.is_file():
            raise PcapError(f"capture file not found: {relative}")
        return candidate

    def list_files(self) -> list[dict[str, Any]]:
        if not self.directory.is_dir():
            return []
        files = []
        for path in sorted(self.directory.rglob("*")):
            if path.suffix.lower() not in {".pcap", ".pcapng", ".cap"} or not path.is_file():
                continue
            stat = path.stat()
            files.append(
                {
                    "path": path.relative_to(self.directory).as_posix(),
                    "filename": path.name,
                    "size_bytes": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                }
            )
        return files

    @property
    def upload_limit_bytes(self) -> int:
        return (
            min(self.settings.api.max_upload_mb, self.settings.capture.max_pcap_size_mb)
            * 1024
            * 1024
        )

    def uploads_size_bytes(self) -> int:
        uploads = self.directory / "uploads"
        if not uploads.is_dir():
            return 0
        return sum(path.stat().st_size for path in uploads.iterdir() if path.is_file())

    async def store_upload(self, filename: str, chunks: Any, *, actor: str) -> dict[str, Any]:
        """Stream an upload to disk, validating the magic number, size limit and quota.

        Raises:
            PcapError: when the file is too large, the upload quota is exhausted, or the
                content is not a pcap/pcapng capture. Nothing is left on disk.
        """
        limit = self.upload_limit_bytes
        quota = self.settings.capture.upload_quota_mb * 1024 * 1024
        used = await asyncio.to_thread(self.uploads_size_bytes)
        if used >= quota:
            raise PcapError(
                f"the upload area is full ({used // 1_048_576} of "
                f"{quota // 1_048_576} MB); delete old uploads or raise CAPTURE__UPLOAD_QUOTA_MB"
            )
        limit = min(limit, quota - used)
        uploads = self.directory / "uploads"
        uploads.mkdir(parents=True, exist_ok=True)
        stem = _SAFE_NAME.sub("_", Path(filename).stem)[:60] or "capture"
        suffix = ".pcapng" if filename.lower().endswith(".pcapng") else ".pcap"
        target = uploads / f"{datetime.now(UTC):%Y%m%d%H%M%S}-{secrets.token_hex(4)}-{stem}{suffix}"
        written = 0
        header = b""
        try:
            with target.open("wb") as handle:
                async for chunk in chunks:
                    if len(header) < 4:
                        header += chunk[: 4 - len(header)]
                    written += len(chunk)
                    if written > limit:
                        raise PcapError(
                            f"upload exceeds the {max(limit // 1_048_576, 1)} MB that can be accepted"
                        )
                    await asyncio.to_thread(handle.write, chunk)
            if header[:4] not in _PCAP_MAGICS:
                raise PcapError("file is not a pcap or pcapng capture")
            metadata = await asyncio.to_thread(pcap_metadata, target)
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        target.chmod(0o640)
        relative = target.relative_to(self.directory).as_posix()
        await self.audit.record(
            actor=actor,
            action="UPLOAD_PCAP",
            target=relative,
            source="api",
            details={"original_name": filename[:200], "size_bytes": written},
        )
        # Relative path last: the metadata's own path is absolute and must not leak.
        return {**metadata, "path": relative}

    async def inspect(self, relative: str) -> dict[str, Any]:
        path = self.resolve(relative)
        metadata = await asyncio.to_thread(pcap_metadata, path)
        return {**metadata, "path": relative}

    # ----------------------------------------------------------------- replay

    async def start(
        self, relative: str, *, actor: str, speed: float = 0.0, limit: int | None = None
    ) -> dict[str, Any]:
        path = self.resolve(relative)
        if sum(1 for task in self._tasks.values() if not task.done()) >= self.max_concurrent:
            raise PcapError(f"at most {self.max_concurrent} replays may run at once")
        if not 0 <= speed <= 100:
            raise PcapError("speed must be between 0 (unpaced) and 100")
        replay_id = new_id()
        options = {"speed": speed, "limit": limit}
        async with self.database.session() as session:
            await ReplayRepository(session).add(
                ReplayRecord(
                    replay_id=replay_id,
                    filename=relative,
                    status="queued",
                    created_by=actor,
                    options=options,
                )
            )
        await self.audit.record(
            actor=actor, action="START_REPLAY", target=relative, source="api", details=options
        )
        self._tasks[replay_id] = asyncio.create_task(
            self._run(replay_id, path, speed, limit), name=f"replay-{replay_id[:8]}"
        )
        return {
            "replay_id": replay_id,
            "status": "queued",
            "filename": relative,
            "options": options,
        }

    def _isolated_pipeline(self, replay_id: str) -> Pipeline:
        replay_settings = self.settings.model_copy(deep=True)
        # Hard safety line: a replay can simulate responses, never apply them.
        replay_settings.response.dry_run = True
        replay_settings.response.firewall_backend = "null"
        if replay_settings.response.mode is ResponseMode.MANUAL_APPROVAL:
            replay_settings.response.mode = (
                ResponseMode.AUTOMATIC
            )  # show decisions instead of queueing approvals
        pipeline = Pipeline(replay_settings, bus=self.bus, firewall=MemoryFirewall())
        pipeline.replay_id = replay_id
        return pipeline

    async def _run(self, replay_id: str, path: Path, speed: float, limit: int | None) -> None:
        pipeline = self._isolated_pipeline(replay_id)
        self._pipelines[replay_id] = pipeline
        self.rules.attach(pipeline.detection)
        await self.rules.apply()
        # The shared bus is already running; only the response engine needs starting.
        await pipeline.response.start()
        await self._update(replay_id, status="running", started_at=datetime.now(UTC))

        async def progress(stats: dict[str, Any]) -> None:
            payload = {"replay_id": replay_id, **stats}
            await self.bus.publish(EventType.REPLAY_PROGRESS, payload)
            await self._update(replay_id, progress=payload)

        try:
            report = await pipeline.run(
                PcapFileCapture(path, speed=speed, limit=limit),
                progress=progress,
                progress_interval=0.5,
            )
            summary = report.as_dict()
            summary["detections"] = [
                detection_to_dict(r.detection, r.risk) for r in report.detections[:500]
            ]
            summary["incidents"] = [incident_to_dict(i) for i in report.incidents.values()]
            summary["decisions"] = [
                decision_payload(d)
                for r in report.detections
                for d in r.decisions
                if d.action.is_preventive
            ][:500]
            summary["safety_note"] = (
                "Replay responses are always simulated; no firewall changes were made."
            )
            await self._update(
                replay_id, status="completed", finished_at=datetime.now(UTC), report=summary
            )
            await self.bus.publish(
                EventType.REPLAY_COMPLETED,
                {
                    "replay_id": replay_id,
                    "status": "completed",
                    **{
                        k: v
                        for k, v in summary.items()
                        if k not in {"detections", "incidents", "decisions"}
                    },
                },
            )
            log.info(
                "replay_completed",
                replay_id=replay_id,
                frames=report.frames,
                detections=len(report.detections),
            )
        except asyncio.CancelledError:
            await self._update(replay_id, status="cancelled", finished_at=datetime.now(UTC))
            await self.bus.publish(
                EventType.REPLAY_COMPLETED, {"replay_id": replay_id, "status": "cancelled"}
            )
            raise
        except Exception as exc:
            message = (
                str(exc) if isinstance(exc, PcapError) else f"{type(exc).__name__}: replay failed"
            )
            log.exception("replay_failed", replay_id=replay_id)
            await self._update(
                replay_id, status="failed", finished_at=datetime.now(UTC), error=message
            )
            await self.bus.publish(
                EventType.REPLAY_COMPLETED,
                {"replay_id": replay_id, "status": "failed", "error": message},
            )
        finally:
            await pipeline.response.stop()
            if pipeline.detection in self.rules.engines:
                self.rules.engines.remove(pipeline.detection)
            self._pipelines.pop(replay_id, None)

    async def cancel(self, replay_id: str, *, actor: str) -> bool:
        task = self._tasks.get(replay_id)
        if task is None or task.done():
            return False
        task.cancel()
        await self.audit.record(actor=actor, action="CANCEL_REPLAY", target=replay_id, source="api")
        return True

    async def wait(self, replay_id: str) -> None:
        task = self._tasks.get(replay_id)
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)

    async def _update(self, replay_id: str, **values: Any) -> None:
        async with self.database.session() as session:
            record = await ReplayRepository(session).get(replay_id)
            if record is not None:
                for key, value in values.items():
                    setattr(record, key, value)

    async def get(self, replay_id: str) -> dict[str, Any] | None:
        async with self.database.session() as session:
            record = await ReplayRepository(session).get(replay_id)
        return replay_to_dict(record) if record else None

    async def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        async with self.database.session() as session:
            records = await ReplayRepository(session).recent(limit=limit)
        return [replay_to_dict(r, include_report=False) for r in records]

    async def shutdown(self) -> None:
        for task in self._tasks.values():
            task.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)


def replay_to_dict(record: ReplayRecord, *, include_report: bool = True) -> dict[str, Any]:
    data: dict[str, Any] = {
        "replay_id": record.replay_id,
        "filename": record.filename,
        "status": record.status,
        "created_at": record.created_at.isoformat(),
        "started_at": record.started_at.isoformat() if record.started_at else None,
        "finished_at": record.finished_at.isoformat() if record.finished_at else None,
        "created_by": record.created_by,
        "options": record.options,
        "progress": record.progress,
        "error": record.error,
    }
    if include_report:
        data["report"] = record.report
    else:
        data["summary"] = (
            {
                k: record.report.get(k)
                for k in (
                    "frames",
                    "detection_count",
                    "incident_count",
                    "packets_per_second",
                    "wall_seconds",
                )
            }
            if record.report
            else None
        )
    return data
