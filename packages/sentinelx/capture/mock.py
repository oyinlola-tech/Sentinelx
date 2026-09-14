"""In-memory capture sources for tests and benchmarks.

:class:`MockCapture` replays a list of frames the caller already has.  It exists
so detection tests need neither a network nor a file, which keeps the unit suite
fast and hermetic.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable, Sequence

from sentinelx.capture.base import PacketCapture, RawFrame
from sentinelx.parser.layers import LinkType

__all__ = ["MockCapture"]


class MockCapture(PacketCapture):
    """Yields a fixed sequence of frames.

    Args:
        frames: the frames to emit, in order.
        delay: optional pause between frames, for exercising timing-sensitive code.
        repeat: how many times to emit the whole sequence. Useful for load tests.

    Example:
        >>> frames = [RawFrame(raw_bytes, timestamp=1.0)]
        >>> async with MockCapture(frames) as capture:
        ...     async for frame in capture.frames():
        ...         ...
    """

    source_kind = "mock"

    def __init__(
        self,
        frames: Sequence[RawFrame] | Iterable[RawFrame],
        *,
        delay: float = 0.0,
        repeat: int = 1,
        interface: str = "mock0",
    ) -> None:
        super().__init__(interface=interface)
        self._frames_source = list(frames)
        self.delay = delay
        if repeat < 1:
            raise ValueError(f"repeat must be >= 1, got {repeat}")
        self.repeat = repeat

    @classmethod
    def from_bytes(
        cls,
        packets: Iterable[bytes],
        *,
        start_time: float = 1_700_000_000.0,
        interval: float = 0.001,
        link_type: int = LinkType.ETHERNET,
        **kwargs: object,
    ) -> MockCapture:
        """Build a source from raw packet bytes, assigning evenly spaced timestamps."""
        frames = [
            RawFrame(data=data, timestamp=start_time + index * interval, link_type=link_type)
            for index, data in enumerate(packets)
        ]
        return cls(frames, **kwargs)  # type: ignore[arg-type]

    async def _open(self) -> None:
        return None

    async def _frames(self) -> AsyncIterator[RawFrame]:
        for _ in range(self.repeat):
            for frame in self._frames_source:
                if not self.running:
                    return
                yield frame
                if self.delay:
                    await asyncio.sleep(self.delay)

    async def _close(self) -> None:
        return None
