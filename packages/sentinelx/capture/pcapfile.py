"""Streaming reader for pcap and pcapng capture files.

Written against the file formats directly (libpcap's savefile format and the pcapng
specification, draft-ietf-opsawg-pcapng) rather than through Scapy, for three reasons
found in testing:

* Timestamp resolution. pcap files can store nanoseconds (magic ``0xa1b23c4d``) and
  pcapng interfaces declare their own resolution (``if_tsresol``); treating every file
  as microseconds reordered and stretched packets.
* Link types. In pcapng each interface has its own link type, so one file can mix
  Ethernet and Linux cooked capture. A single file-wide link type decoded nothing.
* Hostile files. Every length field is validated before anything is read, so a
  corrupt or malicious record cannot make the reader allocate gigabytes.

The reader streams one record at a time; a capture of any size uses constant memory.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from sentinelx.common.errors import PcapError

__all__ = ["CaptureRecord", "detect_format", "read_capture", "read_capture_stream"]

#: Largest record accepted. Real link-layer frames are at most ~65 KiB (jumbo frames,
#: loopback with large MTUs); anything claiming more is corruption or an attack.
MAX_RECORD_BYTES = 262_144
#: Largest pcapng block accepted (non-packet blocks can carry options and names).
MAX_BLOCK_BYTES = 1_048_576

_PCAP_MAGICS: dict[bytes, tuple[str, int]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),  # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),  # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big-endian, nanoseconds
}
_PCAPNG_SECTION = b"\x0a\x0d\x0d\x0a"
_BYTE_ORDER_MAGIC = 0x1A2B3C4D
_BLOCK_INTERFACE = 0x00000001
_BLOCK_SIMPLE_PACKET = 0x00000003
_BLOCK_ENHANCED_PACKET = 0x00000006
_BLOCK_SECTION = 0x0A0D0D0A
_OPTION_TSRESOL = 9
_OPTION_END = 0


@dataclass(frozen=True, slots=True)
class CaptureRecord:
    data: bytes
    timestamp: float
    link_type: int
    wire_length: int


def _read_exact(handle: BinaryIO, size: int, what: str) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise PcapError(f"capture file is truncated: incomplete {what}")
    return data


def read_capture(path: Path | str) -> Iterator[CaptureRecord]:
    """Yield every record of a pcap or pcapng file, in file order.

    Raises:
        PcapError: if the file is missing, not a capture, or corrupt. Records read
            before the corruption have already been yielded.
    """
    path = Path(path)
    try:
        handle = path.open("rb")
    except OSError as exc:
        raise PcapError(f"cannot open capture file {path.name}: {exc.strerror}") from exc
    with handle:
        yield from read_capture_stream(handle)


def read_capture_stream(handle: BinaryIO) -> Iterator[CaptureRecord]:
    """:func:`read_capture` for an open binary file object."""
    magic = handle.read(4)
    if magic in _PCAP_MAGICS:
        yield from _read_pcap(handle, magic)
    elif magic == _PCAPNG_SECTION:
        yield from _read_pcapng(handle)
    elif not magic:
        raise PcapError("capture file is empty")
    else:
        raise PcapError("not a pcap or pcapng capture file")


def detect_format(header: bytes) -> str | None:
    """``"pcap"``, ``"pcapng"`` or ``None`` from the first four bytes of a file."""
    if header[:4] in _PCAP_MAGICS:
        return "pcap"
    if header[:4] == _PCAPNG_SECTION:
        return "pcapng"
    return None


def _read_pcap(handle: BinaryIO, magic: bytes) -> Iterator[CaptureRecord]:
    order, resolution = _PCAP_MAGICS[magic]
    header = _read_exact(handle, 20, "file header")
    _major, _minor, _zone, _sigfigs, snaplen, network = struct.unpack(f"{order}HHiIII", header)
    # The upper bits of the link-type field carry FCS information, not the type.
    link_type = network & 0x0FFFFFFF
    limit = min(max(snaplen, 65_535), MAX_RECORD_BYTES) if snaplen else MAX_RECORD_BYTES
    record_header = struct.Struct(f"{order}IIII")
    while True:
        raw = handle.read(16)
        if not raw:
            return
        if len(raw) != 16:
            raise PcapError("capture file is truncated: incomplete record header")
        seconds, fraction, captured, original = record_header.unpack(raw)
        if captured > limit:
            raise PcapError(f"corrupt capture: record claims {captured} bytes (limit {limit})")
        data = _read_exact(handle, captured, "packet record")
        yield CaptureRecord(
            data, seconds + fraction / resolution, link_type, max(original, captured)
        )


def _tsresol(options: bytes, order: str) -> int:
    """Interface timestamp resolution in ticks per second (default: microseconds)."""
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack_from(f"{order}HH", options, offset)
        offset += 4
        if code == _OPTION_END:
            break
        value = options[offset : offset + length]
        offset += (length + 3) & ~3
        if code == _OPTION_TSRESOL and length >= 1:
            exponent = value[0]
            if exponent & 0x80:
                return int(2 ** min(exponent & 0x7F, 63))
            return int(10 ** min(exponent, 18))
    return 1_000_000


def _read_pcapng(handle: BinaryIO) -> Iterator[CaptureRecord]:
    order = "<"
    interfaces: list[tuple[int, int, int]] = []  # (link_type, resolution, snaplen)
    block_type = _BLOCK_SECTION
    first = True
    last_timestamp = 0.0
    while True:
        if first:
            raw_type = _PCAPNG_SECTION
            first = False
        else:
            raw_type = handle.read(4)
            if not raw_type:
                return
            if len(raw_type) != 4:
                raise PcapError("capture file is truncated: incomplete block header")
        raw_length = _read_exact(handle, 4, "block header")

        if raw_type == _PCAPNG_SECTION:
            magic = _read_exact(handle, 4, "section header")
            if struct.unpack("<I", magic)[0] == _BYTE_ORDER_MAGIC:
                order = "<"
            elif struct.unpack(">I", magic)[0] == _BYTE_ORDER_MAGIC:
                order = ">"
            else:
                raise PcapError("corrupt pcapng: bad byte-order magic")
            block_type = _BLOCK_SECTION
            interfaces = []  # interface ids are per section
            consumed = 4
        else:
            block_type = struct.unpack(f"{order}I", raw_type)[0]
            consumed = 0

        (total_length,) = struct.unpack(f"{order}I", raw_length)
        if total_length < 12 or total_length % 4 or total_length > MAX_BLOCK_BYTES + 32:
            raise PcapError(f"corrupt pcapng: invalid block length {total_length}")
        if total_length - 12 - consumed < 0:
            raise PcapError(f"corrupt pcapng: invalid block length {total_length}")
        body = _read_exact(handle, total_length - 12 - consumed, "block body")
        trailer = _read_exact(handle, 4, "block trailer")
        if struct.unpack(f"{order}I", trailer)[0] != total_length:
            raise PcapError("corrupt pcapng: block length mismatch")

        if block_type == _BLOCK_INTERFACE:
            if len(body) < 8:
                raise PcapError("corrupt pcapng: short interface description block")
            link_type, _reserved, snaplen = struct.unpack_from(f"{order}HHI", body, 0)
            interfaces.append((link_type, _tsresol(body[8:], order), snaplen))
        elif block_type == _BLOCK_ENHANCED_PACKET:
            if len(body) < 20:
                raise PcapError("corrupt pcapng: short packet block")
            interface_id, high, low, captured, original = struct.unpack_from(
                f"{order}IIIII", body, 0
            )
            if interface_id >= len(interfaces):
                raise PcapError(f"corrupt pcapng: packet for undeclared interface {interface_id}")
            if captured > min(len(body) - 20, MAX_RECORD_BYTES):
                raise PcapError(f"corrupt pcapng: packet claims {captured} bytes")
            link_type, resolution, _snaplen = interfaces[interface_id]
            last_timestamp = ((high << 32) | low) / resolution
            yield CaptureRecord(
                body[20 : 20 + captured], last_timestamp, link_type, max(original, captured)
            )
        elif block_type == _BLOCK_SIMPLE_PACKET:
            if not interfaces or len(body) < 4:
                raise PcapError("corrupt pcapng: simple packet block without an interface")
            (original,) = struct.unpack_from(f"{order}I", body, 0)
            link_type, _resolution, snaplen = interfaces[0]
            captured = min(original, len(body) - 4, snaplen or MAX_RECORD_BYTES)
            # Simple packet blocks carry no timestamp; keep file order.
            yield CaptureRecord(body[4 : 4 + captured], last_timestamp, link_type, original)
        # Other block types (name resolution, statistics, custom) are skipped.
