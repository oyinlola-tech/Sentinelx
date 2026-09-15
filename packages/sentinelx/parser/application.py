"""Application-protocol metadata extraction.

Strictly metadata: query names, HTTP request lines and headers, TLS handshake
fields.  Nothing here decrypts anything, and TLS parsing stops at the ClientHello
and ServerHello, which are transmitted in the clear by design.

Bodies are never retained.  Only the small set of fields the detectors actually
use is extracted, which keeps memory per packet bounded and avoids turning the
sensor into an accidental content recorder.
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import Final

__all__ = [
    "DnsInfo",
    "DnsQuestion",
    "HttpInfo",
    "TlsInfo",
    "parse_dns",
    "parse_http",
    "parse_tls",
    "shannon_entropy",
]

#: Cap on how much of a payload we will scan. Bounds worst-case work per packet
#: and stops a crafted jumbo payload from becoming a CPU denial of service.
_MAX_SCAN_BYTES: Final = 4096
_MAX_DNS_NAME_LABELS: Final = 64
_MAX_HTTP_HEADERS: Final = 40

_HTTP_METHODS: Final = frozenset(
    {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT"}
)
#: Headers worth keeping for detection. An allow-list, not a deny-list, so new
#: header types never start leaking into storage by accident.
_HTTP_HEADERS_OF_INTEREST: Final = frozenset(
    {
        "host",
        "user-agent",
        "referer",
        "content-length",
        "content-type",
        "authorization",
        "x-forwarded-for",
        "cookie",
        "connection",
        "accept",
    }
)
#: Headers recorded as present/absent only - never with their value.
_HTTP_SENSITIVE_HEADERS: Final = frozenset({"authorization", "cookie"})

DNS_RECORD_TYPES: Final[dict[int, str]] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    41: "OPT",
    43: "DS",
    48: "DNSKEY",
    252: "AXFR",
    255: "ANY",
}


def shannon_entropy(text: str) -> float:
    """Shannon entropy of a string in bits per character.

    Used to tell an algorithmically generated or data-carrying DNS label
    (``x7f2k9qp3mz.example.com``) from a human-chosen one (``mail.example.com``).
    English hostnames land around 2.5-3.2; encoded data exceeds 3.8.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


# ========================================================================= DNS


@dataclass(frozen=True, slots=True)
class DnsQuestion:
    name: str
    qtype: int
    qclass: int

    @property
    def type_name(self) -> str:
        return DNS_RECORD_TYPES.get(self.qtype, str(self.qtype))


@dataclass(frozen=True, slots=True)
class DnsInfo:
    """Decoded DNS message header and question section."""

    transaction_id: int
    is_response: bool
    opcode: int
    rcode: int
    questions: list[DnsQuestion] = field(default_factory=list)
    answer_count: int = 0
    authority_count: int = 0
    additional_count: int = 0
    truncated: bool = False

    @property
    def query_name(self) -> str | None:
        return self.questions[0].name if self.questions else None

    @property
    def query_type(self) -> str | None:
        return self.questions[0].type_name if self.questions else None

    @property
    def is_nxdomain(self) -> bool:
        """RCODE 3. A burst of these is characteristic of DGA malware."""
        return self.is_response and self.rcode == 3

    @property
    def max_label_length(self) -> int:
        """Longest single label across all questions.

        Long labels are the signature of DNS tunnelling: data is base32/base64
        encoded into the leftmost label, which pushes it towards the 63-byte max.
        """
        longest = 0
        for question in self.questions:
            for label in question.name.split("."):
                longest = max(longest, len(label))
        return longest

    @property
    def name_entropy(self) -> float:
        name = self.query_name
        if not name:
            return 0.0
        leftmost = name.split(".")[0]
        return shannon_entropy(leftmost)


def _read_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a DNS name, following compression pointers.

    Returns the name and the offset just past the name *in the original stream*
    (pointer jumps do not advance the caller's cursor).

    Pointer loops are a classic parser denial-of-service; the visited-offset set
    and the label cap make them terminate.
    """
    labels: list[str] = []
    visited: set[int] = set()
    cursor = offset
    after_pointer: int | None = None

    for _ in range(_MAX_DNS_NAME_LABELS):
        if cursor >= len(data):
            break
        length = data[cursor]
        if length == 0:
            cursor += 1
            break
        if length & 0xC0 in (0x40, 0x80):
            # Extended (EDNS0 bitstring) and reserved label types are obsolete or
            # undefined. Reading them as lengths would yield labels over 63 bytes.
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if cursor + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if pointer in visited or pointer >= len(data):
                break
            visited.add(pointer)
            if after_pointer is None:
                after_pointer = cursor + 2
            cursor = pointer
            continue
        cursor += 1
        label = data[cursor : cursor + length]
        if len(label) < length:
            break
        labels.append(label.decode("ascii", errors="replace"))
        cursor += length

    return ".".join(labels), after_pointer if after_pointer is not None else cursor


def parse_dns(payload: bytes) -> DnsInfo | None:
    """Parse a DNS message header and its question section.

    Answer records are deliberately not parsed: no detector needs them, and
    skipping them keeps per-packet cost low.
    """
    if len(payload) < 12:
        return None
    try:
        transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
            "!HHHHHH", payload
        )
    except struct.error:
        return None

    questions: list[DnsQuestion] = []
    offset = 12
    for _ in range(min(qdcount, 16)):  # a legitimate query has 1; cap the rest
        if offset >= len(payload):
            break
        name, offset = _read_dns_name(payload, offset)
        if offset + 4 > len(payload):
            break
        qtype, qclass = struct.unpack_from("!HH", payload, offset)
        offset += 4
        questions.append(DnsQuestion(name=name, qtype=qtype, qclass=qclass))

    return DnsInfo(
        transaction_id=transaction_id,
        is_response=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0x0F,
        rcode=flags & 0x0F,
        questions=questions,
        answer_count=ancount,
        authority_count=nscount,
        additional_count=arcount,
        truncated=bool(flags & 0x0200),
    )


# ======================================================================== HTTP


@dataclass(frozen=True, slots=True)
class HttpInfo:
    """HTTP/1.x request or response metadata.

    ``headers`` holds only allow-listed headers, with sensitive ones reduced to a
    presence marker so credentials never reach storage or logs.
    """

    is_request: bool
    method: str | None = None
    path: str | None = None
    version: str | None = None
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def host(self) -> str | None:
        return self.headers.get("host")

    @property
    def user_agent(self) -> str | None:
        return self.headers.get("user-agent")

    @property
    def has_authorization(self) -> bool:
        return "authorization" in self.headers


def parse_http(payload: bytes) -> HttpInfo | None:
    """Parse an HTTP/1.x start line and headers.

    Returns ``None`` for anything that is not plausibly the start of an HTTP
    message, including the continuation of a message split across segments - this
    parser is stateless by design, and reassembling streams is out of scope.
    """
    if len(payload) < 16:
        return None
    window = payload[:_MAX_SCAN_BYTES]
    line_end = window.find(b"\r\n")
    if line_end == -1:
        return None
    start_line = window[:line_end]
    parts = start_line.split(b" ")
    if len(parts) < 3:
        return None

    is_request = parts[0] in _HTTP_METHODS
    is_response = parts[0].startswith(b"HTTP/")
    if not (is_request or is_response):
        return None

    method = path = version = None
    status_code = None
    if is_request:
        method = parts[0].decode("ascii", errors="replace")
        path = parts[1].decode("ascii", errors="replace")[:512]
        version = parts[2].decode("ascii", errors="replace")
    else:
        version = parts[0].decode("ascii", errors="replace")
        try:
            status_code = int(parts[1])
        except ValueError:
            return None

    headers: dict[str, str] = {}
    cursor = line_end + 2
    for _ in range(_MAX_HTTP_HEADERS):
        next_end = window.find(b"\r\n", cursor)
        if next_end == -1 or next_end == cursor:
            break
        raw_header = window[cursor:next_end]
        cursor = next_end + 2
        separator = raw_header.find(b":")
        if separator == -1:
            continue
        name = raw_header[:separator].decode("ascii", errors="replace").strip().lower()
        if name not in _HTTP_HEADERS_OF_INTEREST:
            continue
        if name in _HTTP_SENSITIVE_HEADERS:
            headers[name] = "present"
            continue
        value = raw_header[separator + 1 :].decode("utf-8", errors="replace").strip()
        headers[name] = value[:256]

    return HttpInfo(
        is_request=is_request,
        method=method,
        path=path,
        version=version,
        status_code=status_code,
        headers=headers,
    )


# ========================================================================= TLS

_TLS_HANDSHAKE: Final = 0x16
_TLS_CLIENT_HELLO: Final = 0x01
_TLS_SERVER_HELLO: Final = 0x02
_EXT_SERVER_NAME: Final = 0x0000
_EXT_ALPN: Final = 0x0010
_EXT_SUPPORTED_VERSIONS: Final = 0x002B

_TLS_VERSIONS: Final[dict[int, str]] = {
    0x0300: "SSLv3",
    0x0301: "TLS1.0",
    0x0302: "TLS1.1",
    0x0303: "TLS1.2",
    0x0304: "TLS1.3",
}


@dataclass(frozen=True, slots=True)
class TlsInfo:
    """TLS handshake metadata, read from the cleartext portion only."""

    record_version: str
    handshake_type: str
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    cipher_suites: list[int] = field(default_factory=list)
    supported_versions: list[str] = field(default_factory=list)
    selected_cipher: int | None = None

    @property
    def is_client_hello(self) -> bool:
        return self.handshake_type == "client_hello"

    @property
    def negotiated_version(self) -> str:
        """The highest version offered or the one selected."""
        if self.supported_versions:
            return max(self.supported_versions)
        return self.record_version

    @property
    def is_legacy_version(self) -> bool:
        """True for SSLv3/TLS1.0/TLS1.1, which are deprecated and worth flagging."""
        return self.negotiated_version in {"SSLv3", "TLS1.0", "TLS1.1"}


def _parse_tls_extensions(data: bytes) -> tuple[str | None, list[str], list[str]]:
    """Extract SNI, ALPN and supported_versions from an extensions block."""
    sni: str | None = None
    alpn: list[str] = []
    versions: list[str] = []
    cursor = 0

    while cursor + 4 <= len(data):
        ext_type, ext_len = struct.unpack_from("!HH", data, cursor)
        cursor += 4
        body = data[cursor : cursor + ext_len]
        if len(body) < ext_len:
            break
        cursor += ext_len

        if ext_type == _EXT_SERVER_NAME and len(body) >= 5:
            name_len = struct.unpack_from("!H", body, 3)[0]
            raw = body[5 : 5 + name_len]
            if len(raw) == name_len and name_len:
                # Keep the A-label (wire) form: that is what threat-intel feeds and
                # denylists are expressed in. Decoding punycode to Unicode here
                # would break exact matching and invites homograph confusion.
                sni = raw.decode("ascii", errors="replace").lower()[:253]
        elif ext_type == _EXT_ALPN and len(body) >= 2:
            inner = body[2:]
            pos = 0
            while pos < len(inner):
                length = inner[pos]
                pos += 1
                if pos + length > len(inner):
                    break
                alpn.append(inner[pos : pos + length].decode("ascii", errors="replace"))
                pos += length
        elif ext_type == _EXT_SUPPORTED_VERSIONS and len(body) >= 1:
            # Client form: 1-byte list length then 2-byte versions.
            list_len = body[0]
            for pos in range(1, min(1 + list_len, len(body) - 1), 2):
                value = struct.unpack_from("!H", body, pos)[0]
                if value in _TLS_VERSIONS:
                    versions.append(_TLS_VERSIONS[value])

    return sni, alpn, versions


def parse_tls(payload: bytes) -> TlsInfo | None:
    """Parse a TLS ClientHello or ServerHello.

    Returns ``None`` for application data records - once the handshake completes
    there is nothing readable, and attempting more would be pointless.
    """
    if len(payload) < 6 or payload[0] != _TLS_HANDSHAKE:
        return None
    record_version_raw = struct.unpack_from("!H", payload, 1)[0]
    record_version = _TLS_VERSIONS.get(record_version_raw, f"0x{record_version_raw:04x}")

    handshake_type = payload[5]
    if handshake_type not in (_TLS_CLIENT_HELLO, _TLS_SERVER_HELLO):
        return None

    cursor = 9  # record header (5) + handshake type (1) + handshake length (3)
    if len(payload) < cursor + 2 + 32:
        return None
    cursor += 2 + 32  # client_version + random

    if cursor >= len(payload):
        return None
    session_id_len = payload[cursor]
    cursor += 1 + session_id_len
    if cursor > len(payload):
        return None

    cipher_suites: list[int] = []
    selected_cipher: int | None = None

    if handshake_type == _TLS_CLIENT_HELLO:
        if cursor + 2 > len(payload):
            return None
        suites_len = struct.unpack_from("!H", payload, cursor)[0]
        cursor += 2
        for pos in range(cursor, min(cursor + suites_len, len(payload) - 1), 2):
            cipher_suites.append(struct.unpack_from("!H", payload, pos)[0])
        cursor += suites_len
        if cursor >= len(payload):
            return None
        compression_len = payload[cursor]
        cursor += 1 + compression_len
    else:
        if cursor + 3 > len(payload):
            return None
        selected_cipher = struct.unpack_from("!H", payload, cursor)[0]
        cursor += 3  # cipher suite + compression method

    sni: str | None = None
    alpn: list[str] = []
    versions: list[str] = []
    if cursor + 2 <= len(payload):
        ext_total = struct.unpack_from("!H", payload, cursor)[0]
        cursor += 2
        sni, alpn, versions = _parse_tls_extensions(payload[cursor : cursor + ext_total])

    return TlsInfo(
        record_version=record_version,
        handshake_type="client_hello" if handshake_type == _TLS_CLIENT_HELLO else "server_hello",
        sni=sni,
        alpn=alpn,
        cipher_suites=cipher_suites[:64],
        supported_versions=versions,
        selected_cipher=selected_cipher,
    )
