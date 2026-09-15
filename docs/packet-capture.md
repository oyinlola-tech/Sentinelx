# Packet capture

This document covers how SentinelX gets packets: capture sources and live-capture backends, required privileges on each operating system, interface selection, BPF filters, capture settings, what the protocol decoders extract, how malformed traffic is handled, the capture statistics and capability report you can monitor, performance expectations, and troubleshooting.

For how decoded packets flow through detection, see [architecture.md](architecture.md). For running captures through the PCAP Lab, see [pcap-lab.md](pcap-lab.md).

## Capture sources

Every packet source implements `PacketCapture` (`packages/sentinelx/capture/base.py`) and yields `RawFrame` objects. The pipeline consumes only that interface, so live capture, file replay and synthetic frames go through the same decoder and detection code.

| Source | Class and file | `source_kind` | Used by |
|---|---|---|---|
| Live interface | `LiveCapture`, `capture/live.py` (backends in `capture/afpacket.py` and `capture/libpcap.py`) | `live` | `sentinelx start --capture`, `POST /api/v1/sensors/start`, `sentinelx monitor -i` |
| PCAP or pcapng file | `PcapFileCapture`, `capture/pcap.py` (reader in `capture/pcapfile.py`) | `pcap` | `sentinelx replay`, `sentinelx monitor --pcap`, PCAP Lab replays through the API |
| In-memory frames | `MockCapture`, `capture/mock.py` | `mock` | `sentinelx monitor --scenario`, tests, benchmarks |

`create_capture()` in `capture/factory.py` picks the source from configuration: it returns a `PcapFileCapture` when given a file path, otherwise a `LiveCapture` built from `CaptureSettings` (interface, backend, filter, snapshot length, promiscuous mode, buffer size and queue size).

A `RawFrame` carries:

| Field | Meaning |
|---|---|
| `data` | Captured bytes, possibly truncated by the snapshot length |
| `timestamp` | UNIX epoch seconds |
| `link_type` | libpcap link-layer type (DLT) of `data`, set per frame |
| `interface` | Interface the frame arrived on, or `pcap:<filename>` for replays |
| `wire_length` | Original length on the wire, when the source knows it (otherwise the captured length) |

`PacketCapture` also has two discovery methods: `capabilities()` returns a `CaptureCapabilities` record (backend, whether it is available on this host, the reason, a remedy, and whether it supports BPF filters, `any`, promiscuous mode and kernel drop counters), and `list_interfaces()` returns the interfaces a live source can use. File and mock sources report themselves as available and non-live, with no interfaces.

### Live capture

`LiveCapture` is a facade over two backends, selected by `CAPTURE__BACKEND`:

| `backend` | Behaviour |
|---|---|
| `auto` (default) | On Linux, try `af_packet`, then `libpcap`. On other platforms, use `libpcap` only. |
| `af_packet` | Linux `AF_PACKET` raw sockets only. |
| `libpcap` | Scapy's sniffer: libpcap or a packet socket on Linux, `/dev/bpf*` on macOS, the Npcap driver on Windows. |

`auto` moves to the next backend **only** when a backend raises `BackendUnavailableError`, which means it cannot run on this host at all (no `AF_PACKET` support in the kernel or Python build, or Scapy not installed). A missing privilege (`PermissionDeniedError`), an unknown interface (`InterfaceNotFoundError`) and an invalid BPF filter (`CaptureError`) are raised as they are, because falling back would hide them. If no backend can run, `LiveCapture` raises `BackendUnavailableError` listing each backend's reason. The backend in use is logged (`live_capture_ready backend=...`) and reported as `backend` in the sensor status, next to `requested_backend` in the pipeline status.

**AF_PACKET backend (`capture/afpacket.py`, Linux).**

1. A named interface is checked against the interface list (see [Interface selection](#interface-selection)). An unknown name fails with an error listing the available interfaces. `any` is not checked.
2. A raw `AF_PACKET` socket is opened for all protocols (`ETH_P_ALL`). `EPERM` raises `PermissionDeniedError` immediately, with the remedy.
3. The socket receive buffer is set to `buffer_size_mb`.
4. A named interface is bound. If `promiscuous` is true, the socket joins the interface's promiscuous membership (`PACKET_ADD_MEMBERSHIP` with `PACKET_MR_PROMISC`), which the kernel reverts when the socket closes. For `any`, the socket is not bound and promiscuous mode is not requested.
5. If a BPF filter is set, it is compiled with libpcap and attached in the kernel (see [BPF filters](#bpf-filters)).
6. Frames are read in batches on a worker thread: the thread blocks for up to 0.5 seconds for the first frame, then drains up to 512 queued frames without blocking, and hands the batch to the event loop in one step.
7. Each frame is stamped with `time.time()` on the worker thread when it is received.
8. The link type is taken per frame from the ARPHRD hardware type the kernel reports in the socket address: Ethernet (1) and loopback (772, which carries a zeroed Ethernet header) decode as Ethernet; `ARPHRD_NONE` (tun and WireGuard devices), PPP, SIT, IP-GRE and IPv6-in-IPv6 tunnels decode as raw IP. Frames from other hardware types are skipped and counted in `unsupported_frames`. This is what lets `any` decode correctly when interfaces use different framing.
9. On the loopback device, the kernel delivers every packet twice (outgoing and incoming). The outgoing copy is skipped, as libpcap does.
10. Kernel drop counters (`PACKET_STATISTICS`) are read every 64 batches and when the capture closes, and accumulated into `dropped_kernel`.

**libpcap backend (`capture/libpcap.py`).**

1. For `any`, the sniffer is given every interface Scapy lists; if Scapy lists none, opening fails. A named interface must appear in the interface list or in Scapy's interface table (on Windows, Npcap device names differ from friendly names).
2. A Scapy `AsyncSniffer` is started with the filter and promiscuous setting. `open()` waits up to 5 seconds for the sniffer to report that it has started. If the sniffer thread dies first, its exception is translated: a permission failure becomes `PermissionDeniedError`, a filter or syntax error becomes `CaptureError("invalid BPF filter ...")`, anything else becomes `CaptureError`. A sniffer that does not start in time also raises `CaptureError`.
3. While running, the frame iterator checks the sniffer thread on every read timeout (0.5 seconds) and every 256 frames, so a sniffer that fails later surfaces as an error instead of a capture that silently receives nothing.
4. Frames are handed from the sniffer thread to the event loop through a queue of `queue_size` frames (default 20,000). When the queue is full, the frame is dropped and counted in `dropped_queue`.
5. The link type is taken per packet from the Scapy layer class. When Scapy cannot classify a Linux interface (loopback, tun), the frame falls back to the link type derived from the interface's hardware type in `/sys/class/net/<name>/type`. Frames with no decodable link type are counted in `unsupported_frames`.
6. The timestamp is Scapy's packet time (falling back to `time.time()` if absent), the data is cut to `snapshot_length`, and `wire_length` is Scapy's `wirelen` when present.

`tests/kernel/test_live_capture.py`, run by `make test-kernel` inside a private network namespace, captures real traffic and checks that every frame decodes for AF_PACKET on `lo`, on `any` and with a BPF filter, for libpcap on `lo` and on `any`, and for `auto` on `any`.

On Linux, prefer `af_packet` (which `auto` does). Scapy's listening socket cannot tell outgoing from incoming packets, so with the libpcap backend on the loopback device every packet is seen twice. `buffer_size_mb` is not applied by the libpcap backend, and it has no kernel drop counters.

Live capture limitations in the current code:

- **Truncation is not visible with AF_PACKET.** Frames longer than `snapshot_length` are truncated, and the AF_PACKET backend records `wire_length` as the captured length. Byte counts undercount truncated frames.
- **Outgoing packets are captured too.** An `ETH_P_ALL` socket sees traffic the host sends as well as traffic it receives. Only the loopback duplicate is removed.
- **BPF on `any` assumes Ethernet framing.** The AF_PACKET backend compiles the filter for Ethernet. On `any`, it does not match correctly on raw-IP interfaces (tun, WireGuard, PPP). Name the interface when filtering matters.

### PCAP replay

`PcapFileCapture` reads files with SentinelX's own streaming reader, `capture/pcapfile.py`. It does not use Scapy, needs no privileges and no capture library, and returns raw bytes with a link type per record. Decoding uses the SentinelX decoder, exactly as for live traffic.

| Behaviour | Detail |
|---|---|
| pcap | Little- and big-endian files, microsecond (magic `0xa1b2c3d4`) and nanosecond (magic `0xa1b23c4d`) timestamps. The FCS bits in the upper part of the link-type field are masked off |
| pcapng | Multiple sections with either byte order. Each Interface Description Block has its own link type and timestamp resolution (`if_tsresol`, decimal or binary exponent; default microseconds), so one file can mix link types. Enhanced Packet Blocks and Simple Packet Blocks are read; other block types are skipped. A Simple Packet Block has no timestamp and reuses the previous record's timestamp |
| Length validation | Every length is checked before data is read. A pcap record may not exceed the larger of the file's snapshot length and 65,535 bytes, capped at `MAX_RECORD_BYTES` (262,144). A pcapng packet may not exceed its block or `MAX_RECORD_BYTES`; a block may not exceed `MAX_BLOCK_BYTES` (1 MiB). Block trailers must match block lengths |
| Memory | One record is read at a time, so a file of any size uses constant memory |
| Opening errors | `PcapError` for a missing path, a path that is not a regular file, an empty file, or a file whose first four bytes are not a pcap or pcapng magic (`not a pcap or pcapng capture file`). The first record is read at open, so a file that is corrupt from the start fails there |
| Mid-file errors | A truncated or corrupt record raises `PcapError` (for example `capture file is truncated: incomplete packet record`). Records before it have already been processed |
| Timestamps | Taken from each record. `rewrite_timestamps` (library option, off by default) shifts them to the present |
| Wire length | The record's original length, or the captured length if that is larger |
| `speed` | `0` (default) replays as fast as possible. `1.0` reproduces the original timing, `2.0` runs twice as fast. API replays accept 0 to 100 |
| Gaps | A single pacing sleep is capped at 1 second, so long idle gaps in a capture are shortened |
| `limit` | Stop after this many packets |
| Event loop | The replay yields to the event loop whenever it has run for more than 5 ms without yielding, so a full-speed replay does not block the API, the WebSocket stream or database writes |

`tests/capture/test_pcapfile.py` covers nanosecond and big-endian pcap, per-interface link types and resolution in pcapng, hostile and broken files, and checks that a capture converted by Wireshark's `editcap` to pcapng and to nanosecond pcap replays with identical results (skipped when `editcap` is not installed).

From the CLI:

```bash
sentinelx replay capture.pcap                    # as fast as possible
sentinelx replay capture.pcap --speed 1          # original timing
sentinelx replay capture.pcap --limit 10000 --report report.json
sentinelx replay capture.pcap --persist          # store results under a replay id
sentinelx monitor --pcap capture.pcap            # live terminal view at original speed
```

Responses are always simulated during a replay; no firewall is modified. Replays run the same detector set as a live sensor (see [detection-engine.md](detection-engine.md#detection-modes)), and detections carry the capture's own timestamps.

`pcap_metadata()` reads every record of a file to report packet count, total captured bytes, `link_type` (the lowest link type in the file), `link_types` (all of them), first and last timestamps, duration and average packet size without running detection.

Files uploaded through the API are validated by magic number and limited to the smaller of `api.max_upload_mb` (default 200) and `capture.max_pcap_size_mb` (default 512). All uploads together may use at most `capture.upload_quota_mb` (default 2048); further uploads are refused until old ones are removed. In the Docker stack, the front proxy also limits request bodies to `SENTINELX_MAX_UPLOAD_MB` (default 200). Files with `.pcap`, `.pcapng` or `.cap` extensions under `PCAP_DIRECTORY` are listed for replay. See [pcap-lab.md](pcap-lab.md).

### Mock capture

`MockCapture` yields a list of frames the caller already has. It takes `delay` (seconds between frames) and `repeat` (how many times to emit the sequence, at least 1). `MockCapture.from_bytes()` builds frames from raw packet bytes with evenly spaced timestamps (default start `1700000000.0`, interval `0.001` seconds). Its interface name defaults to `mock0`.

`sentinelx monitor --scenario <name>` uses it to feed a synthetic scenario through the pipeline without any privileges.

## Required privileges

Only live capture needs a privilege. PCAP replay, mock capture, fixtures and the rest of the platform do not. The checks live in `packages/sentinelx/system/privileges.py` and ask the operating system's own mechanism rather than testing `euid == 0`.

| Platform | Needed for live capture | How it is checked | Remedy reported |
|---|---|---|---|
| Linux | `CAP_NET_RAW` (or root) | Opens and closes a real `AF_PACKET` socket | Run as root, or `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)` |
| macOS | Read and write access to a `/dev/bpf*` device | Tests access to each BPF device | Run as root, or give your user access to `/dev/bpf*` (Wireshark's ChmodBPF launch daemon does this) |
| Windows | Npcap installed; an elevated process if Npcap was installed with "restrict driver access to Administrators" | Looks for `wpcap.dll` and the Npcap `AdminOnly` registry value | Install Npcap from https://npcap.com, or run from an elevated terminal |

Without the privilege, both backends raise `PermissionDeniedError` when the capture opens, with the remedy in the message. There is no fallback.

Check what this host can do:

```bash
sentinelx capabilities    # capability report (see below)
sentinelx doctor          # includes "live capture" and "packet capture backend" checks
sentinelx interfaces      # prints whether live capture is available, and the remedy
```

### Granting the capability on a Linux host

Running the whole platform as root works, but granting the capability to the Python interpreter is narrower. File capabilities apply to the real binary, not a symlink, so resolve the path first:

```bash
readlink -f .venv/bin/python                                                 # the interpreter binary
sudo setcap cap_net_raw=eip "$(readlink -f .venv/bin/python)"                # capture only
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"  # capture and firewall
getcap "$(readlink -f .venv/bin/python)"                                     # verify
sudo setcap -r "$(readlink -f .venv/bin/python)"                             # remove again
```

`CAP_NET_ADMIN` is needed only when a firewall backend (`nftables` or `iptables`) will modify the host firewall; see [response-engine.md](response-engine.md). Capture alone needs only `CAP_NET_RAW`.

Be aware of what this grants. A virtual environment's `python` is usually a symlink to the system interpreter, so the capability applies to every program run with that interpreter binary, not only SentinelX. On a shared host, use a dedicated copy of the interpreter for the sensor, as the Docker image does. See [security.md](security.md).

### Running under Docker

Containers on a Docker bridge network see only their own traffic, never the host's. The default Compose stack therefore runs detection on PCAP replay and on traffic sent to the stack itself, and its `api` container (`cap_drop: [ALL]`) cannot capture: `sentinelx capabilities` inside it reports live capture as unavailable.

For live capture of host traffic on a Linux host, the `sensor` service in the `capture` profile replaces `api`. It uses host networking, runs `python3-sensor -m sentinelx start --capture` (a separate interpreter copy, `/usr/local/bin/python3-sensor`, that carries the `cap_net_raw,cap_net_admin` file capabilities), is granted `NET_RAW` and `NET_ADMIN`, and listens only on `${FRONTEND_GATEWAY:-172.31.250.1}:${SENSOR_PORT:-8001}`, the `frontend` network's gateway. Start it with the front proxy pointed at it (use `${FRONTEND_GATEWAY}:${SENSOR_PORT}` if you change either):

```bash
SENTINELX_API_UPSTREAM=172.31.250.1:8001 \
  docker compose --profile capture up -d --build --scale api=0
```

`CAPTURE_INTERFACE` (default `any`, which captures and decodes every interface) selects the interface. Docker Desktop on macOS and Windows runs containers in a virtual machine, so host networking there captures the VM's traffic. The sensor's API is reachable by the proxy but not from other hosts or on `127.0.0.1`. Service details, required capabilities and exposure guidance are in [deployment.md](deployment.md#the-capture-profile).

## Interface selection

List interfaces with:

```bash
sentinelx interfaces
sentinelx interfaces --json
```

Interfaces are enumerated with `psutil` (`packages/sentinelx/system/interfaces.py`) on every platform. The table shows name, state, addresses, MAC, MTU, received packets and dropped packets, and ends with a line saying whether live capture is available and through which backend. The JSON form is `{"capture": <capture capabilities>, "interfaces": [...]}`; each interface also has `is_up`, `is_loopback`, `speed_mbps` and transmit and byte counters. `GET /api/v1/interfaces` returns the interface list.

If the operating system refuses interface statistics (`psutil.net_if_stats`, which some sandboxed kernels and QEMU user-mode emulation do), the addresses are still listed. State then comes from `/sys/class/net/<name>/operstate` on Linux when readable and is otherwise `unknown`, with `is_up` false, MTU 0 and no speed; I/O counters that cannot be read are shown as 0. If the addresses themselves cannot be read, enumeration fails with an error, and the firewall safety guard refuses to block (`local_addresses_unknown`) rather than assume the host has no addresses.

Choose the interface in one of these ways:

| Method | Example |
|---|---|
| Environment or `.env` | `CAPTURE_INTERFACE=eth0` or `CAPTURE__INTERFACE=eth0` |
| Server start | `sentinelx start --capture --interface eth0` (`-i` for short) |
| Terminal monitor | `sentinelx monitor -i eth0` |
| API | `POST /api/v1/sensors/start` with `{"interface": "eth0"}` (administrator role; see [api.md](api.md)) |
| Stored setting | `sentinelx config set capture interface '"eth0"'` (applied at the next server start) |

`any` captures from every interface. `sentinelx doctor` fails its "capture interface" check when a named interface does not exist.

## BPF filters

A BPF filter runs before packets reach SentinelX, so packets that do not match are never processed. The expression uses standard pcap-filter syntax, for example:

```text
tcp or udp
not port 8000
host 192.0.2.10 and not port 22
```

Filtering out traffic hides it from every detector. Filter out only traffic you are sure you do not need to inspect, such as the sensor's own API traffic.

Where to set it:

| Method | Example |
|---|---|
| Environment or `.env` | `BPF_FILTER='tcp or udp'` or `CAPTURE__BPF_FILTER='tcp or udp'` |
| Terminal monitor | `sentinelx monitor -i eth0 --bpf 'tcp or udp'` |
| API | `POST /api/v1/sensors/start` with `{"bpf_filter": "tcp or udp"}` (at most 512 characters). If omitted, the configured filter is used |
| Stored setting | `sentinelx config set capture bpf_filter '"tcp or udp"'` |

`sentinelx start` has no filter option; it uses the configured filter. `sentinelx monitor -i` uses `--bpf` when it is given and `BPF_FILTER` otherwise, and opens the capture with the configured `CAPTURE__BACKEND`, `CAPTURE__SNAPSHOT_LENGTH`, `CAPTURE__PROMISCUOUS`, `CAPTURE__BUFFER_SIZE_MB` and `CAPTURE__QUEUE_SIZE`.

Validation and compilation:

- The characters `;`, `|`, `` ` ``, `$`, `\`, newline and carriage return are rejected. The filter is never passed through a shell; rejecting them early turns a confusing compile error into a clear configuration error. Surrounding whitespace is stripped.
- **AF_PACKET.** The expression is compiled by Scapy's `compile_filter`, which calls libpcap, and the program is attached with `SO_ATTACH_FILTER`. The libpcap shared library must be installed (the Docker image installs `libpcap0.8`). A missing libpcap, a missing Scapy, an expression that does not compile, or a program the kernel rejects each raise `CaptureError` and the capture does not start. None of these falls back to another backend or to unfiltered capture.
- **libpcap.** The filter is passed to the Scapy sniffer. An expression that does not compile stops the sniffer thread, and the error is reported as `CaptureError: invalid BPF filter ...` when the capture opens.
- The capability report shows `bpf_filter: true` for a backend when a filter can be compiled on this host.

`tests/kernel/test_live_capture.py` checks that a filter is applied in the kernel and that an invalid filter is refused by both backends.

## Settings

Capture settings are defined by `CaptureSettings` in `packages/sentinelx/config/settings.py`.

| Setting | Default | Nested environment variable | Flat alias | Notes |
|---|---|---|---|---|
| `interface` | `any` | `CAPTURE__INTERFACE` | `CAPTURE_INTERFACE` | `any` captures every interface |
| `backend` | `auto` | `CAPTURE__BACKEND` | none | `auto`, `af_packet` or `libpcap`. See [Live capture](#live-capture) |
| `bpf_filter` | empty | `CAPTURE__BPF_FILTER` | `BPF_FILTER` | See [BPF filters](#bpf-filters) |
| `snapshot_length` | `2048` | `CAPTURE__SNAPSHOT_LENGTH` | none | 64 to 65535. Bytes kept per frame |
| `promiscuous` | `true` | `CAPTURE__PROMISCUOUS` | none | Applied to a named interface by both backends; not applied to `any` by AF_PACKET |
| `buffer_size_mb` | `16` | `CAPTURE__BUFFER_SIZE_MB` | none | 1 to 1024. AF_PACKET socket receive buffer; Linux caps it at `net.core.rmem_max`. Not used by libpcap |
| `queue_size` | `20000` | `CAPTURE__QUEUE_SIZE` | none | Minimum 100. Hand-off queue of the libpcap backend; overflow is counted in `dropped_queue` |
| `home_networks` | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"]` | `CAPTURE__HOME_NETWORKS` (JSON list) | none | Used only to label packet direction. Every entry must be a valid network |
| `pcap_directory` | `pcaps` | `CAPTURE__PCAP_DIRECTORY` | `PCAP_DIRECTORY` | Where replayable and uploaded captures live |
| `max_pcap_size_mb` | `512` | `CAPTURE__MAX_PCAP_SIZE_MB` | none | Per-upload limit, together with `api.max_upload_mb` |
| `upload_quota_mb` | `2048` | `CAPTURE__UPLOAD_QUOTA_MB` | none | Total space uploads may use |

How values are resolved:

- Nested names use a double underscore and are case-insensitive, for example `CAPTURE__SNAPSHOT_LENGTH=512` or `CAPTURE__HOME_NETWORKS='["10.20.0.0/16"]'`.
- Both nested names and flat aliases are read from the process environment and from a `.env` file in the working directory.
- Precedence, highest first: nested environment variable, flat environment variable, nested `.env` entry, flat `.env` entry, default. A real environment variable always beats `.env`, and the nested form wins when both spellings are set at the same level.
- `interface`, `bpf_filter` and `home_networks` can also be changed at runtime. Changes are validated, audited and stored in the database, and stored values are applied at every server start, where they take precedence over environment variables. A change made through the API also updates the running server: a new `home_networks` value replaces the decoder immediately, and a new interface or filter is used the next time capture starts. `sentinelx config set` runs in its own process and only writes the database, so a running server picks the change up at its next start.
- Invalid values stop startup with a validation error naming the field, for example `capture.bpf_filter: Value error, bpf_filter must not contain shell metacharacters`.

`sentinelx config --section capture` shows the effective values.

## Protocol decoders

`packages/sentinelx/parser/decoder.py` turns a frame into a `PacketEvent`. Headers are decoded with `struct` in `parser/layers.py`; application metadata comes from `parser/application.py`.

### Link, network and transport layers

| Layer | Supported | Extracted |
|---|---|---|
| Link | Ethernet (DLT 1), with up to 4 stacked 802.1Q or 802.1ad VLAN tags | Source and destination MAC, ethertype, first VLAN ID (stored as `metadata.vlan_id`) |
| | Linux cooked capture v1 (DLT 113) and v2 (DLT 276) | Ethertype, source MAC when the address is at least 6 bytes |
| | Raw IP (DLT 101, 228, 229) | Family from the IP version nibble |
| | BSD loopback (DLT 0) | Family from the 4-byte header |
| ARP | Ethernet/IPv4 ARP only | Operation (request, reply, other), sender MAC, sender and target IP |
| IPv4 | Header with options (IHL honoured) | Addresses, protocol, TTL, DSCP, identification, fragment offset and more-fragments flag. The payload is trimmed to the header's total length, but never beyond the captured bytes |
| IPv6 | Fixed header plus up to 8 extension headers, and a fragment header | Addresses, next header, hop limit (stored as TTL), traffic class |
| TCP | Header with options | Ports, flags, sequence and acknowledgement numbers, window, payload |
| UDP | Header | Ports, payload |
| ICMP and ICMPv6 | Type, code; identifier and sequence for echo (and ICMP timestamp) messages | `metadata.icmp` with `type`, `code`, `identifier`, `sequence`, `is_echo_request`, `is_unreachable` |

A non-first IPv4 fragment carries no transport header, so it is recorded with `metadata.fragment` (`offset`, `more`) and no ports instead of misreading payload bytes as ports.

Every `PacketEvent` has a timestamp, source and destination IP, protocol, wire length, interface and direction, plus ports, TCP flags, TTL, MAC addresses and payload length where the protocol has them. Missing fields are `None` rather than zero, so "port 0" and "no port" stay distinguishable.

Direction is labelled against `home_networks`: `internal` (both ends inside), `inbound` (destination inside), `outbound` (source inside), `external` (neither). With no home networks configured, every packet is `unknown`.

### Application metadata

Application parsers run on the transport payload when either port matches. They are selected by port, not by inspecting content, so a service on a non-standard port gets no application metadata. Parsers are stateless: there is no TCP stream reassembly.

**DNS** (UDP and TCP, ports 53, 5353, 5355). Stored as `metadata.dns`.

- Parses the 12-byte header and up to 16 questions. Answer, authority and additional records are counted but not parsed.
- Exposes `transaction_id`, `is_response`, `rcode`, `query_name` and `query_type` (from the first question), `answer_count`, `is_nxdomain`, `max_label_length` (longest label across all questions) and `name_entropy` (Shannon entropy of the leftmost label, in bits per character).
- **Compression pointer loop protection.** Compression pointers are followed, but a pointer to an offset already visited, or beyond the end of the message, ends the name. A name is also cut off after 64 labels. A crafted message with a pointer loop therefore terminates instead of spinning. `tests/capture/test_parser.py` covers this case.
- Labels are decoded as ASCII, with undecodable bytes replaced.

**HTTP/1.x** (TCP, ports 80, 8080, 8000, 8008, 8888, 3000). Stored as `metadata.http`.

- Requires a payload of at least 16 bytes that starts with a request line using `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `TRACE` or `CONNECT`, or a status line starting with `HTTP/`. Anything else, including the continuation of a message split across segments, yields no metadata.
- Scans at most the first 4,096 bytes and at most 40 header lines.
- The request path is truncated to 512 characters.
- **Header allowlist.** Only these headers are kept: `host`, `user-agent`, `referer`, `content-length`, `content-type`, `authorization`, `x-forwarded-for`, `cookie`, `connection`, `accept`. Other headers are discarded, so a new header type never starts flowing into storage by accident. Kept values are truncated to 256 characters.
- **Credential redaction.** `authorization` and `cookie` are recorded only as the value `present`. Credential and cookie values are never retained. Bodies are never retained.
- The packet event exposes `is_request`, `method`, `path`, `status_code`, `host`, `user_agent` and `has_authorization`.

**TLS** (TCP, ports 443, 8443, 993, 995, 465, 587, 636, 989, 990, 5061). Stored as `metadata.tls`.

- Reads only a ClientHello or ServerHello at the start of a TLS record. Application data records yield nothing. Nothing is decrypted.
- **SNI** is taken from the `server_name` extension, lowercased, kept in its wire (A-label, punycode) form so it matches threat-intelligence feeds exactly, and truncated to 253 characters.
- **ALPN** protocol names are returned as a list (`alpn`).
- Also exposes `handshake_type` (`client_hello` or `server_hello`), `version` (the highest version in the ClientHello `supported_versions` extension, otherwise the record version), `cipher_count` and `is_legacy_version` (true for SSLv3, TLS 1.0 and TLS 1.1).

Additional parsers can be registered with `register_app_parser(name, parser, protocols)`. A parser that raises is counted in `sentinelx_parse_errors_total` with its name as the `layer` label, and the packet is kept with its network and transport fields.

### Known decoder limitations

- **No reassembly.** IP fragments are not reassembled and TCP streams are not reconstructed. HTTP and TLS metadata comes only from a segment that starts a message or handshake.
- **DNS over TCP is misparsed.** The DNS parser runs on TCP payloads on port 53 but does not skip the 2-byte length prefix that DNS over TCP uses, so the resulting `metadata.dns` fields are wrong.
- **TLS 1.3 ServerHello reports TLS 1.2.** The `supported_versions` extension is read only in its ClientHello form, so a ServerHello that selects TLS 1.3 reports its record version (`TLS1.2`).
- **Non-first IPv6 fragments are misread.** The IPv6 decoder skips the fragment header but does not record the fragment offset, so a non-first fragment's payload is decoded as a transport header (with invented ports) or dropped as a TCP parse error.
- **Only Ethernet/IPv4 ARP** is decoded. Other ethertypes (for example LLDP) are counted as decode failures at the network layer.

## Malformed packet handling

Malformed frames are normal on real networks, and a sensor that crashes on one is easy to defeat. Every decoder is total: bad input produces `None` or a partial result, never an exception.

- A frame too short for its link header, or with an unsupported link type, fails at the `link` layer.
- A frame with an unsupported ethertype, a bad IP version, or an IP header shorter than its minimum fails at the `network` layer.
- A TCP header with a data offset below 20 bytes, or a UDP, ICMP or ARP header shorter than its minimum, fails at that layer (`tcp`, `udp`, `icmp`, `arp`).
- Header lengths are clamped to the captured bytes, so a truncated snapshot or a lying length field never produces a negative or out-of-range slice.
- Loops over attacker-controlled structure are bounded: 4 VLAN tags, 8 IPv6 extension headers, 16 DNS questions, 64 DNS labels, 40 HTTP header lines, 4,096 bytes of HTTP payload, 64 TLS cipher suites kept.
- An exception inside an application parser is caught and counted; the packet is still processed.

Failures are counted in two places: `decoded` and `failed` on the decoder (`pipeline.decoder` in `GET /api/v1/system/status` and `GET /api/v1/metrics/summary`), and the Prometheus counter `sentinelx_parse_errors_total{layer=...}`. `tests/capture/test_parser.py` checks that malformed frames never raise and that failures are counted.

Malformed capture files are handled by the reader's length validation; see [PCAP replay](#pcap-replay).

## Capture statistics

Each capture source keeps a `CaptureStats` object:

| Field | Meaning |
|---|---|
| `received` | Frames delivered to the pipeline |
| `bytes_received` | Sum of frame wire lengths |
| `dropped_kernel` | Frames the kernel reports as dropped before user space read them (AF_PACKET `PACKET_STATISTICS`). Always 0 with libpcap |
| `dropped_queue` | Frames lost because the libpcap backend's hand-off queue was full. Always 0 with AF_PACKET, which has no such queue |
| `errors` | Socket read errors (AF_PACKET) or packets that could not be converted to bytes (libpcap) |
| `elapsed_seconds` | Wall time since the capture opened |
| `packets_per_second`, `megabits_per_second` | Measured from `received`, `bytes_received` and elapsed wall time |
| `capture_span_seconds` | Time between the first and last packet timestamps |
| `drop_rate` | Dropped divided by received plus dropped |

Kernel and queue drops are reported separately because they have different remedies: kernel drops call for a narrower filter or larger buffer, queue drops for faster processing. Live backends also report `unsupported_frames` (frames with a link type the decoder cannot handle) in their description.

Where to see them:

| Place | Content |
|---|---|
| `GET /api/v1/sensors` | Sensor state, interface, filter, `backend`, `capture` statistics, `error`, `capture_capabilities` (the live-capture capability report, cached for 30 seconds) and safety banner |
| `GET /api/v1/system/status` | Platform health, plus `pipeline` with the running capture's description (backend, requested backend, snapshot length, `unsupported_frames`, statistics), decoder counts, feature-extractor state (tracked sources, active flows, evictions) and detection statistics |
| `GET /api/v1/metrics/summary` | Decoder, features and detection counts, the live sensor's capture statistics, the last completed run's report, and event bus statistics |
| `packet.stats` event | Published while frames arrive, at most once per progress interval (1 second for live capture, 0.5 seconds for API replays, 0.2 seconds for `sentinelx replay`), and once more when the run ends: `source`, `kind`, `frames`, `bytes`, `elapsed_seconds`, `packets_per_second`, `detections`, `incidents`, `active_flows`, `tracked_sources`, `dropped`, `protocols`, `cpu_percent`, `memory_bytes`, and `final` on the last one |
| Prometheus | `sentinelx_packets_captured_total{source,interface}` and `sentinelx_packets_dropped_total{reason="capture"}` (kernel plus queue drops) are incremented with each `packet.stats` publication and when the run ends, so they move while a live capture runs |
| `capture_closed` log line | The final statistics when a capture closes |
| `sensor.status` event | Published when the sensor starts, stops or fails |

`sentinelx status` builds its own platform instance, so it does not show a running server's capture statistics. Query the API instead.

## Capability report

`packages/sentinelx/system/capabilities.py` probes what this host can do and explains each answer. The same report is shown by `sentinelx capabilities` (add `--json` for machine-readable output), by `GET /api/v1/system/capabilities` (viewer role; cached for 30 seconds) and on the dashboard, and `sentinelx doctor` turns it into checks.

| Capability | Meaning |
|---|---|
| Detection engine | Always available |
| PCAP replay | A one-packet capture is parsed in memory with the replay reader |
| Interface enumeration | `psutil` returned the interface list |
| Packet capture | A capture mechanism exists on this OS (AF_PACKET and optionally libpcap on Linux, BPF devices on macOS, Npcap on Windows), independent of privileges |
| Live capture | The configured backend (or the one `auto` would pick) can open a capture now, with its reason and remedy. Under WSL it notes that capture sees the WSL virtual machine's traffic; inside a container, that it sees the container's network namespace unless it uses host networking |
| Firewall control, automatic blocking | See [response-engine.md](response-engine.md) |
| Privileged access | Root or elevation, or which of `CAP_NET_RAW` and `CAP_NET_ADMIN` the process holds |

The JSON form also includes the operating system, architecture, detected environment (WSL version, container type) and per-backend firewall reports.

## Performance

- **Decoder.** On the reference Intel Core i5-8350U, the `struct` decoder measured 2.1 to 2.5 times faster than Scapy `Ether(bytes)` across two runs of 50,000 frames.
- **End to end.** The full pipeline (decode, features, detection, rules, scoring, correlation, response decision) processed roughly 2,900 to 4,600 packets per second on one core of that laptop CPU, using in-memory frames. Capture overhead is not included in that figure.
- **Live capture overhead.** The AF_PACKET backend reads up to 512 frames per worker-thread hand-off. The libpcap backend builds a Scapy object per packet and is slower. Throughput and drop rate of either backend under load have not been measured.
- **Suitability.** That is enough for a home network, a lab, a small office uplink or offline PCAP analysis. It is not suitable for multi-gigabit links, or for sustained traffic on links of a few hundred megabits per second, where packet rates are one to two orders of magnitude higher. The sensor will drop packets there, and the drops will appear in `dropped_kernel` (AF_PACKET) or `dropped_queue` (libpcap).

Ways to reduce load:

- A BPF filter that excludes traffic you do not need to inspect.
- A SPAN or mirror port that carries only a subset of traffic.
- A larger `buffer_size_mb` to absorb bursts with AF_PACKET (raise `net.core.rmem_max` if needed).
- A dedicated high-throughput IDS in front of SentinelX for large links.

Full method and results: [benchmarking.md](benchmarking.md).

## Troubleshooting

Start with:

```bash
sentinelx capabilities
sentinelx doctor
```

`sentinelx doctor` checks the Python version, the host environment (WSL, container), dependencies, PCAP replay, interface enumeration, the capture backend, live capture, whether a named capture interface exists, the firewall backend, automatic blocking, safety posture, rules, whether the PCAP directory is writable, the JWT secret, database connectivity and migrations, Redis, and whether the API and dashboard answer. It exits with status 1 if any check fails. Add `--json` for machine-readable output.

| Symptom | Cause and fix |
|---|---|
| `live capture requires CAP_NET_RAW or root: ...` or `live capture was refused (...)` | The process lacks the capture privilege. On Linux, grant it as described in [Granting the capability on a Linux host](#granting-the-capability-on-a-linux-host), or run the `capture` Compose profile; `setcap` must target the resolved interpreter binary, not the `.venv` symlink. On macOS and Windows, follow the remedy in [Required privileges](#required-privileges). |
| Live capture unavailable or denied in Docker | The default `api` container cannot capture. Use the `capture` profile: the `sensor` service runs the `python3-sensor` interpreter with `cap_add: [NET_RAW, NET_ADMIN]` and `no-new-privileges:false`. See [deployment.md](deployment.md#the-capture-profile). |
| `interface 'X' not found; available interfaces: ...` | The name does not exist. Pick one from `sentinelx interfaces`. Inside a container, only host networking exposes host interfaces. |
| `invalid BPF filter '...'` | The expression does not compile. Fix or clear it, and test it with `sentinelx monitor -i <iface> --bpf '<expr>'`. |
| `BPF filters are compiled with libpcap, which is not installed` | Install libpcap (for example `apt install libpcap0.8`) or remove the filter. |
| `no live capture backend can run on this host (...)` | Neither backend exists here (for example Scapy is missing and the host is not Linux). PCAP replay still works. |
| Backend is `libpcap` on Linux | `CAPTURE__BACKEND=libpcap` is set, or AF_PACKET is not available in this kernel or Python build (`capture_backend_unavailable` in the logs gives the reason). Expect lower throughput and duplicate loopback packets. |
| `dropped_queue` rising | The pipeline cannot keep up with the libpcap backend. Switch to `af_packet` on Linux, narrow the filter, or raise `CAPTURE__QUEUE_SIZE`. |
| `received` climbs but `pipeline.decoder.failed` climbs with it | The frames use a link type or protocol the decoder does not support (see [Known decoder limitations](#known-decoder-limitations)). Check `unsupported_frames` in `GET /api/v1/system/status`. |
| Capture started with `sentinelx start --capture` failed but the API is up | Startup capture failures are logged as `startup_capture_failed` and do not stop the API. Fix the cause and start capture through the API or restart. |
| Container sees only its own traffic | Bridge networking. Use the `capture` profile, which runs with `network_mode: host`. |
| `CAPTURE_INTERFACE` or `BPF_FILTER` has no effect | A stored runtime override takes precedence over the environment. Check with `sentinelx config --section capture`. |
| Configuration error on `bpf_filter` | The expression contains a rejected character (`;`, `\|`, `` ` ``, `$`, `\`, newline). |
| `dropped_kernel` rising | The pipeline cannot keep up. Narrow the BPF filter, increase `buffer_size_mb`, or reduce the traffic reaching the sensor. See [Performance](#performance). |
| Replay fails with `not a pcap or pcapng capture file`, `capture file is truncated` or `corrupt capture` | The file is not a capture, is cut short, or has an invalid length field. Check it with `capinfos` or `tcpdump -r`. Records before the damage were already processed. |
| Replay packets decode as failures | The file's link type is not one the decoder supports (see [Link, network and transport layers](#link-network-and-transport-layers)). `pcap_metadata()` and the PCAP Lab show the file's `link_types`. |
| Replayed detections do not appear in "last 24 hours" views | Detections carry the capture time of the triggering packet. A replay of an older capture is filed at that time. Widen the time range, or open the replay's own report. |
