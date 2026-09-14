# Packet capture

This document covers how SentinelX gets packets: capture sources, required privileges, interface selection, BPF filters, capture settings, what the protocol decoders extract, how malformed traffic is handled, the capture statistics you can monitor, performance expectations, and troubleshooting.

For how decoded packets flow through detection, see [architecture.md](architecture.md). For running captures through the PCAP Lab, see [pcap-lab.md](pcap-lab.md).

## Capture sources

Every packet source implements `PacketCapture` (`packages/sentinelx/capture/base.py`) and yields `RawFrame` objects. The pipeline consumes only that interface, so live capture, file replay and synthetic frames go through the same decoder and detection code.

| Source | Class and file | `source_kind` | Used by |
|---|---|---|---|
| Live interface | `LiveCapture`, `capture/live.py` | `live` | `sentinelx start --capture`, `POST /api/v1/sensors/start`, `sentinelx monitor -i` |
| PCAP or pcapng file | `PcapFileCapture`, `capture/pcap.py` | `pcap` | `sentinelx replay`, `sentinelx monitor --pcap`, PCAP Lab replays through the API |
| In-memory frames | `MockCapture`, `capture/mock.py` | `mock` | `sentinelx monitor --scenario`, tests |

`create_capture()` in `capture/factory.py` picks the source from configuration: it returns a `PcapFileCapture` when given a file path, otherwise a `LiveCapture` built from `CaptureSettings`.

A `RawFrame` carries:

| Field | Meaning |
|---|---|
| `data` | Captured bytes, possibly truncated by the snapshot length |
| `timestamp` | UNIX epoch seconds |
| `link_type` | libpcap link-layer type (DLT) of `data` |
| `interface` | Interface name, or `pcap:<filename>` for replays |
| `wire_length` | Original length on the wire, when the source knows it |

### Live capture

`LiveCapture` has two backends, chosen when the capture opens.

**AF_PACKET (preferred, Linux).**

1. The named interface is checked against `/sys/class/net`. An unknown name fails with an error listing the available interfaces.
2. A raw `AF_PACKET` socket is opened for all protocols (`ETH_P_ALL`).
3. The socket receive buffer is set to `buffer_size_mb`.
4. The socket is bound to the named interface. For `any`, it is not bound.
5. If a BPF filter is set, it is compiled and attached to the socket in the kernel (see [BPF filters](#bpf-filters)).
6. Frames are read with `recvfrom(snapshot_length)` in a worker thread, with a 0.5-second read timeout so the capture notices a stop request.
7. Each frame is stamped with `time.time()` when it reaches user space.
8. Kernel drop counters are read with `PACKET_STATISTICS` every 512 frames and when the capture closes.

**Scapy (fallback).** If the AF_PACKET socket cannot be opened or configured for any reason other than a missing privilege, or if the platform is not Linux, `LiveCapture` logs `af_packet_unavailable` and starts a Scapy `AsyncSniffer` instead. Frames are handed to the event loop through a queue of 20,000 frames, use Scapy's packet timestamp and are always labelled as Ethernet. The chosen backend is logged (`live_capture_ready backend=...`) and reported as `backend` in the sensor status, so an unexpected throughput figure can be traced to the backend in use.

A missing privilege never falls back to Scapy. It fails with `PermissionDeniedError`.

Live capture limitations in the current code:

- **Capturing on `any` does not decode.** With `interface` set to `any` (the default), the unbound socket receives frames with each device's own link-layer header, but the frames are labelled as Linux cooked capture (`LINUX_SLL`). The decoder then misreads the header and every frame counts as a decode failure. A BPF filter compiled for `any` has the same header mismatch. **Set `CAPTURE_INTERFACE` to a named interface** such as `eth0` for live capture. This was confirmed by capturing loopback traffic with `any` (every frame failed to decode) and with `lo` (frames decoded correctly).
- **Promiscuous mode is not applied.** The `promiscuous` setting is passed to `LiveCapture` but the AF_PACKET backend does not enable it. On a SPAN or mirror port, enable promiscuous mode on the interface yourself, for example `sudo ip link set dev eth0 promisc on`.
- **Truncation is not visible.** Frames longer than `snapshot_length` are truncated, and the AF_PACKET backend records `wire_length` as the captured length. Byte counts undercount truncated frames.
- **Outgoing packets are captured too.** An `ETH_P_ALL` socket sees traffic the host sends as well as traffic it receives. On loopback, each packet is seen twice.

### PCAP replay

`PcapFileCapture` reads files with Scapy's `RawPcapReader`, falling back to `RawPcapNgReader`. Both return raw bytes and the file's link type without building a Scapy packet per record. Decoding uses the SentinelX decoder, exactly as for live traffic.

| Behaviour | Detail |
|---|---|
| Formats | pcap and pcapng |
| Opening errors | `PcapError` for a missing path, a path that is not a regular file, an empty file, or a file neither reader accepts |
| Timestamps | Taken from each record (`sec`/`usec` for pcap, `tshigh`/`tslow`/`tsresol` for pcapng). A record without a usable timestamp gets `index × 0.001` so ordering is preserved |
| Wire length | Taken from the record's `wirelen` when present, otherwise the captured length |
| `speed` | `0` (default) replays as fast as possible. `1.0` reproduces the original timing, `2.0` runs twice as fast |
| Gaps | A single pacing sleep is capped at 1 second, so long idle gaps in a capture are shortened |
| `limit` | Stop after this many packets |
| `rewrite_timestamps` | Library option (off by default) that shifts timestamps to the present. Detectors window on packet time, so replays normally keep the original timestamps |
| Event loop | The reader yields to the event loop every 256 frames, so a full-speed replay does not block the API |

From the CLI:

```bash
sentinelx replay capture.pcap                    # as fast as possible
sentinelx replay capture.pcap --speed 1          # original timing
sentinelx replay capture.pcap --limit 10000 --report report.json
sentinelx replay capture.pcap --persist          # store results under a replay id
sentinelx monitor --pcap capture.pcap            # live terminal view at original speed
```

Responses are always simulated during a replay; no firewall is modified.

`pcap_metadata()` reads every record header of a file to report packet count, total bytes, link type, first and last timestamps, duration and average packet size without running detection.

Files uploaded through the API are validated by magic number and limited to the smaller of `api.max_upload_mb` (default 200) and `capture.max_pcap_size_mb` (default 512). Files with `.pcap`, `.pcapng` or `.cap` extensions under `PCAP_DIRECTORY` are listed for replay. See [pcap-lab.md](pcap-lab.md).

### Mock capture

`MockCapture` yields a list of frames the caller already has. It takes `delay` (seconds between frames) and `repeat` (how many times to emit the sequence, at least 1). `MockCapture.from_bytes()` builds frames from raw packet bytes with evenly spaced timestamps (default start `1700000000.0`, interval `0.001` seconds). Its interface name defaults to `mock0`.

`sentinelx monitor --scenario <name>` uses it to feed a synthetic scenario through the pipeline without any privileges.

## Required privileges

Opening an `AF_PACKET` socket requires the `CAP_NET_RAW` capability. PCAP replay, mock capture, fixtures and the rest of the platform do not need it.

Check whether the current process can capture:

```bash
sentinelx doctor          # "capture privileges" check
sentinelx interfaces      # warns when capture is not possible
```

Both test this by opening a raw socket rather than by reading capability bits.

### Granting the capability on a host

Running the whole platform as root works, but granting the capability to the Python interpreter is narrower. File capabilities apply to the real binary, not a symlink, so resolve the path first:

```bash
readlink -f .venv/bin/python                                    # the interpreter binary
sudo setcap cap_net_raw=eip "$(readlink -f .venv/bin/python)"   # capture only
getcap "$(readlink -f .venv/bin/python)"                        # verify
sudo setcap -r "$(readlink -f .venv/bin/python)"                # remove again
```

The error message and `sentinelx doctor` suggest `cap_net_raw,cap_net_admin=eip`. `CAP_NET_ADMIN` is needed only when a firewall backend (`nftables` or `iptables`) will modify the host firewall; see [response-engine.md](response-engine.md). Capture alone needs only `CAP_NET_RAW`.

Be aware of what this grants. A virtual environment's `python` is usually a symlink to the system interpreter, so the capability applies to every program run with that interpreter binary, not only SentinelX. On a shared host, consider a dedicated interpreter for the sensor. See [security.md](security.md).

### Running under Docker

Containers on a Docker bridge network see only their own traffic, never the host's. The default Compose stack therefore runs detection on PCAP replay and on traffic sent to the stack itself.

For live capture of host traffic, `docker-compose.yml` defines a `sensor` service in the `capture` profile. It runs the same `sentinelx-api:local` image as `api`, with:

| Setting | Value | Why |
|---|---|---|
| `network_mode` | `host` | Sees the host's interfaces |
| `cap_drop` / `cap_add` | `ALL` / `NET_RAW`, `NET_ADMIN` | Packet capture; `NET_ADMIN` is used only if a firewall backend is enabled |
| `security_opt` | `no-new-privileges:false` | The image grants file capabilities to `python3` (`setcap cap_net_raw,cap_net_admin+eip` in `docker/Dockerfile.api`), which only take effect for the non-root user when privilege gain on exec is allowed |
| `command` | `sentinelx start --capture` | Starts live capture on `CAPTURE_INTERFACE` when the API starts |
| `API_HOST`, `API_PORT` | `0.0.0.0`, `8001` | The API listens on the host network |
| `DATABASE_URL`, `REDIS_URL` | `127.0.0.1:${POSTGRES_HOST_PORT:-5433}`, `127.0.0.1:${REDIS_HOST_PORT:-6381}` | Host networking cannot resolve Compose service names, so the loopback-published ports are used |

It is Linux only. The command from the Compose file replaces `api` with `sensor` and points the dashboard at it:

```bash
CAPTURE_INTERFACE=eth0 \
DASHBOARD_API_URL=http://host.docker.internal:8001 PUBLIC_WS_URL=ws://localhost:8001 \
  docker compose --profile capture up -d --build --scale api=0
```

Set `CAPTURE_INTERFACE` to a named host interface. The Compose default is `any`, which does not decode (see [Live capture](#live-capture)).

Because `API_HOST` is `0.0.0.0` on the host network, the sensor's API on port 8001 is reachable from other machines unless a host firewall blocks it. See [deployment.md](deployment.md) for exposure and TLS guidance.

## Interface selection

List interfaces with:

```bash
sentinelx interfaces
sentinelx interfaces --json
```

The table shows name, state, addresses, MAC, MTU, received packets and dropped packets for every entry in `/sys/class/net`. The JSON form also includes `has_capture_privileges`, `is_up`, `is_loopback` and transmit counters. The same list is available from `GET /api/v1/interfaces`.

Choose the interface in one of these ways:

| Method | Example |
|---|---|
| Environment | `CAPTURE_INTERFACE=eth0` or `CAPTURE__INTERFACE=eth0` |
| Server start | `sentinelx start --capture --interface eth0` (`-i` for short) |
| Terminal monitor | `sentinelx monitor -i eth0` |
| API | `POST /api/v1/sensors/start` with `{"interface": "eth0"}` (administrator role; see [api.md](api.md)) |
| Stored setting | `sentinelx config set capture interface '"eth0"'` (applied at the next server start) |

`sentinelx doctor` fails its "capture interface" check when the configured interface does not exist.

## BPF filters

A BPF filter is attached to the socket in the kernel, so packets that do not match never reach Python and cost nothing to process. The expression uses standard pcap-filter syntax, for example:

```text
tcp or udp
not port 8000
host 192.0.2.10 and not port 22
```

Filtering out traffic hides it from every detector. Filter out only traffic you are sure you do not need to inspect, such as the sensor's own API traffic.

Where to set it:

| Method | Example |
|---|---|
| Environment | `BPF_FILTER='tcp or udp'` or `CAPTURE__BPF_FILTER='tcp or udp'` |
| Terminal monitor | `sentinelx monitor -i eth0 --bpf 'tcp or udp'` |
| API | `POST /api/v1/sensors/start` with `{"bpf_filter": "tcp or udp"}` (at most 512 characters). If omitted, the configured filter is used |
| Stored setting | `sentinelx config set capture bpf_filter '"tcp or udp"'` |

`sentinelx start` has no filter option; it uses the configured filter.

Validation and compilation:

- The characters `;`, `|`, `` ` ``, `$`, `\`, newline and carriage return are rejected. The filter is never passed through a shell; rejecting them early turns a confusing compile error into a clear configuration error. Surrounding whitespace is stripped.
- The expression is compiled by Scapy's `compile_filter`, which calls libpcap. The libpcap shared library must be installed on the host (the Docker image installs `libpcap0.8`).
- If Scapy cannot be imported, the filter is skipped with a `bpf_unavailable` warning and all traffic is captured.
- **An expression that fails to compile does not stop the capture.** The AF_PACKET backend raises an error, `LiveCapture` treats it like any other AF_PACKET failure and falls back to Scapy, and the Scapy sniffer then fails in its own thread. The sensor reports `backend: scapy` and state `running` but receives no packets. The only signs are an `af_packet_unavailable` warning containing `invalid BPF filter` and a received count that stays at 0. A missing libpcap library produces the same outcome. Test a new filter with `sentinelx monitor --bpf` first and check that packets appear.

## Settings

Capture settings are defined by `CaptureSettings` in `packages/sentinelx/config/settings.py`.

| Setting | Default | Nested environment variable | Flat alias | Notes |
|---|---|---|---|---|
| `interface` | `any` | `CAPTURE__INTERFACE` | `CAPTURE_INTERFACE` | Use a named interface for live capture |
| `bpf_filter` | empty | `CAPTURE__BPF_FILTER` | `BPF_FILTER` | See [BPF filters](#bpf-filters) |
| `snapshot_length` | `2048` | `CAPTURE__SNAPSHOT_LENGTH` | none | 64 to 65535. Bytes read per frame |
| `promiscuous` | `true` | `CAPTURE__PROMISCUOUS` | none | Not applied by the AF_PACKET backend |
| `buffer_size_mb` | `16` | `CAPTURE__BUFFER_SIZE_MB` | none | 1 to 1024. Socket receive buffer. Linux caps the value at `net.core.rmem_max` |
| `queue_size` | `20000` | `CAPTURE__QUEUE_SIZE` | none | Minimum 100. Not currently used by any capture backend |
| `home_networks` | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"]` | `CAPTURE__HOME_NETWORKS` (JSON list) | none | Used only to label packet direction. Every entry must be a valid network |
| `pcap_directory` | `pcaps` | `CAPTURE__PCAP_DIRECTORY` | `PCAP_DIRECTORY` | Where replayable and uploaded captures live |
| `max_pcap_size_mb` | `512` | `CAPTURE__MAX_PCAP_SIZE_MB` | none | Upload limit, together with `api.max_upload_mb` |

How values are resolved:

- Nested names use a double underscore and are case-insensitive, for example `CAPTURE__SNAPSHOT_LENGTH=512` or `CAPTURE__HOME_NETWORKS='["10.20.0.0/16"]'`.
- Nested names are read from the process environment and from a `.env` file in the working directory.
- **Flat aliases (`CAPTURE_INTERFACE`, `BPF_FILTER`, `PCAP_DIRECTORY`) are read only from the process environment, not from `.env`.** A flat alias in `.env` is silently ignored unless something exports it into the environment first (Docker Compose does, because it passes `.env` values as container environment variables). When running the Python package directly with a `.env` file, use the nested names.
- When both forms are set in the environment, the nested form wins.
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

## Capture statistics

Each capture source keeps a `CaptureStats` object:

| Field | Meaning |
|---|---|
| `received` | Frames delivered to the pipeline |
| `bytes_received` | Sum of frame wire lengths |
| `dropped_kernel` | Frames the kernel reports as dropped before user space read them (AF_PACKET `PACKET_STATISTICS`) |
| `dropped_queue` | Frames lost in SentinelX's own hand-off queue. Only the Scapy backend has such a queue, so this stays 0 with AF_PACKET |
| `errors` | Socket read errors |
| `elapsed_seconds` | Wall time since the capture opened |
| `packets_per_second`, `megabits_per_second` | Measured from `received`, `bytes_received` and elapsed wall time |
| `capture_span_seconds` | Time between the first and last packet timestamps |
| `drop_rate` | Dropped divided by received plus dropped |

Kernel and queue drops are reported separately because they have different remedies: kernel drops call for a narrower filter or larger buffer, queue drops for faster processing.

Where to see them:

| Place | Content |
|---|---|
| `GET /api/v1/sensors` | Sensor state, interface, filter, backend, `capture` statistics, error, `has_capture_privileges` and safety banner |
| `GET /api/v1/system/status` | Platform health, plus `pipeline` with decoder counts, feature-extractor state (tracked sources, active flows, evictions) and detection statistics |
| `GET /api/v1/metrics/summary` | Decoder, features, detection, capture statistics and event bus statistics |
| `packet.stats` event | Published about once per second during a run: `frames`, `bytes`, `elapsed_seconds`, `packets_per_second`, `detections`, `incidents`, `active_flows`, `tracked_sources`, `dropped`, protocol distribution, CPU and memory |
| `capture_closed` log line | The final statistics when a capture closes |
| `sensor.status` event | Published when the sensor starts, stops or fails |

`sentinelx status` builds its own platform instance, so it does not show a running server's capture statistics. Query the API instead.

Prometheus counters `sentinelx_packets_captured_total{source,interface}` and `sentinelx_packets_dropped_total{reason="capture"}` are incremented only when a capture run ends, so they stay at 0 while a live capture is running. Use `sentinelx_parse_errors_total`, `sentinelx_pipeline_latency_seconds`, the `packet.stats` events and the API for live monitoring.

## Performance

- **Decoder.** On the reference Intel Core i5-8350U, the `struct` decoder measured 2.1 to 2.5 times faster than Scapy `Ether(bytes)` across two runs of 50,000 frames.
- **End to end.** The full pipeline (decode, features, detection, rules, scoring, correlation, response decision) processed roughly 2,900 to 4,600 packets per second on one core of that laptop CPU, using in-memory frames. Capture overhead is not included in that figure.
- **Live capture overhead.** The AF_PACKET backend performs one `recvfrom` per frame, dispatched to a worker thread. Its throughput and drop rate under load have not been measured.
- **Suitability.** That is enough for a home network, a lab, a small office uplink or offline PCAP analysis. It is not suitable for multi-gigabit links, or for sustained traffic on links of a few hundred megabits per second, where packet rates are one to two orders of magnitude higher. The sensor will drop packets there, and the drops will appear in `dropped_kernel`.

Ways to reduce load:

- A BPF filter that excludes traffic you do not need to inspect.
- A SPAN or mirror port that carries only a subset of traffic.
- A larger `buffer_size_mb` to absorb bursts (raise `net.core.rmem_max` if needed).
- A dedicated high-throughput IDS in front of SentinelX for large links.

Full method and results: [benchmarking.md](benchmarking.md).

## Troubleshooting

Start with:

```bash
sentinelx doctor
```

It checks the Python version, configuration validity, safety posture, capture privileges, whether the configured interface exists, firewall binaries, rules, whether the PCAP directory is writable, the JWT secret, database connectivity and migrations, and Redis. It exits with status 1 if any check fails. Add `--json` for machine-readable output.

| Symptom | Cause and fix |
|---|---|
| `live capture needs CAP_NET_RAW. Either run as root, or grant the capability once with: ...` | The process lacks `CAP_NET_RAW`. Grant it as described in [Granting the capability on a host](#granting-the-capability-on-a-host), or run the `capture` Compose profile. `setcap` must target the resolved interpreter binary, not the `.venv` symlink. |
| Capability granted but still denied in Docker | The container needs `cap_add: [NET_RAW]` and `no-new-privileges:false`, as in the `sensor` service. |
| `interface 'X' not found; available interfaces: ...` | The name does not exist in `/sys/class/net`. Pick one from `sentinelx interfaces`. Inside a container, only host networking exposes host interfaces. |
| `received` climbs but no detections, and `pipeline.decoder.failed` climbs with it | The interface is `any`, which does not decode in the current version. Set `CAPTURE_INTERFACE` to a named interface. |
| Sensor state `running`, backend `scapy`, `received` stays at 0 | Usually a BPF expression that failed to compile, or libpcap missing. Look for `af_packet_unavailable` with `invalid BPF filter` in the logs, fix or clear the filter, and test it with `sentinelx monitor -i <iface> --bpf '<expr>'`. |
| Backend is `scapy` without a filter problem | AF_PACKET could not be opened or configured, or the host is not Linux. The `af_packet_unavailable` warning gives the reason. Expect lower throughput. |
| Capture started with `sentinelx start --capture` failed but the API is up | Startup capture failures are logged as `startup_capture_failed` and do not stop the API. Fix the cause and start capture through the API or restart. |
| Container sees only its own traffic | Bridge networking. Use the `capture` profile, which runs with `network_mode: host`. |
| `sensor` container reported unhealthy | The image's health check probes port 8000, but the `sensor` service listens on 8001. Check `http://127.0.0.1:8001/api/v1/system/health` directly. |
| `CAPTURE_INTERFACE` or `BPF_FILTER` in `.env` has no effect | Flat aliases are read only from the process environment. Use `CAPTURE__INTERFACE` and `CAPTURE__BPF_FILTER` in `.env`, or export the variables. Also check for a stored override with `sentinelx config --section capture`. |
| Configuration error on `bpf_filter` | The expression contains a rejected character (`;`, `\|`, `` ` ``, `$`, `\`, newline). |
| `dropped_kernel` rising | The pipeline cannot keep up. Narrow the BPF filter, increase `buffer_size_mb`, or reduce the traffic reaching the sensor. See [Performance](#performance). |
| Replay fails with `not a readable pcap or pcapng file` | The file is corrupt, truncated, or not a capture. Check it with `tcpdump -r` or `capinfos`. |
| Replay packets decode as failures | The file's link type is not one the decoder supports (see [Link, network and transport layers](#link-network-and-transport-layers)). |
