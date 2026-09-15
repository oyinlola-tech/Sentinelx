# Who SentinelX is for, and when to use it

This guide helps you decide whether SentinelX fits your situation before you install it. It describes what the software does in plain terms, the people and environments it was built for, concrete scenarios with the setup each one needs, and, just as importantly, the situations where a different tool is the better choice.

For installation, see the [README](../README.md#installation). For deployment details, see [deployment.md](deployment.md).

## Contents

- [What SentinelX is, in one minute](#what-sentinelx-is-in-one-minute)
- [The problem it solves](#the-problem-it-solves)
- [Who it is for](#who-it-is-for)
- [Use cases](#use-cases)
- [When SentinelX is the right choice](#when-sentinelx-is-the-right-choice)
- [When to use something else](#when-to-use-something-else)
- [How it compares](#how-it-compares)
- [Choosing a deployment for your use case](#choosing-a-deployment-for-your-use-case)
- [A quick decision checklist](#a-quick-decision-checklist)
- [What to expect in practice](#what-to-expect-in-practice)

## What SentinelX is, in one minute

SentinelX watches network traffic and tells you when something on your network is behaving like an attack. It does four things:

1. **Watches.** It reads packets from a network interface on the machine it runs on, or from a saved capture file (PCAP or PCAPNG).
2. **Detects.** It recognises common hostile behaviour: port scans and network sweeps, password guessing against SSH, RDP and other services, SYN, ICMP, HTTP and DNS floods, DNS tunnelling, traffic from addresses on your denylist, malformed TCP flag combinations, and unusual traffic compared with each source's normal pattern. You can add your own rules in YAML.
3. **Explains.** Every detection comes with the evidence that triggered it ("100 distinct ports contacted in 1.1 seconds, threshold 20"), a risk score from 0 to 100 with the contribution of each factor, and related detections grouped into an incident such as "reconnaissance followed by a credential attack".
4. **Responds, only if you allow it.** Out of the box it only observes. If an administrator enables prevention, it can block or rate-limit an attacking address in the host firewall (nftables or iptables on Linux; pf and Windows Firewall adapters exist but are not yet verified on real hosts), after a safety guard checks it will not lock out the host itself, your management addresses or your allowlist.

It comes with a web dashboard, a command-line tool, a REST API with a live event stream, role-based accounts and an audit log. It is self-hosted, open source (Apache-2.0) and runs without internet access.

## The problem it solves

Most people who look after a small network have the same gap. They can see that "something is slow" or that a server's logs are full of failed logins, but they cannot easily answer:

- Who is scanning or attacking this network right now?
- Is this one noisy client, or a coordinated attempt?
- How serious is it, and why?
- What would happen if I blocked it, and did the block actually work?

Enterprise tools answer these questions, but they assume a security team, dedicated sensors and a budget. Lighter tools answer part of them: a firewall log shows drops but not intent, and log-based banning tools see only the services they parse. SentinelX sits between those. It gives one host, or a small network behind it, a readable account of hostile traffic and a careful, reversible way to act on it.

The design principle behind everything is that **an alert you cannot explain is an alert you cannot trust**. SentinelX would rather show you why it thinks a source is hostile and let you decide, than block silently.

## Who it is for

### Homelab and self-hosting enthusiasts

You run services from home or a rented server (a media server, a VPN endpoint, a few containers, perhaps SSH exposed to the internet), and you want to know who is poking at them. You are comfortable with Linux and Docker, but you do not want to run a security operations stack.

**Why SentinelX fits:** a single process or a small Docker Compose stack; detection of the scans and brute-force attempts that internet-facing hosts see every day; plain-language explanations; and optional, carefully guarded automatic blocking.

### Small businesses and small offices without a security team

You have one Linux gateway, file server or web server that matters, and one person (often not a security specialist) who looks after IT. You need to notice attacks and keep evidence of what happened.

**Why SentinelX fits:** it runs in detection-only mode by default, so it cannot break anything while you learn what is normal. The dashboard shows incidents in order of risk, not a stream of raw alerts. The audit log records every block, unblock and settings change with the person who made it.

### Students, educators and training labs

You teach or learn network security and need to see attacks being recognised, understand why, and experiment with detection thresholds and rules.

**Why SentinelX fits:**
- **Synthetic scenarios and the PCAP Lab.** It generates attack captures, replays them through the same pipeline a live sensor uses, and shows each detection's evidence and scoring. Nothing is sent on a network.
- **A readable rule language** that you can test against the bundled scenarios.
- **A benchmark harness** that measures detection rate, false positives and known evasions.

### Security analysts and incident responders working from captures

You receive PCAP files from an incident, a customer or a honeypot, and you want a fast first pass over them.

**Why SentinelX fits:** `sentinelx replay capture.pcap` or the dashboard's PCAP Lab produces detections, incidents and risk explanations from a capture. There is no live deployment and no privileges needed, and replays are reproducible: the same file gives the same results.

### Developers and platform engineers adding detection to their own tooling

You want network detection events inside your own systems: a chat alert, a ticket, a SIEM, a custom dashboard.

**Why SentinelX fits:** a documented REST API with OpenAPI, a WebSocket event stream of detections, incidents and responses, HTTPS webhooks and Prometheus metrics.

### Makers of appliances and edge devices, at small scale

You build a small gateway or edge box and want explainable detection on it.

**Why SentinelX fits (with care):**
- **Offline:** it runs air-gapped.
- **Small footprint:** it works with SQLite and no Redis.
- **Detection-only mode.** Nothing is at risk until you are ready.

Plan for about 5,000 packets per second per process on a laptop-class CPU, and test on your hardware. ARM64 has so far been verified only under emulation.

## Use cases

Each use case below says what you want, how to set SentinelX up, and what you get.

### 1. Know who is attacking an internet-facing Linux server

**You want:** to see the port scans, SSH password guessing and floods hitting a VPS or home server, and to understand which sources are dangerous.

**Setup:**
- Install SentinelX on the server.
- Grant live-capture privileges (run as root, or `setcap cap_net_raw` on the interpreter; see the README).
- Start with `sentinelx start --capture`.
- Keep the default detection-only mode for the first week.

**You get:**
- The Threats page, which ranks sources by risk.
- Incidents such as "reconnaissance followed by a credential attack" when a scanner comes back to guess passwords.
- The full evidence behind each detection.

After a week you know your baseline and can decide whether to enable prevention.

### 2. Automatically block repeat attackers, safely

**You want:** hostile sources blocked without waking up at night, but without locking yourself out.

**Setup:**
1. After running in detection-only mode, set the firewall backend (`FIREWALL_BACKEND=nftables`, or `auto`).
2. Add your own addresses and management networks to the allowlist.
3. Try manual-approval mode: SentinelX proposes blocks and an administrator approves them.
4. When you trust the thresholds, switch to automatic mode, which requires typing the confirmation phrase `ENABLE PREVENTION`.

**You get:**
- Temporary blocks, with expiry, for sources whose risk passes the automatic threshold (85 by default).
- A safety guard that refuses to block loopback, the host's own addresses, management and allowlisted addresses, anyone signed in to the console in the last hour, and oversized address ranges.
- One-click unblock in the dashboard, and an audit trail of every decision.
- Honest failure reporting: if the firewall command fails, the decision is recorded as failed, never as blocked.

### 3. Triage a capture file from an incident

**You want:** a quick, explainable summary of what hostile activity a PCAP contains.

**Setup:** none beyond `pip install -e .`. Run `sentinelx replay incident.pcap` (add `--json` for machine-readable output), or upload the file in the dashboard's PCAP Lab.

**You get:**
- The detections, with evidence and risk, and the correlated incidents.
- A list of the response decisions that would have been made. They are simulated: replays never change a firewall.
- The same results every time you replay the same file, which makes the output suitable for reports.

### 4. Teach or learn intrusion detection

**You want:** a hands-on way to see how scans, brute force, floods and DNS tunnelling look on the wire and how detectors reason about them.

**Setup:**
- Run the dashboard locally.
- Use `sentinelx fixtures generate` or the PCAP Lab's Generate fixture button to create scenarios such as `tcp_port_scan`, `ssh_brute_force`, `dns_tunneling` or `mixed_intrusion`.
- Replay them, then write a rule and test it against the scenarios.

**You get:**
- **Real detector output on controlled traffic.** You can see exactly which threshold was crossed.
- **Known evasions to discuss:** the benchmark includes a slow port scan and a low-rate brute force that stay under the default thresholds on purpose.
- **Safety:** no traffic is sent anywhere.

### 5. Watch a small office network from its gateway

**You want:** visibility of hostile traffic entering or crossing a small network.

**Setup:**
- Run SentinelX on the Linux machine that routes the network's traffic, or on a machine connected to a mirror (SPAN) port on a managed switch.
- Capture on that interface.
- Use PostgreSQL for storage and Redis if several people use the dashboard.

Docker Compose provides both, and its `capture` profile runs the sensor on the host network.

**You get:**
- **One console for everyone:**
  - Live detections and open incidents.
  - Viewer, analyst and administrator roles.
  - An audit log of who changed what.
- **Retention:** old data is removed on a schedule.

A single sensor sees only the traffic that passes the interface it captures on, so place it where the traffic flows.

### 6. Feed network detections into existing alerting

**You want:** SentinelX findings in Slack, Microsoft Teams, a ticketing system, Grafana or a SIEM.

**Setup:**
- **Webhooks:** set `RESPONSE__WEBHOOK_URL` to an HTTPS endpoint. Private addresses are refused unless you explicitly allow them.
- **Metrics:** point Prometheus at `/api/v1/metrics`, protected by `API__METRICS_TOKEN` when scraped from another host.
- **Your own integrations:** consume `GET /api/v1/detections` and `/incidents`, or the WebSocket stream, from your own code.

**You get:** structured JSON events carrying the same evidence and risk explanation the dashboard shows.

### 7. Evaluate and tune detection before rolling out a bigger product

**You want:** to understand your network's normal behaviour and which thresholds make sense, before committing to a heavier IDS.

**Setup:**
- Run SentinelX in detection-only mode.
- Review false positives in the Analytics page.
- Adjust thresholds in Settings, and use the benchmark harness to measure the effect.

**You get:** measured detection rates, false-positive counts and time-to-detect figures for the scenarios that matter to you, plus a record of what your network normally looks like.

## When SentinelX is the right choice

SentinelX is a good fit when most of these are true:

- **Scale:** you protect one host or a small network, in the range of a homelab, small office, lab or single important server. Your traffic rate is within what one process handles, around a few thousand packets per second on modest hardware.
- **Understanding over volume:** you value knowing why an alert fired more than having thousands of signatures.
- **People and time:** you have no dedicated security team, or you want a tool a generalist can operate.
- **Hosting:** you want everything self-hosted and able to run without internet access.
- **Trust before action:** you want prevention to be possible but deliberate, off by default, reviewable and reversible.
- **Kinds of traffic:** your concerns are the common network-level threats (scanning, brute force, floods, DNS abuse, known bad addresses), not deep inspection of application payloads.
- **Captures:** you work with PCAP files and want reproducible, explainable analysis of them.
- **Platform:** you run Linux, the platform on which live capture and firewall control have been tested.

## When to use something else

Be honest with yourself about these. SentinelX is not the right tool when:

| Your need | Why SentinelX is not the best fit | Consider instead |
|---|---|---|
| Inspecting traffic on high-speed links (1 Gbit/s and above at sustained load) | Detection runs in a single Python process, measured at about 5,000 packets per second on a laptop-class CPU | Suricata, Zeek, or a commercial network detection product with hardware acceleration |
| Matching tens of thousands of known exploit and malware signatures in packet payloads | SentinelX inspects headers and metadata (flows, DNS, HTTP request lines, TLS SNI/ALPN), not full payloads, and has a small rule set | Suricata or Snort with the ET Open or commercial rule sets |
| Full network security monitoring with long-term flow logs, full packet capture and hunting | SentinelX stores detections and incidents, not every connection or packet | Zeek, Security Onion, Arkime |
| Detecting slow, low-and-slow or distributed attacks designed to stay under thresholds | Threshold detectors can be evaded by design; the benchmark shows this | Long-window analytics in a SIEM, or dedicated NDR products |
| Blocking brute force based on application logs (web login failures, mail server logs) | SentinelX sees network behaviour, not application log messages | fail2ban or CrowdSec |
| Protecting Windows or macOS hosts in production today | Adapters exist but have not been run on real Windows or macOS hosts | Native endpoint protection, or run SentinelX on a Linux gateway in front of them |
| A regulated environment that needs a certified or vendor-supported product | SentinelX is beta-quality open source with no certification or support contract | A supported commercial IDS/IPS |
| Decrypting TLS to inspect encrypted traffic | SentinelX does not decrypt traffic | A TLS-inspecting proxy or firewall, where that is legal and appropriate |
| Monitoring a large, multi-site network from one console | Each sensor keeps its own detection state; there is no multi-sensor correlation | Security Onion, a SIEM with multiple sensors, or a commercial NDR |

Many of these tools also work well alongside SentinelX. A common pattern is fail2ban or CrowdSec for application-log bans, with SentinelX for network-level visibility and explanations.

## How it compares

A simplified comparison, to position SentinelX rather than rank tools. Each of the others is excellent at what it was designed for.

| | SentinelX | Suricata / Snort | Zeek | fail2ban / CrowdSec |
|---|---|---|---|---|
| Main approach | Behavioural detectors, small YAML rule set, statistical anomalies | Large signature rule sets, payload inspection | Protocol analysis and rich logs | Log parsing, then banning |
| Explains each alert | Yes: evidence, risk contributions, correlation | Rule message and metadata | Logs; detection is scripted by you | Log line that matched |
| Correlates into incidents | Yes, built in | Not built in; usually a SIEM | Through scripts | Not built in |
| Blocking | Optional, guarded, audited, with dry run | IPS mode inline | Not a blocker by itself | Yes, its main purpose |
| Web dashboard included | Yes | Via third-party tools | Via third-party tools | CrowdSec console; fail2ban none |
| Throughput | Thousands of packets per second | Multi-gigabit with tuning | Gigabit and above with clusters | Not packet based |
| Learning curve | Low | Moderate to high | High | Low |
| Best at | Small networks, explanations, teaching, PCAP triage | Signature detection at scale | Deep network visibility and hunting | Log-based brute-force protection |

## Choosing a deployment for your use case

| Use case | Recommended setup | Storage | Privileges |
|---|---|---|---|
| Learning, rule writing, PCAP triage | `pip install -e .` and the CLI, or `make dev` for the dashboard | SQLite | None |
| Single server or homelab host | `sentinelx start --capture` on the host, or Docker Compose with the `capture` profile | SQLite, or PostgreSQL via Compose | Capture: `CAP_NET_RAW` or root; prevention: `CAP_NET_ADMIN` too |
| Small office gateway or mirror port | Docker Compose with the `capture` profile on the Linux gateway | PostgreSQL and Redis | As above |
| Integrations and alerting | Any of the above, plus webhooks, API tokens and Prometheus | PostgreSQL recommended | As above |
| Air-gapped lab | Local install from wheels, or Docker images built beforehand | SQLite or PostgreSQL | None for replay |

In every case, start in detection-only mode. Switch prevention on only after you have reviewed a period of detections for your network.

## A quick decision checklist

Answer yes or no:

1. Is the traffic you care about within a few thousand packets per second at peak?
2. Does the machine running SentinelX see that traffic (it is the host, the gateway, or connected to a mirror port)?
3. Is it a Linux host, or Docker on a Linux host?
4. Are your main concerns scanning, brute force, floods, DNS abuse or known bad addresses?
5. Do you want explanations you can read, rather than a large signature feed?
6. Are you comfortable reviewing detections before allowing automatic blocking?

**Six yes:** SentinelX is a strong fit.

**Four or five:** it will likely help; read [When to use something else](#when-to-use-something-else) for the gap.

**Three or fewer:** pair it with, or choose, one of the tools listed there.

## What to expect in practice

- **First hour:** you install SentinelX, replay the bundled `mixed_intrusion` scenario, and see a port scan, an SSH brute force and an ICMP flood correlated into one incident, with the evidence and risk breakdown. `sentinelx doctor` tells you what your host can and cannot do.
- **First week, live:**
  - Internet-facing hosts usually see scans and password guessing within hours. Expect detections for them, ranked by risk on the Threats page.
  - Use the Analytics page to spot noisy but harmless sources (monitoring systems, backup jobs), then add them to the allowlist or adjust thresholds.
- **Turning on prevention:**
  1. Start with manual approval: approve or reject proposed blocks in the Firewall page.
  2. Move to automatic mode once the proposals match your judgement.
  3. Blocks are temporary by default and expire on their own. Unblocking is one click, and every action is in the audit log.
- **Ongoing:** keep an eye on the health panel in Settings and on the live stream indicator in the navigation bar.
  - SentinelX reports degraded components (for example, Redis unavailable) rather than failing silently.
  - It keeps detections if the database is briefly unavailable, writing them once it returns.

SentinelX is beta software. It has been tested end to end on Linux x86_64 and in Docker (see [audit-report.md](audit-report.md) for exactly what was verified), but it has not yet run for long periods on production networks. Treat it as a well-tested beta: valuable for visibility and learning today, and deserving careful evaluation before you rely on it for prevention.
