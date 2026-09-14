# Security policy

## Reporting a vulnerability

Please report security vulnerabilities privately. Do not open a public issue, pull request or discussion.

Use GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**.

Include as much of the following as you can:

- The affected component (packet decoder, detection engine, rule engine, response engine or firewall adapter, API, WebSocket, dashboard, container images).
- The SentinelX version or commit, and the relevant configuration (for example `ENVIRONMENT`, `RESPONSE_MODE`, `DRY_RUN`, `FIREWALL_BACKEND`), with secrets removed.
- Steps to reproduce, and the impact you believe it has.
- A packet capture or rule file that triggers the issue, if relevant. Strip unrelated traffic first.

## What to expect

- Acknowledgement of your report within 5 working days.
- An initial assessment, including whether it is accepted as a vulnerability, within 14 days.
- Coordinated disclosure. We aim to release a fix within 90 days of the report, and will agree the publication date with you. Reporters are credited in the release notes unless they ask not to be.

## Scope

In scope, for example:

- A way to make the response engine block an address the safety guard should protect (loopback, allowlisted networks, management addresses, the sensor's own addresses), or to block a larger prefix than permitted.
- A way to change the firewall while `DRY_RUN=true`, while in `detect_only` mode, or from a PCAP Lab replay.
- Command injection through firewall adapters, or code execution through rules, uploaded captures or configuration.
- Packets that crash the sensor, stop detection, or cause resource use out of proportion to the traffic sent.
- Authentication or authorisation bypass, CSRF, session fixation, or WebSocket ticket reuse.
- Secrets or credentials appearing in logs, API responses or stored data.

Out of scope:

- Attacks that are missed because they stay below configured detection thresholds. These are documented limitations; see [docs/benchmarking.md](docs/benchmarking.md). Improvements are welcome as ordinary issues.
- Denial of service by sending more traffic than the sensor's measured throughput.
- Issues requiring root access on the sensor host, or write access to its configuration, rules directory or model files.
- Loading a machine-learning model file from an untrusted source (documented as unsafe).
- Deployments that ignore the production configuration checks, such as `ENVIRONMENT=development` exposed to the internet.

## Supported versions

SentinelX is pre-1.0. Security fixes are made on the `main` branch and included in the next release.

## Security design

The threat model, the controls and the operator's residual responsibilities are described in [docs/security.md](docs/security.md).
