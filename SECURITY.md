# Security policy

## Reporting a vulnerability

Please report security vulnerabilities privately. Do not put vulnerability details in a public issue, pull request or discussion.

Use GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**.

If that button is not shown, private reporting is not enabled for the repository. In that case open a public issue that asks the maintainer for a private contact and contains nothing else: no description of the problem, the affected component or how to reproduce it. Send the details only once a private channel exists.

Include as much of the following as you can:

- The affected component (packet decoder or capture-file reader, detection engine, rule engine, response engine or firewall adapter, API, WebSocket, dashboard, CLI, container images or the nginx proxy).
- The SentinelX version or commit, and the relevant configuration (for example `ENVIRONMENT`, `RESPONSE_MODE`, `DRY_RUN`, `FIREWALL_BACKEND`, whether Redis is available), with secrets removed.
- Steps to reproduce, and the impact you believe it has.
- A packet capture, rule file or request that triggers the issue, if relevant. Strip unrelated traffic first, and remove secrets from any traceback or log you include; see [docs/pcap-lab.md](docs/pcap-lab.md#privacy-when-sharing-captures).

## What to expect

- Acknowledgement of your report within 5 working days.
- An initial assessment, including whether it is accepted as a vulnerability, within 14 days.
- Coordinated disclosure. We aim to release a fix within 90 days of the report, and will agree the publication date with you. Reporters are credited in the release notes unless they ask not to be.

These are targets, not contractual guarantees.

## Scope

In scope, for example:

- A way to make the response engine block an address the safety guard should protect (loopback, allowlisted networks, management addresses, the sensor's own addresses, the address of a recently signed-in operator), or to block a larger prefix than permitted.
- A way to change the firewall while `DRY_RUN=true`, while in `detect_only` mode without the confirmation phrase having been given, or from a PCAP Lab replay.
- Command injection through firewall adapters, or code execution through rules, uploaded captures, scenario parameters or configuration.
- Packets, capture files, rule definitions or scenario parameters that crash the sensor, stop detection, or cause resource use out of proportion to the input.
- Authentication or authorisation bypass, lockout bypass or abuse, CSRF, session fixation, refresh-token or WebSocket ticket reuse, or use of a revoked token or of an access token issued before a sign-out, password change or password reset (revocation of an individual access token is per process while Redis is unavailable, as documented; the sign-out cut-off is stored in the database).
- Secrets or credentials appearing in logs, API responses, the configuration view or stored data.
- Reaching internal services through the webhook destination check, or bypassing the upload size limit or quota.
- Client address spoofing past the rate limiter, lockout or audit log when `trusted_proxies` is configured as documented.

Out of scope:

- Attacks that are missed because they stay below configured detection thresholds. These are documented limitations; see [docs/benchmarking.md](docs/benchmarking.md). Improvements are welcome as ordinary issues.
- Denial of service by sending more traffic than the sensor's measured throughput.
- Issues requiring root access on the sensor host, or write access to its configuration, environment, rules directory or model files.
- Loading a machine-learning model file from an untrusted source (documented as unsafe).
- Deployments that ignore the production configuration checks, such as `ENVIRONMENT=development` exposed to the internet.
- The residual risks already listed in [docs/security.md](docs/security.md#residual-risks-and-operator-responsibilities), such as the lack of MFA, the shared HS256 secret, DNS rebinding between the webhook address check and the connection, per-process limits while Redis is unavailable, and the unverified pf and Windows Firewall adapters. A report showing that one of these is worse than documented is in scope.

## Supported versions

SentinelX is pre-1.0 (version 0.1.0). Security fixes are made on the `main` branch and included in the next release. Older commits and releases are not patched.

## Security design

The threat model, the controls and the operator's residual responsibilities are described in [docs/security.md](docs/security.md).
