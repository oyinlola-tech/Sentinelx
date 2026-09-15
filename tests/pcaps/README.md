# PCAP test suite

Small capture files replayed by `tests/capture/test_pcap_suite.py` through the full
detection pipeline: built-in detectors, anomaly detection, local threat intelligence
and the rules in `rules/`.

## Source and licence

Every file here is synthetic. `scripts/generate_test_pcaps.py` builds the packets in
memory with `sentinelx.testing.scenarios`, or writes the bytes directly for the
malformed files. Nothing was captured on a real network, so the files contain no
third-party traffic or personal data. They are covered by the project's Apache-2.0
licence (see `LICENSE`).

The addresses are from documentation ranges (`192.0.2.0/24`, `198.51.100.0/24` and
`203.0.113.0/24`, RFC 5737) and private ranges (RFC 1918). The MAC addresses are
locally administered.

Do not add captures from real networks or third-party datasets unless their licence
allows redistribution. Record the source and licence here when you do.

## Layout

| Directory    | Contents                                                                                                                                                                         |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `benign/`    | Normal mixed traffic. Any detection is a false positive.                                                                                                                         |
| `attacks/`   | Scans, brute force, DNS tunnelling and a multi-stage intrusion. The intended detector must fire, and only against the attacking address.                                         |
| `evasion/`   | Attacks slowed to stay under the default thresholds. The intended detector does not fire. This is a known limitation, kept here so that any change in behaviour shows up in tests. |
| `malformed/` | Truncated, oversized, empty and non-capture files. The reader must reject each one with `PcapError`, without crashing or allocating the claimed size.                             |

`MANIFEST.json` records each file's SHA-256, packet count, and the exact
`detector@source` pairs and incident count that a replay produces.

## Changing the suite

The generator is deterministic: the same scenario always produces byte-identical
files. The tests fail in three cases:

- a committed file changes;
- the generator no longer produces the committed bytes;
- detection results differ from the manifest.

After an intended change, regenerate the suite and review the manifest diff:

```sh
python scripts/generate_test_pcaps.py
git diff tests/pcaps/MANIFEST.json
```

Larger fixtures for every scenario are available without committing them:

```sh
sentinelx fixtures generate
```
