# Rule engine

SentinelX custom rules are YAML documents. Each rule has a condition written in a small expression language, an observation window, and metadata that decides how a match is reported. Rules run inside the same detection engine as the built-in detectors, see the same per-source features, and produce the same explainable `Detection` objects.

This document is the reference for rule authors and for operators who manage rule sets. For the detectors that ship as code, see [detection-engine.md](detection-engine.md). For what happens after a rule matches, see [risk-scoring.md](risk-scoring.md) and [response-engine.md](response-engine.md).

Code: `packages/sentinelx/signatures/` (`rules.py`, `dsl.py`, `detector.py`, `runner.py`), `packages/sentinelx/services/rules.py`, `packages/sentinelx/api/routes/rules.py`.

## Contents

- [A first rule](#a-first-rule)
- [Rule file format](#rule-file-format)
- [Condition language](#condition-language)
- [Field reference](#field-reference)
- [Durations and the within window](#durations-and-the-within-window)
- [Actions and the preventive-rule safety check](#actions-and-the-preventive-rule-safety-check)
- [How a rule runs](#how-a-rule-runs)
- [Embedded rule tests](#embedded-rule-tests)
- [Workflow](#workflow)
- [Common validation errors](#common-validation-errors)
- [Limits](#limits)

## A first rule

```yaml
rules:
  - name: Telnet Password Guessing
    description: Repeated short-lived Telnet sessions from one source.
    condition: protocol == tcp and destination_port == 23 and short_sessions >= 10
    within: 60s
    severity: high
    category: brute_force
    confidence: 0.85
    action: temporary_block
    duration: 1800
    tags: [telnet, t1110]
    references: [https://attack.mitre.org/techniques/T1110/]
    tests:
      - scenario: ssh_brute_force
        params: {port: 23}
        expect: match
      - scenario: ssh_brute_force
        params: {port: 23, attempts: 5}
        expect: no_match
      - scenario: normal_traffic
        expect: no_match
```

Save it as `rules/telnet.yml`, then check and test it:

```bash
sentinelx rules validate rules/telnet.yml
sentinelx rules test rules/telnet.yml
```

When the rule matches, the detection explains itself:

```text
Threat:     Telnet Password Guessing
Detector:   rule:telnet_password_guessing
Category:   brute_force
Severity:   high  (confidence 85%)
Source:     198.51.100.23
Target:     192.168.10.10
Evidence:
  - short_sessions = 10 in the last 60s (rule requires >= 10)
  - protocol = 'tcp' (rule requires protocol == tcp)
  - destination_port = 23 (rule requires destination_port == 23)
  - matched rule 'Telnet Password Guessing': protocol == tcp and destination_port == 23 and short_sessions >= 10
Recommends: temporary_block
```

The shipped rule files in `rules/` (`authentication.yml`, `dns-and-web.yml`, `network-recon.yml`) are further working examples; all of them validate and pass their embedded tests.

## Rule file format

Rule files are YAML. A file holds either a list under `rules:` or a single mapping under `rule:`:

```yaml
rule:
  name: Internal Host Contacts Test Network
  condition: source_ip in_network ["10.0.0.0/8", "192.168.0.0/16"] and destination_ip in_network "203.0.113.0/24"
  within: 30s
  severity: low
  category: policy_violation
  action: log
```

Files larger than 1 MiB (1,048,576 bytes) are rejected. When a directory is loaded, every `*.yml` and `*.yaml` file beneath it is read, including subdirectories, in sorted order.

### Restricted YAML loader

Rule files and definitions sent to the API are parsed by `load_rule_yaml` in `packages/sentinelx/signatures/rules.py`, a subclass of PyYAML's `SafeLoader` with two further restrictions:

| Restriction | Error | Why |
|---|---|---|
| No anchors (`&name`) or aliases (`*name`) anywhere in the document | `not valid YAML: YAML anchors and aliases are not allowed in rules` | Aliases let a few hundred bytes expand into a very large document once it is copied or echoed back (the "billion laughs" pattern). Before this restriction, a definition of about 400 bytes sent to `POST /rules/validate` produced a response of about 30 MB |
| Nesting at most 32 levels deep | `not valid YAML: YAML nested deeper than 32 levels` | Deep nesting exhausts the parser's recursion. Flow-style brackets (`[` and `{`) are counted before parsing starts, so a line of thousands of `[` is refused without being tokenised, and block nesting is counted while the document is composed |

As with `SafeLoader`, YAML tags that construct Python objects are not supported. Rules need none of these features: repeat a value instead of aliasing it. `sentinelx rules validate` reports the same errors in the form `<file>: not valid YAML (<reason>)`.

### Rule keys

Defined by the `Rule` model in `packages/sentinelx/signatures/rules.py`. Unknown keys are rejected.

| Key | Required | Default | Constraint | Meaning |
|---|---|---|---|---|
| `name` | yes | | 3-120 characters | Display name and title of detections |
| `id` | no | derived from `name` | | Stable identifier. Derived by lowercasing the name, replacing each run of characters other than `a-z` and `0-9` with `_`, trimming `_` from both ends, and truncating to 64 characters. `SSH Brute Force` becomes `ssh_brute_force` |
| `description` | no | `""` | up to 2,000 characters | Used as the detection description |
| `enabled` | no | `true` | boolean | Initial state. For file rules, the stored state wins once the rule has been synced (see [Workflow](#workflow)) |
| `condition` | yes | | 1-2,000 characters; see [Condition language](#condition-language) | When the rule matches |
| `within` | no | `60` seconds | a [duration](#durations-and-the-within-window), no longer than the feature window | Window for counted fields |
| `severity` | no | `medium` | `info`, `low`, `medium`, `high`, `critical` | Detection severity |
| `category` | no | `policy_violation` | `reconnaissance`, `brute_force`, `denial_of_service`, `exfiltration`, `protocol_anomaly`, `policy_violation`, `malicious_reputation`, `anomaly`, `lateral_movement`, `other` | Detection category |
| `confidence` | no | `0.8` | 0.05-0.99 | Detection confidence, fixed per rule |
| `action` | no | `alert` | see [Actions](#actions-and-the-preventive-rule-safety-check) | Recommended action |
| `duration` | no | none | integer 30-86,400 | Block or rate-limit duration in seconds for automatic responses to this rule's detections. Required when `action` is `temporary_block`; see [Actions](#actions-and-the-preventive-rule-safety-check) |
| `tags` | no | `[]` | up to 20 items | Added to detection tags after `rule` |
| `references` | no | `[]` | up to 20 items | Reference URLs |
| `tests` | no | `[]` | up to 50 items | [Embedded tests](#embedded-rule-tests) |

Rule ids must be unique across all loaded files; a duplicate is reported and the second rule is skipped.

### YAML pitfalls

The condition is a YAML string, so YAML's own syntax applies first:

- A condition containing `: ` (colon followed by a space) is not valid as a plain YAML scalar. Wrap the whole condition in single quotes: `condition: 'http_path contains "/a: b" and http_request_count >= 50'`.
- ` #` starts a YAML comment and silently truncates a plain scalar. Quote the whole condition if it contains `#`.
- Long conditions can be written as a folded block, which joins lines with spaces:

  ```yaml
  condition: >-
    protocol == tcp
    and destination_port in [445, 139]
    and unique_dst_ips >= 30
  ```

## Condition language

Code: `packages/sentinelx/signatures/dsl.py`.

A condition is a boolean expression of comparisons, combined with `and`, `or`, `not` and parentheses:

```text
protocol == tcp and destination_port in [22, 2222] and short_sessions >= 20
handshake_complete == false and (syn_ratio > 0.9 or refusal_ratio > 0.8)
dns_query_name endswith ".example.test" and dns_query_count > 100
source_ip in_network "203.0.113.0/24"
```

The language is parsed by a hand-written tokenizer and recursive-descent parser. There is no `eval`, and the grammar has no function calls, attribute access, arithmetic or regular expressions, so a rule cannot run code and cannot trigger catastrophic regex backtracking. Rules are operator input that can end up driving a firewall; the grammar is deliberately no more powerful than that requires.

### Lexical rules

| Token | Pattern | Examples |
|---|---|---|
| whitespace | spaces, tabs, newlines | ignored between tokens |
| comparison operator | `==` `!=` `>=` `<=` `>` `<` | |
| NUMBER | an optional `-`, digits, optionally `.` and more digits | `22`, `-1`, `0.9` |
| STRING | text in `"double"` or `'single'` quotes; a backslash escapes the next character | `"/admin"`, `'say \'hi\''` |
| WORD | a letter or `_`, then letters, digits, `_`, `.`, `:`, `/`, `-` | `protocol`, `tcp`, `fd00::/8`, `a.example` |
| punctuation | `(` `)` `[` `]` `,` | |

Anything else is a syntax error (`unexpected character`). There is no single `=`.

Keywords (`and`, `or`, `not`, `in`, `contains`, `startswith`, `endswith`, `in_network`, `true`, `false`) and field names are case-insensitive.

Because a WORD must start with a letter or underscore, and a NUMBER cannot contain a second dot, **IPv4 addresses and networks must be quoted**: `source_ip == "10.0.0.1"`, `source_ip in_network "10.0.0.0/8"`. IPv6 networks that begin with a letter, such as `fd00::/8`, happen to tokenize as a WORD, but quoting every address is clearer. Values containing spaces, `/` at the start, or other characters outside the WORD set must also be quoted.

### Grammar

Derived from `_Parser` in `dsl.py`, in EBNF:

```ebnf
condition   = or_expr ;
or_expr     = and_expr , { "or" , and_expr } ;
and_expr    = not_expr , { "and" , not_expr } ;
not_expr    = "not" , not_expr
            | primary ;
primary     = "(" , or_expr , ")"
            | comparison ;
comparison  = field , operator , value ;
field       = WORD ;                      (* any WORD except and, or, not, in;
                                             must name a registered field *)
operator    = "==" | "!=" | ">" | ">=" | "<" | "<="
            | "in" | "not" , "in"
            | "contains" | "startswith" | "endswith"
            | "in_network" ;
value       = scalar | list ;
list        = "[" , scalar , { "," , scalar } , "]" ;
scalar      = NUMBER | STRING | WORD ;     (* the WORDs true and false are booleans *)
```

Consequences of the grammar:

- **Precedence**, from tightest to loosest: comparison, `not`, `and`, `or`. `a or b and c` means `a or (b and c)`; `not a and b` means `(not a) and b`. Use parentheses when in doubt.
- `and` and `or` are n-ary and left to right.
- A comparison is always `field operator value`. A value cannot be on the left, and two fields cannot be compared with each other.
- **A boolean field cannot be used on its own.** `handshake_complete and syn_count > 5` is a syntax error; write `handshake_complete == true`.
- Lists cannot be empty, cannot be nested, and cannot have a trailing comma.
- `not` binds to the following `not_expr`: `not destination_port in [22]` is `not (destination_port in [22])`, which is equivalent to `destination_port not in [22]` except for missing values (see [Evaluation semantics](#evaluation-semantics)).

### Parser bounds

A hostile or accidental rule cannot make parsing or evaluation expensive:

| Limit | Value | Error |
|---|---|---|
| `MAX_CONDITION_LENGTH` | 2,000 characters | `condition exceeds 2000 characters` |
| `MAX_TOKENS` | 400 tokens | `condition exceeds 400 tokens` |
| `MAX_DEPTH` | 16 levels; each `not` and each pair of parentheses adds one level (`and` and `or` chains do not) | `condition nests deeper than 16 levels` |
| `MAX_LIST_ITEMS` | 128 items per list | `list exceeds 128 items` |

Most syntax errors report the character offset where the problem was found, for example `missing ')' (at character 34)`. A condition longer than 2,000 characters in a rule file is rejected earlier, by the rule model, with `condition: String should have at most 2000 characters`.

### Operators and field kinds

Every field has a kind. After parsing, each comparison is type-checked against the field registry, and every problem in the rule is reported at once.

| Operator | `count` | `number` | `string` | `boolean` | `address` | Value |
|---|---|---|---|---|---|---|
| `==`, `!=` | yes | yes | yes | yes | yes | number for count and number fields; `true` or `false` for boolean fields |
| `>`, `>=`, `<`, `<=` | yes | yes | no | no | no | number |
| `in`, `not in` | yes | yes | yes | yes | yes | list |
| `contains`, `startswith`, `endswith` | no | no | yes | no | no | STRING or WORD |
| `in_network` | no | no | no | no | yes | one network, or a list of networks, each a valid IPv4 or IPv6 network |

The type checker does not inspect list item types, and does not reject a number compared with a string field (`protocol == 5` validates but can never match).

### Evaluation semantics

- **Short-circuit.** `and` stops at the first false operand and `or` at the first true one, left to right. Fields are resolved lazily and cached per packet, so put cheap packet fields (`protocol`, `destination_port`) before windowed counts.
- **Missing values never match.** A field with no value for the current packet, such as `dns_query_name` on a TCP packet or `ttl` on ARP, makes every comparison on it false, including `!=` and `not in`. "Unknown" is not evidence. Note that `not` inverts that false: `not dns_query_name == "x.example"` is true for every non-DNS packet.
- **Text comparisons are case-insensitive.** `==`, `!=`, `in`, `not in`, `contains`, `startswith` and `endswith` lowercase both sides when they are strings, so `protocol == TCP` and `protocol == tcp` are equivalent.
- **Numeric comparisons** convert both sides to float. A value that cannot be converted makes the comparison false.
- **Evidence.** Every comparison that held on the path that made the rule match becomes an evidence item with the observed value and the rule's requirement. Comparisons under `not` are not recorded, since they describe something that was not true. Count-field evidence is weighted 1.0 and sorted first; other evidence is weighted 0.5. A final `rule` evidence item quotes the rule name and condition.

## Field reference

This table is generated from the `FIELDS` registry in `dsl.py` and matches the output of `sentinelx rules fields` and `GET /api/v1/rules/fields`. The last column describes how `packages/sentinelx/signatures/detector.py` resolves each field.

All behaviour fields describe the **packet's sender**: the source profile used is always that of `source_ip`.

### Packet fields

| Field | Kind | Description | Resolved from |
|---|---|---|---|
| `protocol` | string | tcp, udp, icmp, icmpv6, arp | current packet (lowercase value) |
| `source_ip` | address | sender address | current packet |
| `destination_ip` | address | receiver address | current packet |
| `source_port` | number | sender port | current packet; no value for portless protocols |
| `destination_port` | number | receiver port | current packet; no value for portless protocols |
| `packet_length` | number | frame length in bytes | current packet |
| `payload_length` | number | bytes above the transport header | current packet |
| `ttl` | number | IP TTL / hop limit | current packet |
| `direction` | string | inbound, outbound, internal, external, unknown | current packet, labelled using `CAPTURE__HOME_NETWORKS` |
| `tcp_flags` | string | flag label such as S, SA, FPU | current TCP packet; letters in the order `F S R P A U E C`, `.` when no flag is set |

### Flow fields

| Field | Kind | Description | Resolved from |
|---|---|---|---|
| `handshake_complete` | boolean | the TCP three-way handshake completed | the conversation's flow state (SYN, SYN-ACK and ACK all seen) |
| `flow_duration` | number | seconds since the flow's first packet | flow state |
| `flow_packets` | number | packets in this flow | flow state, both directions |

### Source behaviour fields

Count fields are counted over the rule's `within` window, ending at the current packet.

| Field | Kind | Description | Resolved from |
|---|---|---|---|
| `packet_count` | count | packets sent by the source | all packets in `within` |
| `syn_count` | count | bare SYNs sent | TCP packets with SYN and none of ACK, RST, FIN |
| `connection_attempts` | count | new TCP connections started | bare SYNs |
| `failed_attempts` | count | connection attempts refused with RST | RSTs received by the source |
| `short_sessions` | count | completed sessions torn down within seconds (auth failures) | flows the source initiated that completed a handshake and were closed with FIN or RST in under 5 seconds |
| `rst_count` | count | RSTs received | RSTs received by the source |
| `icmp_count` | count | ICMP packets sent | ICMP and ICMPv6 packets |
| `dns_query_count` | count | DNS queries sent | decoded DNS queries with a name |
| `http_request_count` | count | HTTP requests sent | decoded HTTP requests |
| `unique_dst_ports` | count | distinct TCP destination ports | distinct values in `within` |
| `unique_dst_ips` | count | distinct destination hosts | distinct values in `within` |
| `unique_udp_ports` | count | distinct UDP destination ports | distinct values; history is limited to `port_scan_window_seconds` (15 s by default) regardless of `within`, and packets from a port below 1024 to a port at or above 1024 are not counted |
| `dns_unique_domains` | count | distinct names queried | distinct query names in `within` |
| `syn_ratio` | number | fraction of the source's packets that are bare SYNs | `syn_count / packet_count` over `within`; 0.0 with no packets |
| `syn_ack_ratio` | number | SYN-ACKs received per SYN sent | over `within`; 0.0 with no SYNs |
| `refusal_ratio` | number | fraction of attempts refused | computed over the full feature window, not `within` |
| `packet_rate` | number | packets per second | `packet_count / within` (the nominal window, not the observed span) |

### Application fields

These have a value only when the corresponding decoder recognised the packet. The DNS decoder runs on ports 53, 5353 and 5355; the HTTP decoder on TCP ports 80, 8080, 8000, 8008, 8888 and 3000; the TLS decoder on TCP ports 443, 8443, 993, 995, 465, 587, 636, 989, 990 and 5061.

| Field | Kind | Description | Notes |
|---|---|---|---|
| `dns_query_name` | string | queried name | first question |
| `dns_query_type` | string | A, AAAA, TXT, ... | first question |
| `dns_is_nxdomain` | boolean | response code NXDOMAIN | only ever true on responses, so the matching source is the resolver, not the client |
| `dns_label_length` | number | longest label in the name | across all questions |
| `dns_name_entropy` | number | Shannon entropy of the leftmost label | bits per character |
| `http_method` | string | request method | |
| `http_path` | string | request path | |
| `http_host` | string | Host header | |
| `http_user_agent` | string | User-Agent header | |
| `tls_sni` | string | TLS server name indication | |
| `tls_version` | string | negotiated or offered TLS version | |
| `tls_is_legacy_version` | boolean | SSLv3, TLS 1.0 or TLS 1.1 | |

Encrypted payloads are not decoded: HTTP fields are empty for HTTPS, and DNS fields are empty for DNS over HTTPS or TLS.

## Durations and the within window

`within` accepts:

- a number of seconds: `60`, `2.5`;
- a string matching `<number><unit>`, with optional spaces, where unit is `ms`, `s`, `m` or `h` (case-insensitive) or absent (seconds): `500ms`, `30s`, `5m`, `1h`.

The value must be positive. Anything else, such as `10 minutes`, fails with `invalid duration '10 minutes'; use e.g. 30s, 5m or 1h`.

**The upper bound.** Counted features are only retained for the feature window, which is the longest of the six detection window settings (`DETECTION__PORT_SCAN_WINDOW_SECONDS`, `DETECTION__BRUTE_FORCE_WINDOW_SECONDS`, `DETECTION__CONNECTION_RATE_WINDOW_SECONDS`, `DETECTION__ICMP_FLOOD_WINDOW_SECONDS`, `DETECTION__DNS_WINDOW_SECONDS`, `DETECTION__HTTP_FLOOD_WINDOW_SECONDS`). With defaults that is 60 seconds. A rule whose `within` is longer could never see that much history and would silently under-count, so it is rejected:

```text
within 300s exceeds the 60s of history the feature engine keeps; shorten it or raise the detection window settings
```

Raising one of the window settings raises the limit, at the cost of more state per source (see [detection-engine.md](detection-engine.md#windows)). Validation uses the settings of the process doing the validation, so a rule that validates on a workstation with longer windows can fail on a sensor with the defaults.

`within` applies to count fields, `syn_ratio`, `syn_ack_ratio` and `packet_rate`. Packet, flow and application fields describe the current packet and are not windowed. The exceptions noted in the field reference (`unique_udp_ports`, `refusal_ratio`) apply.

The `duration` key is a plain integer number of seconds, not a duration string.

## Actions and the preventive-rule safety check

| Action | Preventive | Meaning |
|---|---|---|
| `alert` | no | Record and surface the detection (default) |
| `log` | no | Informational |
| `webhook` | no | Recommend a webhook notification |
| `none` | no | No recommendation |
| `rate_limit` | yes | Recommend rate limiting the source |
| `temporary_block` | yes | Recommend blocking the source for a period; requires `duration` |
| `block_ip` | yes | Recommend blocking the source |
| `quarantine` | yes | Recommend quarantining the source |
| `unblock_ip` | | Rejected: `rules may not unblock addresses` |

A rule's action is a recommendation carried on the detection as `recommended_action`. Whether anything changes on the network depends on the risk score, `RESPONSE_MODE`, `DRY_RUN`, the response allowlist and the safety guard, all described in [response-engine.md](response-engine.md). With the default `RESPONSE_MODE=detect_only` and `DRY_RUN=true`, no rule ever modifies traffic.

The rule's `duration` travels with each detection as `recommended_duration_seconds` (in WebSocket payloads and replay reports; it is not a column of stored detections). When the response engine acts automatically on a rule detection whose action is `temporary_block` or `rate_limit`, it uses that duration, capped at `RESPONSE__MAX_BLOCK_SECONDS` (default 86,400). A rule without `duration` falls back to `RESPONSE__DEFAULT_BLOCK_SECONDS` (default 900). In `manual_approval` mode the pending action carries the same duration. `duration` has no effect on `block_ip` or `quarantine`, which are not time-limited, and it does not apply to the temporary blocks the engine issues for a high-risk incident, which always use `RESPONSE__DEFAULT_BLOCK_SECONDS`.

### The safety check

A condition like `protocol == tcp` with `action: block_ip` would recommend blocking every TCP speaker on the network. To prevent that class of mistake, `validate_rule` requires every preventive rule to be **selective**: every way of satisfying the condition must pass a count threshold.

A condition is selective when:

| Node | Selective when |
|---|---|
| comparison | the field's kind is `count`, the operator is `>` or `>=`, and the value is a number of at least 2 |
| `a and b and ...` | at least one operand is selective |
| `a or b or ...` | every operand is selective |
| `not ...` | never |

Examples:

| Condition | Selective | Why |
|---|---|---|
| `protocol == tcp and destination_port == 22 and short_sessions >= 20` | yes | one conjunct is a count threshold |
| `protocol == tcp and (unique_dst_ports >= 100 or unique_dst_ips >= 50)` | yes | both `or` branches are thresholds |
| `short_sessions >= 20 or destination_port == 23` | no | the second branch alone can match |
| `syn_count >= 1` | no | the value must be at least 2 |
| `syn_ratio > 0.9` | no | `syn_ratio` is a number, not a count |
| `syn_count == 50` | no | only `>` and `>=` qualify |
| `not short_sessions < 20` | no | negations are never trusted, even when logically equivalent to a threshold |

A failing preventive rule is rejected with:

```text
action 'block_ip' requires the condition to include a count threshold (e.g. 'short_sessions >= 20') on every branch; without one this rule could block every source matching 'protocol == tcp and destination_port == 22'
```

The check is a floor, not a guarantee of precision. `packet_count >= 2` passes it and matches almost every active host. Choose thresholds from observed traffic, and prefer `alert` until a rule has been tested against real captures.

## How a rule runs

Each enabled rule becomes one `RuleDetector` named `rule:<id>` in the detection engine. For every packet:

1. The condition is evaluated against a field resolver for that packet, with counts narrowed to `within`.
2. If it matches, a `Detection` is built with the rule's `name` as title, `description` (or a generic sentence), `severity`, `category`, `confidence` and `action`, `rule_name` set to the rule name, `observation_window_seconds` set to `within`, `packet_count` set to the source's packets in `within`, tags `rule` plus the rule's tags, and the evidence described in [Evaluation semantics](#evaluation-semantics).
3. The engine applies its usual policy: evidence check, `DETECTION__ALLOWLIST_NETWORKS`, and the per-`(rule:<id>, source)` cooldown with escalation. A rule whose condition stays true is therefore reported once per cooldown period per source, not once per packet. See [detection-engine.md](detection-engine.md#the-detection-engine).

Rules run after the built-in detectors, and they are attached whatever `DETECTION_MODE` is set to, including `disabled`.

The detection's `source_ip` is always the packet's sender. Write conditions from the point of view of the host whose behaviour you are counting: `destination_port == 22 and short_sessions >= 20` matches on packets the client sends to the SSH server.

## Embedded rule tests

Code: `packages/sentinelx/signatures/runner.py`, scenarios in `packages/sentinelx/testing/scenarios.py`.

Each rule can carry positive and negative expectations:

```yaml
tests:
  - scenario: ssh_brute_force
    params: {port: 23}
    expect: match
  - scenario: normal_traffic
    expect: no_match
```

| Key | Required | Meaning |
|---|---|---|
| `scenario` | yes | Name of a synthetic scenario |
| `expect` | yes | `match` or `no_match` |
| `params` | no | Keyword arguments passed to the scenario builder. Validated with the rule (see [Scenario parameters](#scenario-parameters)) |

Test scenarios and their parameters are checked when the rule is validated, not only when tests run. An unknown scenario name, an unknown parameter, a wrong type or an out-of-range value makes the rule invalid, so `sentinelx rules validate`, `POST /rules/validate`, rule creation and the loading of rule files all report it, for example `tests[2]: unknown scenario 'nope'; available: ...` or `tests[1]: ports: must be between 1 and 50000` (tests are numbered from 1).

For each test, the runner builds the scenario's frames and runs them through the real decoder, a fresh feature extractor and a detection engine containing only this rule, with the rule forced to enabled and the cooldown set to 0. The actual result is `match` when the rule produced at least one detection. Because the cooldown is disabled, detection counts in test output include every matching packet (the Telnet example produces 150 detections against its positive scenario).

Tests use the detection settings of the process running them, so window settings, and therefore the `within` limit, come from the environment.

### Scenarios

| Scenario | Parameters (defaults) |
|---|---|
| `normal_traffic` | `seed` (7), `packet_count` (600) |
| `tcp_port_scan` | `attacker`, `target`, `ports` (220), `seed` |
| `horizontal_scan` | `attacker`, `port` (445), `hosts` (120), `seed` |
| `udp_scan` | `attacker`, `target`, `ports` (150), `seed` |
| `ssh_brute_force` | `attacker`, `target`, `attempts` (60), `seed`, `port` (22) |
| `syn_flood` | `target`, `count` (3000), `sources` (1), `seed` |
| `icmp_flood` | `attacker`, `target`, `count` (1200), `seed` |
| `http_flood` | `attacker`, `target`, `count` (900), `seed` |
| `dns_tunneling` | `client`, `resolver`, `count` (400), `seed` |
| `dns_flood` | `client`, `resolver`, `count` (900), `seed` |
| `mixed_intrusion` | `seed` |
| `dns_rate_spike` | `baseline_seconds` (180), `spike_seconds` (20), `normal_qps` (20), `spike_qps` (300), `seed` |
| `slow_port_scan` | `attacker`, `target`, `ports` (60), `interval` (1.2), `seed` |
| `low_rate_brute_force` | `attacker`, `target`, `attempts` (30), `interval` (8.0), `seed` |

`sentinelx fixtures list` describes each scenario, and `GET /api/v1/rules/fields` returns the scenario names. Every scenario is deterministic for a given set of parameters, including `seed`.

### Scenario parameters

`validate_scenario_params` in `scenarios.py` applies these bounds, both to embedded tests and to fixtures generated through the API:

| Parameter | Accepted values |
|---|---|
| any name the scenario does not accept | refused, listing the accepted names |
| any boolean value | refused |
| `seed` | integer, 0 to 2^32 |
| `port` | integer, 1 to 65,535 |
| `packet_count`, `count`, `hosts`, `attempts`, `ports`, `sources` | integer, 1 to 50,000 |
| `normal_qps`, `spike_qps` | integer, 0 to 50,000 |
| `baseline_seconds`, `spike_seconds` | integer, 0 to 3,600 |
| `interval` | number, 0.001 to 600 |
| `attacker`, `target`, `client`, `resolver` | an IPv4 or IPv6 address |
| `dns_rate_spike` | refused as a whole when the parameters would generate more than 2,000,000 packets |

### Writing good tests

- Include at least one `match` and one `no_match`. `normal_traffic` is the standard negative.
- Add a near-miss negative that shares the surface of the attack but stays under your threshold, as the shipped rules do: `ssh_brute_force` with `attempts: 10` against a threshold of 20, or `tcp_port_scan` with `ports: 30` against a threshold of 50.
- Scenario names and parameters are checked by validation, so a misspelled scenario or parameter is reported as a validation problem and `sentinelx rules test` exits with status 1 without running the tests. An unknown name passed to the `--scenario` option of `sentinelx rules test` exits with status 2 and lists the available scenarios.
- A rule with no tests is reported as `<id> has no embedded tests` by `sentinelx rules test` but does not fail the command.

## Workflow

### File rules and API rules

Rules have one of two origins, stored together in the database:

| | File rules | API rules |
|---|---|---|
| Where defined | YAML under `RULES_DIRECTORY` (default `rules`) | Created in the dashboard or through the API |
| Version control | yes | no; they live in the database |
| Change the definition | edit the file | `PUT /api/v1/rules/{rule_id}` or the dashboard editor |
| Delete | remove it from the file | `DELETE /api/v1/rules/{rule_id}` or the dashboard |
| Enable or disable | CLI, API or dashboard | CLI, API or dashboard |

At server start, file rules are synced into the database. A new file rule takes its `enabled` value from the file; an existing one keeps its stored enabled state, so a rule disabled from the dashboard stays disabled across restarts. File rules whose file no longer defines them are removed. A file rule whose id is already used by an API rule is skipped and listed as a load problem. Invalid file rules are skipped and reported; valid rules in the same file still load.

Every stored definition is re-validated whenever it is loaded.

### CLI

All commands below exist as shown in `sentinelx rules --help`.

| Command | What it does |
|---|---|
| `sentinelx rules list [--json]` | Rules known to the platform, with state and origin (ID, name, enabled, severity, action, within, origin, condition). Opens the database and syncs file rules first. Invalid rules are printed as `invalid rule skipped:` |
| `sentinelx rules validate [PATHS]... [--json]` | Validate rule files or directories without loading them into the platform. Defaults to `RULES_DIRECTORY`. Prints `valid <id>` or `invalid <problem>` and exits 1 if there is any problem, for CI |
| `sentinelx rules test PATH [--pcap FILE] [--scenario TEXT] [--json]` | For each rule in one file: run its embedded tests (default), or run it against a capture (`--pcap`) or one scenario with default parameters (`--scenario`). Exits 1 if the file has validation problems or an embedded test fails, and 2 for an unknown `--scenario` name |
| `sentinelx rules enable RULE_ID` | Enable a rule in the database. A running server picks this up on restart |
| `sentinelx rules disable RULE_ID` | Disable a rule in the database. A running server picks this up on restart |
| `sentinelx rules fields` | Print the field reference table |

With `--pcap` or `--scenario`, `rules test` reports per rule the packet count, whether it matched, the number of detections and the matching sources, and does not fail on a lack of matches.

A typical CI step:

```bash
sentinelx rules validate rules/
sentinelx rules test rules/authentication.yml
sentinelx rules test rules/dns-and-web.yml
sentinelx rules test rules/network-recon.yml
```

### API

All paths are under `/api/v1`. Changes made through the API are applied to the running engine immediately, written to the audit log, and published as a `RULE_CHANGED` event. Full request and response details are in [api.md](api.md).

| Method and path | Role | Purpose |
|---|---|---|
| `GET /rules` | viewer | All rules with parsed metadata, live detector stats, and `load_problems` |
| `GET /rules/fields` | viewer | Field registry, operator list and scenario names |
| `GET /rules/{rule_id}` | viewer | One rule |
| `POST /rules/validate` | analyst | Validate a definition. Body `{"definition": "<yaml>"}`. Returns `{"valid", "problems", "rule"}` and never fails on an invalid rule |
| `POST /rules/test` | analyst | Run a definition without saving it. Body `{"definition", "scenario"?, "pcap_path"?}`: with `pcap_path` (relative to `PCAP_DIRECTORY`) it runs against that capture, with `scenario` against that scenario, otherwise its embedded tests |
| `POST /rules` | admin | Create an API rule. Returns 201 |
| `PUT /rules/{rule_id}` | admin | Replace an API rule's definition. The new definition must produce the same id |
| `PATCH /rules/{rule_id}/enabled` | admin | Body `{"enabled": true or false}` |
| `DELETE /rules/{rule_id}` | admin | Delete an API rule. Returns 204 |

Roles are hierarchical: admin can do everything analyst can, analyst everything viewer can.

Definitions sent to the API must be 10-20,000 characters and contain exactly one rule, under `rule:` or as a one-item `rules:` list. An invalid definition on create, update or test returns HTTP 422:

```json
{"detail": "rule is invalid", "problems": ["..."]}
```

The same 422 shape is returned when updating a file rule (`'<id>' is defined in <path>; edit the file instead`), when deleting one (`'<id>' is defined in <path>; delete it there or disable it`), when renaming an API rule through `PUT` (`renaming a rule changes its id; create a new rule instead`), and when creating a rule whose id already exists. An unknown rule id returns 404.

### Dashboard

The Rules page lists every rule with its severity, action, window, condition, hit count, origin and an enable switch. Selecting a rule opens the editor:

- The editor validates the YAML as you type, by calling `POST /rules/validate` shortly after typing stops, and lists every problem.
- **Test against** offers the rule's embedded tests, any scenario, or any capture in `PCAP_DIRECTORY`; **Run test** calls `POST /rules/test` without saving.
- Admins can create API rules (**Create and apply**) and edit them (**Save and apply**); both buttons stay disabled until the rule is valid. Admins can delete API rules.
- File rules open read-only, with a note naming the file. You can still edit the text in the editor and test changes, but saving must be done in the file.
- Analysts can write and test rules but cannot save, enable, disable or delete them. Viewers can see rules.

## Common validation errors

The messages below are the exact problem texts, shown without the `<file> rule '<name>':` prefix that `rules validate` adds.

| Message | Cause | Fix |
|---|---|---|
| `condition: unknown field 'dest_port' in 'dest_port == 22'; did you mean destination_ip, destination_port?` | Field name not in the registry | Use a name from `sentinelx rules fields` |
| `condition: unexpected character '.' (at character 25)` | Unquoted IPv4 address or network, or a number with two dots | Quote the value: `source_ip in_network "10.0.0.0/8"` |
| `condition: unexpected character '/' (at character 19)` | Unquoted value starting with `/` | Quote it: `http_path contains "/admin"` |
| `condition: unexpected character '=' (at character 4)` | Single `=` | Use `==` |
| `condition: boolean field 'handshake_complete' needs an explicit comparison: ...` | Boolean field used on its own | Write `handshake_complete == true` or `== false` |
| `condition: 'handshake_complete == yes': handshake_complete is boolean; compare with true or false` | Boolean compared with something else | Use `true` or `false` |
| `condition: 'destination_port in 22': 'in' needs a list, e.g. [22, 2222]` | `in` or `not in` without brackets | `destination_port in [22]` |
| `condition: 'protocol > 5': '>' needs a numeric field, but protocol is string` | Ordering operator on a non-numeric field | Use `==`, `in` or a text operator |
| `condition: 'syn_count contains a': 'contains' needs a text field, but syn_count is count` | Text operator on a non-string field | Use a numeric operator |
| `condition: 'destination_port == 22': destination_port is numeric; compare with a number` | Number field compared with a quoted string (`"22"`) | Remove the quotes |
| `condition: 'source_ip in_network 10.0.0.300/8': '10.0.0.300/8' is not a valid network` | Malformed network | Correct the address or prefix |
| `condition: missing ')' (at character 34)` | Unbalanced parentheses | Close every `(` |
| `condition: empty list (at character 20)` | `[]` | Give at least one item |
| `condition: expected a field name, found 'end of condition' (at character 12)` | Condition ends with `and`, `or` or `not` | Complete or remove the trailing operator |
| `condition: unexpected 'ttl'; expected 'and', 'or' or end (at character 8)` | Two comparisons without `and` or `or` | Join them with `and` or `or` |
| `condition: condition nests deeper than 16 levels (at character N)`, `condition: list exceeds 128 items (at character N)`, `condition: condition exceeds 400 tokens`, `condition: String should have at most 2000 characters` | A parser or model bound was hit | Simplify the condition, or split it into several rules |
| `within 300s exceeds the 60s of history the feature engine keeps; ...` | `within` longer than the feature window | Shorten `within`, or raise a detection window setting |
| `tests[1]: unknown scenario 'nope'; available: ...` | Misspelled scenario in an embedded test | Use a name from `sentinelx fixtures list` |
| `tests[1]: scenario 'tcp_port_scan' has no parameter(s) bogus; accepted: attacker, target, ports, seed` | Unknown scenario parameter | Use one of the accepted names |
| `tests[1]: ports: must be between 1 and 50000` | Scenario parameter out of range (likewise `expected an integer`, `must be an IP address`, `booleans are not accepted`) | See [Scenario parameters](#scenario-parameters) |
| `within: Value error, invalid duration '10 minutes'; use e.g. 30s, 5m or 1h` | Unsupported duration format | Use `600s` or `10m` |
| `action 'block_ip' requires the condition to include a count threshold ... on every branch; ...` | Preventive action without a selective condition | Add a `count >= N` (N at least 2) to every `or` branch, remove the negation, or use `action: alert` |
| `action 'temporary_block' requires 'duration' (seconds)` | `temporary_block` without `duration` | Add `duration: 900` (30-86,400) |
| `action: Value error, rules may not unblock addresses` | `action: unblock_ip` | Unblock through the response workflow instead ([response-engine.md](response-engine.md)) |
| `severity: Input should be 'info', 'low', 'medium', 'high' or 'critical'` | Invalid enum value (likewise for `category` and `action`) | Use a listed value |
| `threshold: Extra inputs are not permitted` | Unknown key in the rule | Remove it; see [Rule keys](#rule-keys) |
| `not valid YAML (mapping values are not allowed here ...)` | A `: ` inside an unquoted condition | Quote the whole condition |
| `not valid YAML (YAML anchors and aliases are not allowed in rules)` | `&anchor` or `*alias` in the file | Repeat the value instead |
| `not valid YAML (YAML nested deeper than 32 levels)` | More than 32 levels of nesting | Flatten the document |
| `expected a top-level 'rules:' list or 'rule:' mapping` | File has neither key | Put rules under `rules:` or a single rule under `rule:` |
| `rule id '<id>' duplicates one in <file>` | Two rules with the same id, usually the same name | Rename one, or set a distinct `id` |

## Limits

- **Rules see features, not payloads.** There is no byte or regular-expression matching on packet payloads. The application fields cover a few decoded DNS, HTTP and TLS attributes on the ports listed above.
- **Counts are per source address and bounded by the feature window.** A rule cannot look back further than the longest detection window (60 seconds by default) and cannot aggregate across sources, so slow and distributed activity escapes rules for the same reasons it escapes the built-in detectors ([detection-engine.md](detection-engine.md#limits)).
- **A few fields ignore `within`.** `unique_udp_ports` is limited to `port_scan_window_seconds`, and `refusal_ratio` always covers the feature window.
- **No cross-rule logic.** A rule cannot reference another rule or a previous detection. Multi-stage activity is grouped by the correlation engine after detection.
- **Confidence is static.** A rule's confidence does not grow with how far past its threshold the traffic is, unlike the built-in detectors, so repeat reports within the cooldown only escalate if severity or confidence change, which for a rule they do not.
- **The safety check catches unbounded preventive rules, not imprecise ones.** A rule can pass it and still match legitimate traffic.
- **`duration` applies to rule detections only.** Incident-level automatic blocks use `RESPONSE__DEFAULT_BLOCK_SECONDS`, and every duration is capped at `RESPONSE__MAX_BLOCK_SECONDS`.
- **Test scenarios are synthetic.** Passing embedded tests shows a rule behaves as intended on generated traffic. Test against captures from your own network with `sentinelx rules test <file> --pcap <capture>` before relying on it; see [pcap-lab.md](pcap-lab.md).
- **CLI enable and disable** change the database only; a running server applies them on restart. Use the API or dashboard to change a running server.
