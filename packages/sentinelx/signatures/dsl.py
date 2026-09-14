"""The rule condition language.

A small, deliberately limited expression language::

    protocol == TCP and destination_port in [22, 2222] and short_sessions >= 20
    not handshake_complete and (syn_ratio > 0.9 or refusal_ratio > 0.8)
    dns_query_name endswith ".example.test" and dns_query_count > 100
    source_ip in_network "203.0.113.0/24"

Why a hand-written parser rather than ``eval`` or a general expression library:
rules are operator input that ends up deciding whether to modify a firewall.  The
only safe amount of expressive power is the amount the grammar below grants - no
function calls, no attribute access, no arithmetic, no regular expressions (and
so no ReDoS) - and a parser we control is the only way to guarantee that.

Grammar::

    expression := or_expr
    or_expr    := and_expr ("or" and_expr)*
    and_expr   := not_expr ("and" not_expr)*
    not_expr   := "not" not_expr | primary
    primary    := "(" expression ")" | comparison
    comparison := FIELD operator value
    operator   := == | != | > | >= | < | <= | in | not in
                | contains | startswith | endswith | in_network
    value      := NUMBER | STRING | WORD | "true" | "false" | list
    list       := "[" value ("," value)* "]"

Parsing is bounded (length, token count, nesting depth, list size) so a hostile
rule cannot make the parser or evaluator expensive.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from sentinelx.common.netutils import IPNetworkT, parse_ip, parse_network

__all__ = [
    "FIELDS",
    "And",
    "Comparison",
    "ConditionSyntaxError",
    "FieldKind",
    "FieldSpec",
    "Node",
    "Not",
    "Or",
    "comparisons",
    "evaluate",
    "parse_condition",
    "validate_semantics",
]

MAX_CONDITION_LENGTH: Final = 2000
MAX_TOKENS: Final = 400
MAX_DEPTH: Final = 16
MAX_LIST_ITEMS: Final = 256


class ConditionSyntaxError(ValueError):
    """A condition could not be parsed. ``position`` is a character offset."""

    def __init__(self, message: str, position: int | None = None) -> None:
        super().__init__(message if position is None else f"{message} (at character {position})")
        self.position = position


class FieldKind(StrEnum):
    COUNT = "count"
    """Windowed event counts. Thresholds on these are what make a rule selective."""
    NUMBER = "number"
    STRING = "string"
    BOOLEAN = "boolean"
    ADDRESS = "address"


@dataclass(frozen=True, slots=True)
class FieldSpec:
    name: str
    kind: FieldKind
    description: str


def _f(name: str, kind: FieldKind, description: str) -> FieldSpec:
    return FieldSpec(name, kind, description)


K = FieldKind

#: Every field a rule may reference. Anything else is rejected by the validator,
#: so a typo is a load-time error rather than a rule that silently never matches.
FIELDS: Final[dict[str, FieldSpec]] = {
    spec.name: spec
    for spec in (
        # packet
        _f("protocol", K.STRING, "tcp, udp, icmp, icmpv6, arp"),
        _f("source_ip", K.ADDRESS, "sender address"),
        _f("destination_ip", K.ADDRESS, "receiver address"),
        _f("source_port", K.NUMBER, "sender port"),
        _f("destination_port", K.NUMBER, "receiver port"),
        _f("packet_length", K.NUMBER, "frame length in bytes"),
        _f("payload_length", K.NUMBER, "bytes above the transport header"),
        _f("ttl", K.NUMBER, "IP TTL / hop limit"),
        _f("direction", K.STRING, "inbound, outbound, internal, external, unknown"),
        _f("tcp_flags", K.STRING, "flag label such as S, SA, FPU"),
        # flow
        _f("handshake_complete", K.BOOLEAN, "the TCP three-way handshake completed"),
        _f("flow_duration", K.NUMBER, "seconds since the flow's first packet"),
        _f("flow_packets", K.NUMBER, "packets in this flow"),
        # source behaviour, counted over the rule's `within` window
        _f("packet_count", K.COUNT, "packets sent by the source"),
        _f("syn_count", K.COUNT, "bare SYNs sent"),
        _f("connection_attempts", K.COUNT, "new TCP connections started"),
        _f("failed_attempts", K.COUNT, "connection attempts refused with RST"),
        _f("short_sessions", K.COUNT, "completed sessions torn down within seconds (auth failures)"),
        _f("rst_count", K.COUNT, "RSTs received"),
        _f("icmp_count", K.COUNT, "ICMP packets sent"),
        _f("dns_query_count", K.COUNT, "DNS queries sent"),
        _f("http_request_count", K.COUNT, "HTTP requests sent"),
        _f("unique_dst_ports", K.COUNT, "distinct TCP destination ports"),
        _f("unique_dst_ips", K.COUNT, "distinct destination hosts"),
        _f("unique_udp_ports", K.COUNT, "distinct UDP destination ports"),
        _f("dns_unique_domains", K.COUNT, "distinct names queried"),
        _f("syn_ratio", K.NUMBER, "fraction of the source's packets that are bare SYNs"),
        _f("syn_ack_ratio", K.NUMBER, "SYN-ACKs received per SYN sent"),
        _f("refusal_ratio", K.NUMBER, "fraction of attempts refused"),
        _f("packet_rate", K.NUMBER, "packets per second"),
        # application metadata
        _f("dns_query_name", K.STRING, "queried name"),
        _f("dns_query_type", K.STRING, "A, AAAA, TXT, ..."),
        _f("dns_is_nxdomain", K.BOOLEAN, "response code NXDOMAIN"),
        _f("dns_label_length", K.NUMBER, "longest label in the name"),
        _f("dns_name_entropy", K.NUMBER, "Shannon entropy of the leftmost label"),
        _f("http_method", K.STRING, "request method"),
        _f("http_path", K.STRING, "request path"),
        _f("http_host", K.STRING, "Host header"),
        _f("http_user_agent", K.STRING, "User-Agent header"),
        _f("tls_sni", K.STRING, "TLS server name indication"),
        _f("tls_version", K.STRING, "negotiated or offered TLS version"),
        _f("tls_is_legacy_version", K.BOOLEAN, "SSLv3, TLS 1.0 or TLS 1.1"),
    )
}

_NUMERIC_OPS: Final = frozenset({">", ">=", "<", "<="})
_STRING_OPS: Final = frozenset({"contains", "startswith", "endswith"})
_OPERATORS: Final = frozenset({"==", "!=", "in", "not in", "in_network", *_NUMERIC_OPS, *_STRING_OPS})


# ===================================================================== AST


@dataclass(frozen=True, slots=True)
class Comparison:
    field: str
    operator: str
    value: Any
    position: int

    def describe(self) -> str:
        shown = self.value
        if isinstance(shown, tuple):
            shown = "[" + ", ".join(str(v) for v in shown) + "]"
        return f"{self.field} {self.operator} {shown}"


@dataclass(frozen=True, slots=True)
class And:
    items: tuple[Node, ...]


@dataclass(frozen=True, slots=True)
class Or:
    items: tuple[Node, ...]


@dataclass(frozen=True, slots=True)
class Not:
    item: Node


Node = Comparison | And | Or | Not


# =================================================================== lexer


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str  # op, number, string, word, lparen, rparen, lbracket, rbracket, comma, end
    text: str
    position: int


_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<op>==|!=|>=|<=|>|<)
  | (?P<number>-?\d+(?:\.\d+)?)
  | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<word>[A-Za-z_][A-Za-z0-9_.:/-]*)
  | (?P<lparen>\() | (?P<rparen>\)) | (?P<lbracket>\[) | (?P<rbracket>\]) | (?P<comma>,)
    """,
    re.VERBOSE,
)


def _tokenise(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    position = 0
    while position < len(text):
        match = _TOKEN_RE.match(text, position)
        if match is None:
            raise ConditionSyntaxError(f"unexpected character {text[position]!r}", position)
        kind = match.lastgroup or ""
        if kind != "ws":
            tokens.append(_Token(kind, match.group(), position))
            if len(tokens) > MAX_TOKENS:
                raise ConditionSyntaxError(f"condition exceeds {MAX_TOKENS} tokens")
        position = match.end()
    tokens.append(_Token("end", "", len(text)))
    return tokens


# ================================================================== parser


class _Parser:
    def __init__(self, text: str) -> None:
        self.tokens = _tokenise(text)
        self.index = 0
        self.depth = 0

    def peek(self) -> _Token:
        return self.tokens[self.index]

    def advance(self) -> _Token:
        token = self.tokens[self.index]
        self.index += 1
        return token

    def keyword(self, word: str) -> bool:
        token = self.peek()
        return token.kind == "word" and token.text.lower() == word

    def parse(self) -> Node:
        node = self.or_expr()
        token = self.peek()
        if token.kind != "end":
            raise ConditionSyntaxError(f"unexpected {token.text!r}; expected 'and', 'or' or end", token.position)
        return node

    def _enter(self, position: int) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise ConditionSyntaxError(f"condition nests deeper than {MAX_DEPTH} levels", position)

    def or_expr(self) -> Node:
        items = [self.and_expr()]
        while self.keyword("or"):
            self.advance()
            items.append(self.and_expr())
        return items[0] if len(items) == 1 else Or(tuple(items))

    def and_expr(self) -> Node:
        items = [self.not_expr()]
        while self.keyword("and"):
            self.advance()
            items.append(self.not_expr())
        return items[0] if len(items) == 1 else And(tuple(items))

    def not_expr(self) -> Node:
        if self.keyword("not"):
            token = self.advance()
            self._enter(token.position)
            node = Not(self.not_expr())
            self.depth -= 1
            return node
        return self.primary()

    def primary(self) -> Node:
        token = self.peek()
        if token.kind == "lparen":
            self.advance()
            self._enter(token.position)
            node = self.or_expr()
            self.depth -= 1
            closing = self.advance()
            if closing.kind != "rparen":
                raise ConditionSyntaxError("missing ')'", closing.position)
            return node
        return self.comparison()

    def comparison(self) -> Comparison:
        field_token = self.advance()
        if field_token.kind != "word" or field_token.text.lower() in {"and", "or", "not", "in"}:
            raise ConditionSyntaxError(
                f"expected a field name, found {field_token.text or 'end of condition'!r}", field_token.position
            )
        operator = self.operator()
        value = self.value()
        return Comparison(field_token.text.lower(), operator, value, field_token.position)

    def operator(self) -> str:
        token = self.advance()
        if token.kind == "op":
            return token.text
        if token.kind == "word":
            word = token.text.lower()
            if word == "not" and self.keyword("in"):
                self.advance()
                return "not in"
            if word in _OPERATORS:
                return word
        raise ConditionSyntaxError(
            f"expected an operator (==, !=, >, >=, <, <=, in, not in, contains, startswith, endswith, "
            f"in_network), found {token.text or 'end of condition'!r}",
            token.position,
        )

    def value(self) -> Any:
        token = self.advance()
        if token.kind == "number":
            return float(token.text) if "." in token.text else int(token.text)
        if token.kind == "string":
            body = token.text[1:-1]
            return re.sub(r"\\(.)", r"\1", body)
        if token.kind == "word":
            lowered = token.text.lower()
            if lowered in {"true", "false"}:
                return lowered == "true"
            return token.text
        if token.kind == "lbracket":
            items: list[Any] = []
            if self.peek().kind == "rbracket":
                raise ConditionSyntaxError("empty list", token.position)
            while True:
                item = self.value()
                if isinstance(item, tuple):
                    raise ConditionSyntaxError("nested lists are not allowed", token.position)
                items.append(item)
                if len(items) > MAX_LIST_ITEMS:
                    raise ConditionSyntaxError(f"list exceeds {MAX_LIST_ITEMS} items", token.position)
                separator = self.advance()
                if separator.kind == "rbracket":
                    return tuple(items)
                if separator.kind != "comma":
                    raise ConditionSyntaxError("expected ',' or ']' in list", separator.position)
        raise ConditionSyntaxError(f"expected a value, found {token.text or 'end of condition'!r}", token.position)


def parse_condition(text: str) -> Node:
    """Parse a condition string into an AST.

    Raises:
        ConditionSyntaxError: with the character position of the problem.
    """
    if not text or not text.strip():
        raise ConditionSyntaxError("condition is empty")
    if len(text) > MAX_CONDITION_LENGTH:
        raise ConditionSyntaxError(f"condition exceeds {MAX_CONDITION_LENGTH} characters")
    return _Parser(text).parse()


def comparisons(node: Node) -> list[Comparison]:
    """Every comparison in the tree, in source order."""
    if isinstance(node, Comparison):
        return [node]
    if isinstance(node, Not):
        return comparisons(node.item)
    found: list[Comparison] = []
    for item in node.items:
        found.extend(comparisons(item))
    return found


# =============================================================== semantics


def validate_semantics(node: Node) -> list[str]:
    """Type-check every comparison against :data:`FIELDS`. Returns all problems."""
    problems: list[str] = []
    for comparison in comparisons(node):
        spec = FIELDS.get(comparison.field)
        where = f"'{comparison.describe()}'"
        if spec is None:
            close = [name for name in FIELDS if name.startswith(comparison.field[:4])][:3]
            hint = f"; did you mean {', '.join(close)}?" if close else ""
            problems.append(f"unknown field '{comparison.field}' in {where}{hint}")
            continue
        op, value = comparison.operator, comparison.value
        if op in _NUMERIC_OPS and spec.kind not in (K.COUNT, K.NUMBER):
            problems.append(f"{where}: '{op}' needs a numeric field, but {spec.name} is {spec.kind}")
        is_number = isinstance(value, (int, float)) and not isinstance(value, bool)
        if op in _NUMERIC_OPS and not is_number:
            problems.append(f"{where}: '{op}' needs a number")
        if op in _STRING_OPS and spec.kind is not K.STRING:
            problems.append(f"{where}: '{op}' needs a text field, but {spec.name} is {spec.kind}")
        if op in _STRING_OPS and not isinstance(value, str):
            problems.append(f"{where}: '{op}' needs a text value")
        if op in {"in", "not in"} and not isinstance(value, tuple):
            problems.append(f"{where}: '{op}' needs a list, e.g. [22, 2222]")
        if op == "in_network":
            if spec.kind is not K.ADDRESS:
                problems.append(f"{where}: 'in_network' needs an address field")
            networks = value if isinstance(value, tuple) else (value,)
            for network in networks:
                try:
                    parse_network(str(network))
                except ValueError:
                    problems.append(f"{where}: {network!r} is not a valid network")
        if spec.kind is K.BOOLEAN and op in {"==", "!="} and not isinstance(value, bool):
            problems.append(f"{where}: {spec.name} is boolean; compare with true or false")
        if spec.kind in (K.COUNT, K.NUMBER) and op in {"==", "!="} and not isinstance(value, (int, float)):
            problems.append(f"{where}: {spec.name} is numeric; compare with a number")
    return problems


# ============================================================== evaluation

Resolver = Callable[[str], Any]


def evaluate(node: Node, resolve: Resolver, matched: list[tuple[Comparison, Any]] | None = None) -> bool:
    """Evaluate against lazily resolved field values.

    ``and``/``or`` short-circuit, and ``resolve`` is called only for fields that are
    actually reached, so placing cheap packet fields first in a rule keeps windowed
    features from being computed for irrelevant packets.

    Comparisons that held are appended to ``matched`` with their observed value;
    that list becomes the detection's evidence.  A field with no value (e.g.
    ``dns_query_name`` on a TCP packet) never satisfies any comparison, including
    ``!=`` - "unknown" is not evidence.
    """
    if isinstance(node, Comparison):
        observed = resolve(node.field)
        result = _compare(node, observed)
        if result and matched is not None:
            matched.append((node, observed))
        return result
    if isinstance(node, And):
        return all(evaluate(item, resolve, matched) for item in node.items)
    if isinstance(node, Or):
        return any(evaluate(item, resolve, matched) for item in node.items)
    # Evidence gathered beneath a negation describes what was *not* true; discard it.
    return not evaluate(node.item, resolve, None)


_network_cache: dict[str, IPNetworkT] = {}


def _network(value: Any) -> IPNetworkT:
    key = str(value)
    cached = _network_cache.get(key)
    if cached is None:
        cached = parse_network(key)
        if len(_network_cache) < 10_000:
            _network_cache[key] = cached
    return cached


def _normalise(value: Any) -> Any:
    return value.lower() if isinstance(value, str) else value


def _compare(node: Comparison, observed: Any) -> bool:
    if observed is None:
        return False
    op, expected = node.operator, node.value
    try:
        if op == "in_network":
            address = parse_ip(str(observed))
            networks = expected if isinstance(expected, tuple) else (expected,)
            return any(address.version == net.version and address in net for net in map(_network, networks))
        if op in {"in", "not in"}:
            present = _normalise(observed) in {_normalise(item) for item in expected}
            return present if op == "in" else not present
        if op in _STRING_OPS:
            text, needle = str(observed).lower(), str(expected).lower()
            if op == "contains":
                return needle in text
            if op == "startswith":
                return text.startswith(needle)
            return text.endswith(needle)
        if op in {"==", "!="}:
            equal = _normalise(observed) == _normalise(expected)
            return equal if op == "==" else not equal
        observed_number, expected_number = float(observed), float(expected)
    except (TypeError, ValueError):
        return False
    if op == ">":
        return observed_number > expected_number
    if op == ">=":
        return observed_number >= expected_number
    if op == "<":
        return observed_number < expected_number
    return observed_number <= expected_number
