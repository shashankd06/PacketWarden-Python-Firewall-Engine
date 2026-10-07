"""Stateless firewall rule engine for PacketWarden.

Rule File Syntax:
  - Rules are evaluated top-to-bottom. First match wins.
  - ALLOW|DENY <proto|any> <src_cidr|any>[:port|range] -> <dst_cidr|any>[:port|range]
  - DEFAULT ALLOW|DENY sets default fallback (defaults to DENY if omitted).
  - Lines starting with # are comments. Empty lines are ignored.
"""

import ipaddress
from dataclasses import dataclass

from packetwarden.models import PacketInfo


class RuleParseError(ValueError):
    """Raised when a rule line contains invalid syntax, with line number context."""

    def __init__(self, line_num: int, line_text: str, message: str) -> None:
        self.line_num = line_num
        self.line_text = line_text
        self.message = message
        super().__init__(f"Line {line_num}: {message} -> '{line_text}'")


@dataclass(slots=True, frozen=True)
class PortSpec:
    """Represents a port matching specification: any, single port, list, or range."""

    is_any: bool = True
    ports: frozenset[int] = frozenset()
    port_range: tuple[int, int] | None = None

    def matches(self, port: int | None) -> bool:
        if self.is_any:
            return True
        if port is None:
            return False
        if port in self.ports:
            return True
        if self.port_range is not None:
            low, high = self.port_range
            return low <= port <= high
        return False


@dataclass(slots=True, frozen=True)
class EndpointSpec:
    """Represents network endpoint matcher: IP network (or any) and port matcher."""

    network: ipaddress.IPv4Network | None
    port_spec: PortSpec

    def matches(self, ip_str: str, port: int | None) -> bool:
        if self.network is not None:
            try:
                ip_obj = ipaddress.IPv4Address(ip_str)
                if ip_obj not in self.network:
                    return False
            except ValueError:
                return False
        return self.port_spec.matches(port)


@dataclass(slots=True)
class Rule:
    """A single firewall rule."""

    line_num: int
    raw_text: str
    action: str  # 'ALLOW' or 'DENY'
    protocol: str  # 'tcp', 'udp', 'icmp', or 'any'
    src_spec: EndpointSpec
    dst_spec: EndpointSpec

    def matches(self, pkt: PacketInfo) -> bool:
        """Evaluate whether a normalized packet matches this rule."""
        if self.protocol != "any" and self.protocol != pkt.protocol:
            return False
        if not self.src_spec.matches(pkt.src_ip, pkt.src_port):
            return False
        return self.dst_spec.matches(pkt.dst_ip, pkt.dst_port)


class RuleEngine:
    """Stateless firewall ruleset evaluation engine."""

    def __init__(self, rules: list[Rule], default_action: str = "DENY") -> None:
        self.rules = rules
        self.default_action = default_action

    def evaluate(self, pkt: PacketInfo) -> tuple[str, Rule | None]:
        """Evaluate packet against rules.

        Returns:
            tuple[str, Rule | None]: (Action 'ALLOW'/'DENY', matching Rule or None if default)
        """
        for rule in self.rules:
            if rule.matches(pkt):
                return rule.action, rule
        return self.default_action, None

    @classmethod
    def from_string(cls, content: str) -> "RuleEngine":
        """Parse rules from text content."""
        rules: list[Rule] = []
        default_action = "DENY"

        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check for DEFAULT line: DEFAULT ALLOW|DENY
            if stripped.startswith("DEFAULT"):
                parts = stripped.split()
                if len(parts) != 2 or parts[1] not in ("ALLOW", "DENY"):
                    raise RuleParseError(
                        idx, stripped, "Invalid DEFAULT directive. Expected: DEFAULT ALLOW|DENY"
                    )
                default_action = parts[1]
                continue

            # Standard rule syntax:
            # ALLOW|DENY <proto|any> <src> -> <dst>
            tokens = stripped.split()
            if len(tokens) != 5:
                raise RuleParseError(
                    idx,
                    stripped,
                    "Expected 5 tokens: <ALLOW|DENY> <proto|any> <src> -> <dst>",
                )

            action, proto, src_tok, arrow, dst_tok = tokens
            if action not in ("ALLOW", "DENY"):
                raise RuleParseError(idx, stripped, f"Invalid action '{action}'. Must be ALLOW or DENY")

            proto_lower = proto.lower()
            if proto_lower not in ("tcp", "udp", "icmp", "any"):
                raise RuleParseError(
                    idx, stripped, f"Invalid protocol '{proto}'. Must be tcp, udp, icmp, or any"
                )

            if arrow != "->":
                raise RuleParseError(idx, stripped, f"Expected arrow '->' between src and dst, got '{arrow}'")

            src_spec = cls._parse_endpoint(idx, stripped, src_tok)
            dst_spec = cls._parse_endpoint(idx, stripped, dst_tok)

            rules.append(
                Rule(
                    line_num=idx,
                    raw_text=stripped,
                    action=action,
                    protocol=proto_lower,
                    src_spec=src_spec,
                    dst_spec=dst_spec,
                )
            )

        return cls(rules=rules, default_action=default_action)

    @classmethod
    def from_file(cls, path: str) -> "RuleEngine":
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_string(f.read())

    @staticmethod
    def _parse_port_spec(line_num: int, line_text: str, port_str: str) -> PortSpec:
        """Parse port specification: single (80), list (80,443), or range (1024-65535)."""
        if port_str == "any":
            return PortSpec(is_any=True)

        if "-" in port_str:
            parts = port_str.split("-")
            if len(parts) != 2:
                raise RuleParseError(line_num, line_text, f"Invalid port range format: '{port_str}'")
            try:
                start_p, end_p = int(parts[0]), int(parts[1])
                if not (0 <= start_p <= 65535 and 0 <= end_p <= 65535 and start_p <= end_p):
                    raise ValueError
                return PortSpec(is_any=False, port_range=(start_p, end_p))
            except ValueError as err:
                raise RuleParseError(line_num, line_text, f"Invalid port range numbers: '{port_str}'") from err

        if "," in port_str:
            try:
                ports = {int(p) for p in port_str.split(",")}
                if any(not (0 <= p <= 65535) for p in ports):
                    raise ValueError
                return PortSpec(is_any=False, ports=frozenset(ports))
            except ValueError as err:
                raise RuleParseError(line_num, line_text, f"Invalid port list: '{port_str}'") from err

        try:
            p = int(port_str)
            if not (0 <= p <= 65535):
                raise ValueError
            return PortSpec(is_any=False, ports=frozenset([p]))
        except ValueError as err:
            raise RuleParseError(line_num, line_text, f"Invalid port value: '{port_str}'") from err

    @classmethod
    def _parse_endpoint(cls, line_num: int, line_text: str, endpoint_token: str) -> EndpointSpec:
        """Parse <cidr|any>[:port|range]."""
        # Split by ':' for port, but watch for IPv6 notation if any (we focus on IPv4/any)
        parts = endpoint_token.rsplit(":", 1)
        ip_token = parts[0]
        port_spec = PortSpec(is_any=True)

        if len(parts) == 2:
            port_spec = cls._parse_port_spec(line_num, line_text, parts[1])

        if ip_token.lower() == "any":
            network = None
        else:
            try:
                # support both CIDR (192.168.1.0/24) and single host (192.168.1.1)
                network = ipaddress.IPv4Network(ip_token, strict=False)
            except ValueError as err:
                raise RuleParseError(
                    line_num, line_text, f"Invalid IP address or CIDR network: '{ip_token}'"
                ) from err

        return EndpointSpec(network=network, port_spec=port_spec)
