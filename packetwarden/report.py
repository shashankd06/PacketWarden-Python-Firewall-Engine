"""Report generation and formatting for PacketWarden analysis results."""

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from packetwarden.detectors.base import Alert
from packetwarden.parser import ParseStats


@dataclass
class FirewallStats:
    """Statistics for firewall rule matches."""

    allowed_count: int = 0
    blocked_count: int = 0
    stateful_permitted_replies: int = 0
    rule_hits: dict[str, int] = field(default_factory=dict)
    default_policy_hits: dict[str, int] = field(default_factory=dict)


@dataclass
class WardenReport:
    """Complete summary report of capture analysis."""

    capture_file: str
    parse_stats: ParseStats
    firewall_stats: FirewallStats
    top_src_ips: list[tuple[str, int]]
    top_dst_ips: list[tuple[str, int]]
    top_dst_ports: list[tuple[int, int]]
    active_connections: int
    expired_connections: int
    alerts: list[Alert]

    def to_dict(self) -> dict[str, Any]:
        """Convert report to JSON-serializable dictionary."""
        return {
            "capture_file": self.capture_file,
            "parse_stats": asdict(self.parse_stats),
            "firewall_stats": {
                "allowed_count": self.firewall_stats.allowed_count,
                "blocked_count": self.firewall_stats.blocked_count,
                "stateful_permitted_replies": self.firewall_stats.stateful_permitted_replies,
                "rule_hits": self.firewall_stats.rule_hits,
                "default_policy_hits": self.firewall_stats.default_policy_hits,
            },
            "top_src_ips": self.top_src_ips,
            "top_dst_ips": self.top_dst_ips,
            "top_dst_ports": self.top_dst_ports,
            "connection_stats": {
                "active_connections": self.active_connections,
                "expired_connections": self.expired_connections,
            },
            "alert_summary": {
                "total_alerts": len(self.alerts),
                "high_severity": sum(1 for a in self.alerts if a.severity == "HIGH"),
                "medium_severity": sum(1 for a in self.alerts if a.severity == "MEDIUM"),
                "low_severity": sum(1 for a in self.alerts if a.severity == "LOW"),
            },
            "alerts": [asdict(a) for a in self.alerts],
        }

    def save_json(self, output_path: str) -> None:
        """Write JSON report to disk."""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    def render_terminal(self) -> str:
        """Generate a clean, structured plain-text terminal summary."""
        lines = []
        divider = "=" * 70
        subdiv = "-" * 70

        lines.append(divider)
        lines.append("                  PACKETWARDEN ANALYSIS REPORT                  ")
        lines.append(divider)
        lines.append(f"Capture File: {self.capture_file}")
        lines.append(
            f"Packets Processed: {self.parse_stats.parsed_packets} / {self.parse_stats.total_packets} "
            f"(Non-IP: {self.parse_stats.non_ip_packets}, Malformed: {self.parse_stats.malformed_packets})"
        )
        lines.append(subdiv)

        lines.append("FIREWALL EVALUATION:")
        lines.append(f"  Allowed Packets:        {self.firewall_stats.allowed_count}")
        lines.append(f"  Blocked Packets:        {self.firewall_stats.blocked_count}")
        lines.append(f"  Stateful Flow Matches:  {self.firewall_stats.stateful_permitted_replies}")
        if self.firewall_stats.rule_hits:
            lines.append("  Rule Match Breakdown:")
            for rule_desc, count in self.firewall_stats.rule_hits.items():
                lines.append(f"    - [{count:4d}] {rule_desc}")
        lines.append(subdiv)

        lines.append("TRAFFIC PROFILE (TOP TALKERS):")
        top_src_str = ", ".join(f"{ip} ({cnt})" for ip, cnt in self.top_src_ips[:4])
        top_dst_str = ", ".join(f"{ip} ({cnt})" for ip, cnt in self.top_dst_ips[:4])
        top_ports_str = ", ".join(f"{p} ({cnt})" for p, cnt in self.top_dst_ports[:4])
        lines.append(f"  Top Sources:      {top_src_str or 'None'}")
        lines.append(f"  Top Destinations: {top_dst_str or 'None'}")
        lines.append(f"  Top Dst Ports:    {top_ports_str or 'None'}")
        lines.append(subdiv)

        lines.append("CONNECTION TRACKING:")
        lines.append(f"  Active States in Table:  {self.active_connections}")
        lines.append(f"  Expired Flow States:     {self.expired_connections}")
        lines.append(subdiv)

        lines.append(f"SECURITY ALERTS DETECTED ({len(self.alerts)} total):")
        if not self.alerts:
            lines.append("  [+] No anomalous security events or attack patterns detected.")
        else:
            for idx, alert in enumerate(self.alerts, start=1):
                sev_tag = f"[{alert.severity}]"
                lines.append(
                    f"  {idx}. {sev_tag:<8} {alert.detector_name} from {alert.source_ip} "
                    f"at t={alert.end_time:.2f}s"
                )
                lines.append(f"     Details: {alert.description}")
        lines.append(divider)

        return "\n".join(lines)
