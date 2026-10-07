"""CLI interface and pipeline orchestration for PacketWarden."""

import argparse
import sys
from collections import Counter

from packetwarden.config import WardenConfig
from packetwarden.conntrack import ConnectionTracker, TcpState
from packetwarden.detectors.base import Alert
from packetwarden.detectors.dns import DnsAnomalyDetector
from packetwarden.detectors.portscan import PortScanDetector
from packetwarden.detectors.synflood import SynFloodDetector
from packetwarden.parser import PcapParser
from packetwarden.report import FirewallStats, WardenReport
from packetwarden.rules import RuleEngine


def run_analysis(
    pcap_path: str,
    rules_path: str | None = None,
    config: WardenConfig | None = None,
) -> WardenReport:
    """Run full PacketWarden inspection pipeline over a pcap file."""
    if config is None:
        config = WardenConfig()

    rule_engine = (
        RuleEngine.from_file(rules_path)
        if rules_path
        else RuleEngine(rules=[], default_action="ALLOW")
    )

    conntrack = ConnectionTracker(
        idle_timeout=config.idle_timeout,
        tcp_syn_timeout=config.tcp_syn_timeout,
        max_table_size=config.max_conntrack_entries,
    )

    detectors = [
        PortScanDetector(
            port_threshold=config.port_scan_threshold,
            time_window=config.port_scan_window,
            syn_ratio_threshold=config.port_scan_syn_ratio,
        ),
        SynFloodDetector(
            syn_threshold=config.syn_flood_threshold,
            time_window=config.syn_flood_window,
            max_completion_ratio=config.syn_flood_max_completion_ratio,
        ),
        DnsAnomalyDetector(
            max_qname_length=config.dns_max_qname_length,
            rate_threshold=config.dns_rate_threshold,
            subdomain_diversity_threshold=config.dns_subdomain_diversity_threshold,
            time_window=config.dns_window,
        ),
    ]

    parser = PcapParser(pcap_path)
    firewall_stats = FirewallStats()
    src_ip_counter: Counter[str] = Counter()
    dst_ip_counter: Counter[str] = Counter()
    dst_port_counter: Counter[int] = Counter()
    all_alerts: list[Alert] = []

    for pkt in parser.parse_iter():
        src_ip_counter[pkt.src_ip] += 1
        dst_ip_counter[pkt.dst_ip] += 1
        if pkt.dst_port is not None:
            dst_port_counter[pkt.dst_port] += 1

        # 1. Stateful connection tracking
        conn, is_reply = conntrack.process_packet(pkt)

        # 2. Firewall evaluation
        # In stateful mode: established bidirectional reply traffic initiated lawfully is permitted.
        # However, unsolicited inbound non-SYN packets without prior connection state are dropped.
        if config.stateful_mode and pkt.is_tcp:
            if conn is not None and is_reply and conn.state in (TcpState.ESTABLISHED, TcpState.CLOSING):
                firewall_stats.allowed_count += 1
                firewall_stats.stateful_permitted_replies += 1
            elif conn is None and ("A" in pkt.tcp_flag_set or "F" in pkt.tcp_flag_set):
                # Unsolicited reply / rogue packet without state
                firewall_stats.blocked_count += 1
                firewall_stats.default_policy_hits["STATEFUL_UNSOLICITED_DROP"] = (
                    firewall_stats.default_policy_hits.get("STATEFUL_UNSOLICITED_DROP", 0) + 1
                )
            else:
                action, rule = rule_engine.evaluate(pkt)
                if action == "ALLOW":
                    firewall_stats.allowed_count += 1
                else:
                    firewall_stats.blocked_count += 1

                if rule is not None:
                    firewall_stats.rule_hits[rule.raw_text] = (
                        firewall_stats.rule_hits.get(rule.raw_text, 0) + 1
                    )
                else:
                    firewall_stats.default_policy_hits[rule_engine.default_action] = (
                        firewall_stats.default_policy_hits.get(rule_engine.default_action, 0) + 1
                    )
        else:
            action, rule = rule_engine.evaluate(pkt)
            if action == "ALLOW":
                firewall_stats.allowed_count += 1
            else:
                firewall_stats.blocked_count += 1

            if rule is not None:
                firewall_stats.rule_hits[rule.raw_text] = (
                    firewall_stats.rule_hits.get(rule.raw_text, 0) + 1
                )
            else:
                firewall_stats.default_policy_hits[rule_engine.default_action] = (
                    firewall_stats.default_policy_hits.get(rule_engine.default_action, 0) + 1
                )

        # 3. Detectors evaluation
        for detector in detectors:
            triggered = detector.process_packet(pkt, conn)
            if triggered:
                all_alerts.extend(triggered)

    return WardenReport(
        capture_file=pcap_path,
        parse_stats=parser.stats,
        firewall_stats=firewall_stats,
        top_src_ips=src_ip_counter.most_common(config.top_n_stats),
        top_dst_ips=dst_ip_counter.most_common(config.top_n_stats),
        top_dst_ports=dst_port_counter.most_common(config.top_n_stats),
        active_connections=len(conntrack.table),
        expired_connections=conntrack.expired_count,
        alerts=all_alerts,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="packetwarden",
        description="PacketWarden: PCAP analyzer, stateful rule engine, and attack detector.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a PCAP file.")
    analyze_parser.add_argument("pcap", help="Path to .pcap or .pcapng file")
    analyze_parser.add_argument("--rules", help="Path to firewall rules text file", default=None)
    analyze_parser.add_argument("--report", help="Path to output JSON report file", default=None)
    analyze_parser.add_argument(
        "--no-stateful",
        action="store_true",
        help="Disable stateful connection tracking for firewall rules",
    )

    args = parser.parse_args(argv)

    if args.subcommand == "analyze":
        config = WardenConfig(stateful_mode=not args.no_stateful)
        try:
            report = run_analysis(pcap_path=args.pcap, rules_path=args.rules, config=config)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"Error during analysis: {exc}\n")
            return 2

        # Render terminal summary
        print(report.render_terminal())

        # Write JSON report if requested
        if args.report:
            report.save_json(args.report)
            print(f"\n[+] Detailed JSON report exported to: {args.report}")

        # Exit code non-zero if any high-severity alert fired
        has_high_severity = any(a.severity == "HIGH" for a in report.alerts)
        if has_high_severity:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
