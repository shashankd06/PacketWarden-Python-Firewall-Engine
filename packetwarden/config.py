"""Configuration dataclass for PacketWarden analysis pipeline."""

from dataclasses import dataclass, field


@dataclass(slots=True)
class WardenConfig:
    """Runtime configuration for firewall engine and attack detectors."""

    # Connection tracking options
    stateful_mode: bool = True
    idle_timeout: float = 300.0  # seconds (TCP established)
    tcp_syn_timeout: float = 30.0  # seconds (TCP handshake)
    udp_idle_timeout: float = 30.0  # seconds (UDP flows)
    udp_dns_timeout: float = 5.0  # seconds (DNS port 53 query/response)
    max_conntrack_entries: int = 100_000

    # Port scan detector
    port_scan_threshold: int = 15  # distinct ports or destinations
    port_scan_window: float = 10.0  # seconds
    port_scan_syn_ratio: float = 0.8  # ratio of SYNs for stealth scan

    # SYN flood detector
    syn_flood_threshold: int = 50  # SYN packets
    syn_flood_window: float = 5.0  # seconds
    syn_flood_max_completion_ratio: float = 0.15  # 15% completion threshold

    # DNS anomaly detector
    dns_max_qname_length: int = 65  # characters
    dns_rate_threshold: int = 30  # queries per source
    dns_subdomain_diversity_threshold: int = 15  # unique subdomains under one parent
    dns_window: float = 10.0  # seconds

    # CLI / Reporting options
    top_n_stats: int = 5
    rules_file: str | None = None
    report_output: str | None = None
    extra_options: dict[str, str] = field(default_factory=dict)
