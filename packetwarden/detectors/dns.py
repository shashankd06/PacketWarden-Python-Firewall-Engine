"""DNS anomaly and tunneling detector using sliding time windows.

Detects:
1. Exceptionally long query names (indicative of base64/hex data exfiltration).
2. High rate of DNS queries originating from a single source host.
3. High subdomain diversity/ratio under a single registered domain (DNS tunneling heuristic).
"""

from collections import defaultdict, deque
from dataclasses import dataclass

from packetwarden.conntrack import TcpConnection
from packetwarden.detectors.base import Alert, BaseDetector
from packetwarden.models import PacketInfo


@dataclass(slots=True)
class DnsQueryRecord:
    timestamp: float
    qname: str
    length: int
    parent_domain: str


def extract_parent_domain(qname: str) -> str:
    """Extract effective parent domain (e.g. data.tunnel.example.com -> example.com)."""
    parts = qname.strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return qname


class DnsAnomalyDetector(BaseDetector):
    """Detects DNS exfiltration, tunneling, and high-rate query bursts."""

    def __init__(
        self,
        max_qname_length: int = 65,  # RFC 1035 label max is 63 chars; >65 overall is suspicious
        rate_threshold: int = 30,  # >30 queries per source within window
        subdomain_diversity_threshold: int = 15,  # >15 distinct subdomains under same parent
        time_window: float = 10.0,
    ) -> None:
        self.max_qname_length = max_qname_length
        self.rate_threshold = rate_threshold
        self.subdomain_diversity_threshold = subdomain_diversity_threshold
        self.time_window = time_window

        # Map src_ip -> deque[DnsQueryRecord]
        self.history: dict[str, deque[DnsQueryRecord]] = defaultdict(deque)
        self.last_alert_time: dict[tuple[str, str], float] = {}

    def _purge_old(self, src_ip: str, current_time: float) -> None:
        records = self.history[src_ip]
        cutoff = current_time - self.time_window
        while records and records[0].timestamp < cutoff:
            records.popleft()

    def process_packet(
        self, pkt: PacketInfo, conn: TcpConnection | None = None
    ) -> list[Alert]:
        if pkt.dns_query is None:
            return []

        qname = pkt.dns_query
        src_ip = pkt.src_ip
        qlen = len(qname)
        parent_domain = extract_parent_domain(qname)

        alerts: list[Alert] = []

        # 1. Suspicious Query Length (Immediate Check)
        if qlen > self.max_qname_length:
            alert_key = (src_ip, f"length_{parent_domain}")
            last_alert = self.last_alert_time.get(alert_key)
            if last_alert is None or pkt.timestamp - last_alert >= self.time_window:
                self.last_alert_time[alert_key] = pkt.timestamp
                alerts.append(
                    Alert(
                        detector_name="DnsAnomalyDetector",
                        severity="MEDIUM",
                        source_ip=src_ip,
                        start_time=pkt.timestamp,
                        end_time=pkt.timestamp,
                        evidence={
                            "anomaly_type": "Excessive Query Length",
                            "qname_length": qlen,
                            "qname_sample": qname[:80],
                            "parent_domain": parent_domain,
                        },
                        description=(
                            f"Suspiciously long DNS query ({qlen} chars) from {src_ip} "
                            f"querying '{qname[:50]}...'"
                        ),
                    )
                )

        # Record into sliding window
        self.history[src_ip].append(
            DnsQueryRecord(
                timestamp=pkt.timestamp,
                qname=qname,
                length=qlen,
                parent_domain=parent_domain,
            )
        )
        self._purge_old(src_ip, pkt.timestamp)
        records = self.history[src_ip]

        # 2. High Query Rate Check
        if len(records) >= self.rate_threshold:
            alert_key = (src_ip, "high_rate")
            last_alert = self.last_alert_time.get(alert_key)
            if last_alert is None or pkt.timestamp - last_alert >= self.time_window:
                self.last_alert_time[alert_key] = pkt.timestamp
                alerts.append(
                    Alert(
                        detector_name="DnsAnomalyDetector",
                        severity="LOW",
                        source_ip=src_ip,
                        start_time=records[0].timestamp,
                        end_time=pkt.timestamp,
                        evidence={
                            "anomaly_type": "High Query Rate",
                            "query_count": len(records),
                            "window": self.time_window,
                        },
                        description=(
                            f"High DNS query rate from {src_ip}: {len(records)} queries "
                            f"sent within {self.time_window}s."
                        ),
                    )
                )

        # 3. Subdomain Tunneling Check (many distinct subdomains under same parent domain)
        domain_subdomains: dict[str, set[str]] = defaultdict(set)
        for r in records:
            domain_subdomains[r.parent_domain].add(r.qname)

        for pdomain, subdomains in domain_subdomains.items():
            if len(subdomains) >= self.subdomain_diversity_threshold:
                alert_key = (src_ip, f"tunnel_{pdomain}")
                last_alert = self.last_alert_time.get(alert_key)
                if last_alert is None or pkt.timestamp - last_alert >= self.time_window:
                    self.last_alert_time[alert_key] = pkt.timestamp
                    alerts.append(
                        Alert(
                            detector_name="DnsAnomalyDetector",
                            severity="HIGH",
                            source_ip=src_ip,
                            start_time=records[0].timestamp,
                            end_time=pkt.timestamp,
                            evidence={
                                "anomaly_type": "DNS Tunneling / High Entropy Subdomains",
                                "parent_domain": pdomain,
                                "unique_subdomains": len(subdomains),
                                "sample": list(subdomains)[:3],
                            },
                            description=(
                                f"Potential DNS Tunneling detected from {src_ip}: {len(subdomains)} "
                                f"unique subdomains queried under parent '{pdomain}' within {self.time_window}s."
                            ),
                        )
                    )

        return alerts
