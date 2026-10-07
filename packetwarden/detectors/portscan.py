"""Port scan detector using a sliding time window.

Detects single source IPs contacting more than N distinct destination ports or hosts
within a time window. Distinguishes SYN scans (many pure SYNs, minimal completed handshakes)
from benign high-connection applications.
"""

from collections import defaultdict, deque
from dataclasses import dataclass

from packetwarden.conntrack import TcpConnection, TcpState
from packetwarden.detectors.base import Alert, BaseDetector
from packetwarden.models import PacketInfo


@dataclass(slots=True)
class PortScanRecord:
    timestamp: float
    dst_ip: str
    dst_port: int
    is_syn: bool
    is_handshake_complete: bool


class PortScanDetector(BaseDetector):
    """Detects horizontal and vertical port scans within a sliding time window."""

    def __init__(
        self,
        port_threshold: int = 15,  # Distinct ports threshold to trigger alert
        time_window: float = 10.0,  # 10 second window
        syn_ratio_threshold: float = 0.8,  # >80% incomplete SYNs classifies as stealth/SYN scan
    ) -> None:
        self.port_threshold = port_threshold
        self.time_window = time_window
        self.syn_ratio_threshold = syn_ratio_threshold

        # Map src_ip -> deque[PortScanRecord]
        self.history: dict[str, deque[PortScanRecord]] = defaultdict(deque)
        # Avoid spamming duplicate alerts within the same window for an IP
        self.last_alert_time: dict[str, float] = {}

    def _purge_old(self, src_ip: str, current_time: float) -> None:
        records = self.history[src_ip]
        cutoff = current_time - self.time_window
        while records and records[0].timestamp < cutoff:
            records.popleft()

    def process_packet(
        self, pkt: PacketInfo, conn: TcpConnection | None = None
    ) -> list[Alert]:
        if not pkt.is_tcp or pkt.src_port is None or pkt.dst_port is None:
            return []

        flags = pkt.tcp_flag_set
        is_syn = "S" in flags and "A" not in flags
        is_handshake_complete = conn is not None and conn.state == TcpState.ESTABLISHED

        # Record outgoing attempts or syn probes from initiator
        # If conn exists and packet is reply from responder, do not count as scanning
        if conn is not None and not conn.is_from_initiator(pkt.src_ip, pkt.src_port):
            return []

        # Only track SYN attempts or initial connection packets
        if not is_syn and not (conn is not None and conn.packets_count <= 2):
            return []

        src_ip = pkt.src_ip
        self.history[src_ip].append(
            PortScanRecord(
                timestamp=pkt.timestamp,
                dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port,
                is_syn=is_syn,
                is_handshake_complete=is_handshake_complete,
            )
        )
        self._purge_old(src_ip, pkt.timestamp)

        records = self.history[src_ip]
        distinct_ports = {r.dst_port for r in records}
        distinct_dsts = {r.dst_ip for r in records}

        # Check threshold
        if len(distinct_ports) >= self.port_threshold or len(distinct_dsts) >= self.port_threshold:
            # Check suppression
            last_alert = self.last_alert_time.get(src_ip)
            if last_alert is None or pkt.timestamp - last_alert >= self.time_window:
                syn_count = sum(1 for r in records if r.is_syn)
                ratio = syn_count / len(records) if records else 0.0

                is_stealth = ratio >= self.syn_ratio_threshold
                scan_type = "SYN Port Scan" if is_stealth else "Port Scan / Sweep"
                severity = "HIGH" if is_stealth else "MEDIUM"

                self.last_alert_time[src_ip] = pkt.timestamp
                alert = Alert(
                    detector_name="PortScanDetector",
                    severity=severity,
                    source_ip=src_ip,
                    start_time=records[0].timestamp,
                    end_time=pkt.timestamp,
                    evidence={
                        "distinct_ports": len(distinct_ports),
                        "distinct_destinations": len(distinct_dsts),
                        "total_probes": len(records),
                        "syn_ratio": round(ratio, 2),
                        "scan_type": scan_type,
                    },
                    description=(
                        f"{scan_type} detected: {src_ip} targeted {len(distinct_ports)} distinct "
                        f"ports across {len(distinct_dsts)} hosts within {self.time_window}s "
                        f"(SYN ratio: {ratio:.0%})."
                    ),
                )
                return [alert]

        return []
