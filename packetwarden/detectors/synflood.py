"""SYN Flood detector using sliding time window.

Detects high volumes of incoming SYN packets targeting a destination host with very low
handshake completion ratios (classic TCP half-open resource exhaustion attack).
"""

from collections import defaultdict, deque
from dataclasses import dataclass

from packetwarden.conntrack import TcpConnection, TcpState
from packetwarden.detectors.base import Alert, BaseDetector
from packetwarden.models import PacketInfo


@dataclass(slots=True)
class SynProbe:
    timestamp: float
    src_ip: str
    is_completed: bool = False


class SynFloodDetector(BaseDetector):
    """Detects SYN Flood attacks targeting a destination IP."""

    def __init__(
        self,
        syn_threshold: int = 50,  # Minimum SYNs targeting the destination within window
        time_window: float = 5.0,  # 5-second evaluation window
        max_completion_ratio: float = 0.15,  # Alert if <15% of SYNs result in ESTABLISHED
    ) -> None:
        self.syn_threshold = syn_threshold
        self.time_window = time_window
        self.max_completion_ratio = max_completion_ratio

        # Map target dst_ip -> deque[SynProbe]
        self.dst_probes: dict[str, deque[SynProbe]] = defaultdict(deque)
        self.last_alert_time: dict[str, float] = {}

    def _purge_old(self, dst_ip: str, current_time: float) -> None:
        probes = self.dst_probes[dst_ip]
        cutoff = current_time - self.time_window
        while probes and probes[0].timestamp < cutoff:
            probes.popleft()

    def process_packet(
        self, pkt: PacketInfo, conn: TcpConnection | None = None
    ) -> list[Alert]:
        if not pkt.is_tcp:
            return []

        flags = pkt.tcp_flag_set
        is_syn = "S" in flags and "A" not in flags

        target_ip = pkt.dst_ip

        if is_syn:
            self.dst_probes[target_ip].append(
                SynProbe(timestamp=pkt.timestamp, src_ip=pkt.src_ip, is_completed=False)
            )

        # Mark completed if connection reached ESTABLISHED
        if conn is not None and conn.state == TcpState.ESTABLISHED:
            probes = self.dst_probes[target_ip]
            for p in reversed(probes):
                if p.src_ip == conn.initiator_ip and not p.is_completed:
                    p.is_completed = True
                    break

        self._purge_old(target_ip, pkt.timestamp)
        probes = self.dst_probes[target_ip]

        if len(probes) >= self.syn_threshold:
            last_alert = self.last_alert_time.get(target_ip)
            if last_alert is None or pkt.timestamp - last_alert >= self.time_window:
                completed_count = sum(1 for p in probes if p.is_completed)
                completion_ratio = completed_count / len(probes)

                if completion_ratio <= self.max_completion_ratio:
                    self.last_alert_time[target_ip] = pkt.timestamp
                    # Identify primary attacker IP (or "spoofed / distributed" if diverse)
                    sources = {p.src_ip for p in probes}
                    primary_src = probes[0].src_ip if len(sources) == 1 else "distributed/spoofed"

                    alert = Alert(
                        detector_name="SynFloodDetector",
                        severity="HIGH",
                        source_ip=primary_src,
                        start_time=probes[0].timestamp,
                        end_time=pkt.timestamp,
                        evidence={
                            "target_ip": target_ip,
                            "syn_count": len(probes),
                            "completed_count": completed_count,
                            "completion_ratio": round(completion_ratio, 3),
                            "distinct_sources": len(sources),
                        },
                        description=(
                            f"SYN Flood detected against target {target_ip}: {len(probes)} SYNs received "
                            f"in {self.time_window}s with only {completion_ratio:.1%} completed handshakes."
                        ),
                    )
                    return [alert]

        return []
