"""Core packet data models for PacketWarden."""

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class PacketInfo:
    """Normalized representation of a single captured network packet.

    Extracts Layer 3/4 headers and protocol-specific metadata needed
    for rule evaluation and attack detection without retaining large raw payloads.
    """

    timestamp: float
    length: int
    src_ip: str
    dst_ip: str
    protocol: str  # 'tcp', 'udp', 'icmp', or 'other'
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None  # e.g., 'S', 'SA', 'A', 'FA', 'R'
    dns_query: str | None = None  # Normalized lowercase QNAME (without trailing dot)

    @property
    def is_tcp(self) -> bool:
        return self.protocol == "tcp"

    @property
    def is_udp(self) -> bool:
        return self.protocol == "udp"

    @property
    def is_icmp(self) -> bool:
        return self.protocol == "icmp"

    @property
    def tcp_flag_set(self) -> set[str]:
        """Return the TCP flags as an individual character set."""
        return set(self.tcp_flags) if self.tcp_flags else set()
