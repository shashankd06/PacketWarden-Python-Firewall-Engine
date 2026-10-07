"""Streaming PCAP parser for PacketWarden using Scapy.

Reads capture files iteratively via PcapReader so large captures do not exhaust memory.
Extracts normalized PacketInfo instances, while counting non-IP and malformed packets.
"""

import logging
from collections.abc import Iterator
from dataclasses import dataclass

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.utils import PcapReader

from packetwarden.models import PacketInfo

logger = logging.getLogger(__name__)


@dataclass
class ParseStats:
    """Summary of packet parsing results."""

    total_packets: int = 0
    parsed_packets: int = 0
    non_ip_packets: int = 0
    malformed_packets: int = 0


class PcapParser:
    """Streaming PCAP reader that normalizes packets into PacketInfo records."""

    def __init__(self, pcap_path: str) -> None:
        self.pcap_path = pcap_path
        self.stats = ParseStats()

    def parse_iter(self) -> Iterator[PacketInfo]:
        """Iterate over the PCAP file yielding normalized PacketInfo instances."""
        with PcapReader(self.pcap_path) as reader:
            for raw_pkt in reader:
                self.stats.total_packets += 1
                try:
                    # Check for IPv4 Layer
                    if not raw_pkt.haslayer(IP):
                        self.stats.non_ip_packets += 1
                        continue

                    ip_layer = raw_pkt[IP]

                    # Validate IPv4 header sanity
                    if ip_layer.version != 4 or (ip_layer.ihl is not None and ip_layer.ihl < 5):
                        self.stats.malformed_packets += 1
                        continue

                    src_ip = str(ip_layer.src)
                    dst_ip = str(ip_layer.dst)
                    timestamp = float(raw_pkt.time)
                    length = len(raw_pkt)

                    src_port = None
                    dst_port = None
                    tcp_flags = None
                    dns_query = None

                    if raw_pkt.haslayer(TCP):
                        protocol = "tcp"
                        tcp_layer = raw_pkt[TCP]
                        src_port = int(tcp_layer.sport)
                        dst_port = int(tcp_layer.dport)
                        # flags can be represented as str (e.g. 'S', 'SA', 'PA')
                        tcp_flags = str(tcp_layer.flags)
                    elif raw_pkt.haslayer(UDP):
                        protocol = "udp"
                        udp_layer = raw_pkt[UDP]
                        src_port = int(udp_layer.sport)
                        dst_port = int(udp_layer.dport)

                        # Inspect for DNS query
                        if raw_pkt.haslayer(DNS):
                            dns_layer = raw_pkt[DNS]
                            # Look for standard query question (qd)
                            qd_field = dns_layer.qd
                            if qd_field is not None:
                                # In newer scapy versions, qd can be a PacketListField or single layer
                                qd_first = qd_field[0] if isinstance(qd_field, list) or hasattr(qd_field, "__getitem__") else qd_field
                                if hasattr(qd_first, "qname") and qd_first.qname:
                                    qname = qd_first.qname
                                    if isinstance(qname, bytes):
                                        qname_str = qname.decode("utf-8", errors="ignore")
                                    else:
                                        qname_str = str(qname)
                                    dns_query = qname_str.rstrip(".").lower()
                    elif raw_pkt.haslayer(ICMP):
                        protocol = "icmp"
                    else:
                        protocol = "other"

                    pkt_info = PacketInfo(
                        timestamp=timestamp,
                        length=length,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol=protocol,
                        src_port=src_port,
                        dst_port=dst_port,
                        tcp_flags=tcp_flags,
                        dns_query=dns_query,
                    )
                    self.stats.parsed_packets += 1
                    yield pkt_info

                except Exception as exc:  # noqa: BLE001
                    # Never crash the streaming loop on malformed packets
                    self.stats.malformed_packets += 1
                    logger.debug("Malformed packet skipped at index %d: %s", self.stats.total_packets, exc)
