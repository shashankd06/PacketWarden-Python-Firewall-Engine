"""Helper functions to generate test PCAP captures using Scapy."""

import tempfile

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap


def create_temp_pcap(packets: list) -> str:
    """Write packets to a temporary .pcap file and return its path."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as temp_file:
        file_path = temp_file.name
    wrpcap(file_path, packets)
    return file_path


def make_tcp_handshake(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    sport: int = 12345,
    dport: int = 80,
    base_time: float = 1000.0,
) -> list:
    """Generate SYN, SYN-ACK, ACK handshake packets."""
    syn = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S", seq=100)
    syn.time = base_time

    synack = Ether() / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=200, ack=101)
    synack.time = base_time + 0.01

    ack = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A", seq=101, ack=201)
    ack.time = base_time + 0.02

    return [syn, synack, ack]


def make_udp_packet(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "8.8.8.8",
    sport: int = 50000,
    dport: int = 53,
    time: float = 1000.0,
) -> Ether:
    """Generate a standard UDP datagram."""
    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / b"hello udp"
    pkt.time = time
    return pkt


def make_dns_query(
    qname: str = "example.com",
    src_ip: str = "192.168.1.10",
    dst_ip: str = "8.8.8.8",
    sport: int = 53000,
    dport: int = 53,
    time: float = 1000.0,
) -> Ether:
    """Generate a DNS question query packet."""
    pkt = (
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=dport)
        / DNS(rd=1, qd=DNSQR(qname=qname))
    )
    pkt.time = time
    return pkt


def make_icmp_echo(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "1.1.1.1",
    time: float = 1000.0,
) -> Ether:
    """Generate an ICMP Echo Request packet."""
    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / ICMP(type=8, code=0)
    pkt.time = time
    return pkt


def make_arp_packet(time: float = 1000.0) -> Ether:
    """Generate an ARP broadcast packet (non-IP)."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1")
    pkt.time = time
    return pkt

