"""Generates a small valid sample capture for examples/ and runs performance benchmark."""

import os
import time

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from packetwarden.cli import run_analysis
from packetwarden.config import WardenConfig
from tests.helpers import make_dns_query, make_icmp_echo, make_tcp_handshake


def generate_sample_pcap(path: str) -> None:
    """Generate small (<1MB) realistic multi-protocol capture file for examples/."""
    packets = []
    base_t = 1700000000.0

    # 1. Normal web traffic (Handshake + data)
    for i in range(5):
        handshake = make_tcp_handshake(
            src_ip=f"192.168.1.{10+i}",
            dst_ip="93.184.216.34",
            sport=40000 + i,
            dport=443,
            base_time=base_t + i * 2,
        )
        packets.extend(handshake)

    # 2. DNS queries with matching server replies (demonstrating stateful UDP return flow)
    dns_domains = ["google.com", "github.com", "python.org", "wikipedia.org"]
    for idx, domain in enumerate(dns_domains):
        cport = 53000 + idx
        t_query = base_t + 15.0 + (idx * 0.5)
        # Client query (outbound)
        packets.append(
            make_dns_query(
                qname=domain,
                src_ip="192.168.1.15",
                dst_ip="8.8.8.8",
                sport=cport,
                dport=53,
                time=t_query,
            )
        )
        # Server response (inbound reply permitted statefully)
        packets.append(
            make_dns_query(
                qname=domain,
                src_ip="8.8.8.8",
                dst_ip="192.168.1.15",
                sport=53,
                dport=cport,
                time=t_query + 0.05,
            )
        )

    # 3. ICMP ping
    packets.append(make_icmp_echo(src_ip="192.168.1.20", dst_ip="1.1.1.1", time=base_t + 20.0))

    # 4. Port scan attempt by external reconnaissance IP
    for p in range(1, 18):
        syn = (
            Ether()
            / IP(src="203.0.113.55", dst="192.168.1.1")
            / TCP(sport=50000 + p, dport=p * 50, flags="S")
        )
        syn.time = base_t + 25.0 + (p * 0.05)
        packets.append(syn)

    wrpcap(path, packets)
    print(f"Generated sample capture: {path} ({len(packets)} packets, {os.path.getsize(path)} bytes)")


def benchmark_throughput(num_packets: int = 10_000) -> None:
    """Benchmark raw packet processing throughput (packets/sec)."""
    temp_bench_pcap = "temp_bench.pcap"
    print(f"Synthesizing {num_packets} packets for performance benchmark...")

    packets = []
    base_t = 1000.0
    for i in range(num_packets):
        # Mix of TCP SYNs, ACKs, and UDP queries
        pkt = (
            Ether()
            / IP(src=f"10.0.{i % 250}.{(i // 250) % 250}", dst="192.168.1.1")
            / TCP(sport=1024 + (i % 60000), dport=80, flags="S")
        )
        pkt.time = base_t + (i * 0.001)
        packets.append(pkt)

    wrpcap(temp_bench_pcap, packets)
    file_size_mb = os.path.getsize(temp_bench_pcap) / (1024 * 1024)
    print(f"Bench PCAP generated ({file_size_mb:.2f} MB). Running analysis pipeline...")

    config = WardenConfig()
    start_time = time.perf_counter()
    report = run_analysis(temp_bench_pcap, config=config)
    elapsed = time.perf_counter() - start_time

    pps = report.parse_stats.parsed_packets / elapsed
    print("\nBENCHMARK RESULTS:")
    print(f"  Total Packets:    {report.parse_stats.parsed_packets}")
    print(f"  Elapsed Time:     {elapsed:.3f} seconds")
    print(f"  Throughput:       {pps:.1f} packets/second")

    if os.path.exists(temp_bench_pcap):
        os.remove(temp_bench_pcap)


if __name__ == "__main__":
    sample_path = os.path.join("examples", "sample_capture.pcap")
    generate_sample_pcap(sample_path)
    benchmark_throughput(num_packets=10_000)
