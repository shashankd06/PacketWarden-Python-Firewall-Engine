"""Unit tests for attack detectors: PortScan, SynFlood, and DnsAnomaly.

Covers positive triggers, benign negative scenarios, and exact boundary threshold tests.
"""

from packetwarden.conntrack import ConnectionTracker
from packetwarden.detectors.dns import DnsAnomalyDetector
from packetwarden.detectors.portscan import PortScanDetector
from packetwarden.detectors.synflood import SynFloodDetector
from packetwarden.models import PacketInfo

# ==========================================
# 1. Port Scan Detector Tests
# ==========================================

def test_portscan_positive_and_boundary():
    detector = PortScanDetector(port_threshold=10, time_window=10.0)

    # Under boundary: 9 distinct ports probed with SYN
    alerts = []
    for port in range(1, 10):
        pkt = PacketInfo(
            timestamp=100.0 + (port * 0.1),
            length=60,
            src_ip="192.168.1.55",
            dst_ip="10.0.0.1",
            protocol="tcp",
            src_port=40000 + port,
            dst_port=port,
            tcp_flags="S",
        )
        alerts.extend(detector.process_packet(pkt))
    assert len(alerts) == 0  # Under threshold (9 < 10)

    # Exactly reaches threshold: 10th distinct port
    pkt_boundary = PacketInfo(
        timestamp=101.0,
        length=60,
        src_ip="192.168.1.55",
        dst_ip="10.0.0.1",
        protocol="tcp",
        src_port=40010,
        dst_port=10,
        tcp_flags="S",
    )
    alerts.extend(detector.process_packet(pkt_boundary))
    assert len(alerts) == 1
    assert alerts[0].detector_name == "PortScanDetector"
    assert alerts[0].severity == "HIGH"  # Pure SYNs -> stealth/SYN scan
    assert alerts[0].evidence["distinct_ports"] == 10


def test_portscan_negative_benign_traffic():
    detector = PortScanDetector(port_threshold=10, time_window=10.0)
    tracker = ConnectionTracker()

    # Normal browser traffic: many requests to only 2 distinct ports (80 and 443)
    alerts = []
    for i in range(50):
        target_port = 80 if i % 2 == 0 else 443
        pkt = PacketInfo(
            timestamp=100.0 + (i * 0.05),
            length=60,
            src_ip="192.168.1.55",
            dst_ip="93.184.216.34",
            protocol="tcp",
            src_port=50000 + i,
            dst_port=target_port,
            tcp_flags="S",
        )
        conn, _ = tracker.process_packet(pkt)
        alerts.extend(detector.process_packet(pkt, conn))

    assert len(alerts) == 0


# ==========================================
# 2. SYN Flood Detector Tests
# ==========================================

def test_synflood_positive_and_boundary():
    detector = SynFloodDetector(syn_threshold=20, time_window=5.0, max_completion_ratio=0.1)

    # 19 SYNs without completion (under threshold)
    alerts = []
    for i in range(19):
        pkt = PacketInfo(
            timestamp=10.0 + (i * 0.1),
            length=60,
            src_ip=f"172.16.0.{i}",
            dst_ip="192.168.1.1",
            protocol="tcp",
            src_port=10000 + i,
            dst_port=80,
            tcp_flags="S",
        )
        alerts.extend(detector.process_packet(pkt))
    assert len(alerts) == 0

    # 20th SYN reaches threshold with 0 completed handshakes -> Trigger HIGH Alert
    pkt20 = PacketInfo(
        timestamp=12.0,
        length=60,
        src_ip="172.16.0.20",
        dst_ip="192.168.1.1",
        protocol="tcp",
        src_port=10020,
        dst_port=80,
        tcp_flags="S",
    )
    alerts.extend(detector.process_packet(pkt20))
    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["syn_count"] == 20
    assert alerts[0].evidence["completed_count"] == 0


def test_synflood_negative_healthy_high_volume():
    detector = SynFloodDetector(syn_threshold=20, time_window=5.0, max_completion_ratio=0.1)
    tracker = ConnectionTracker()

    # 30 SYNs that all complete 3-way handshakes
    alerts = []
    for i in range(30):
        t = 10.0 + (i * 0.1)
        client = f"10.0.0.{i % 5}"
        cport = 20000 + i
        syn = PacketInfo(timestamp=t, length=60, src_ip=client, dst_ip="192.168.1.1", protocol="tcp", src_port=cport, dst_port=80, tcp_flags="S")
        conn, _ = tracker.process_packet(syn)
        alerts.extend(detector.process_packet(syn, conn))

        # SYN-ACK
        synack = PacketInfo(timestamp=t + 0.01, length=60, src_ip="192.168.1.1", dst_ip=client, protocol="tcp", src_port=80, dst_port=cport, tcp_flags="SA")
        conn, _ = tracker.process_packet(synack)
        detector.process_packet(synack, conn)

        # ACK (ESTABLISHED)
        ack = PacketInfo(timestamp=t + 0.02, length=60, src_ip=client, dst_ip="192.168.1.1", protocol="tcp", src_port=cport, dst_port=80, tcp_flags="A")
        conn, _ = tracker.process_packet(ack)
        detector.process_packet(ack, conn)

    # Because handshakes complete (100% completion ratio), no alert should fire
    assert len(alerts) == 0


# ==========================================
# 3. DNS Anomaly Detector Tests
# ==========================================

def test_dns_anomalies_positive_negative_and_boundary():
    detector = DnsAnomalyDetector(
        max_qname_length=50,
        rate_threshold=10,
        subdomain_diversity_threshold=5,
        time_window=10.0,
    )

    # A) Long QNAME exfiltration check
    normal_dns = PacketInfo(
        timestamp=1.0, length=70, src_ip="192.168.1.10", dst_ip="8.8.8.8", protocol="udp", src_port=53000, dst_port=53, dns_query="api.github.com"
    )
    alerts = detector.process_packet(normal_dns)
    assert len(alerts) == 0

    long_dns = PacketInfo(
        timestamp=2.0, length=120, src_ip="192.168.1.10", dst_ip="8.8.8.8", protocol="udp", src_port=53000, dst_port=53,
        dns_query="a" * 55 + ".exfiltrate.com"
    )
    alerts = detector.process_packet(long_dns)
    assert len(alerts) == 1
    assert alerts[0].evidence["anomaly_type"] == "Excessive Query Length"

    # B) Tunneling / Subdomain diversity test
    tunnel_detector = DnsAnomalyDetector(
        max_qname_length=100,
        rate_threshold=50,
        subdomain_diversity_threshold=5,
        time_window=10.0,
    )

    # 4 distinct subdomains (under threshold 5)
    for i in range(4):
        pkt = PacketInfo(
            timestamp=10.0 + i, length=70, src_ip="192.168.1.20", dst_ip="8.8.8.8", protocol="udp", src_port=53001, dst_port=53,
            dns_query=f"chunk{i}.tunnel.evil.org"
        )
        assert len(tunnel_detector.process_packet(pkt)) == 0

    # 5th distinct subdomain hits threshold
    pkt5 = PacketInfo(
        timestamp=15.0, length=70, src_ip="192.168.1.20", dst_ip="8.8.8.8", protocol="udp", src_port=53001, dst_port=53,
        dns_query="chunk4.tunnel.evil.org"
    )
    alerts5 = tunnel_detector.process_packet(pkt5)
    assert len(alerts5) == 1
    assert alerts5[0].severity == "HIGH"
    assert alerts5[0].evidence["unique_subdomains"] == 5
    assert alerts5[0].evidence["parent_domain"] == "evil.org"
