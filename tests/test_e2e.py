"""End-to-end integration tests for PacketWarden CLI and analysis engine."""

import json
import os
import tempfile

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from packetwarden.cli import main
from tests.helpers import create_temp_pcap, make_dns_query, make_tcp_handshake


def test_end_to_end_analysis_mixed_traffic(capsys):
    packets = []
    base_t = 1000.0

    # 1. Normal TCP handshake to port 80 (Allowed)
    normal_flow = make_tcp_handshake(
        src_ip="192.168.1.10",
        dst_ip="93.184.216.34",
        sport=50000,
        dport=80,
        base_time=base_t,
    )
    packets.extend(normal_flow)

    # 2. Port scan: 18 distinct ports probed by 192.168.1.200 (Blocked by policy & triggers PortScan Alert)
    for p in range(1, 19):
        syn = (
            Ether()
            / IP(src="192.168.1.200", dst="10.0.0.5")
            / TCP(sport=60000 + p, dport=p, flags="S")
        )
        syn.time = base_t + 1.0 + (p * 0.05)
        packets.append(syn)

    # 3. DNS queries: 1 normal, 1 tunneling pattern (16 unique subdomains under attack.org)
    normal_dns = make_dns_query(
        qname="docs.python.org",
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        time=base_t + 2.0,
    )
    packets.append(normal_dns)

    for i in range(16):
        tunnel_dns = make_dns_query(
            qname=f"sub{i}.attack.org",
            src_ip="192.168.1.99",
            dst_ip="8.8.8.8",
            time=base_t + 2.1 + (i * 0.02),
        )
        packets.append(tunnel_dns)

    pcap_path = create_temp_pcap(packets)

    # Create rules file: allow 192.168.1.10 to port 80 and DNS to 8.8.8.8, deny the rest
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as rf:
        rf.write(
            "DEFAULT DENY\n"
            "ALLOW tcp 192.168.1.10:any -> any:80\n"
            "ALLOW udp any:any -> 8.8.8.8:53\n"
        )
        rules_path = rf.name

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as jf:
        report_json_path = jf.name

    try:
        # Run CLI analysis
        exit_code = main(["analyze", pcap_path, "--rules", rules_path, "--report", report_json_path])

        # Because port scan and DNS tunneling produce HIGH severity alerts, exit code must be 1
        assert exit_code == 1

        # Verify JSON report structure and contents
        with open(report_json_path, "r", encoding="utf-8") as jf:
            report_data = json.load(jf)

        assert report_data["parse_stats"]["parsed_packets"] == len(packets)
        assert report_data["firewall_stats"]["allowed_count"] > 0
        assert report_data["firewall_stats"]["blocked_count"] > 0
        assert report_data["alert_summary"]["total_alerts"] >= 2
        assert report_data["alert_summary"]["high_severity"] >= 1

        detector_names = {a["detector_name"] for a in report_data["alerts"]}
        assert "PortScanDetector" in detector_names
        assert "DnsAnomalyDetector" in detector_names

        # Verify terminal capture output
        captured = capsys.readouterr()
        assert "PACKETWARDEN ANALYSIS REPORT" in captured.out
        assert "FIREWALL EVALUATION:" in captured.out
        assert "SECURITY ALERTS DETECTED" in captured.out

    finally:
        for p in (pcap_path, rules_path, report_json_path):
            if os.path.exists(p):
                os.remove(p)
