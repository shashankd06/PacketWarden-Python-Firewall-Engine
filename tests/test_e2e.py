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
        sport=53000,
        dport=53,
        time=base_t + 2.0,
    )
    packets.append(normal_dns)

    # Inbound DNS reply matching the outbound UDP query (testing stateful UDP return flow)
    dns_reply = make_dns_query(
        qname="docs.python.org",
        src_ip="8.8.8.8",
        dst_ip="192.168.1.10",
        sport=53,
        dport=53000,
        time=base_t + 2.05,
    )
    packets.append(dns_reply)

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
        assert report_data["firewall_stats"]["stateful_permitted_replies"] > 0
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


def test_cli_stateless_flag():
    # Verify --no-stateful disables stateful connection tracking
    pkt = make_tcp_handshake(src_ip="192.168.1.10", dst_ip="10.0.0.1")[0]
    pcap_path = create_temp_pcap([pkt])
    try:
        exit_code = main(["analyze", pcap_path, "--no-stateful"])
        assert exit_code == 0
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)


def test_tcp_stateful_handshake_and_unsolicited_reply():
    """Verify stateful vs stateless behavior for TCP.

    - 1 complete outbound TCP handshake (SYN, SYN-ACK, ACK) plus data (client -> server and server -> client)
    - 1 unsolicited inbound SYN-ACK (server -> client on unknown port)
    - Policy: DEFAULT DENY, ALLOW tcp 192.168.1.10:any -> any:80

    In stateful mode:
      - Outbound packets (SYN, ACK, client data) are allowed by rule.
      - Return reply packets (SYN-ACK, server data reply) are allowed by stateful conntrack.
      - Stateful flow matches counter is >= 1 (SYN-ACK + server data = 2 matches).
      - Unsolicited inbound SYN-ACK is blocked (stateful drop).

    In --no-stateful mode:
      - Return reply packets from server are blocked because they match no inbound ALLOW rule.
      - Stateful flow matches is 0.
    """
    base_t = 2000.0
    client_ip = "192.168.1.10"
    server_ip = "93.184.216.34"

    # Outbound handshake: SYN, SYN-ACK, ACK
    handshake = make_tcp_handshake(
        src_ip=client_ip,
        dst_ip=server_ip,
        sport=54321,
        dport=80,
        base_time=base_t,
    )

    # Client data (outbound)
    client_data = (
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=54321, dport=80, flags="PA", seq=102, ack=202)
        / b"GET / HTTP/1.1\r\n\r\n"
    )
    client_data.time = base_t + 0.03

    # Server data reply (inbound return traffic)
    server_reply = (
        Ether()
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=80, dport=54321, flags="PA", seq=202, ack=120)
        / b"HTTP/1.1 200 OK\r\n\r\n"
    )
    server_reply.time = base_t + 0.05

    # Unsolicited inbound SYN-ACK (no prior outbound SYN)
    unsolicited_synack = (
        Ether()
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=8080, dport=59999, flags="SA", seq=500, ack=1)
    )
    unsolicited_synack.time = base_t + 0.10

    packets = handshake + [client_data, server_reply, unsolicited_synack]
    pcap_path = create_temp_pcap(packets)

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as rf:
        rf.write(
            "DEFAULT DENY\n"
            "ALLOW tcp 192.168.1.10:any -> any:80\n"
        )
        rules_path = rf.name

    try:
        from packetwarden.cli import run_analysis
        from packetwarden.config import WardenConfig

        # 1. Stateful mode
        rep_stateful = run_analysis(pcap_path, rules_path, WardenConfig(stateful_mode=True))
        # Total packets: 3 (handshake) + 2 (data/reply) + 1 (unsolicited) = 6 packets
        assert rep_stateful.parse_stats.parsed_packets == 6
        # Server replies (SYN-ACK and HTTP data response) permitted by conntrack
        assert rep_stateful.firewall_stats.stateful_permitted_replies >= 1
        # Unsolicited packet is blocked
        assert rep_stateful.firewall_stats.blocked_count >= 1
        # In stateful mode, all 5 legitimate packets are allowed, 1 unsolicited blocked
        assert rep_stateful.firewall_stats.allowed_count == 5
        assert rep_stateful.firewall_stats.blocked_count == 1

        # 2. Stateless mode (--no-stateful)
        rep_stateless = run_analysis(pcap_path, rules_path, WardenConfig(stateful_mode=False))
        # In stateless mode: server replies cannot match outbound rule (src=192.168.1.10)
        # So SYN-ACK and server reply are blocked!
        assert rep_stateless.firewall_stats.stateful_permitted_replies == 0
        # Outbound packets allowed: SYN, client ACK, client data = 3
        assert rep_stateless.firewall_stats.allowed_count == 3
        # Inbound packets blocked: server SYN-ACK, server reply, unsolicited SYN-ACK = 3
        assert rep_stateless.firewall_stats.blocked_count == 3
    finally:
        for p in (pcap_path, rules_path):
            if os.path.exists(p):
                os.remove(p)
