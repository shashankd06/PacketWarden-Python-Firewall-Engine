"""Unit tests for PacketWarden PCAP parser and data models."""

import os

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from packetwarden.parser import PcapParser
from tests.helpers import (
    create_temp_pcap,
    make_arp_packet,
    make_dns_query,
    make_icmp_echo,
    make_tcp_handshake,
    make_udp_packet,
)


def test_parser_normal_and_edge_packets():
    # 1. TCP Handshake (3 pkts)
    tcp_pkts = make_tcp_handshake(src_ip="192.168.1.50", dst_ip="93.184.216.34", sport=45000, dport=80)
    # 2. UDP datagram (1 pkt)
    udp_pkt = make_udp_packet(src_ip="192.168.1.50", dst_ip="8.8.8.8", sport=45001, dport=123)
    # 3. ICMP echo (1 pkt)
    icmp_pkt = make_icmp_echo(src_ip="192.168.1.50", dst_ip="1.1.1.1")
    # 4. DNS query (1 pkt)
    dns_pkt = make_dns_query(qname="portal.example.com", src_ip="192.168.1.50", dst_ip="8.8.8.8")
    # 5. Non-IP packet (ARP) (1 pkt)
    arp_pkt = make_arp_packet()

    # 6. Malformed packet: An IPv4 packet with invalid IHL = 2 (minimum valid IPv4 IHL is 5)
    valid_ip_bytes = bytearray(
        bytes(
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.168.1.99", dst="10.0.0.99")
        )
    )
    valid_ip_bytes[14] = 0x42  # IPv4, IHL = 2
    malformed_pkt = Ether(bytes(valid_ip_bytes))

    packets = tcp_pkts + [udp_pkt, icmp_pkt, dns_pkt, arp_pkt, malformed_pkt]
    pcap_path = create_temp_pcap(packets)

    try:
        parser = PcapParser(pcap_path)
        parsed_list = list(parser.parse_iter())

        assert len(parsed_list) == 6
        assert parser.stats.total_packets == 8
        assert parser.stats.non_ip_packets == 1
        assert parser.stats.malformed_packets == 1
        assert parser.stats.parsed_packets == 6

        # Verify TCP handshake packets
        syn_pkt = parsed_list[0]
        assert syn_pkt.protocol == "tcp"
        assert syn_pkt.src_ip == "192.168.1.50"
        assert syn_pkt.dst_ip == "93.184.216.34"
        assert syn_pkt.src_port == 45000
        assert syn_pkt.dst_port == 80
        assert syn_pkt.tcp_flags == "S"
        assert "S" in syn_pkt.tcp_flag_set

        synack_pkt = parsed_list[1]
        assert synack_pkt.tcp_flags == "SA"

        # Verify UDP
        udp_parsed = parsed_list[3]
        assert udp_parsed.protocol == "udp"
        assert udp_parsed.dst_port == 123

        # Verify ICMP
        icmp_parsed = parsed_list[4]
        assert icmp_parsed.protocol == "icmp"
        assert icmp_parsed.dst_ip == "1.1.1.1"

        # Verify DNS
        dns_parsed = parsed_list[5]
        assert dns_parsed.protocol == "udp"
        assert dns_parsed.dns_query == "portal.example.com"

    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
