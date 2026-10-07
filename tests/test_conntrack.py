"""Unit tests for stateful TCP connection tracking."""

from packetwarden.conntrack import ConnectionTracker, FlowKey, TcpState
from packetwarden.models import PacketInfo


def make_pkt(
    time: float,
    src: str,
    dst: str,
    sport: int,
    dport: int,
    flags: str,
    length: int = 60,
) -> PacketInfo:
    return PacketInfo(
        timestamp=time,
        length=length,
        src_ip=src,
        dst_ip=dst,
        protocol="tcp",
        src_port=sport,
        dst_port=dport,
        tcp_flags=flags,
    )


def test_full_tcp_handshake_data_and_teardown():
    tracker = ConnectionTracker()
    client_ip, srv_ip = "192.168.1.100", "93.184.216.34"
    cport, sport = 54321, 80

    # 1. SYN
    syn = make_pkt(100.0, client_ip, srv_ip, cport, sport, "S")
    conn, is_reply = tracker.process_packet(syn)
    assert conn is not None
    assert conn.state == TcpState.NEW
    assert is_reply is False

    # 2. SYN-ACK
    synack = make_pkt(100.02, srv_ip, client_ip, sport, cport, "SA")
    conn, is_reply = tracker.process_packet(synack)
    assert conn is not None
    assert conn.state == TcpState.SYN_RECEIVED
    assert is_reply is True

    # 3. ACK completing handshake
    ack = make_pkt(100.04, client_ip, srv_ip, cport, sport, "A")
    conn, is_reply = tracker.process_packet(ack)
    assert conn is not None
    assert conn.state == TcpState.ESTABLISHED
    assert is_reply is False

    # 4. Data transfer
    data_client = make_pkt(100.1, client_ip, srv_ip, cport, sport, "PA", length=200)
    conn, is_reply = tracker.process_packet(data_client)
    assert conn.state == TcpState.ESTABLISHED

    data_srv = make_pkt(100.15, srv_ip, client_ip, sport, cport, "PA", length=1500)
    conn, is_reply = tracker.process_packet(data_srv)
    assert conn.state == TcpState.ESTABLISHED
    assert is_reply is True

    # 5. Teardown: Client FIN
    fin_c = make_pkt(100.5, client_ip, srv_ip, cport, sport, "FA")
    conn, _ = tracker.process_packet(fin_c)
    assert conn.state == TcpState.CLOSING
    assert conn.fin_initiator is True

    # Server FIN-ACK
    fin_s = make_pkt(100.52, srv_ip, client_ip, sport, cport, "FA")
    conn, _ = tracker.process_packet(fin_s)
    assert conn.fin_responder is True

    # Final ACK from client closes state
    final_ack = make_pkt(100.54, client_ip, srv_ip, cport, sport, "A")
    conn, _ = tracker.process_packet(final_ack)
    assert conn.state == TcpState.CLOSED


def test_unsolicited_reply_without_prior_state_is_dropped():
    tracker = ConnectionTracker()
    # Inbound SYN-ACK or ACK with no prior SYN seen
    unsolicited = make_pkt(100.0, "93.184.216.34", "192.168.1.100", 80, 54321, "SA")
    conn, _is_reply = tracker.process_packet(unsolicited)
    assert conn is None
    assert len(tracker.table) == 0


def test_rst_immediately_closes_connection():
    tracker = ConnectionTracker()
    syn = make_pkt(100.0, "192.168.1.10", "10.0.0.1", 1000, 80, "S")
    conn, _ = tracker.process_packet(syn)
    assert conn.state == TcpState.NEW

    rst = make_pkt(100.05, "10.0.0.1", "192.168.1.10", 80, 1000, "R")
    conn, is_reply = tracker.process_packet(rst)
    assert conn is not None
    assert conn.state == TcpState.CLOSED
    assert is_reply is True


def test_idle_timeout_expiration():
    tracker = ConnectionTracker(idle_timeout=60.0, tcp_syn_timeout=10.0)
    # Establish connection at t=100.0
    tracker.process_packet(make_pkt(100.0, "10.0.0.1", "10.0.0.2", 1111, 80, "S"))
    tracker.process_packet(make_pkt(100.01, "10.0.0.2", "10.0.0.1", 80, 1111, "SA"))
    tracker.process_packet(make_pkt(100.02, "10.0.0.1", "10.0.0.2", 1111, 80, "A"))
    assert len(tracker.table) == 1

    # Packet at t=150.0 (within 60s idle timeout) keeps it alive
    tracker.process_packet(make_pkt(150.0, "10.0.0.1", "10.0.0.2", 1111, 80, "A"))
    assert len(tracker.table) == 1

    # Unrelated packet at t=220.0 (>60s since 150.0) triggers expiration
    tracker.process_packet(make_pkt(220.0, "10.0.0.5", "10.0.0.6", 2222, 443, "S"))
    key_old = FlowKey.from_endpoints("tcp", "10.0.0.1", 1111, "10.0.0.2", 80)
    assert key_old not in tracker.table
    assert tracker.expired_count == 1


def test_duplicate_or_reordered_packets_do_not_corrupt_state():
    tracker = ConnectionTracker()
    tracker.process_packet(make_pkt(10.0, "1.1.1.1", "2.2.2.2", 5000, 80, "S"))
    # Duplicate SYN
    conn, _ = tracker.process_packet(make_pkt(10.5, "1.1.1.1", "2.2.2.2", 5000, 80, "S"))
    assert conn.state == TcpState.NEW

    tracker.process_packet(make_pkt(10.6, "2.2.2.2", "1.1.1.1", 80, 5000, "SA"))
    # Duplicate SYN-ACK
    conn, _ = tracker.process_packet(make_pkt(10.7, "2.2.2.2", "1.1.1.1", 80, 5000, "SA"))
    assert conn.state == TcpState.SYN_RECEIVED
