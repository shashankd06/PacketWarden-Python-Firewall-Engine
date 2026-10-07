"""Stateful TCP connection tracking engine for PacketWarden.

Maintains bidirectional flow states indexed by a canonical 5-tuple key.
States tracked:
  - NEW: Initial SYN seen from originator.
  - SYN_RECEIVED: SYN-ACK reply seen from responder.
  - ESTABLISHED: Handshake completed (ACK) or ongoing data flow.
  - CLOSING: FIN teardown initiated.
  - CLOSED: Teardown complete (FIN/ACK exchange or RST).

Stateful filtering principle:
  Packets belonging to an ESTABLISHED or valid ongoing connection that was initiated
  from an allowed direction are permitted. Inbound packets that arrive with ACK, FIN,
  or data but have no tracked connection table entry are unsolicited replies / rogue
  packets and are dropped.
"""

from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum

from packetwarden.models import PacketInfo


class TcpState(str, Enum):
    NEW = "NEW"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"


class UdpState(str, Enum):
    ACTIVE = "ACTIVE"


@dataclass(slots=True, frozen=True)
class FlowKey:
    """Canonical 5-tuple flow key ensuring bidirectional traffic maps to the same entry."""

    proto: str
    ip1: str
    port1: int
    ip2: str
    port2: int

    @classmethod
    def from_endpoints(
        cls, proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int
    ) -> "FlowKey":
        """Sort endpoints lexicographically so (A:p1 -> B:p2) and (B:p2 -> A:p1) yield identical keys."""
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return cls(proto, src_ip, src_port, dst_ip, dst_port)
        return cls(proto, dst_ip, dst_port, src_ip, src_port)


@dataclass(slots=True)
class TcpConnection:
    """Represents the tracked state and metadata of a TCP connection."""

    key: FlowKey
    initiator_ip: str
    initiator_port: int
    responder_ip: str
    responder_port: int
    state: TcpState
    last_seen: float
    packets_count: int = 1
    bytes_count: int = 0
    fin_initiator: bool = False
    fin_responder: bool = False

    def is_from_initiator(self, src_ip: str, src_port: int) -> bool:
        return src_ip == self.initiator_ip and src_port == self.initiator_port


@dataclass(slots=True)
class UdpFlow:
    """Represents the pseudo-state and metadata of a UDP flow."""

    key: FlowKey
    initiator_ip: str
    initiator_port: int
    responder_ip: str
    responder_port: int
    state: UdpState
    last_seen: float
    packets_count: int = 1
    bytes_count: int = 0

    def is_from_initiator(self, src_ip: str, src_port: int) -> bool:
        return src_ip == self.initiator_ip and src_port == self.initiator_port


Flow = TcpConnection | UdpFlow


class ConnectionTracker:
    """Stateful connection tracker for TCP and UDP with bounded table size and idle timeouts."""

    def __init__(
        self,
        idle_timeout: float = 300.0,  # 5 minutes idle timeout for TCP
        tcp_syn_timeout: float = 30.0,  # TCP Handshake timeout
        udp_idle_timeout: float = 30.0,  # Standard UDP flow idle timeout
        udp_dns_timeout: float = 5.0,  # Shorter timeout for DNS (port 53)
        max_table_size: int = 100_000,
    ) -> None:
        self.idle_timeout = idle_timeout
        self.tcp_syn_timeout = tcp_syn_timeout
        self.udp_idle_timeout = udp_idle_timeout
        self.udp_dns_timeout = udp_dns_timeout
        self.max_table_size = max_table_size
        # LRU ordering: OrderedDict key -> Flow (TcpConnection or UdpFlow)
        self.table: OrderedDict[FlowKey, Flow] = OrderedDict()
        self.expired_count: int = 0
        self.evicted_count: int = 0

    def cleanup_expired(self, current_time: float) -> None:
        """Evict flows that exceeded idle timeouts relative to packet timestamp."""
        keys_to_remove: list[FlowKey] = []
        for key, flow in self.table.items():
            if isinstance(flow, TcpConnection):
                timeout = (
                    self.tcp_syn_timeout
                    if flow.state in (TcpState.NEW, TcpState.SYN_RECEIVED)
                    else self.idle_timeout
                )
            else:  # UdpFlow
                # Shorter timeout for DNS queries/replies (port 53)
                is_dns = flow.initiator_port == 53 or flow.responder_port == 53
                timeout = self.udp_dns_timeout if is_dns else self.udp_idle_timeout

            if current_time - flow.last_seen > timeout:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.table[key]
            self.expired_count += 1

    def create_udp_flow(self, pkt: PacketInfo) -> UdpFlow | None:
        """Create a new UDP flow entry when an outbound packet is allowed by policy."""
        if not pkt.is_udp or pkt.src_port is None or pkt.dst_port is None:
            return None

        self.cleanup_expired(pkt.timestamp)

        key = FlowKey.from_endpoints(
            pkt.protocol, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port
        )
        if key in self.table:
            flow = self.table[key]
            if isinstance(flow, UdpFlow):
                self.table.move_to_end(key)
                flow.last_seen = pkt.timestamp
                flow.packets_count += 1
                flow.bytes_count += pkt.length
                return flow

        # Enforce max capacity by evicting oldest item (LRU)
        if len(self.table) >= self.max_table_size:
            self.table.popitem(last=False)
            self.evicted_count += 1

        flow = UdpFlow(
            key=key,
            initiator_ip=pkt.src_ip,
            initiator_port=pkt.src_port,
            responder_ip=pkt.dst_ip,
            responder_port=pkt.dst_port,
            state=UdpState.ACTIVE,
            last_seen=pkt.timestamp,
            bytes_count=pkt.length,
        )
        self.table[key] = flow
        return flow

    def process_packet(
        self, pkt: PacketInfo
    ) -> tuple[Flow | None, bool]:
        """Track packet through connection state machine.

        Returns:
            tuple[Flow | None, bool]:
              - Flow instance (or None if untracked / non-TCP/UDP)
              - is_reply: True if packet originated from responder back to initiator
        """
        if pkt.src_port is None or pkt.dst_port is None:
            return None, False

        # Evict timed out connections periodically
        self.cleanup_expired(pkt.timestamp)

        key = FlowKey.from_endpoints(
            pkt.protocol, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port
        )

        # Handle UDP packets
        if pkt.is_udp:
            flow = self.table.get(key)
            if flow is None:
                # Unsolicited UDP or initial packet before rule approval
                return None, False

            # Existing UDP flow: refresh last_seen and increment counters
            self.table.move_to_end(key)
            flow.last_seen = pkt.timestamp
            flow.packets_count += 1
            flow.bytes_count += pkt.length
            is_reply = not flow.is_from_initiator(pkt.src_ip, pkt.src_port)
            return flow, is_reply

        # Handle TCP packets
        if not pkt.is_tcp:
            return None, False

        flags = pkt.tcp_flag_set
        has_syn = "S" in flags
        has_ack = "A" in flags
        has_fin = "F" in flags
        has_rst = "R" in flags

        flow = self.table.get(key)

        if flow is None:
            # Enforce max capacity by evicting oldest item (LRU)
            if len(self.table) >= self.max_table_size:
                self.table.popitem(last=False)
                self.evicted_count += 1

            # Only a pure SYN (no ACK, no RST, no FIN) can legitimately initiate a new connection
            if has_syn and not has_ack and not has_rst:
                conn = TcpConnection(
                    key=key,
                    initiator_ip=pkt.src_ip,
                    initiator_port=pkt.src_port,
                    responder_ip=pkt.dst_ip,
                    responder_port=pkt.dst_port,
                    state=TcpState.NEW,
                    last_seen=pkt.timestamp,
                    bytes_count=pkt.length,
                )
                self.table[key] = conn
                return conn, False

            # If it's not a SYN (e.g. unsolicited ACK, FIN, or data without prior state),
            # it is untracked and dropped by stateful inspection.
            return None, False

        # Existing connection: Move to MRU position
        if not isinstance(flow, TcpConnection):
            return None, False

        conn = flow
        self.table.move_to_end(key)
        conn.last_seen = pkt.timestamp
        conn.packets_count += 1
        conn.bytes_count += pkt.length
        is_reply = not conn.is_from_initiator(pkt.src_ip, pkt.src_port)

        # RST aborts the connection immediately
        if has_rst:
            conn.state = TcpState.CLOSED
            return conn, is_reply

        # State transitions
        if conn.state == TcpState.NEW:
            # Expecting SYN-ACK from responder
            if is_reply and has_syn and has_ack:
                conn.state = TcpState.SYN_RECEIVED
            elif not is_reply and has_syn and not has_ack:
                # Retransmitted SYN
                pass

        elif conn.state == TcpState.SYN_RECEIVED:
            # Expecting ACK from initiator to complete three-way handshake
            if not is_reply and has_ack and not has_syn:
                conn.state = TcpState.ESTABLISHED
            elif is_reply and has_syn and has_ack:
                # Retransmitted SYN-ACK
                pass

        elif conn.state == TcpState.ESTABLISHED:
            # FIN begins teardown
            if has_fin:
                conn.state = TcpState.CLOSING
                if not is_reply:
                    conn.fin_initiator = True
                else:
                    conn.fin_responder = True

        elif conn.state == TcpState.CLOSING:
            if has_fin:
                if not is_reply:
                    conn.fin_initiator = True
                else:
                    conn.fin_responder = True

            # If both parties have sent FIN and ACKs are exchanged, state is CLOSED
            if conn.fin_initiator and conn.fin_responder and has_ack:
                conn.state = TcpState.CLOSED

        return conn, is_reply
