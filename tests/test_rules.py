"""Unit tests for the stateless rule engine."""

import pytest

from packetwarden.models import PacketInfo
from packetwarden.rules import RuleEngine, RuleParseError


def test_rule_parsing_and_first_match_wins():
    rules_text = """
    # Firewall Ruleset Test
    DEFAULT DENY

    ALLOW tcp 192.168.1.0/24:any -> any:80,443
    DENY tcp 192.168.1.50:any -> any:80
    ALLOW udp any:any -> 8.8.8.8:53
    ALLOW icmp 192.168.1.0/24 -> any
    """
    engine = RuleEngine.from_string(rules_text)
    assert len(engine.rules) == 4
    assert engine.default_action == "DENY"

    # Packet from 192.168.1.50 to port 80 matches the FIRST rule (ALLOW), even though rule 2 is DENY
    pkt1 = PacketInfo(
        timestamp=1.0,
        length=60,
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",
        protocol="tcp",
        src_port=49000,
        dst_port=80,
    )
    action1, rule1 = engine.evaluate(pkt1)
    assert action1 == "ALLOW"
    assert rule1 is not None
    assert rule1.line_num == 5

    # Packet from outside subnet to port 80 falls through to DEFAULT DENY
    pkt_outside = PacketInfo(
        timestamp=1.0,
        length=60,
        src_ip="10.0.0.5",
        dst_ip="93.184.216.34",
        protocol="tcp",
        src_port=49000,
        dst_port=80,
    )
    action_out, rule_out = engine.evaluate(pkt_outside)
    assert action_out == "DENY"
    assert rule_out is None


def test_port_ranges_and_default_allow():
    rules_text = """
    DEFAULT ALLOW
    DENY tcp any:any -> any:1-1024
    """
    engine = RuleEngine.from_string(rules_text)
    assert engine.default_action == "ALLOW"

    # Port in range 1-1024 is blocked
    blocked_pkt = PacketInfo(
        timestamp=1.0,
        length=60,
        src_ip="1.2.3.4",
        dst_ip="5.6.7.8",
        protocol="tcp",
        src_port=50000,
        dst_port=443,
    )
    action, rule = engine.evaluate(blocked_pkt)
    assert action == "DENY"
    assert rule is not None

    # High port is allowed via DEFAULT ALLOW
    allowed_pkt = PacketInfo(
        timestamp=1.0,
        length=60,
        src_ip="1.2.3.4",
        dst_ip="5.6.7.8",
        protocol="tcp",
        src_port=50000,
        dst_port=8080,
    )
    action, rule = engine.evaluate(allowed_pkt)
    assert action == "ALLOW"
    assert rule is None


def test_invalid_rules_raise_informative_errors():
    # Bad token count
    with pytest.raises(RuleParseError) as exc1:
        RuleEngine.from_string("ALLOW tcp 1.1.1.1 ->")
    assert "Line 1" in str(exc1.value)

    # Bad action
    with pytest.raises(RuleParseError) as exc2:
        RuleEngine.from_string("PERMIT tcp any -> any")
    assert "Invalid action" in str(exc2.value)

    # Bad protocol
    with pytest.raises(RuleParseError) as exc3:
        RuleEngine.from_string("ALLOW bogus_proto any -> any")
    assert "Invalid protocol" in str(exc3.value)

    # Bad CIDR
    with pytest.raises(RuleParseError) as exc4:
        RuleEngine.from_string("ALLOW tcp 999.999.999.999 -> any")
    assert "Invalid IP address or CIDR network" in str(exc4.value)

    # Bad port range (start > end)
    with pytest.raises(RuleParseError) as exc5:
        RuleEngine.from_string("ALLOW tcp any:500-100 -> any")
    assert "Invalid port range" in str(exc5.value)

    # Bad DEFAULT directive
    with pytest.raises(RuleParseError) as exc6:
        RuleEngine.from_string("DEFAULT MAYBE")
    assert "Invalid DEFAULT directive" in str(exc6.value)
