from __future__ import annotations

import json
import socket
import threading
from datetime import datetime, timezone

from logsalvo.receiver import ReceiverConfig, SyslogReceiver, export_messages, parse_syslog


def free_port(socktype: int) -> int:
    with socket.socket(socket.AF_INET, socktype) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_receiver_accepts_privileged_port_configuration() -> None:
    assert ReceiverConfig(port=514).port == 514


def test_parse_rfc5424() -> None:
    parsed = parse_syslog(
        b'<134>1 2026-08-01T12:30:00Z router1 bgpd 42 SESSION [site@1 name="lon"] peer up',
        sender="192.0.2.10",
        sender_port=50000,
        protocol="udp",
    )
    assert parsed.format == "RFC5424"
    assert parsed.facility_name == "local0"
    assert parsed.severity_name == "info"
    assert parsed.hostname == "router1"
    assert parsed.app == "bgpd"
    assert parsed.message == "peer up"


def test_parse_rfc3164_and_raw_fallback() -> None:
    parsed = parse_syslog(
        b"<163>Aug  1 12:30:00 switch1 LINK[7]: interface down",
        sender="192.0.2.20",
        sender_port=514,
        protocol="udp",
    )
    assert parsed.format == "RFC3164"
    assert parsed.facility_name == "local4"
    assert parsed.severity_name == "err"
    assert parsed.app == "LINK"
    assert parsed.message == "interface down"
    malformed = parse_syslog(b"not syslog", sender="host", sender_port=1, protocol="tcp")
    assert malformed.format == "raw"
    assert malformed.parse_error


def test_udp_receiver_delivers_message() -> None:
    port = free_port(socket.SOCK_DGRAM)
    received = []
    ready = threading.Event()
    receiver = SyslogReceiver(
        ReceiverConfig("127.0.0.1", port, "udp"),
        lambda message: (received.append(message), ready.set()),
        lambda error: (_ for _ in ()).throw(error),
    )
    receiver.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"<134>Aug  1 12:30:00 host app: received", ("127.0.0.1", port))
        assert ready.wait(2)
        assert received[0].message == "received"
        assert received[0].protocol == "UDP"
    finally:
        receiver.stop()


def test_tcp_receiver_supports_lf_and_octet_framing() -> None:
    for framing, wire in (
        ("lf", b"<134>Aug  1 12:30:00 host app: line\n"),
        ("octet", b"36 <134>Aug  1 12:30:00 host app: octet"),
    ):
        port = free_port(socket.SOCK_STREAM)
        received = []
        ready = threading.Event()
        receiver = SyslogReceiver(
            ReceiverConfig("127.0.0.1", port, "tcp", framing),
            lambda message, received=received, ready=ready: (
                received.append(message),
                ready.set(),
            ),
            lambda error: (_ for _ in ()).throw(error),
        )
        receiver.start()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sender:
                sender.sendall(wire)
            assert ready.wait(2)
            assert received[0].format == "RFC3164"
        finally:
            receiver.stop()


def test_export_csv_jsonl_and_raw(tmp_path) -> None:
    message = parse_syslog(
        b"<134>Aug  1 12:30:00 host app: exported",
        sender="127.0.0.1",
        sender_port=12345,
        protocol="udp",
        received_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    csv_path = tmp_path / "messages.csv"
    jsonl_path = tmp_path / "messages.jsonl"
    raw_path = tmp_path / "messages.log"
    export_messages([message], csv_path, "csv")
    export_messages([message], jsonl_path, "jsonl")
    export_messages([message], raw_path, "raw")
    assert "facility_name" in csv_path.read_text()
    assert json.loads(jsonl_path.read_text())["message"] == "exported"
    assert raw_path.read_text().endswith("app: exported\n")
