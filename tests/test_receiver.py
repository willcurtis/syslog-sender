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


def test_parse_pri_only_raw_message() -> None:
    parsed = parse_syslog(
        b"  <134>interface Ethernet1/1 changed state",
        sender="192.0.2.30",
        sender_port=514,
        protocol="udp",
    )
    assert parsed.format == "PRI"
    assert parsed.priority == 134
    assert parsed.facility_name == "local0"
    assert parsed.severity_name == "info"
    assert parsed.message == "interface Ethernet1/1 changed state"
    assert not parsed.parse_error


def test_parse_json_raw_message() -> None:
    parsed = parse_syslog(
        b'{"src":"fw-lon-01","app":"kernel","event":"disk_full","note":"95% used",'
        b'"sev":"crit","sev_num":2,"fac":"local4","fac_num":20,"ts":"2026-08-01T12:30:00Z"}',
        sender="192.0.2.40",
        sender_port=514,
        protocol="udp",
    )
    assert parsed.format == "JSON"
    assert parsed.hostname == "fw-lon-01"
    assert parsed.app == "kernel"
    assert parsed.msgid == "disk_full"
    assert parsed.message == "disk_full: 95% used"
    assert parsed.facility_name == "local4"
    assert parsed.severity_name == "crit"
    assert parsed.priority == 162
    assert not parsed.parse_error


def test_parse_cisco_ios_raw_message() -> None:
    parsed = parse_syslog(
        b"000123: Aug  1 12:30:00.123 UTC: %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down",
        sender="192.0.2.50",
        sender_port=514,
        protocol="udp",
    )
    assert parsed.format == "Cisco IOS"
    assert parsed.app == "LINK"
    assert parsed.msgid == "UPDOWN"
    assert parsed.severity_name == "err"
    assert parsed.message == "Interface Gi1/0/1, changed state to down"
    assert not parsed.parse_error


def test_invalid_priority_is_not_reported_as_valid() -> None:
    parsed = parse_syslog(b"<999>message", sender="host", sender_port=1, protocol="udp")
    assert parsed.priority is None
    assert parsed.format == "raw"
    assert parsed.parse_error


def test_parse_unifi_cef_message() -> None:
    parsed = parse_syslog(
        b"CEF:0|Ubiquiti|UniFi Network|9.3.33|401|WiFi Client Disconnected|2|"
        b"UNIFIcategory=Monitoring UNIFIsubCategory=WiFi UNIFIhost=Office UDM Pro "
        b"UNIFIclientHostname=Craig Watch src=192.0.2.60 "
        b"msg=Craig Watch disconnected from Employee WiFi.",
        sender="192.0.2.60",
        sender_port=514,
        protocol="udp",
    )
    assert parsed.format == "UniFi CEF"
    assert parsed.hostname == "Office UDM Pro"
    assert parsed.app == "UniFi Network"
    assert parsed.msgid == "401"
    assert parsed.severity_name == "info"
    assert parsed.message == "Craig Watch disconnected from Employee WiFi."
    assert "UNIFIcategory" in parsed.structured_data
    assert not parsed.parse_error


def test_parse_rfc3164_wrapped_unifi_cef_message() -> None:
    parsed = parse_syslog(
        b"<134>Aug  1 12:30:00 console CEF:0|Ubiquiti|UniFi Network|9.3.33|544|"
        b"Admin Accessed UniFi Network|1|UNIFIhost=Office UDM Pro msg=Admin logged in",
        sender="192.0.2.61",
        sender_port=514,
        protocol="udp",
    )
    assert parsed.format == "UniFi CEF"
    assert parsed.priority == 134
    assert parsed.hostname == "Office UDM Pro"
    assert parsed.timestamp == "Aug  1 12:30:00"
    assert parsed.message == "Admin logged in"


def test_parse_unifi_cef_with_bsd_envelope_without_priority() -> None:
    parsed = parse_syslog(
        b"Aug 01 23:12:41 site-udm CEF:0|Ubiquiti|UniFi Network|10.5.67|546|"
        b"Config Modified|5|UNIFIcategory=Audit UNIFIhost=site-udm "
        b"UNIFIsettingsChanges=cron_expr: 0 5 * * * UNIFIaccessMethod=web "
        b"UNIFIsettingsSection=Internet UNIFIadmin=Admin src=192.0.2.70 "
        b"UNIFIutcTime=2026-08-01T22:12:41.222Z "
        b"msg=Admin made a change to Internet settings.",
        sender="192.0.2.1",
        sender_port=35207,
        protocol="udp",
    )
    assert parsed.format == "UniFi CEF"
    assert parsed.priority is None
    assert parsed.timestamp == "Aug 01 23:12:41"
    assert parsed.hostname == "site-udm"
    assert parsed.app == "UniFi Network"
    assert parsed.msgid == "546"
    assert parsed.severity_name == "warn"
    assert parsed.message == "Admin made a change to Internet settings."
    assert "cron_expr: 0 5 * * *" in parsed.structured_data
    assert not parsed.parse_error


def test_parse_unifi_access_point_device_log() -> None:
    parsed = parse_syslog(
        b"<30>6c63f8863465,U7-Pro-Wall-8.3.2+18064: hostapd[5343]: wifi1ap6: STA connected",
        sender="192.0.2.62",
        sender_port=514,
        protocol="udp",
    )
    assert parsed.format == "UniFi device"
    assert parsed.hostname == "U7-Pro-Wall-8.3.2+18064"
    assert parsed.app == "hostapd"
    assert parsed.procid == "5343"
    assert parsed.message == "wifi1ap6: STA connected"
    assert parsed.structured_data == "device_mac=6c63f8863465"


def test_parse_unifi_gateway_device_log() -> None:
    parsed = parse_syslog(
        b"UCG-Fiber bash[2616997]: HISTORY: admin ran a command",
        sender="192.0.2.63",
        sender_port=514,
        protocol="udp",
    )
    assert parsed.format == "UniFi device"
    assert parsed.hostname == "UCG-Fiber"
    assert parsed.app == "bash"
    assert parsed.procid == "2616997"
    assert parsed.message == "HISTORY: admin ran a command"


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
