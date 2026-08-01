from __future__ import annotations

import socket
import threading
import time

import pytest

from logsalvo import MessageConfig, RunConfig, Sender, SenderConfig


class UdpCollector:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(1)
        self.messages: list[bytes] = []

    @property
    def port(self) -> int:
        return self.socket.getsockname()[1]

    def collect(self, count: int) -> None:
        try:
            while len(self.messages) < count:
                self.messages.append(self.socket.recvfrom(65535)[0])
        finally:
            self.socket.close()


def test_empty_source_is_rejected() -> None:
    with pytest.raises(ValueError, match="empty"):
        Sender(SenderConfig("localhost"), MessageConfig(), RunConfig(), [])


def test_udp_integration_and_template_sequence() -> None:
    collector = UdpCollector()
    thread = threading.Thread(target=collector.collect, args=(3,))
    thread.start()
    stats = Sender(
        SenderConfig("127.0.0.1", collector.port),
        MessageConfig(),
        RunConfig(count=3),
        ["test {seq}"],
    ).run()
    thread.join(timeout=2)
    assert (stats.attempted, stats.sent, stats.failed) == (3, 3, 0)
    assert [
        message.endswith(f"test {seq}".encode())
        for seq, message in enumerate(collector.messages, 1)
    ] == [True] * 3


def test_rate_limiter_does_not_double_requested_rate() -> None:
    stats = Sender(
        SenderConfig("localhost"),
        MessageConfig(),
        RunConfig(count=6, rate=20),
        ["test"],
        dry_run=True,
    ).run()
    assert stats.elapsed >= 0.24
    assert stats.effective_rate < 26


def test_failed_attempts_terminate_at_count(monkeypatch: pytest.MonkeyPatch) -> None:
    from logsalvo import sender as sender_module

    class BrokenTransport:
        def __init__(self, _: object):
            pass

        def connect(self) -> None:
            pass

        def send(self, _: bytes) -> int:
            raise OSError("broken")

        def close(self) -> None:
            pass

    monkeypatch.setattr(sender_module, "SyslogTransport", BrokenTransport)
    stats = Sender(
        SenderConfig("localhost", retries=0), MessageConfig(), RunConfig(count=3), ["test"]
    ).run()
    assert (stats.attempted, stats.sent, stats.failed) == (3, 0, 3)


def test_duration_stops_infinite_count() -> None:
    started = time.monotonic()
    stats = Sender(
        SenderConfig("localhost"),
        MessageConfig(),
        RunConfig(count=0, duration=0.05),
        ["test"],
        dry_run=True,
    ).run()
    assert stats.elapsed >= 0.05
    assert time.monotonic() - started < 0.5
