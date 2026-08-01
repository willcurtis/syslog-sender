from datetime import datetime, timezone

import pytest

from syslog_sender.formatters import build_message, validate_structured_data
from syslog_sender.models import MessageConfig

NOW = datetime(2026, 8, 1, 12, 30, 45, tzinfo=timezone.utc)


def test_rfc3164_message() -> None:
    payload = build_message(
        MessageConfig(
            format="3164", facility=16, severity=6, hostname="router1", app="test", procid="42"
        ),
        "interface up",
        NOW,
    )
    assert payload.startswith(
        (
            b"<134>Aug  1 13:30:45 router1 test[42]: interface up",
            b"<134>Aug  1 12:30:45 router1 test[42]: interface up",
        )
    )


def test_rfc5424_message() -> None:
    payload = build_message(
        MessageConfig(format="5424", hostname="host", app="test", procid="7", msgid="EVENT"),
        "hello",
        NOW,
    )
    assert payload.startswith(b"<134>1 ")
    assert b" host test 7 EVENT - hello" in payload


def test_wire_size_means_encoded_payload_size() -> None:
    payload = build_message(MessageConfig(wire_size=250), "\N{SNOWMAN}", NOW)
    assert len(payload) == 250


@pytest.mark.parametrize("value", ["invalid", "[broken", "[x]tail"])
def test_rejects_invalid_structured_data(value: str) -> None:
    with pytest.raises(ValueError):
        validate_structured_data(value)


def test_rejects_invalid_rfc5424_app() -> None:
    with pytest.raises(ValueError, match="app"):
        build_message(MessageConfig(format="5424", app="bad app"), "hello", NOW)
