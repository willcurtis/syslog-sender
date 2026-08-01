from __future__ import annotations

from datetime import datetime

from .models import MessageConfig


def _ascii_field(value: str, name: str, maximum: int, *, allow_nil: bool = True) -> str:
    if allow_nil and value == "-":
        return value
    if not value or len(value) > maximum:
        raise ValueError(f"{name} must contain 1-{maximum} characters")
    if any(ord(char) < 33 or ord(char) > 126 or char in ' ="]' for char in value):
        raise ValueError(f"{name} contains characters disallowed by RFC 5424")
    return value


def validate_structured_data(value: str) -> str:
    if value == "-":
        return value
    if not value.startswith("[") or not value.endswith("]"):
        raise ValueError("structured data must be '-' or one or more [element ...] blocks")
    escaped = False
    depth = 0
    for char in value:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth < 0:
                raise ValueError("structured data has an unmatched closing bracket")
    if depth or escaped:
        raise ValueError("structured data has an unmatched bracket or trailing escape")
    return value


def build_message(config: MessageConfig, body: str, now: datetime) -> bytes:
    priority = config.facility * 8 + config.severity
    if config.format == "3164":
        timestamp = f"{now.astimezone():%b} {now.astimezone().day:>2} {now.astimezone():%H:%M:%S}"
        tag = config.app if config.procid in {"", "-"} else f"{config.app}[{config.procid}]"
        payload = f"<{priority}>{timestamp} {config.hostname} {tag}: {body}".encode(
            "utf-8", "replace"
        )
    else:
        hostname = _ascii_field(config.hostname, "hostname", 255)
        app = _ascii_field(config.app, "app", 48)
        procid = _ascii_field(config.procid or "-", "procid", 128)
        msgid = _ascii_field(config.msgid or "-", "msgid", 32)
        sd = validate_structured_data(config.structured_data or "-")
        timestamp = now.astimezone().isoformat(timespec="milliseconds")
        payload = f"<{priority}>1 {timestamp} {hostname} {app} {procid} {msgid} {sd} {body}".encode(
            "utf-8", "replace"
        )
    if config.wire_size and len(payload) < config.wire_size:
        payload += b" " * (config.wire_size - len(payload))
    return payload
