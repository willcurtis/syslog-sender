from __future__ import annotations

from dataclasses import dataclass

FACILITIES = {
    "kern": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "authpriv": 10,
    "ftp": 11,
    "ntp": 12,
    "audit": 13,
    "alert": 14,
    "clock": 15,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}
SEVERITIES = {
    "emerg": 0,
    "alert": 1,
    "crit": 2,
    "err": 3,
    "warn": 4,
    "notice": 5,
    "info": 6,
    "debug": 7,
}


def named_number(value: str | int, choices: dict[str, int], label: str) -> int:
    if isinstance(value, int) or str(value).lstrip("+").isdigit():
        result = int(value)
        if result in choices.values():
            return result
    else:
        key = str(value).lower()
        if key in choices:
            return choices[key]
    limits = f"{min(choices.values())}-{max(choices.values())}"
    raise ValueError(f"unknown {label} {value!r}; use a name or number {limits}")


@dataclass(frozen=True)
class SenderConfig:
    target: str
    port: int = 514
    transport: str = "udp"
    tls: bool = False
    cafile: str | None = None
    certfile: str | None = None
    keyfile: str | None = None
    insecure: bool = False
    sni: str | None = None
    tcp_framing: str = "octet"
    bind_ip: str | None = None
    timeout: float = 5.0
    retries: int = 2

    def __post_init__(self) -> None:
        if not self.target.strip():
            raise ValueError("target is required")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if self.transport not in {"udp", "tcp"}:
            raise ValueError("transport must be udp or tcp")
        if self.tls and self.transport != "tcp":
            raise ValueError("TLS requires TCP")
        if self.tcp_framing not in {"octet", "lf"}:
            raise ValueError("TCP framing must be octet or lf")
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if self.retries < 0:
            raise ValueError("retries cannot be negative")
        if self.keyfile and not self.certfile:
            raise ValueError("a client key requires a client certificate")


@dataclass(frozen=True)
class MessageConfig:
    format: str = "3164"
    facility: int = 16
    severity: int = 6
    hostname: str = "localhost"
    app: str = "syslog-sender"
    procid: str = "-"
    msgid: str = "TEST"
    structured_data: str = "-"
    wire_size: int = 0

    def __post_init__(self) -> None:
        if self.format not in {"3164", "5424"}:
            raise ValueError("format must be 3164 or 5424")
        if not 0 <= self.facility <= 23:
            raise ValueError("facility must be between 0 and 23")
        if not 0 <= self.severity <= 7:
            raise ValueError("severity must be between 0 and 7")
        if self.wire_size < 0:
            raise ValueError("wire size cannot be negative")


@dataclass(frozen=True)
class RunConfig:
    count: int = 1
    duration: float = 0
    rate: float = 0
    delay: float = 0

    def __post_init__(self) -> None:
        if self.count < 0:
            raise ValueError("count cannot be negative")
        if self.duration < 0 or self.rate < 0 or self.delay < 0:
            raise ValueError("duration, rate and delay cannot be negative")
        if self.rate and self.delay:
            raise ValueError("rate and delay are mutually exclusive")
        if self.count == 0 and self.duration == 0:
            raise ValueError("count 0 requires a duration")


@dataclass
class Stats:
    attempted: int = 0
    sent: int = 0
    failed: int = 0
    bytes_sent: int = 0
    elapsed: float = 0
    cancelled: bool = False

    @property
    def effective_rate(self) -> float:
        return self.sent / self.elapsed if self.elapsed > 0 else 0.0
