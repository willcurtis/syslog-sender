from __future__ import annotations

import csv
import json
import re
import socket
import threading
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<sd>-|(?:\[[^\]]*(?:\\.[^\]]*)*\])+)(?:\s(?P<message>.*))?$"
)
RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Z][a-z]{2}\s+[ \d]\d\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+(?:(?P<app>[^\s:\[]+)(?:\[(?P<procid>[^\]]+)\])?:\s*)?"
    r"(?P<message>.*)$"
)

FACILITY_NAMES = [
    "kern",
    "user",
    "mail",
    "daemon",
    "auth",
    "syslog",
    "lpr",
    "news",
    "uucp",
    "cron",
    "authpriv",
    "ftp",
    "ntp",
    "audit",
    "alert",
    "clock",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
]
SEVERITY_NAMES = ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"]


@dataclass(frozen=True)
class ReceiverConfig:
    bind_address: str = "0.0.0.0"
    port: int = 5514
    protocol: str = "udp"
    tcp_framing: str = "auto"
    max_message_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValueError("receiver port must be between 1 and 65535")
        if self.protocol not in {"udp", "tcp"}:
            raise ValueError("receiver protocol must be UDP or TCP")
        if self.tcp_framing not in {"auto", "octet", "lf"}:
            raise ValueError("TCP framing must be auto, octet or lf")
        if self.max_message_bytes < 480:
            raise ValueError("maximum message size must be at least 480 bytes")


@dataclass(frozen=True)
class ReceivedMessage:
    received_at: datetime
    sender: str
    sender_port: int
    protocol: str
    raw: str
    format: str = "raw"
    priority: int | None = None
    facility: int | None = None
    facility_name: str = "unknown"
    severity: int | None = None
    severity_name: str = "unknown"
    timestamp: str = ""
    hostname: str = ""
    app: str = ""
    procid: str = ""
    msgid: str = ""
    structured_data: str = ""
    message: str = ""
    parse_error: str = ""

    def export_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["received_at"] = self.received_at.isoformat(timespec="milliseconds")
        return result


def _priority_fields(priority: int) -> tuple[int, str, int, str]:
    facility = priority // 8
    severity = priority % 8
    facility_name = FACILITY_NAMES[facility] if facility < len(FACILITY_NAMES) else "unknown"
    severity_name = SEVERITY_NAMES[severity] if severity < len(SEVERITY_NAMES) else "unknown"
    return facility, facility_name, severity, severity_name


def parse_syslog(
    payload: bytes,
    *,
    sender: str,
    sender_port: int,
    protocol: str,
    received_at: datetime | None = None,
) -> ReceivedMessage:
    received = received_at or datetime.now(timezone.utc)
    raw = payload.decode("utf-8", "replace").rstrip("\r\n")
    for format_name, pattern in (("RFC5424", RFC5424), ("RFC3164", RFC3164)):
        match = pattern.match(raw)
        if not match:
            continue
        values = match.groupdict(default="")
        priority = int(values["pri"])
        if not 0 <= priority <= 191:
            break
        facility, facility_name, severity, severity_name = _priority_fields(priority)
        return ReceivedMessage(
            received,
            sender,
            sender_port,
            protocol.upper(),
            raw,
            format_name,
            priority,
            facility,
            facility_name,
            severity,
            severity_name,
            values.get("timestamp", ""),
            values.get("hostname", ""),
            values.get("app", "").removesuffix(":"),
            values.get("procid", ""),
            values.get("msgid", ""),
            values.get("sd", ""),
            values.get("message", ""),
        )
    priority_match = re.match(r"^<(\d{1,3})>", raw)
    priority = int(priority_match.group(1)) if priority_match else None
    if priority is not None and 0 <= priority <= 191:
        facility, facility_name, severity, severity_name = _priority_fields(priority)
    else:
        facility = severity = None
        facility_name = severity_name = "unknown"
    return ReceivedMessage(
        received,
        sender,
        sender_port,
        protocol.upper(),
        raw,
        priority=priority,
        facility=facility,
        facility_name=facility_name,
        severity=severity,
        severity_name=severity_name,
        message=raw,
        parse_error="Message did not match RFC 3164 or RFC 5424",
    )


MessageHandler = Callable[[ReceivedMessage], None]
ErrorHandler = Callable[[Exception], None]


class SyslogReceiver:
    def __init__(self, config: ReceiverConfig, on_message: MessageHandler, on_error: ErrorHandler):
        self.config = config
        self.on_message = on_message
        self.on_error = on_error
        self._stop = threading.Event()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._clients: set[socket.socket] = set()
        self._client_threads: set[threading.Thread] = set()
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.running:
            raise RuntimeError("receiver is already running")
        self._stop.clear()
        socktype = socket.SOCK_DGRAM if self.config.protocol == "udp" else socket.SOCK_STREAM
        infos = socket.getaddrinfo(
            self.config.bind_address or None,
            self.config.port,
            socket.AF_UNSPEC,
            socktype,
            0,
            socket.AI_PASSIVE,
        )
        errors: list[OSError] = []
        for family, resolved_type, protocol, _, address in infos:
            candidate: socket.socket | None = None
            try:
                candidate = socket.socket(family, resolved_type, protocol)
                candidate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    candidate.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                candidate.bind(address)
                if self.config.protocol == "tcp":
                    candidate.listen(64)
                candidate.settimeout(0.25)
                self._socket = candidate
                break
            except OSError as error:
                errors.append(error)
                if candidate:
                    candidate.close()
        if self._socket is None:
            if errors:
                raise errors[-1]
            raise OSError("no usable local address was found")
        target = self._udp_loop if self.config.protocol == "udp" else self._tcp_loop
        self._thread = threading.Thread(target=target, name="logsalvo-receiver", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._socket:
            self._socket.close()
            self._socket = None
        with self._lock:
            clients = tuple(self._clients)
        for client in clients:
            client.close()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=1.5)
        for thread in tuple(self._client_threads):
            if thread is not threading.current_thread():
                thread.join(timeout=0.5)
        self._thread = None

    def _deliver(self, payload: bytes, address: tuple, protocol: str) -> None:
        if not payload:
            return
        if len(payload) > self.config.max_message_bytes:
            payload = payload[: self.config.max_message_bytes]
        self.on_message(
            parse_syslog(
                payload,
                sender=str(address[0]),
                sender_port=int(address[1]),
                protocol=protocol,
            )
        )

    def _udp_loop(self) -> None:
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                payload, address = self._socket.recvfrom(self.config.max_message_bytes + 1)
                self._deliver(payload, address, "UDP")
            except TimeoutError:
                continue
            except OSError as error:
                if not self._stop.is_set():
                    self.on_error(error)
                break

    def _tcp_loop(self) -> None:
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                client, address = self._socket.accept()
                client.settimeout(0.25)
                with self._lock:
                    self._clients.add(client)
                thread = threading.Thread(
                    target=self._tcp_client,
                    args=(client, address),
                    name=f"logsalvo-client-{address[0]}:{address[1]}",
                    daemon=True,
                )
                self._client_threads.add(thread)
                thread.start()
            except TimeoutError:
                continue
            except OSError as error:
                if not self._stop.is_set():
                    self.on_error(error)
                break

    def _tcp_client(self, client: socket.socket, address: tuple) -> None:
        buffer = bytearray()
        framing = self.config.tcp_framing
        try:
            while not self._stop.is_set():
                try:
                    chunk = client.recv(65_536)
                except TimeoutError:
                    continue
                if not chunk:
                    break
                buffer.extend(chunk)
                if framing == "auto" and buffer:
                    separator = buffer.find(b" ")
                    if buffer.startswith(b"<"):
                        framing = "lf"
                    elif separator >= 0:
                        framing = "octet" if bytes(buffer[:separator]).isdigit() else "lf"
                    elif not bytes(buffer).isdigit():
                        framing = "lf"
                    else:
                        continue
                if framing == "octet":
                    self._consume_octet_frames(buffer, address)
                else:
                    self._consume_lf_frames(buffer, address)
                if len(buffer) > self.config.max_message_bytes + 32:
                    raise ValueError("incoming TCP frame exceeds the configured size limit")
            if buffer and framing != "octet":
                self._deliver(bytes(buffer).rstrip(b"\r\n"), address, "TCP")
        except (OSError, ValueError) as error:
            if not self._stop.is_set():
                self.on_error(error)
        finally:
            with self._lock:
                self._clients.discard(client)
            client.close()
            self._client_threads.discard(threading.current_thread())

    def _consume_lf_frames(self, buffer: bytearray, address: tuple) -> None:
        while b"\n" in buffer:
            frame, _, remainder = buffer.partition(b"\n")
            buffer[:] = remainder
            self._deliver(bytes(frame).rstrip(b"\r"), address, "TCP")

    def _consume_octet_frames(self, buffer: bytearray, address: tuple) -> None:
        while True:
            separator = buffer.find(b" ")
            if separator < 0:
                return
            length_text = bytes(buffer[:separator])
            if not length_text.isdigit():
                raise ValueError("invalid RFC 6587 octet-counted frame")
            length = int(length_text)
            if length > self.config.max_message_bytes:
                raise ValueError("incoming TCP frame exceeds the configured size limit")
            frame_start = separator + 1
            frame_end = frame_start + length
            if len(buffer) < frame_end:
                return
            self._deliver(bytes(buffer[frame_start:frame_end]), address, "TCP")
            del buffer[:frame_end]


def export_messages(
    messages: Sequence[ReceivedMessage], path: str | Path, format_name: str
) -> None:
    destination = Path(path)
    if format_name == "csv":
        rows = [message.export_dict() for message in messages]
        with destination.open("w", encoding="utf-8", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=list(ReceivedMessage.__dataclass_fields__))
            writer.writeheader()
            writer.writerows(rows)
    elif format_name == "jsonl":
        with destination.open("w", encoding="utf-8") as target:
            for message in messages:
                target.write(json.dumps(message.export_dict(), ensure_ascii=False) + "\n")
    elif format_name == "raw":
        with destination.open("w", encoding="utf-8") as target:
            for message in messages:
                target.write(message.raw + "\n")
    else:
        raise ValueError("export format must be csv, jsonl or raw")
