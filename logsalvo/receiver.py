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
CISCO_IOS = re.compile(
    r"^(?:(?P<sequence>\d+):\s*)?"
    r"(?:(?P<timestamp>\*?[A-Z][a-z]{2}\s+[ \d]\d\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+\S+)?)?:?\s*)?"
    r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>[0-7])-(?P<mnemonic>[A-Z0-9_]+):\s*"
    r"(?P<message>.*)$",
    re.IGNORECASE,
)
UNIFI_AP = re.compile(
    r"^(?P<mac>[0-9a-f]{12}),(?P<device>[^:\s,]+):\s*"
    r"(?P<app>[^\s:\[]+)(?:\[(?P<procid>[^\]]+)\])?:\s*(?P<message>.*)$",
    re.IGNORECASE,
)
UNIFI_GATEWAY = re.compile(
    r"^(?P<hostname>(?:UDM|UCG|UXG|USG|UniFi|CloudKey)[^\s]*)\s+"
    r"(?P<app>[^\s:\[]+)(?:\[(?P<procid>[^\]]+)\])?:\s*(?P<message>.*)$",
    re.IGNORECASE,
)
CEF_EXTENSION_KEY = re.compile(r"(?:^|\s)(?P<key>[A-Za-z][A-Za-z0-9_]*)=")

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


def _integer(value: object, minimum: int, maximum: int) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        result = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return result if minimum <= result <= maximum else None


def _first_text(values: dict[str, object], *keys: str) -> str:
    for key in keys:
        value = values.get(key)
        if value is not None and not isinstance(value, (dict, list)):
            text = str(value).strip()
            if text:
                return text
    return ""


def _json_message(values: dict[str, object]) -> str:
    message = _first_text(values, "message", "msg", "event", "description", "note")
    note = _first_text(values, "note")
    event = _first_text(values, "event")
    if event and note and message in {event, note}:
        return f"{event}: {note}"
    return message or json.dumps(values, ensure_ascii=False, separators=(",", ":"))


def _parse_json(raw: str) -> dict[str, object] | None:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _cef_parts(raw: str) -> list[str] | None:
    if not raw.startswith("CEF:"):
        return None
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for character in raw:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "|" and len(parts) < 7:
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    parts.append("".join(current))
    return parts if len(parts) == 8 else None


def _cef_extension(raw: str) -> dict[str, str]:
    matches = list(CEF_EXTENSION_KEY.finditer(raw))
    values: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(raw)
        values[match.group("key")] = raw[match.end() : end].strip()
    return values


def _cef_severity(value: str) -> int | None:
    severity = _integer(value, 0, 10)
    if severity is None:
        return None
    if severity <= 3:
        return 6
    if severity <= 6:
        return 4
    if severity <= 8:
        return 3
    return 2 if severity == 9 else 1


def _parse_cef(
    body: str,
    *,
    received: datetime,
    sender: str,
    sender_port: int,
    protocol: str,
    raw: str,
    priority: int | None = None,
    timestamp: str = "",
    envelope_hostname: str = "",
) -> ReceivedMessage | None:
    parts = _cef_parts(body)
    if parts is None:
        return None
    version, vendor, product, device_version, event_id, name, cef_level, extension = parts
    if not version.removeprefix("CEF:").isdigit():
        return None
    fields = _cef_extension(extension)
    is_unifi = vendor.casefold() == "ubiquiti" or "unifi" in product.casefold()
    if priority is not None:
        facility, facility_name, severity, severity_name = _priority_fields(priority)
    else:
        facility = None
        facility_name = "unknown"
        severity = _cef_severity(cef_level)
        severity_name = SEVERITY_NAMES[severity] if severity is not None else "unknown"
    hostname = fields.get("UNIFIhost", fields.get("dhost", envelope_hostname))
    message = fields.get("msg", name)
    return ReceivedMessage(
        received_at=received,
        sender=sender,
        sender_port=sender_port,
        protocol=protocol.upper(),
        raw=raw,
        format="UniFi CEF" if is_unifi else "CEF",
        priority=priority,
        facility=facility,
        facility_name=facility_name,
        severity=severity,
        severity_name=severity_name,
        timestamp=timestamp,
        hostname=hostname,
        app=product,
        msgid=event_id,
        structured_data=json.dumps(
            {
                "vendor": vendor,
                "product": product,
                "device_version": device_version,
                "name": name,
                "cef_severity": cef_level,
                **fields,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ),
        message=message,
    )


def parse_syslog(
    payload: bytes,
    *,
    sender: str,
    sender_port: int,
    protocol: str,
    received_at: datetime | None = None,
) -> ReceivedMessage:
    received = received_at or datetime.now(timezone.utc)
    raw = payload.decode("utf-8-sig", "replace").rstrip("\x00\r\n")
    candidate = raw.lstrip()
    for format_name, pattern in (("RFC5424", RFC5424), ("RFC3164", RFC3164)):
        match = pattern.match(candidate)
        if not match:
            continue
        values = match.groupdict(default="")
        priority = int(values["pri"])
        if not 0 <= priority <= 191:
            break
        facility, facility_name, severity, severity_name = _priority_fields(priority)
        nested_message = values.get("message", "")
        if values.get("app", "").casefold() == "cef":
            nested_message = f"CEF:{nested_message}"
        cef_message = _parse_cef(
            nested_message,
            received=received,
            sender=sender,
            sender_port=sender_port,
            protocol=protocol,
            raw=raw,
            priority=priority,
            timestamp=values.get("timestamp", ""),
            envelope_hostname=values.get("hostname", ""),
        )
        if cef_message is not None:
            return cef_message
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
    priority_match = re.match(r"^<(\d{1,3})>", candidate)
    priority = _integer(priority_match.group(1), 0, 191) if priority_match else None
    body = candidate[priority_match.end() :].lstrip() if priority is not None else candidate
    if priority is not None:
        facility, facility_name, severity, severity_name = _priority_fields(priority)
    else:
        facility = severity = None
        facility_name = severity_name = "unknown"

    cef_message = _parse_cef(
        body,
        received=received,
        sender=sender,
        sender_port=sender_port,
        protocol=protocol,
        raw=raw,
        priority=priority,
    )
    if cef_message is not None:
        return cef_message

    json_values = _parse_json(body)
    if json_values is not None:
        json_facility = _integer(json_values.get("facility", json_values.get("fac_num")), 0, 23)
        json_severity = _integer(json_values.get("severity", json_values.get("sev_num")), 0, 7)
        if priority is None and json_facility is not None and json_severity is not None:
            priority = (json_facility * 8) + json_severity
        if json_facility is not None:
            facility = json_facility
            facility_name = FACILITY_NAMES[facility]
        else:
            named_facility = _first_text(json_values, "facility_name", "facility", "fac").lower()
            if named_facility in FACILITY_NAMES:
                facility = FACILITY_NAMES.index(named_facility)
                facility_name = named_facility
        if json_severity is not None:
            severity = json_severity
            severity_name = SEVERITY_NAMES[severity]
        else:
            named_severity = _first_text(json_values, "severity_name", "severity", "sev").lower()
            if named_severity in SEVERITY_NAMES:
                severity = SEVERITY_NAMES.index(named_severity)
                severity_name = named_severity
        if priority is None and facility is not None and severity is not None:
            priority = (facility * 8) + severity
        return ReceivedMessage(
            received_at=received,
            sender=sender,
            sender_port=sender_port,
            protocol=protocol.upper(),
            raw=raw,
            format="JSON",
            priority=priority,
            facility=facility,
            facility_name=facility_name,
            severity=severity,
            severity_name=severity_name,
            timestamp=_first_text(json_values, "timestamp", "ts", "time", "@timestamp"),
            hostname=_first_text(json_values, "hostname", "host", "source", "src"),
            app=_first_text(json_values, "app", "application", "program", "service"),
            procid=_first_text(json_values, "procid", "pid", "process_id"),
            msgid=_first_text(json_values, "msgid", "event", "event_id"),
            structured_data=json.dumps(json_values, ensure_ascii=False, separators=(",", ":")),
            message=_json_message(json_values),
        )

    cisco_match = CISCO_IOS.match(body)
    if cisco_match:
        values = cisco_match.groupdict(default="")
        cisco_severity = int(values["severity"])
        if severity is None:
            severity = cisco_severity
            severity_name = SEVERITY_NAMES[severity]
        return ReceivedMessage(
            received_at=received,
            sender=sender,
            sender_port=sender_port,
            protocol=protocol.upper(),
            raw=raw,
            format="Cisco IOS",
            priority=priority,
            facility=facility,
            facility_name=facility_name,
            severity=severity,
            severity_name=severity_name,
            timestamp=values["timestamp"],
            app=values["facility"].upper(),
            msgid=values["mnemonic"].upper(),
            message=values["message"],
        )

    for pattern in (UNIFI_AP, UNIFI_GATEWAY):
        unifi_match = pattern.match(body)
        if not unifi_match:
            continue
        values = unifi_match.groupdict(default="")
        hostname = values.get("hostname") or values.get("device", "")
        identity = values.get("mac", "")
        return ReceivedMessage(
            received_at=received,
            sender=sender,
            sender_port=sender_port,
            protocol=protocol.upper(),
            raw=raw,
            format="UniFi device",
            priority=priority,
            facility=facility,
            facility_name=facility_name,
            severity=severity,
            severity_name=severity_name,
            hostname=hostname,
            app=values["app"],
            procid=values["procid"],
            structured_data=f"device_mac={identity}" if identity else "",
            message=values["message"],
        )

    if priority is not None:
        return ReceivedMessage(
            received_at=received,
            sender=sender,
            sender_port=sender_port,
            protocol=protocol.upper(),
            raw=raw,
            format="PRI",
            priority=priority,
            facility=facility,
            facility_name=facility_name,
            severity=severity,
            severity_name=severity_name,
            message=body,
        )
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
        message=candidate,
        parse_error="Message did not match a supported syslog or structured raw format",
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
