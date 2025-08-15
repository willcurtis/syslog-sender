#!/usr/bin/env python3
"""
syslog-pro.py — A professional syslog traffic generator for troubleshooting.
Features:
- RFC3164 (BSD) and RFC5424 formats
- UDP, TCP, or TLS transport (RFC6587 octet-counting or LF-delimited framing)
- Custom facility/severity (names or numbers), app-name, hostname, procid, msgid
- Message templates with variables: {seq}, {uuid}, {timestamp}, {randint:a:b}, {hostname}, {app}, {severity}, {facility}
- Rate control (--rate msgs/sec) or fixed delay (--delay), count or duration
- Read messages from a file or stdin; or generate random examples
- Bind to a local source IP, IPv4/IPv6 support
- Stats and progress; dry-run mode and verbose echo
"""
import argparse
import ipaddress
import os
import random
import socket
import ssl
import sys
import time
import uuid
import re
from datetime import datetime, timezone

EXAMPLE_MESSAGES = [
    "System rebooted",
    "User login successful",
    "Interface eth0 down",
    "Disk usage exceeded threshold",
    "Firewall rule matched",
    "Configuration changed",
    "Service restarted",
    "Unauthorized access attempt",
    "VPN tunnel established",
    "NTP sync successful",
    "Link flapping detected",
    "CPU usage high",
    "Memory pressure warning",
    "BGP session reset",
]

FACILITY_MAP = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6,
    "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11, "ntp": 12, "audit": 13,
    "alert": 14, "clock": 15, "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23
}
SEVERITY_MAP = {
    "emerg": 0, "alert": 1, "crit": 2, "err": 3, "warn": 4, "notice": 5, "info": 6, "debug": 7
}

def parse_facility(value: str) -> int:
    if value.isdigit():
        n = int(value)
        if 0 <= n <= 23:
            return n
        raise argparse.ArgumentTypeError("Facility number must be 0-23")
    key = value.lower()
    if key in FACILITY_MAP:
        return FACILITY_MAP[key]
    raise argparse.ArgumentTypeError(f"Unknown facility: {value}")

def parse_severity(value: str) -> int:
    if value.isdigit():
        n = int(value)
        if 0 <= n <= 7:
            return n
        raise argparse.ArgumentTypeError("Severity number must be 0-7")
    key = value.lower()
    if key in SEVERITY_MAP:
        return SEVERITY_MAP[key]
    raise argparse.ArgumentTypeError(f"Unknown severity: {value}")

def pri(facility: int, severity: int) -> int:
    return facility * 8 + severity

def _bsd_timestamp(dt: datetime) -> str:
    # RFC3164: "Mmm dd hh:mm:ss" with space before single-digit day
    month = dt.strftime("%b")
    day = dt.day
    ts = dt.strftime("%H:%M:%S")
    return f"{month} {day:>2} {ts}"

def _iso_timestamp(dt: datetime) -> str:
    # RFC5424 recommends full-precision with TZ; here: millisecond precision
    dt = dt.astimezone()  # local tz
    return dt.isoformat(timespec="milliseconds")

RANDINT_RE = re.compile(r"{randint:(-?\d+):(-?\d+)}")

def apply_template(template: str, *, seq: int, host: str, app: str, facility: int, severity: int) -> str:
    msg = template
    now = datetime.now(timezone.utc).astimezone()
    replacement_map = {
        "{seq}": str(seq),
        "{uuid}": str(uuid.uuid4()),
        "{timestamp}": now.isoformat(timespec="milliseconds"),
        "{hostname}": host,
        "{app}": app,
        "{facility}": str(facility),
        "{severity}": str(severity),
    }
    for k, v in replacement_map.items():
        msg = msg.replace(k, v)
    # {randint:a:b}
    def _rand(m):
        a, b = int(m.group(1)), int(m.group(2))
        return str(random.randint(a, b))
    msg = RANDINT_RE.sub(_rand, msg)
    return msg

def build_3164(facility: int, severity: int, hostname: str, app: str, procid: str, msg: str, dt: datetime) -> bytes:
    pri_val = pri(facility, severity)
    ts = _bsd_timestamp(dt.astimezone())  # local time preferred
    tag = f"{app}[{procid}]" if procid else app
    line = f"<{pri_val}>{ts} {hostname} {tag}: {msg}"
    return line.encode("utf-8", "replace")

def build_5424(facility: int, severity: int, hostname: str, app: str, procid: str, msgid: str, sd: str, msg: str, dt: datetime) -> bytes:
    pri_val = pri(facility, severity)
    # VERSION is 1
    ts = _iso_timestamp(dt)
    if not sd:
        sd = "-"  # no structured data
    if not msgid:
        msgid = "-"
    proc = procid if procid else "-"
    line = f"<{pri_val}>1 {ts} {hostname} {app} {proc} {msgid} {sd} {msg}"
    return line.encode("utf-8", "replace")

def resolve_host(h: str) -> str:
    try:
        ipaddress.ip_address(h)
        return h  # already an IP literal
    except ValueError:
        return h  # let getaddrinfo resolve DNS

def open_socket(transport: str, target: str, port: int, *, tls: bool, cafile: str, certfile: str, keyfile: str, insecure: bool, sni: str, bind_ip: str):
    family = socket.AF_UNSPEC
    type_ = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    err = None
    addrinfo = socket.getaddrinfo(resolve_host(target), port, family, type_)
    if bind_ip:
        bind_addrinfo = socket.getaddrinfo(bind_ip, 0, family, socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM)[0]
    else:
        bind_addrinfo = None
    for af, socktype, proto, canonname, sa in addrinfo:
        try:
            s = socket.socket(af, socktype, proto)
            if bind_addrinfo:
                s.bind((bind_addrinfo[4][0], 0))
            if transport == "udp":
                return s, sa  # we'll use sendto
            # TCP/TLS
            s.settimeout(5)
            s.connect(sa)
            if tls:
                ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile if not insecure else None)
                if insecure:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                if certfile:
                    ctx.load_cert_chain(certfile, keyfile=keyfile or None)
                hostname = sni or (target if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target) else None)
                s = ctx.wrap_socket(s, server_hostname=hostname)
            return s, sa
        except Exception as e:
            err = e
            try:
                s.close()
            except Exception:
                pass
            continue
    raise RuntimeError(f"Could not open socket to {target}:{port}: {err}")

def send_message(sock, addr, payload: bytes, *, transport: str, tcp_framing: str):
    if transport == "udp":
        return sock.sendto(payload, addr)
    # TCP/TLS
    if tcp_framing == "octet":
        frame = f"{len(payload)} ".encode("ascii") + payload
    else:
        frame = payload + b"\n"
    sock.sendall(frame)
    return len(payload)

def main():
    parser = argparse.ArgumentParser(description="Professional syslog generator for troubleshooting (RFC3164/RFC5424 over UDP/TCP/TLS).")
    parser.add_argument("target", help="Syslog server IP or hostname")
    parser.add_argument("-p", "--port", type=int, default=514, help="Destination port (default: 514 or 6514 for TLS)")
    parser.add_argument("--transport", choices=["udp", "tcp"], default="udp", help="Transport protocol (default: udp)")
    parser.add_argument("--tls", action="store_true", help="Enable TLS (use with --transport tcp, default port 6514 if -p not set)")
    parser.add_argument("--cafile", help="Path to CA bundle or certificate file (TLS)")
    parser.add_argument("--certfile", help="Client certificate (TLS)")
    parser.add_argument("--keyfile", help="Client key (TLS)")
    parser.add_argument("--insecure", action="store_true", help="TLS: do not verify server certificate")
    parser.add_argument("--sni", help="TLS: override SNI server name")
    parser.add_argument("--tcp-framing", choices=["octet", "lf"], default="octet", help="TCP framing: RFC6587 octet-counting or LF-delimited (default: octet)")
    parser.add_argument("--bind-ip", help="Bind to this local source IP")
    parser.add_argument("--format", choices=["3164", "5424"], default="3164", help="Syslog message format (default: 3164)")
    parser.add_argument("--facility", type=parse_facility, default=16, help="Facility (name or 0-23). Default: local0")
    parser.add_argument("--severity", type=parse_severity, default=6, help="Severity (name or 0-7). Default: info")
    parser.add_argument("--app", default="syslog-pro", help="APP-NAME / TAG (default: syslog-pro)")
    parser.add_argument("--hostname", default=socket.gethostname(), help="Hostname to place in message")
    parser.add_argument("--procid", default=str(os.getpid()), help="ProcID / PID (default: current PID)")
    parser.add_argument("--msgid", default="TEST", help="RFC5424 MSGID (default: TEST)")
    parser.add_argument("--sd", default="", help="RFC5424 Structured Data, e.g. [example@32473 iut=\"3\" eventSource=\"App\" eventID=\"1011\"]")
    parser.add_argument("-m", "--message", help="Message template. Variables: {seq},{uuid},{timestamp},{randint:a:b},{hostname},{app},{facility},{severity}")
    parser.add_argument("--from-file", help="Read messages from a file (one per line)")
    parser.add_argument("--stdin", action="store_true", help="Read messages from stdin")
    parser.add_argument("-n", "--count", type=int, default=1, help="Number of messages to send (0 for infinite)")
    parser.add_argument("--duration", type=float, default=0, help="Send for N seconds (overrides --count if >0)")
    parser.add_argument("--rate", type=float, default=0, help="Target rate msgs/sec (token-bucket). Mutually exclusive with --delay")
    parser.add_argument("--delay", type=float, default=0, help="Fixed delay between messages (seconds). Mutually exclusive with --rate")
    parser.add_argument("--interval", type=float, default=0, help="Repeat entire batch every N seconds (0 = once)")
    parser.add_argument("--size", type=int, default=0, help="Pad message to at least N bytes to test MTU/fragmentation")
    parser.add_argument("--echo", action="store_true", help="Print each message to stdout")
    parser.add_argument("--dry-run", action="store_true", help="Do not send; just print what would be sent")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    if args.tls and args.transport != "tcp":
        parser.error("--tls requires --transport tcp")
    if args.tls and args.port == 514 and not any(opt in sys.argv for opt in ("-p", "--port")):
        args.port = 6514  # sensible default for TLS
    if args.rate and args.delay:
        parser.error("Use either --rate or --delay, not both")

    # Build message source
    lines = []
    if args.stdin:
        lines = [ln.rstrip("\r\n") for ln in sys.stdin]
    elif args.from_file:
        with open(args.from_file, "r", encoding="utf-8") as f:
            lines = [ln.rstrip("\r\n") for ln in f]
    elif args.message:
        lines = [args.message]
    else:
        lines = EXAMPLE_MESSAGES[:]

    # Open socket unless dry run
    sock = None
    addr = None
    if not args.dry_run:
        sock, addr = open_socket(args.transport, args.target, args.port, tls=args.tls, cafile=args.cafile or "", certfile=args.certfile or "", keyfile=args.keyfile or "", insecure=args.insecure, sni=args.sni or "", bind_ip=args.bind_ip or "")
        if args.verbose:
            fam = "IPv6" if addr[0].count(":") else "IPv4"
            print(f"Connected via {args.transport.upper()}{'/TLS' if args.tls else ''} to {addr[0]}:{addr[1]} ({fam})")

    def _build(seq: int, content: str) -> bytes:
        msg = apply_template(content, seq=seq, host=args.hostname, app=args.app, facility=args.facility, severity=args.severity)
        if args.size and len(msg) < args.size:
            msg = msg + " " * (args.size - len(msg))
        now = datetime.now(timezone.utc)
        if args.format == "3164":
            return build_3164(args.facility, args.severity, args.hostname, args.app, args.procid, msg, now)
        else:
            return build_5424(args.facility, args.severity, args.hostname, args.app, args.procid, args.msgid, args.sd, msg, now)

    def _send(seq: int, content: str):
        payload = _build(seq, content)
        if args.echo or args.verbose or args.dry_run:
            print(payload.decode("utf-8", "replace"))
        if args.dry_run:
            return len(payload)
        return send_message(sock, addr, payload, transport=args.transport, tcp_framing=args.tcp_framing)

    def run_once():
        total = 0
        errors = 0
        start = time.perf_counter()
        seq = 1
        end_time = None
        if args.duration > 0:
            end_time = start + args.duration
        # Setup rate limiting
        last_ts = time.perf_counter()
        tokens = 0.0
        while True:
            for line in lines:
                if end_time and time.perf_counter() >= end_time:
                    return total, errors, time.perf_counter() - start
                try:
                    _send(seq, line)
                    total += 1
                except Exception as e:
                    errors += 1
                    if args.verbose:
                        print(f"Send error: {e}", file=sys.stderr)
                seq += 1
                # Termination on count (if not infinite)
                if args.duration <= 0 and args.count > 0 and total >= args.count:
                    return total, errors, time.perf_counter() - start
                # Pacing
                if args.rate > 0:
                    now = time.perf_counter()
                    tokens += args.rate * (now - last_ts)
                    last_ts = now
                    if tokens < 1.0:
                        sleep_for = (1.0 - tokens) / args.rate
                        time.sleep(sleep_for)
                        tokens = 0.0
                    else:
                        tokens -= 1.0
                elif args.delay > 0:
                    time.sleep(args.delay)

    if args.interval > 0:
        try:
            while True:
                sent, errs, elapsed = run_once()
                rate = sent / elapsed if elapsed > 0 else float("inf")
                print(f"Batch complete: sent={sent}, errors={errs}, elapsed={elapsed:.2f}s, rate={rate:.1f} msg/s")
                if args.interval > 0:
                    time.sleep(args.interval)
        except KeyboardInterrupt:
            print("Stopped.")
    else:
        sent, errs, elapsed = run_once()
        rate = sent / elapsed if elapsed > 0 else float("inf")
        print(f"Done: sent={sent}, errors={errs}, elapsed={elapsed:.2f}s, rate={rate:.1f} msg/s")

if __name__ == "__main__":
    main()
