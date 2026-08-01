from __future__ import annotations

import argparse
import os
import socket
import sys

from .models import FACILITIES, SEVERITIES, MessageConfig, RunConfig, SenderConfig, named_number
from .sender import Sender
from .templates import EXAMPLE_MESSAGES


def positive_port(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return number


def nonnegative(value: str) -> float:
    number = float(value)
    if number < 0:
        raise argparse.ArgumentTypeError("value cannot be negative")
    return number


def named(value: str, choices: dict[str, int], label: str) -> int:
    try:
        return named_number(value, choices, label)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="logsalvo", description="LogSalvo RFC 3164/5424 syslog traffic generator."
    )
    result.add_argument("target", help="collector IP address or hostname")
    result.add_argument("-p", "--port", type=positive_port, default=None)
    result.add_argument("--transport", choices=["udp", "tcp"], default="udp")
    result.add_argument("--tls", action="store_true")
    result.add_argument("--cafile")
    result.add_argument("--certfile")
    result.add_argument("--keyfile")
    result.add_argument("--insecure", action="store_true")
    result.add_argument("--sni")
    result.add_argument("--tcp-framing", choices=["octet", "lf"], default="octet")
    result.add_argument("--bind-ip")
    result.add_argument("--timeout", type=nonnegative, default=5.0)
    result.add_argument("--retries", type=int, default=2)
    result.add_argument("--format", choices=["3164", "5424"], default="3164")
    result.add_argument("--facility", type=lambda v: named(v, FACILITIES, "facility"), default=16)
    result.add_argument("--severity", type=lambda v: named(v, SEVERITIES, "severity"), default=6)
    result.add_argument("--hostname", default=socket.gethostname())
    result.add_argument("--app", default="logsalvo")
    result.add_argument("--procid", default=str(os.getpid()))
    result.add_argument("--msgid", default="TEST")
    result.add_argument("--sd", default="-")
    result.add_argument(
        "--wire-size", type=int, default=0, help="minimum complete payload size in bytes"
    )
    source = result.add_mutually_exclusive_group()
    source.add_argument("-m", "--message")
    source.add_argument("--from-file")
    source.add_argument("--stdin", action="store_true")
    result.add_argument(
        "-n", "--count", type=int, default=1, help="attempt count; 0 requires duration"
    )
    result.add_argument("--duration", type=nonnegative, default=0)
    pacing = result.add_mutually_exclusive_group()
    pacing.add_argument("--rate", type=nonnegative, default=0)
    pacing.add_argument("--delay", type=nonnegative, default=0)
    result.add_argument("--dry-run", action="store_true")
    result.add_argument("--echo", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        port = arguments.port or (6514 if arguments.tls else 514)
        if arguments.stdin:
            messages = [line.rstrip("\r\n") for line in sys.stdin]
        elif arguments.from_file:
            with open(arguments.from_file, encoding="utf-8") as source:
                messages = [line.rstrip("\r\n") for line in source]
        elif arguments.message is not None:
            messages = [arguments.message]
        else:
            messages = EXAMPLE_MESSAGES
        sender_config = SenderConfig(
            arguments.target,
            port,
            arguments.transport,
            arguments.tls,
            arguments.cafile,
            arguments.certfile,
            arguments.keyfile,
            arguments.insecure,
            arguments.sni,
            arguments.tcp_framing,
            arguments.bind_ip,
            arguments.timeout,
            arguments.retries,
        )
        message_config = MessageConfig(
            arguments.format,
            arguments.facility,
            arguments.severity,
            arguments.hostname,
            arguments.app,
            arguments.procid,
            arguments.msgid,
            arguments.sd,
            arguments.wire_size,
        )
        run_config = RunConfig(arguments.count, arguments.duration, arguments.rate, arguments.delay)
        sender = Sender(
            sender_config, message_config, run_config, messages, dry_run=arguments.dry_run
        )
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    def echo(_: int, payload: bytes) -> None:
        if arguments.echo or arguments.dry_run:
            print(payload.decode("utf-8", "replace"))

    def report_error(seq: int, error: Exception) -> None:
        print(f"send {seq} failed: {error}", file=sys.stderr)

    try:
        stats = sender.run(on_message=echo, on_error=report_error)
    except (OSError, ConnectionError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        sender.cancel()
        print("stopped", file=sys.stderr)
        return 130
    print(
        f"attempted={stats.attempted} sent={stats.sent} failed={stats.failed} "
        f"bytes={stats.bytes_sent} elapsed={stats.elapsed:.2f}s rate={stats.effective_rate:.1f}/s"
    )
    return 1 if stats.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
