from __future__ import annotations

import threading
import time
from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from .formatters import build_message
from .models import MessageConfig, RunConfig, SenderConfig, Stats
from .templates import apply_template
from .transports import SyslogTransport

MessageCallback = Callable[[int, bytes], None]
ErrorCallback = Callable[[int, Exception], None]
ProgressCallback = Callable[[Stats], None]


class Sender:
    def __init__(
        self,
        sender: SenderConfig,
        message: MessageConfig,
        run: RunConfig,
        messages: Sequence[str],
        *,
        dry_run: bool = False,
    ):
        if not messages:
            raise ValueError("message source is empty")
        self.sender_config = sender
        self.message_config = message
        self.run_config = run
        self.messages = tuple(messages)
        self.dry_run = dry_run
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(
        self,
        *,
        on_message: MessageCallback | None = None,
        on_error: ErrorCallback | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> Stats:
        stats = Stats()
        started = time.monotonic()
        deadline = started + self.run_config.duration if self.run_config.duration else None
        period = 1 / self.run_config.rate if self.run_config.rate else 0
        next_send = started
        transport = SyslogTransport(self.sender_config)
        seq = 1
        try:
            while not self._cancel.is_set():
                now_monotonic = time.monotonic()
                if deadline is not None and now_monotonic >= deadline:
                    break
                if self.run_config.count and stats.attempted >= self.run_config.count:
                    break
                if period:
                    wait = next_send - now_monotonic
                    if wait > 0 and self._cancel.wait(wait):
                        break
                    next_send = max(next_send + period, time.monotonic())

                template = self.messages[(seq - 1) % len(self.messages)]
                generated_at = datetime.now(timezone.utc)
                body = apply_template(
                    template,
                    seq=seq,
                    hostname=self.message_config.hostname,
                    app=self.message_config.app,
                    facility=self.message_config.facility,
                    severity=self.message_config.severity,
                    now=generated_at,
                )
                payload = build_message(self.message_config, body, generated_at)
                stats.attempted += 1
                if on_message:
                    on_message(seq, payload)

                error: Exception | None = None
                if self.dry_run:
                    stats.sent += 1
                    stats.bytes_sent += len(payload)
                else:
                    for retry in range(self.sender_config.retries + 1):
                        try:
                            stats.bytes_sent += transport.send(payload)
                            stats.sent += 1
                            error = None
                            break
                        except (OSError, ConnectionError) as caught:
                            error = caught
                            transport.close()
                            if retry < self.sender_config.retries and self._cancel.wait(
                                min(0.25 * (2**retry), 2.0)
                            ):
                                break
                    if error is not None:
                        stats.failed += 1
                        if on_error:
                            on_error(seq, error)
                seq += 1
                stats.elapsed = time.monotonic() - started
                if on_progress:
                    on_progress(stats)
                if self.run_config.delay and self._cancel.wait(self.run_config.delay):
                    break
        finally:
            transport.close()
            stats.elapsed = time.monotonic() - started
            stats.cancelled = self._cancel.is_set()
        return stats
