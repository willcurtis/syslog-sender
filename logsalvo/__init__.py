"""Reusable LogSalvo syslog generation and transport package."""

from .models import MessageConfig, RunConfig, SenderConfig, Stats
from .sender import Sender

__all__ = ["MessageConfig", "RunConfig", "Sender", "SenderConfig", "Stats"]
__version__ = "2.1.1"
__app_name__ = "LogSalvo"
__copyright__ = "Copyright © 2025–2026 The Tech Shed"
