from __future__ import annotations

import random
import re
import uuid
from datetime import datetime

RANDINT = re.compile(r"\{randint:(-?\d+):(-?\d+)\}")

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


def apply_template(
    template: str, *, seq: int, hostname: str, app: str, facility: int, severity: int, now: datetime
) -> str:
    replacements = {
        "{seq}": str(seq),
        "{uuid}": str(uuid.uuid4()),
        "{timestamp}": now.astimezone().isoformat(timespec="milliseconds"),
        "{hostname}": hostname,
        "{app}": app,
        "{facility}": str(facility),
        "{severity}": str(severity),
    }
    result = template
    for token, value in replacements.items():
        result = result.replace(token, value)

    def random_integer(match: re.Match[str]) -> str:
        start, end = int(match.group(1)), int(match.group(2))
        if start > end:
            raise ValueError(f"invalid randint range: {start} is greater than {end}")
        return str(random.randint(start, end))

    return RANDINT.sub(random_integer, result)
