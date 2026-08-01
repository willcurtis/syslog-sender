from datetime import datetime, timezone

import pytest

from logsalvo.templates import apply_template


def test_expands_supported_tokens() -> None:
    result = apply_template(
        "{seq} {hostname} {app} {facility} {severity} {randint:4:4}",
        seq=9,
        hostname="host",
        app="app",
        facility=16,
        severity=6,
        now=datetime.now(timezone.utc),
    )
    assert result == "9 host app 16 6 4"


def test_rejects_reversed_random_range() -> None:
    with pytest.raises(ValueError, match="randint"):
        apply_template(
            "{randint:9:1}",
            seq=1,
            hostname="host",
            app="app",
            facility=16,
            severity=6,
            now=datetime.now(timezone.utc),
        )
