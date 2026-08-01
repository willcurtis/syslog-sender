import pytest

from logsalvo.models import FACILITIES, RunConfig, SenderConfig, named_number


def test_named_facility_accepts_name_and_number() -> None:
    assert named_number("local4", FACILITIES, "facility") == 20
    assert named_number("20", FACILITIES, "facility") == 20


@pytest.mark.parametrize(
    "kwargs",
    [
        {"target": ""},
        {"target": "host", "port": 0},
        {"target": "host", "port": 65536},
        {"target": "host", "transport": "udp", "tls": True},
        {"target": "host", "retries": -1},
    ],
)
def test_invalid_sender_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        SenderConfig(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"count": -1},
        {"count": 0, "duration": 0},
        {"delay": -1},
        {"rate": 1, "delay": 1},
    ],
)
def test_invalid_run_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        RunConfig(**kwargs)
