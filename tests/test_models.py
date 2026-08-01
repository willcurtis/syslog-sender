from pathlib import Path

import pytest

import logsalvo
from logsalvo import __copyright__, __version__
from logsalvo.cli import parser
from logsalvo.gui import THEME_STYLESHEETS
from logsalvo.models import FACILITIES, RunConfig, SenderConfig, named_number


def test_named_facility_accepts_name_and_number() -> None:
    assert named_number("local4", FACILITIES, "facility") == 20
    assert named_number("20", FACILITIES, "facility") == 20


def test_version_metadata_is_exposed_by_cli(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        parser().parse_args(["--version"])
    assert exit_info.value.code == 0
    output = capsys.readouterr().out
    assert __version__ in output
    assert __copyright__ in output


def test_packaged_brand_asset_is_present() -> None:
    logo = Path(logsalvo.__file__).with_name("assets") / "tts-round-outline.png"
    assert logo.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")


def test_gui_provides_distinct_light_and_dark_themes() -> None:
    assert set(THEME_STYLESHEETS) == {"dark", "light"}
    assert "background: #081820" in THEME_STYLESHEETS["dark"]
    assert "background: #eef6f8" in THEME_STYLESHEETS["light"]
    assert "QPushButton#themeSwitch" in THEME_STYLESHEETS["light"]
    for stylesheet in THEME_STYLESHEETS.values():
        assert "QTabBar#workspaceTabBar" in stylesheet
        assert "QTabBar#senderTabBar" in stylesheet
    assert "QTabBar::tab" not in THEME_STYLESHEETS["dark"]
    assert "QTabWidget#senderTabs::tab-bar { left: 0px; }" in THEME_STYLESHEETS["dark"]


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
