from pathlib import Path

import pytest

import logsalvo
from logsalvo import __copyright__, __version__
from logsalvo.cli import parser
from logsalvo.gui import THEME_STYLESHEETS, newest_visible_source_row, ordered_bind_addresses
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
    for stylesheet in THEME_STYLESHEETS.values():
        assert "QComboBox::drop-down" not in stylesheet


def test_bind_addresses_are_deduplicated_and_ordered() -> None:
    addresses = ordered_bind_addresses(["192.0.2.20", "::1", "10.0.0.4", "192.0.2.20"])
    assert addresses[:4] == ["0.0.0.0", "::", "127.0.0.1", "::1"]
    assert addresses[4:] == ["10.0.0.4", "192.0.2.20"]


def test_newest_visible_receiver_row_respects_filters_and_recent_batch() -> None:
    visible_rows = {1, 3, 7}
    is_visible = visible_rows.__contains__

    assert newest_visible_source_row(8, 8, is_visible) == 7
    assert newest_visible_source_row(8, 3, is_visible) == 7
    assert newest_visible_source_row(8, 1, is_visible) == 7
    assert newest_visible_source_row(9, 1, is_visible) is None


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
