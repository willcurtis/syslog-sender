from __future__ import annotations

import json
import socket
import sys
from collections.abc import Callable
from pathlib import Path

from . import __app_name__, __copyright__, __version__
from .formatters import build_message
from .models import FACILITIES, SEVERITIES, MessageConfig, RunConfig, SenderConfig
from .receiver import (
    FACILITY_NAMES,
    SEVERITY_NAMES,
    ReceivedMessage,
    ReceiverConfig,
    SyslogReceiver,
    export_messages,
)
from .sender import Sender

STYLESHEET = """
QWidget#appRoot {
    background: #081820;
    color: #dcecf2;
    font-family: "Inter", "SF Pro Text", "Segoe UI", sans-serif;
    font-size: 13px;
}
QFrame#brandHeader {
    background: #0b202b;
    border: 1px solid #154052;
    border-radius: 14px;
}
QLabel#brandLogo { background: transparent; }
QLabel#productName {
    color: #f1fbff;
    font-size: 30px;
    font-weight: 700;
}
QLabel#tagline {
    color: #00b0f0;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 2px;
}
QLabel#brandDescription { color: #91aeb9; font-size: 12px; }
QLabel#versionBadge {
    background: #073442;
    color: #00c898;
    border: 1px solid #00a882;
    border-radius: 11px;
    padding: 5px 10px;
    font-size: 11px;
    font-weight: 700;
}
QTabWidget#workspaceTabs {
    background: #081820;
    border: none;
}
QTabWidget#workspaceTabs::pane {
    background: #0b202b;
    border: 1px solid #154052;
    border-radius: 12px;
    top: 7px;
}
QTabWidget#workspaceTabs::tab-bar { left: 0px; }
QTabBar#workspaceTabBar {
    background: #081820;
    border: none;
}
QTabBar#workspaceTabBar::tab {
    background: #0c2632;
    color: #91aeb9;
    border: 1px solid #1a4758;
    border-radius: 9px;
    padding: 10px 28px;
    margin-right: 7px;
    font-weight: 700;
}
QTabBar#workspaceTabBar::tab:selected {
    background: #00a77f;
    color: #031612;
    border-color: #00d4a2;
}
QTabBar#workspaceTabBar::tab:hover:!selected {
    background: #123846;
    color: #68d5ff;
    border-color: #007ca8;
}
QTabWidget#senderTabs {
    background: #0b202b;
    border: none;
}
QTabWidget#senderTabs::pane {
    background: #0b202b;
    border: 1px solid #154052;
    border-radius: 9px;
    top: -1px;
}
QTabWidget#senderTabs::tab-bar { left: 0px; }
QTabBar#senderTabBar {
    background: #0b202b;
    border: none;
}
QTabBar#senderTabBar::tab {
    background: transparent;
    color: #7f9ca7;
    border: none;
    border-bottom: 3px solid transparent;
    padding: 10px 22px 9px 22px;
    margin: 0 5px 0 0;
    font-weight: 600;
}
QTabBar#senderTabBar::tab:selected {
    background: #102b36;
    color: #00c898;
    border-bottom-color: #00c898;
}
QTabBar#senderTabBar::tab:hover:!selected {
    background: #0c2632;
    color: #00b0f0;
}
QScrollArea#tabScroll, QScrollArea#tabScroll QWidget#qt_scrollarea_viewport,
QWidget#tabPage {
    background: #0b202b;
    border: none;
}
QGroupBox {
    background: #0b202b;
    border: 1px solid #154052;
    border-radius: 10px;
    margin-top: 12px;
    padding: 12px;
    font-weight: 600;
    color: #c9e2ea;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 7px;
    color: #00b0f0;
}
QLabel { color: #b8d0d9; }
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit {
    background: #07151c;
    color: #e4f4f8;
    border: 1px solid #1a4758;
    border-radius: 6px;
    padding: 7px 9px;
    selection-background-color: #007f9e;
    min-height: 22px;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus,
QDoubleSpinBox:focus, QPlainTextEdit:focus {
    border: 1px solid #00b0f0;
}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled,
QDoubleSpinBox:disabled, QPlainTextEdit:disabled {
    background: #0a171d;
    color: #526b74;
}
QComboBox QAbstractItemView {
    background: #0b202b;
    color: #dcecf2;
    border: 1px solid #1a4758;
    selection-background-color: #07536a;
}
QCheckBox { color: #b8d0d9; spacing: 8px; }
QCheckBox::indicator {
    width: 17px;
    height: 17px;
    border: 1px solid #2a6072;
    border-radius: 4px;
    background: #07151c;
}
QCheckBox::indicator:checked {
    background: #00c898;
    border-color: #00e1ae;
}
QPushButton {
    background: #12303d;
    color: #dcecf2;
    border: 1px solid #245567;
    border-radius: 7px;
    padding: 8px 16px;
    font-weight: 600;
}
QPushButton:hover { background: #174456; border-color: #00b0f0; }
QPushButton:pressed { background: #0d2935; }
QPushButton:disabled { color: #506873; background: #10232c; border-color: #173744; }
QPushButton#primaryButton {
    background: #00a77f;
    color: #031612;
    border-color: #00d4a2;
    min-width: 100px;
}
QPushButton#primaryButton:hover { background: #00c898; }
QPushButton#dangerButton { border-color: #9e5260; color: #ffb6c1; min-width: 80px; }
QPushButton#dangerButton:hover { background: #6d2633; border-color: #e26c7c; }
QPushButton#receiverExpand:checked {
    background: #073442;
    color: #66f2ca;
    border-color: #00a882;
}
QPushButton#linkButton {
    background: transparent;
    border: none;
    color: #00b0f0;
    padding: 4px 8px;
}
QPushButton#linkButton:hover { color: #00d9ff; text-decoration: underline; }
QLabel#statusPill {
    background: #102b36;
    color: #91aeb9;
    border: 1px solid #1a4758;
    border-radius: 7px;
    padding: 8px 12px;
    font-weight: 600;
}
QLabel#statusPill[state="running"] { color: #68d5ff; border-color: #007ca8; background: #082c3b; }
QLabel#statusPill[state="success"] { color: #66f2ca; border-color: #008f6c; background: #073328; }
QLabel#statusPill[state="error"] { color: #ff9cac; border-color: #a44757; background: #381821; }
QLabel#statusPill[state="stopping"] { color: #ffd28c; border-color: #9d6a20; background: #392a12; }
QLabel#copyright { color: #607d88; font-size: 11px; }
QScrollBar:vertical {
    background: #07151c;
    width: 11px;
    margin: 1px;
}
QScrollBar::handle:vertical { background: #245567; border-radius: 5px; min-height: 24px; }
QScrollBar::handle:vertical:hover { background: #00a77f; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QToolTip {
    background: #102b36;
    color: #e4f4f8;
    border: 1px solid #00b0f0;
    padding: 5px;
}
QTableView {
    background: #07151c;
    alternate-background-color: #0a1d26;
    color: #dcecf2;
    border: 1px solid #1a4758;
    border-radius: 7px;
    gridline-color: #123440;
    selection-background-color: #07536a;
    selection-color: #ffffff;
}
QHeaderView::section {
    background: #102b36;
    color: #91c7d8;
    border: none;
    border-right: 1px solid #1a4758;
    border-bottom: 1px solid #1a4758;
    padding: 8px;
    font-weight: 700;
}
QSplitter::handle { background: #154052; height: 2px; }
QLabel#listenerHelp { color: #7f9ca7; font-size: 11px; }
QLabel#receiverSummary { color: #91c7d8; font-weight: 600; }
QPushButton#themeSwitch {
    background: #102b36;
    color: #b8d0d9;
    border: 1px solid #245567;
    border-radius: 12px;
    padding: 5px 11px;
    min-width: 92px;
    font-size: 11px;
}
QPushButton#themeSwitch:hover { border-color: #00b0f0; }
QPushButton#themeSwitch:checked {
    background: #dff8f1;
    color: #07536a;
    border-color: #00a77f;
}
"""

LIGHT_STYLESHEET = (
    STYLESHEET
    + """
QWidget#appRoot { background: #eef6f8; color: #173440; }
QFrame#brandHeader, QTabWidget#workspaceTabs::pane, QTabWidget#senderTabs::pane,
QScrollArea#tabScroll,
QScrollArea#tabScroll QWidget#qt_scrollarea_viewport, QWidget#tabPage,
QWidget#workspacePage, QGroupBox { background: #ffffff; border-color: #b9d4dc; }
QLabel#productName { color: #092a36; }
QLabel#brandDescription { color: #587985; }
QLabel#versionBadge { background: #e2f8f3; color: #007c60; border-color: #00a882; }
QTabWidget#workspaceTabs { background: #eef6f8; }
QTabBar#workspaceTabBar { background: #eef6f8; }
QTabBar#workspaceTabBar::tab {
    background: #dcecef;
    color: #456873;
    border-color: #a9c8d0;
}
QTabBar#workspaceTabBar::tab:selected {
    background: #008f6c;
    color: #ffffff;
    border-color: #00765a;
}
QTabBar#workspaceTabBar::tab:hover:!selected {
    background: #c9e2e7;
    color: #005f82;
    border-color: #68aebf;
}
QTabWidget#senderTabs, QTabBar#senderTabBar { background: #ffffff; }
QTabBar#senderTabBar::tab { background: transparent; color: #587985; }
QTabBar#senderTabBar::tab:selected {
    background: #e7f5f2;
    color: #007c60;
    border-bottom-color: #00a77f;
}
QTabBar#senderTabBar::tab:hover:!selected { background: #edf7f9; color: #007ca8; }
QGroupBox { color: #244a57; }
QGroupBox::title, QLabel#tagline { color: #007ca8; }
QLabel { color: #365965; }
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit {
    background: #f8fcfd;
    color: #153945;
    border-color: #9cbfc9;
    selection-background-color: #80d9ec;
}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled,
QDoubleSpinBox:disabled, QPlainTextEdit:disabled { background: #e8f0f2; color: #839ba3; }
QComboBox QAbstractItemView { background: #ffffff; color: #173440; border-color: #9cbfc9; selection-background-color: #c6edf5; }
QCheckBox { color: #365965; }
QCheckBox::indicator { background: #ffffff; border-color: #789faa; }
QPushButton { background: #e5f0f3; color: #244a57; border-color: #91b4be; }
QPushButton:hover { background: #d6e9ed; border-color: #007ca8; }
QPushButton:pressed { background: #c7dde2; }
QPushButton:disabled { color: #8aa0a7; background: #edf2f3; border-color: #c7d7db; }
QPushButton#primaryButton { background: #00a77f; color: #ffffff; border-color: #007f64; }
QPushButton#primaryButton:hover { background: #008f6c; }
QPushButton#dangerButton { background: #fff4f5; border-color: #c95b6c; color: #a83245; }
QPushButton#dangerButton:hover { background: #ffe4e8; border-color: #a83245; }
QPushButton#receiverExpand:checked {
    background: #d9f7ef;
    color: #006b54;
    border-color: #00a882;
}
QPushButton#linkButton { background: transparent; color: #007ca8; border: none; }
QPushButton#linkButton:hover { color: #005b7c; }
QLabel#statusPill { background: #e5f0f3; color: #526f79; border-color: #9cbfc9; }
QLabel#statusPill[state="running"] { color: #005f82; border-color: #269ac2; background: #dff4fb; }
QLabel#statusPill[state="success"] { color: #006c52; border-color: #28a786; background: #def7ef; }
QLabel#statusPill[state="error"] { color: #9c2e40; border-color: #d97887; background: #ffe7eb; }
QLabel#statusPill[state="stopping"] { color: #80540d; border-color: #d3a34f; background: #fff1d6; }
QLabel#copyright, QLabel#listenerHelp { color: #6f8992; }
QLabel#receiverSummary { color: #356575; }
QScrollBar:vertical { background: #e6f0f2; }
QScrollBar::handle:vertical { background: #91b4be; }
QScrollBar::handle:vertical:hover { background: #00a77f; }
QToolTip { background: #ffffff; color: #173440; border-color: #007ca8; }
QTableView {
    background: #ffffff;
    alternate-background-color: #edf6f8;
    color: #173440;
    border-color: #9cbfc9;
    gridline-color: #c9dde2;
    selection-background-color: #bce8f1;
    selection-color: #092a36;
}
QHeaderView::section { background: #dcecef; color: #285462; border-color: #aac7cf; }
QSplitter::handle { background: #aac7cf; }
QPushButton#themeSwitch { background: #dff8f1; color: #07536a; border-color: #00a77f; }
QPushButton#themeSwitch:hover { background: #c8f1e7; border-color: #007f64; }
"""
)

THEME_STYLESHEETS = {"dark": STYLESHEET, "light": LIGHT_STYLESHEET}


def ordered_bind_addresses(addresses: list[str]) -> list[str]:
    """Return unique bind addresses with the safest common choices first."""
    preferred = ["0.0.0.0", "::", "127.0.0.1", "::1"]
    unique = {address.strip() for address in addresses if address.strip()}
    unique.update(preferred)
    remainder = sorted(
        unique.difference(preferred),
        key=lambda address: (":" in address, address.casefold()),
    )
    return preferred + remainder


def newest_visible_source_row(
    row_count: int,
    candidate_count: int,
    is_visible: Callable[[int], bool],
) -> int | None:
    """Return the newest visible source row among recently appended candidates."""
    first_candidate = max(0, row_count - max(0, candidate_count))
    for row in range(row_count - 1, first_candidate - 1, -1):
        if is_visible(row):
            return row
    return None


def main() -> int:
    try:
        from PySide6.QtCore import (
            QAbstractTableModel,
            QModelIndex,
            QObject,
            QSettings,
            QSortFilterProxyModel,
            Qt,
            QThread,
            Signal,
            Slot,
        )
        from PySide6.QtGui import QBrush, QColor, QIcon, QPixmap
        from PySide6.QtNetwork import QNetworkInterface
        from PySide6.QtWidgets import (
            QAbstractItemView,
            QApplication,
            QCheckBox,
            QComboBox,
            QDoubleSpinBox,
            QFileDialog,
            QFormLayout,
            QFrame,
            QGridLayout,
            QGroupBox,
            QHBoxLayout,
            QHeaderView,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMessageBox,
            QPlainTextEdit,
            QPushButton,
            QScrollArea,
            QSizePolicy,
            QSpinBox,
            QSplitter,
            QTableView,
            QTabWidget,
            QVBoxLayout,
            QWidget,
        )
    except ImportError:
        print(
            "The GUI requires PySide6. Install it with: pip install 'logsalvo[gui]'",
            file=sys.stderr,
        )
        return 2

    class Worker(QObject):
        log = Signal(str)
        progress = Signal(int, int, int, float)
        finished = Signal(object)
        failed = Signal(str)

        def __init__(self, sender: Sender):
            super().__init__()
            self.sender = sender

        @Slot()
        def run(self) -> None:
            try:
                stats = self.sender.run(
                    on_message=lambda seq, payload: self.log.emit(
                        f"{seq}: {payload.decode('utf-8', 'replace')}"
                    ),
                    on_error=lambda seq, error: self.log.emit(f"ERROR {seq}: {error}"),
                    on_progress=lambda stats: self.progress.emit(
                        stats.attempted, stats.sent, stats.failed, stats.effective_rate
                    ),
                )
                self.finished.emit(stats)
            except Exception as error:  # noqa: BLE001 - worker must report unexpected GUI-boundary errors
                self.failed.emit(str(error))

        @Slot()
        def cancel(self) -> None:
            self.sender.cancel()

    class ReceiverBridge(QObject):
        message = Signal(object)
        error = Signal(str)

    class ReceiverTableModel(QAbstractTableModel):
        HEADERS = (
            "Received",
            "Sender",
            "Protocol",
            "Hostname",
            "Facility",
            "Severity",
            "Application",
            "Message",
        )

        def __init__(self, maximum: int = 10_000):
            super().__init__()
            self.messages: list[ReceivedMessage] = []
            self.maximum = maximum
            self.theme = "dark"

        def rowCount(self, parent: QModelIndex | None = None) -> int:
            return 0 if parent is not None and parent.isValid() else len(self.messages)

        def columnCount(self, parent: QModelIndex | None = None) -> int:
            return 0 if parent is not None and parent.isValid() else len(self.HEADERS)

        def headerData(self, section: int, orientation: Qt.Orientation, role: int):
            if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
                return self.HEADERS[section]
            return None

        def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
            if not index.isValid() or not 0 <= index.row() < len(self.messages):
                return None
            message = self.messages[index.row()]
            values = (
                message.received_at.astimezone().strftime("%H:%M:%S.%f")[:-3],
                f"{message.sender}:{message.sender_port}",
                message.protocol,
                message.hostname or "—",
                message.facility_name,
                message.severity_name,
                message.app or "—",
                message.message,
            )
            if role == Qt.ItemDataRole.DisplayRole:
                return values[index.column()]
            if role == Qt.ItemDataRole.ToolTipRole:
                return message.raw
            if role == Qt.ItemDataRole.UserRole:
                return message
            if role == Qt.ItemDataRole.ForegroundRole and index.column() == 5:
                dark_colours = {
                    "emerg": "#ff6379",
                    "alert": "#ff7184",
                    "crit": "#ff8797",
                    "err": "#ff9cac",
                    "warn": "#ffd28c",
                    "notice": "#68d5ff",
                    "info": "#66f2ca",
                    "debug": "#91aeb9",
                }
                light_colours = {
                    "emerg": "#a9152e",
                    "alert": "#b51f38",
                    "crit": "#bd2c43",
                    "err": "#a83a4b",
                    "warn": "#8a5a08",
                    "notice": "#006a91",
                    "info": "#00735a",
                    "debug": "#526f79",
                }
                colours = light_colours if self.theme == "light" else dark_colours
                fallback = "#526f79" if self.theme == "light" else "#91aeb9"
                return QBrush(QColor(colours.get(message.severity_name, fallback)))
            return None

        def set_theme(self, theme: str) -> None:
            self.theme = theme
            if self.messages:
                top_left = self.index(0, 5)
                bottom_right = self.index(len(self.messages) - 1, 5)
                self.dataChanged.emit(top_left, bottom_right, [Qt.ItemDataRole.ForegroundRole])

        def add_message(self, message: ReceivedMessage) -> None:
            while len(self.messages) >= self.maximum:
                self.beginRemoveRows(QModelIndex(), 0, 0)
                self.messages.pop(0)
                self.endRemoveRows()
            row = len(self.messages)
            self.beginInsertRows(QModelIndex(), row, row)
            self.messages.append(message)
            self.endInsertRows()

        def set_maximum(self, maximum: int) -> None:
            self.maximum = maximum
            excess = len(self.messages) - maximum
            if excess > 0:
                self.beginRemoveRows(QModelIndex(), 0, excess - 1)
                del self.messages[:excess]
                self.endRemoveRows()

        def clear(self) -> None:
            if not self.messages:
                return
            self.beginResetModel()
            self.messages.clear()
            self.endResetModel()

    class ReceiverFilterProxy(QSortFilterProxyModel):
        def __init__(self):
            super().__init__()
            self.search_text = ""
            self.severity = "All severities"
            self.facility = "All facilities"
            self.protocol = "All protocols"
            self.setDynamicSortFilter(True)

        def set_filters(self, search: str, severity: str, facility: str, protocol: str) -> None:
            self.search_text = search.casefold().strip()
            self.severity = severity
            self.facility = facility
            self.protocol = protocol
            self.invalidateFilter()

        def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
            model = self.sourceModel()
            index = model.index(source_row, 0, source_parent)
            message = model.data(index, Qt.ItemDataRole.UserRole)
            if not isinstance(message, ReceivedMessage):
                return False
            if self.severity != "All severities" and message.severity_name != self.severity:
                return False
            if self.facility != "All facilities" and message.facility_name != self.facility:
                return False
            if self.protocol != "All protocols" and message.protocol != self.protocol:
                return False
            if self.search_text:
                haystack = (
                    f"{message.raw} {message.sender} {message.hostname} {message.app} "
                    f"{message.facility_name} {message.severity_name}"
                ).casefold()
                if self.search_text not in haystack:
                    return False
            return True

    class Window(QMainWindow):
        def __init__(self):
            super().__init__()
            self.logo_path = Path(__file__).with_name("assets") / "tts-round-outline.png"
            self.logo = QPixmap(str(self.logo_path))
            self.settings = QSettings("The Tech Shed", __app_name__)
            saved_theme = str(self.settings.value("appearance/theme", "dark")).lower()
            self.theme = saved_theme if saved_theme in THEME_STYLESHEETS else "dark"
            self.setWindowTitle(f"{__app_name__} · Syslog Traffic Studio · v{__version__}")
            self.setWindowIcon(QIcon(str(self.logo_path)))
            self.resize(1080, 860)
            self.setMinimumSize(900, 720)
            self.thread: QThread | None = None
            self.worker: Worker | None = None
            self.receiver: SyslogReceiver | None = None
            self.receiver_bridge = ReceiverBridge()
            self.receiver_bridge.message.connect(self.receive_message)
            self.receiver_bridge.error.connect(self.receiver_error)
            self.receiver_total = 0
            self.receiver_pending: list[ReceivedMessage] = []
            self.receiver_paused = False
            self.receiver_log_expanded = False
            self._receiver_splitter_sizes: list[int] = []
            self._build()
            self.preview()

        def _line(self, value: str = "") -> QLineEdit:
            widget = QLineEdit(value)
            self._expand_field(widget)
            widget.textChanged.connect(self.preview)
            return widget

        def _expand_field(self, widget: QWidget, minimum_width: int = 440) -> None:
            widget.setMinimumWidth(minimum_width)
            widget.setMinimumHeight(38)
            widget.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Fixed,
            )

        def _form(self, parent: QWidget | None = None) -> QFormLayout:
            form = QFormLayout(parent)
            form.setContentsMargins(32, 28, 32, 28)
            form.setHorizontalSpacing(22)
            form.setVerticalSpacing(14)
            form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            form.setFormAlignment(Qt.AlignmentFlag.AlignTop)
            form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
            form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
            return form

        def _scrollable_tab(self, content: QWidget) -> QScrollArea:
            scroll = QScrollArea()
            scroll.setObjectName("tabScroll")
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            scroll.setWidget(content)
            return scroll

        def _build(self) -> None:
            root = QWidget()
            root.setObjectName("appRoot")
            layout = QVBoxLayout(root)
            layout.setContentsMargins(24, 20, 24, 16)
            layout.setSpacing(14)

            header = QFrame()
            header.setObjectName("brandHeader")
            header_layout = QHBoxLayout(header)
            header_layout.setContentsMargins(20, 14, 20, 14)
            logo = QLabel()
            logo.setObjectName("brandLogo")
            logo.setPixmap(
                self.logo.scaled(
                    92,
                    92,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
            logo.setFixedSize(96, 96)
            header_layout.addWidget(logo)
            brand_copy = QVBoxLayout()
            brand_copy.setSpacing(2)
            product_name = QLabel(__app_name__)
            product_name.setObjectName("productName")
            tagline = QLabel("SYSLOG TRAFFIC STUDIO")
            tagline.setObjectName("tagline")
            description = QLabel(
                "Send, receive and inspect standards-aware syslog traffic with confidence."
            )
            description.setObjectName("brandDescription")
            brand_copy.addWidget(product_name)
            brand_copy.addWidget(tagline)
            brand_copy.addWidget(description)
            header_layout.addLayout(brand_copy)
            header_layout.addStretch()
            version = QLabel(f"VERSION {__version__}")
            version.setObjectName("versionBadge")
            version.setAlignment(Qt.AlignmentFlag.AlignCenter)
            header_controls = QVBoxLayout()
            header_controls.setSpacing(8)
            header_controls.addWidget(version, alignment=Qt.AlignmentFlag.AlignRight)
            self.theme_switch = QPushButton()
            self.theme_switch.setObjectName("themeSwitch")
            self.theme_switch.setCheckable(True)
            self.theme_switch.setChecked(self.theme == "light")
            self.theme_switch.setAccessibleName("Use light mode")
            self.theme_switch.setToolTip("Switch between dark and light appearance")
            self.theme_switch.toggled.connect(self.apply_theme)
            header_controls.addWidget(self.theme_switch, alignment=Qt.AlignmentFlag.AlignRight)
            header_layout.addLayout(header_controls)
            layout.addWidget(header)

            workspace = QTabWidget()
            workspace.setObjectName("workspaceTabs")
            workspace.setDocumentMode(True)
            workspace.tabBar().setObjectName("workspaceTabBar")
            workspace.tabBar().setDrawBase(False)

            sender_page = QWidget()
            sender_page.setObjectName("workspacePage")
            sender_layout = QVBoxLayout(sender_page)
            sender_layout.setContentsMargins(0, 8, 0, 0)
            sender_layout.setSpacing(12)

            tabs = QTabWidget()
            tabs.setObjectName("senderTabs")
            tabs.setDocumentMode(True)
            tabs.tabBar().setObjectName("senderTabBar")
            tabs.tabBar().setDrawBase(False)
            tabs.setMinimumHeight(420)
            sender_layout.addWidget(tabs, 3)

            connection = QWidget()
            connection.setObjectName("tabPage")
            connection_form = self._form(connection)
            self.target = self._line("127.0.0.1")
            self.port = QSpinBox()
            self.port.setRange(1, 65535)
            self.port.setValue(514)
            self._expand_field(self.port)
            self.transport = QComboBox()
            self.transport.addItems(["udp", "tcp"])
            self._expand_field(self.transport)
            self.tls = QCheckBox("Enable TLS")
            self.tls.setMinimumHeight(38)
            self.framing = QComboBox()
            self.framing.addItems(["octet", "lf"])
            self._expand_field(self.framing)
            self.bind_ip = self._line()
            self.cafile = self._line()
            self.certfile = self._line()
            self.keyfile = self._line()
            self.insecure = QCheckBox("Disable certificate verification (testing only)")
            self.sni = self._line()
            for label, widget in [
                ("Destination", self.target),
                ("Port", self.port),
                ("Transport", self.transport),
                ("TLS", self.tls),
                ("TCP framing", self.framing),
                ("Source IP", self.bind_ip),
                ("CA file", self.cafile),
                ("Client certificate", self.certfile),
                ("Client key", self.keyfile),
                ("SNI override", self.sni),
                ("TLS verification", self.insecure),
            ]:
                connection_form.addRow(label, widget)
            tabs.addTab(self._scrollable_tab(connection), "Connection")

            message_tab = QWidget()
            message_tab.setObjectName("tabPage")
            message_layout = QVBoxLayout(message_tab)
            message_layout.setContentsMargins(32, 28, 32, 24)
            message_layout.setSpacing(14)
            message_form = self._form()
            message_form.setContentsMargins(0, 0, 0, 0)
            self.format = QComboBox()
            self.format.addItems(["3164", "5424"])
            self._expand_field(self.format)
            self.facility = QComboBox()
            self.facility.addItems(FACILITIES)
            self._expand_field(self.facility)
            self.severity = QComboBox()
            self.severity.addItems(SEVERITIES)
            self._expand_field(self.severity)
            self.severity.setCurrentText("info")
            self.hostname = self._line(socket.gethostname())
            self.app = self._line("logsalvo")
            self.procid = self._line("-")
            self.msgid = self._line("TEST")
            self.sd = self._line("-")
            self.wire_size = QSpinBox()
            self.wire_size.setRange(0, 65507)
            self._expand_field(self.wire_size)
            for label, widget in [
                ("Format", self.format),
                ("Facility", self.facility),
                ("Severity", self.severity),
                ("Hostname", self.hostname),
                ("Application", self.app),
                ("PROCID", self.procid),
                ("MSGID", self.msgid),
                ("Structured data", self.sd),
                ("Minimum wire bytes", self.wire_size),
            ]:
                message_form.addRow(label, widget)
            message_layout.addLayout(message_form)
            self.messages = QPlainTextEdit("Test event {seq} id={uuid} at {timestamp}")
            self.messages.setMinimumHeight(140)
            self.messages.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Expanding,
            )
            self.messages.textChanged.connect(self.preview)
            message_layout.addWidget(QLabel("Messages (one template per line)"))
            message_layout.addWidget(self.messages)
            import_button = QPushButton("Import message file")
            import_button.clicked.connect(self.import_messages)
            message_layout.addWidget(import_button)
            tabs.addTab(self._scrollable_tab(message_tab), "Message")

            run_tab = QWidget()
            run_tab.setObjectName("tabPage")
            run_form = self._form(run_tab)
            self.count = QSpinBox()
            self.count.setRange(0, 10_000_000)
            self.count.setValue(10)
            self._expand_field(self.count)
            self.duration = QDoubleSpinBox()
            self.duration.setRange(0, 86400)
            self.duration.setSuffix(" s")
            self._expand_field(self.duration)
            self.rate = QDoubleSpinBox()
            self.rate.setRange(0, 1_000_000)
            self.rate.setSuffix(" msg/s")
            self._expand_field(self.rate)
            self.delay = QDoubleSpinBox()
            self.delay.setRange(0, 3600)
            self.delay.setDecimals(3)
            self.delay.setSuffix(" s")
            self._expand_field(self.delay)
            self.retries = QSpinBox()
            self.retries.setRange(0, 20)
            self.retries.setValue(2)
            self._expand_field(self.retries)
            self.dry_run = QCheckBox("Build messages without sending")
            self.dry_run.setMinimumHeight(38)
            for label, widget in [
                ("Attempt count", self.count),
                ("Duration", self.duration),
                ("Rate", self.rate),
                ("Fixed delay", self.delay),
                ("Retries", self.retries),
                ("Dry run", self.dry_run),
            ]:
                run_form.addRow(label, widget)
            tabs.addTab(self._scrollable_tab(run_tab), "Run")

            preview_group = QGroupBox("Live preview")
            preview_group.setObjectName("previewGroup")
            preview_layout = QVBoxLayout(preview_group)
            self.preview_box = QPlainTextEdit()
            self.preview_box.setReadOnly(True)
            self.preview_box.setMaximumHeight(100)
            preview_layout.addWidget(self.preview_box)
            sender_layout.addWidget(preview_group)
            controls = QHBoxLayout()
            self.start_button = QPushButton("Start")
            self.start_button.setObjectName("primaryButton")
            self.start_button.clicked.connect(self.start)
            self.stop_button = QPushButton("Stop")
            self.stop_button.setObjectName("dangerButton")
            self.stop_button.clicked.connect(self.stop)
            self.stop_button.setEnabled(False)
            save_button = QPushButton("Save profile")
            save_button.clicked.connect(self.save_profile)
            load_button = QPushButton("Load profile")
            load_button.clicked.connect(self.load_profile)
            controls.addWidget(self.start_button)
            controls.addWidget(self.stop_button)
            controls.addStretch()
            controls.addWidget(save_button)
            controls.addWidget(load_button)
            sender_layout.addLayout(controls)
            self.status = QLabel("Ready")
            self.status.setObjectName("statusPill")
            self.status.setProperty("state", "ready")
            self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sender_layout.addWidget(self.status)
            self.log = QPlainTextEdit()
            self.log.setReadOnly(True)
            self.log.setMinimumHeight(120)
            self.log.setPlaceholderText("Transmission events and errors will appear here.")
            sender_layout.addWidget(self.log)

            workspace.addTab(sender_page, "Send")
            workspace.addTab(self._build_receiver_page(), "Receive")
            layout.addWidget(workspace, 1)

            footer = QHBoxLayout()
            copyright_label = QLabel(__copyright__)
            copyright_label.setObjectName("copyright")
            footer.addWidget(copyright_label)
            footer.addStretch()
            about_button = QPushButton("About LogSalvo")
            about_button.setObjectName("linkButton")
            about_button.clicked.connect(self.about)
            footer.addWidget(about_button)
            layout.addLayout(footer)
            self.setCentralWidget(root)
            self.apply_theme(self.theme == "light", persist=False)
            for widget in [self.format, self.facility, self.severity]:
                widget.currentTextChanged.connect(self.preview)
            self.wire_size.valueChanged.connect(self.preview)

        def apply_theme(self, light_mode: bool, *, persist: bool = True) -> None:
            self.theme = "light" if light_mode else "dark"
            self.theme_switch.setText("☀  Light mode" if light_mode else "☾  Dark mode")
            self.theme_switch.setAccessibleDescription(
                "Light mode is active" if light_mode else "Dark mode is active"
            )
            self.setStyleSheet(THEME_STYLESHEETS[self.theme])
            if hasattr(self, "receiver_model"):
                self.receiver_model.set_theme(self.theme)
            if persist:
                self.settings.setValue("appearance/theme", self.theme)

        def _build_receiver_page(self) -> QWidget:
            page = QWidget()
            page.setObjectName("workspacePage")
            page_layout = QVBoxLayout(page)
            page_layout.setContentsMargins(0, 8, 0, 0)
            page_layout.setSpacing(12)

            self.receiver_listener_group = QGroupBox("Listener")
            listener_grid = QGridLayout(self.receiver_listener_group)
            listener_grid.setContentsMargins(18, 18, 18, 14)
            listener_grid.setHorizontalSpacing(12)
            listener_grid.setVerticalSpacing(10)
            self.receiver_bind = QComboBox()
            self.receiver_bind.setObjectName("bindAddressSelector")
            self.receiver_bind.setEditable(True)
            self.receiver_bind.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
            self.receiver_bind.setMaxVisibleItems(16)
            self.receiver_bind.setPlaceholderText("0.0.0.0, ::, or a local address")
            self.receiver_bind.setAccessibleName("Receiver bind address")
            self.receiver_bind.setToolTip(
                "Open the list to select a detected local address, or type an address manually"
            )
            self.receiver_bind_refresh = QPushButton("Refresh")
            self.receiver_bind_refresh.setToolTip(
                "Rescan this host's active IPv4 and IPv6 interface addresses"
            )
            self.receiver_bind_refresh.clicked.connect(self.refresh_bind_addresses)
            self.refresh_bind_addresses()
            self.receiver_port = QSpinBox()
            self.receiver_port.setRange(1, 65535)
            self.receiver_port.setValue(5514)
            self.receiver_protocol = QComboBox()
            self.receiver_protocol.addItems(["UDP", "TCP"])
            self.receiver_framing = QComboBox()
            self.receiver_framing.addItems(["auto", "octet", "lf"])
            self.receiver_framing.setEnabled(False)
            self.receiver_protocol.currentTextChanged.connect(
                lambda protocol: self.receiver_framing.setEnabled(protocol == "TCP")
            )
            self.receiver_retention = QSpinBox()
            self.receiver_retention.setRange(100, 1_000_000)
            self.receiver_retention.setValue(10_000)
            self.receiver_retention.setSingleStep(1_000)
            self.receiver_retention.setSuffix(" messages")
            for widget in (
                self.receiver_bind,
                self.receiver_port,
                self.receiver_protocol,
                self.receiver_framing,
                self.receiver_retention,
            ):
                widget.setMinimumHeight(38)
                widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            self.receiver_bind.setMinimumWidth(240)
            self.receiver_bind_refresh.setMinimumHeight(38)
            bind_address_row = QHBoxLayout()
            bind_address_row.setContentsMargins(0, 0, 0, 0)
            bind_address_row.setSpacing(8)
            bind_address_row.addWidget(self.receiver_bind, 1)
            bind_address_row.addWidget(self.receiver_bind_refresh)
            listener_grid.addWidget(QLabel("Bind address"), 0, 0)
            listener_grid.addLayout(bind_address_row, 1, 0)
            listener_grid.addWidget(QLabel("Port"), 0, 1)
            listener_grid.addWidget(self.receiver_port, 1, 1)
            listener_grid.addWidget(QLabel("Protocol"), 0, 2)
            listener_grid.addWidget(self.receiver_protocol, 1, 2)
            listener_grid.addWidget(QLabel("TCP framing"), 0, 3)
            listener_grid.addWidget(self.receiver_framing, 1, 3)
            listener_grid.addWidget(QLabel("Retention"), 0, 4)
            listener_grid.addWidget(self.receiver_retention, 1, 4)
            listener_grid.setColumnStretch(0, 3)
            for column in range(1, 5):
                listener_grid.setColumnStretch(column, 1)

            listener_actions = QHBoxLayout()
            self.receiver_start = QPushButton("Start listening")
            self.receiver_start.setObjectName("primaryButton")
            self.receiver_start.clicked.connect(self.start_receiver)
            self.receiver_stop = QPushButton("Stop")
            self.receiver_stop.setObjectName("dangerButton")
            self.receiver_stop.setEnabled(False)
            self.receiver_stop.clicked.connect(self.stop_receiver)
            self.receiver_status = QLabel("Stopped")
            self.receiver_status.setObjectName("statusPill")
            self.receiver_status.setProperty("state", "ready")
            listener_actions.addWidget(self.receiver_start)
            listener_actions.addWidget(self.receiver_stop)
            listener_actions.addWidget(self.receiver_status, 1)
            listener_grid.addLayout(listener_actions, 2, 0, 1, 5)
            privilege_help = QLabel(
                "Ports 1–65535 are supported. Ports below 1024 may require elevated privileges "
                "or an operating-system bind capability."
            )
            privilege_help.setObjectName("listenerHelp")
            privilege_help.setWordWrap(True)
            listener_grid.addWidget(privilege_help, 3, 0, 1, 5)
            page_layout.addWidget(self.receiver_listener_group)

            filter_group = QGroupBox("Find and filter")
            filter_layout = QHBoxLayout(filter_group)
            self.receiver_search = QLineEdit()
            self.receiver_search.setPlaceholderText(
                "Search message text, sender, hostname, application, facility…"
            )
            self.receiver_search.setMinimumHeight(38)
            self.receiver_severity = QComboBox()
            self.receiver_severity.addItems(["All severities", *SEVERITY_NAMES])
            self.receiver_facility = QComboBox()
            self.receiver_facility.addItems(["All facilities", *FACILITY_NAMES])
            self.receiver_protocol_filter = QComboBox()
            self.receiver_protocol_filter.addItems(["All protocols", "UDP", "TCP"])
            for widget in (
                self.receiver_severity,
                self.receiver_facility,
                self.receiver_protocol_filter,
            ):
                widget.setMinimumHeight(38)
            filter_layout.addWidget(self.receiver_search, 3)
            filter_layout.addWidget(self.receiver_severity)
            filter_layout.addWidget(self.receiver_facility)
            filter_layout.addWidget(self.receiver_protocol_filter)
            page_layout.addWidget(filter_group)

            self.receiver_model = ReceiverTableModel(self.receiver_retention.value())
            self.receiver_proxy = ReceiverFilterProxy()
            self.receiver_proxy.setSourceModel(self.receiver_model)
            self.receiver_table = QTableView()
            self.receiver_table.setModel(self.receiver_proxy)
            self.receiver_table.setAlternatingRowColors(True)
            self.receiver_table.setSortingEnabled(True)
            self.receiver_table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
            self.receiver_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            self.receiver_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            self.receiver_table.verticalHeader().setVisible(False)
            self.receiver_table.setWordWrap(False)
            header = self.receiver_table.horizontalHeader()
            header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
            self.receiver_table.selectionModel().selectionChanged.connect(self.show_receiver_detail)

            self.receiver_detail = QPlainTextEdit()
            self.receiver_detail.setReadOnly(True)
            self.receiver_detail.setPlaceholderText(
                "Select a received message to inspect parsed fields and the original payload."
            )
            self.receiver_detail.setMinimumHeight(130)
            self.receiver_splitter = QSplitter(Qt.Orientation.Vertical)
            self.receiver_splitter.addWidget(self.receiver_table)
            self.receiver_splitter.addWidget(self.receiver_detail)
            self.receiver_splitter.setStretchFactor(0, 4)
            self.receiver_splitter.setStretchFactor(1, 1)
            self.receiver_splitter.setSizes([480, 150])
            page_layout.addWidget(self.receiver_splitter, 1)

            footer = QHBoxLayout()
            self.receiver_summary = QLabel("Received 0 · Showing 0 · Malformed 0")
            self.receiver_summary.setObjectName("receiverSummary")
            self.receiver_pause = QPushButton("Pause display")
            self.receiver_pause.setCheckable(True)
            self.receiver_pause.toggled.connect(self.toggle_receiver_pause)
            self.receiver_expand = QPushButton("Expand log view")
            self.receiver_expand.setObjectName("receiverExpand")
            self.receiver_expand.setCheckable(True)
            self.receiver_expand.setAccessibleName("Expand received log view")
            self.receiver_expand.setToolTip(
                "Use more of the receiver page for incoming messages; select again to restore"
            )
            self.receiver_expand.toggled.connect(self.toggle_receiver_log_expansion)
            clear = QPushButton("Clear")
            clear.clicked.connect(self.clear_receiver_messages)
            export = QPushButton("Export filtered…")
            export.clicked.connect(self.export_receiver_messages)
            footer.addWidget(self.receiver_summary)
            footer.addStretch()
            footer.addWidget(self.receiver_expand)
            footer.addWidget(self.receiver_pause)
            footer.addWidget(clear)
            footer.addWidget(export)
            page_layout.addLayout(footer)

            for widget in (
                self.receiver_search,
                self.receiver_severity,
                self.receiver_facility,
                self.receiver_protocol_filter,
            ):
                if isinstance(widget, QLineEdit):
                    widget.textChanged.connect(self.apply_receiver_filters)
                else:
                    widget.currentTextChanged.connect(self.apply_receiver_filters)
            self.receiver_retention.valueChanged.connect(self.receiver_model.set_maximum)
            return page

        @Slot(bool)
        def toggle_receiver_log_expansion(self, expanded: bool) -> None:
            self.receiver_log_expanded = expanded
            if expanded:
                self._receiver_splitter_sizes = self.receiver_splitter.sizes()
                self.receiver_listener_group.hide()
                self.receiver_detail.hide()
                self.receiver_expand.setText("Restore layout")
                self.receiver_expand.setAccessibleName("Restore receiver layout")
            else:
                self.receiver_listener_group.show()
                self.receiver_detail.show()
                self.receiver_splitter.setSizes(self._receiver_splitter_sizes or [480, 150])
                self.receiver_expand.setText("Expand log view")
                self.receiver_expand.setAccessibleName("Expand received log view")

        @Slot()
        def refresh_bind_addresses(self) -> None:
            current = self.receiver_bind.currentText().strip() or "0.0.0.0"
            detected = [address.toString() for address in QNetworkInterface.allAddresses()]
            choices = ordered_bind_addresses(detected)
            if current not in choices:
                choices.append(current)
            self.receiver_bind.blockSignals(True)
            self.receiver_bind.clear()
            self.receiver_bind.addItems(choices)
            self.receiver_bind.setCurrentText(current)
            self.receiver_bind.blockSignals(False)

        def set_receiver_status(self, text: str, state: str) -> None:
            self.receiver_status.setText(text)
            self.receiver_status.setProperty("state", state)
            self.receiver_status.style().unpolish(self.receiver_status)
            self.receiver_status.style().polish(self.receiver_status)

        @Slot()
        def start_receiver(self) -> None:
            config = ReceiverConfig(
                self.receiver_bind.currentText().strip() or "0.0.0.0",
                self.receiver_port.value(),
                self.receiver_protocol.currentText().lower(),
                self.receiver_framing.currentText(),
            )
            receiver = SyslogReceiver(
                config,
                self.receiver_bridge.message.emit,
                lambda error: self.receiver_bridge.error.emit(str(error)),
            )
            try:
                receiver.start()
            except PermissionError as error:
                QMessageBox.critical(
                    self,
                    "Elevation required",
                    f"LogSalvo was not permitted to listen on port {config.port}.\n\n"
                    "Choose a port above 1023, relaunch LogSalvo with administrator/root "
                    "privileges, or grant the Python executable permission to bind privileged ports.\n\n"
                    f"Operating-system response: {error}",
                )
                self.set_receiver_status("Permission denied", "error")
                return
            except OSError as error:
                QMessageBox.critical(
                    self,
                    "Could not start listener",
                    f"Could not listen on {config.bind_address}:{config.port}/{config.protocol.upper()}.\n\n"
                    f"{error}",
                )
                self.set_receiver_status("Listener failed", "error")
                return
            self.receiver = receiver
            self.receiver_start.setEnabled(False)
            self.receiver_stop.setEnabled(True)
            for widget in (
                self.receiver_bind,
                self.receiver_bind_refresh,
                self.receiver_port,
                self.receiver_protocol,
                self.receiver_framing,
            ):
                widget.setEnabled(False)
            self.set_receiver_status(
                f"Listening on {config.bind_address}:{config.port}/{config.protocol.upper()}",
                "running",
            )

        @Slot()
        def stop_receiver(self) -> None:
            if self.receiver:
                self.receiver.stop()
                self.receiver = None
            self.receiver_start.setEnabled(True)
            self.receiver_stop.setEnabled(False)
            for widget in (
                self.receiver_bind,
                self.receiver_bind_refresh,
                self.receiver_port,
                self.receiver_protocol,
            ):
                widget.setEnabled(True)
            self.receiver_framing.setEnabled(self.receiver_protocol.currentText() == "TCP")
            self.set_receiver_status("Stopped", "ready")

        @Slot(object)
        def receive_message(self, message: object) -> None:
            if not isinstance(message, ReceivedMessage):
                return
            self.receiver_total += 1
            if self.receiver_paused:
                self.receiver_pending.append(message)
                maximum = self.receiver_retention.value()
                if len(self.receiver_pending) > maximum:
                    del self.receiver_pending[: len(self.receiver_pending) - maximum]
            else:
                self.receiver_model.add_message(message)
                self.scroll_to_latest_receiver_message()
            self.update_receiver_summary()

        def scroll_to_latest_receiver_message(self, candidate_count: int = 1) -> None:
            row_count = self.receiver_model.rowCount()

            def proxy_index_for(source_row: int) -> QModelIndex:
                return self.receiver_proxy.mapFromSource(self.receiver_model.index(source_row, 0))

            source_row = newest_visible_source_row(
                row_count,
                candidate_count,
                lambda row: proxy_index_for(row).isValid(),
            )
            if source_row is not None:
                self.receiver_table.scrollTo(
                    proxy_index_for(source_row),
                    QAbstractItemView.ScrollHint.EnsureVisible,
                )

        @Slot(str)
        def receiver_error(self, error: str) -> None:
            self.set_receiver_status(f"Listener error: {error}", "error")
            if self.receiver:
                self.receiver.stop()
                self.receiver = None
            self.receiver_start.setEnabled(True)
            self.receiver_stop.setEnabled(False)

        @Slot(bool)
        def toggle_receiver_pause(self, paused: bool) -> None:
            self.receiver_paused = paused
            self.receiver_pause.setText("Resume display" if paused else "Pause display")
            if not paused and self.receiver_pending:
                pending, self.receiver_pending = self.receiver_pending, []
                for message in pending:
                    self.receiver_model.add_message(message)
                self.scroll_to_latest_receiver_message(len(pending))
            self.update_receiver_summary()

        @Slot()
        def apply_receiver_filters(self) -> None:
            self.receiver_proxy.set_filters(
                self.receiver_search.text(),
                self.receiver_severity.currentText(),
                self.receiver_facility.currentText(),
                self.receiver_protocol_filter.currentText(),
            )
            self.update_receiver_summary()

        def update_receiver_summary(self) -> None:
            malformed = sum(bool(message.parse_error) for message in self.receiver_model.messages)
            paused = f" · Queued {len(self.receiver_pending)}" if self.receiver_paused else ""
            self.receiver_summary.setText(
                f"Received {self.receiver_total:,} · Showing {self.receiver_proxy.rowCount():,} "
                f"· Malformed {malformed:,}{paused}"
            )

        @Slot()
        def show_receiver_detail(self) -> None:
            indexes = self.receiver_table.selectionModel().selectedRows()
            if not indexes:
                self.receiver_detail.clear()
                return
            source = self.receiver_proxy.mapToSource(indexes[0])
            message = self.receiver_model.messages[source.row()]
            fields = (
                f"Received:  {message.received_at.astimezone().isoformat(timespec='milliseconds')}",
                f"Sender:    {message.sender}:{message.sender_port} via {message.protocol}",
                f"Format:    {message.format}",
                f"Priority:  {message.priority if message.priority is not None else 'unknown'}",
                f"Facility:  {message.facility_name} ({message.facility})",
                f"Severity:  {message.severity_name} ({message.severity})",
                f"Hostname:  {message.hostname or '—'}",
                f"App:       {message.app or '—'}",
                f"PROCID:    {message.procid or '—'}",
                f"MSGID:     {message.msgid or '—'}",
                f"Timestamp: {message.timestamp or '—'}",
                f"Error:     {message.parse_error or '—'}",
                "",
                "Raw message",
                "───────────",
                message.raw,
            )
            self.receiver_detail.setPlainText("\n".join(fields))

        @Slot()
        def clear_receiver_messages(self) -> None:
            if self.receiver_model.messages or self.receiver_pending:
                answer = QMessageBox.question(
                    self, "Clear received messages", "Remove all captured messages from this view?"
                )
                if answer != QMessageBox.StandardButton.Yes:
                    return
            self.receiver_model.clear()
            self.receiver_pending.clear()
            self.receiver_total = 0
            self.receiver_detail.clear()
            self.update_receiver_summary()

        def filtered_receiver_messages(self) -> list[ReceivedMessage]:
            messages = []
            for row in range(self.receiver_proxy.rowCount()):
                source = self.receiver_proxy.mapToSource(self.receiver_proxy.index(row, 0))
                messages.append(self.receiver_model.messages[source.row()])
            return messages

        @Slot()
        def export_receiver_messages(self) -> None:
            messages = self.filtered_receiver_messages()
            if not messages:
                QMessageBox.information(
                    self, "Nothing to export", "No visible messages match the filters."
                )
                return
            filename, selected = QFileDialog.getSaveFileName(
                self,
                "Export filtered messages",
                "logsalvo-received.csv",
                "CSV (*.csv);;JSON Lines (*.jsonl);;Raw syslog (*.log)",
            )
            if not filename:
                return
            format_name = "jsonl" if "JSON" in selected else "raw" if "Raw" in selected else "csv"
            suffix = {"csv": ".csv", "jsonl": ".jsonl", "raw": ".log"}[format_name]
            destination = Path(filename)
            if not destination.suffix:
                destination = destination.with_suffix(suffix)
            try:
                export_messages(messages, destination, format_name)
            except OSError as error:
                QMessageBox.critical(self, "Export failed", str(error))
                return
            QMessageBox.information(
                self,
                "Export complete",
                f"Exported {len(messages):,} filtered messages to:\n{destination}",
            )

        def set_status(self, text: str, state: str) -> None:
            self.status.setText(text)
            self.status.setProperty("state", state)
            self.status.style().unpolish(self.status)
            self.status.style().polish(self.status)

        @Slot()
        def about(self) -> None:
            dialog = QMessageBox(self)
            dialog.setWindowTitle(f"About {__app_name__}")
            dialog.setIconPixmap(
                self.logo.scaled(
                    148,
                    148,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
            dialog.setText(f"<h2>{__app_name__}</h2><p><b>Version {__version__}</b></p>")
            dialog.setInformativeText(
                "A professional RFC 3164/5424 traffic studio for sending, receiving and "
                "inspecting messages across collectors, SIEM platforms and log pipelines.<br><br>"
                f"{__copyright__}<br>Released under the MIT License."
            )
            dialog.exec()

        def message_config(self) -> MessageConfig:
            return MessageConfig(
                self.format.currentText(),
                FACILITIES[self.facility.currentText()],
                SEVERITIES[self.severity.currentText()],
                self.hostname.text(),
                self.app.text(),
                self.procid.text(),
                self.msgid.text(),
                self.sd.text(),
                self.wire_size.value(),
            )

        @Slot()
        def preview(self) -> None:
            try:
                from datetime import datetime, timezone

                from .templates import apply_template

                template = (
                    self.messages.toPlainText().splitlines()[0]
                    if self.messages.toPlainText().splitlines()
                    else ""
                )
                config = self.message_config()
                now = datetime.now(timezone.utc)
                body = apply_template(
                    template,
                    seq=1,
                    hostname=config.hostname,
                    app=config.app,
                    facility=config.facility,
                    severity=config.severity,
                    now=now,
                )
                payload = build_message(config, body, now)
                self.preview_box.setPlainText(
                    f"{len(payload)} bytes\n{payload.decode('utf-8', 'replace')}"
                )
            except (IndexError, OSError, ValueError) as error:
                self.preview_box.setPlainText(f"Invalid configuration: {error}")

        def make_sender(self) -> Sender:
            if self.rate.value() > 10_000:
                answer = QMessageBox.question(
                    self, "High message rate", "Send at more than 10,000 messages/sec?"
                )
                if answer != QMessageBox.StandardButton.Yes:
                    raise ValueError("high-rate run cancelled")
            sender_config = SenderConfig(
                self.target.text(),
                self.port.value(),
                self.transport.currentText(),
                self.tls.isChecked(),
                self.cafile.text() or None,
                self.certfile.text() or None,
                self.keyfile.text() or None,
                self.insecure.isChecked(),
                self.sni.text() or None,
                self.framing.currentText(),
                self.bind_ip.text() or None,
                5.0,
                self.retries.value(),
            )
            run = RunConfig(
                self.count.value(), self.duration.value(), self.rate.value(), self.delay.value()
            )
            return Sender(
                sender_config,
                self.message_config(),
                run,
                self.messages.toPlainText().splitlines(),
                dry_run=self.dry_run.isChecked(),
            )

        @Slot()
        def start(self) -> None:
            try:
                sender = self.make_sender()
            except ValueError as error:
                QMessageBox.warning(self, "Invalid configuration", str(error))
                return
            self.log.clear()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.set_status("Starting transmission…", "running")
            self.thread = QThread(self)
            self.worker = Worker(sender)
            self.worker.moveToThread(self.thread)
            self.thread.started.connect(self.worker.run)
            self.worker.log.connect(self.log.appendPlainText)
            self.worker.progress.connect(
                lambda attempted, sent, failed, rate: self.set_status(
                    f"Attempted {attempted} | Sent {sent} | Failed {failed} | {rate:.1f} msg/s",
                    "running",
                )
            )
            self.worker.finished.connect(self.done)
            self.worker.failed.connect(self.failed)
            self.worker.finished.connect(self.thread.quit)
            self.worker.failed.connect(self.thread.quit)
            self.thread.finished.connect(self.thread.deleteLater)
            self.thread.start()

        @Slot()
        def stop(self) -> None:
            if self.worker:
                self.worker.cancel()
                self.set_status("Stopping…", "stopping")

        @Slot(object)
        def done(self, stats: object) -> None:
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.set_status(
                f"Complete: {stats.sent} sent, {stats.failed} failed in {stats.elapsed:.2f}s",
                "success" if not stats.failed else "error",
            )
            self.worker = None
            self.thread = None

        @Slot(str)
        def failed(self, error: str) -> None:
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.set_status("Transmission failed", "error")
            self.log.appendPlainText(f"ERROR: {error}")
            self.worker = None
            self.thread = None

        @Slot()
        def import_messages(self) -> None:
            filename, _ = QFileDialog.getOpenFileName(
                self, "Import messages", "", "Text files (*.txt);;All files (*)"
            )
            if filename:
                self.messages.setPlainText(Path(filename).read_text(encoding="utf-8"))

        def profile(self) -> dict[str, object]:
            return {
                "target": self.target.text(),
                "port": self.port.value(),
                "transport": self.transport.currentText(),
                "tls": self.tls.isChecked(),
                "framing": self.framing.currentText(),
                "bind_ip": self.bind_ip.text(),
                "cafile": self.cafile.text(),
                "certfile": self.certfile.text(),
                "keyfile": self.keyfile.text(),
                "insecure": self.insecure.isChecked(),
                "sni": self.sni.text(),
                "format": self.format.currentText(),
                "facility": self.facility.currentText(),
                "severity": self.severity.currentText(),
                "hostname": self.hostname.text(),
                "app": self.app.text(),
                "procid": self.procid.text(),
                "msgid": self.msgid.text(),
                "sd": self.sd.text(),
                "wire_size": self.wire_size.value(),
                "messages": self.messages.toPlainText(),
                "count": self.count.value(),
                "duration": self.duration.value(),
                "rate": self.rate.value(),
                "delay": self.delay.value(),
                "retries": self.retries.value(),
                "dry_run": self.dry_run.isChecked(),
            }

        @Slot()
        def save_profile(self) -> None:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save profile", "profile.json", "JSON (*.json)"
            )
            if filename:
                Path(filename).write_text(
                    json.dumps(self.profile(), indent=2) + "\n", encoding="utf-8"
                )

        @Slot()
        def load_profile(self) -> None:
            filename, _ = QFileDialog.getOpenFileName(self, "Load profile", "", "JSON (*.json)")
            if not filename:
                return
            try:
                data = json.loads(Path(filename).read_text(encoding="utf-8"))
                self.target.setText(str(data["target"]))
                self.port.setValue(int(data["port"]))
                self.transport.setCurrentText(str(data["transport"]))
                self.tls.setChecked(bool(data["tls"]))
                self.framing.setCurrentText(str(data.get("framing", "octet")))
                self.bind_ip.setText(str(data.get("bind_ip", "")))
                self.cafile.setText(str(data.get("cafile", "")))
                self.certfile.setText(str(data.get("certfile", "")))
                self.keyfile.setText(str(data.get("keyfile", "")))
                self.insecure.setChecked(bool(data.get("insecure", False)))
                self.sni.setText(str(data.get("sni", "")))
                self.format.setCurrentText(str(data["format"]))
                self.facility.setCurrentText(str(data["facility"]))
                self.severity.setCurrentText(str(data["severity"]))
                self.hostname.setText(str(data["hostname"]))
                self.app.setText(str(data["app"]))
                self.procid.setText(str(data["procid"]))
                self.msgid.setText(str(data["msgid"]))
                self.sd.setText(str(data["sd"]))
                self.wire_size.setValue(int(data.get("wire_size", 0)))
                self.messages.setPlainText(str(data["messages"]))
                self.count.setValue(int(data["count"]))
                self.duration.setValue(float(data["duration"]))
                self.rate.setValue(float(data["rate"]))
                self.delay.setValue(float(data["delay"]))
                self.retries.setValue(int(data.get("retries", 2)))
                self.dry_run.setChecked(bool(data.get("dry_run", False)))
            except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError) as error:
                QMessageBox.critical(self, "Could not load profile", str(error))

        def closeEvent(self, event: object) -> None:
            if self.receiver:
                self.receiver.stop()
                self.receiver = None
            if self.worker:
                self.worker.cancel()
                assert self.thread is not None
                self.thread.quit()
                self.thread.wait(3000)
            event.accept()

    application = QApplication(sys.argv)
    application.setApplicationName(__app_name__)
    application.setApplicationDisplayName(__app_name__)
    application.setApplicationVersion(__version__)
    application.setOrganizationName("The Tech Shed")
    logo_path = Path(__file__).with_name("assets") / "tts-round-outline.png"
    application.setWindowIcon(QIcon(str(logo_path)))
    window = Window()
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
