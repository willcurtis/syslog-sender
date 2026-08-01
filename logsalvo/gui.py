from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

from . import __app_name__, __copyright__, __version__
from .formatters import build_message
from .models import FACILITIES, SEVERITIES, MessageConfig, RunConfig, SenderConfig
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
QTabWidget::pane {
    background: #0b202b;
    border: 1px solid #154052;
    border-radius: 10px;
    top: -1px;
}
QScrollArea#tabScroll, QScrollArea#tabScroll QWidget#qt_scrollarea_viewport,
QWidget#tabPage {
    background: #0b202b;
    border: none;
}
QTabBar::tab {
    background: #0a1b24;
    color: #7f9ca7;
    border: 1px solid #154052;
    border-bottom: none;
    padding: 10px 24px;
    margin-right: 3px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    font-weight: 600;
}
QTabBar::tab:selected {
    background: #0b202b;
    color: #00c898;
    border-top: 2px solid #00c898;
}
QTabBar::tab:hover:!selected { color: #00b0f0; background: #0c2632; }
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
QComboBox::drop-down { border: none; width: 24px; }
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
"""


def main() -> int:
    try:
        from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
        from PySide6.QtGui import QIcon, QPixmap
        from PySide6.QtWidgets import (
            QApplication,
            QCheckBox,
            QComboBox,
            QDoubleSpinBox,
            QFileDialog,
            QFormLayout,
            QFrame,
            QGroupBox,
            QHBoxLayout,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMessageBox,
            QPlainTextEdit,
            QPushButton,
            QScrollArea,
            QSizePolicy,
            QSpinBox,
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

    class Window(QMainWindow):
        def __init__(self):
            super().__init__()
            self.logo_path = Path(__file__).with_name("assets") / "tts-round-outline.png"
            self.logo = QPixmap(str(self.logo_path))
            self.setWindowTitle(f"{__app_name__} · Syslog Traffic Studio · v{__version__}")
            self.setWindowIcon(QIcon(str(self.logo_path)))
            self.resize(1080, 860)
            self.setMinimumSize(900, 720)
            self.thread: QThread | None = None
            self.worker: Worker | None = None
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
                "Build, preview and transmit standards-aware test traffic with confidence."
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
            header_layout.addWidget(version, alignment=Qt.AlignmentFlag.AlignTop)
            layout.addWidget(header)

            tabs = QTabWidget()
            tabs.setDocumentMode(True)
            tabs.setMinimumHeight(420)
            layout.addWidget(tabs, 3)

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
            layout.addWidget(preview_group)
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
            layout.addLayout(controls)
            self.status = QLabel("Ready")
            self.status.setObjectName("statusPill")
            self.status.setProperty("state", "ready")
            self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(self.status)
            self.log = QPlainTextEdit()
            self.log.setReadOnly(True)
            self.log.setMinimumHeight(120)
            self.log.setPlaceholderText("Transmission events and errors will appear here.")
            layout.addWidget(self.log)

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
            self.setStyleSheet(STYLESHEET)
            for widget in [self.format, self.facility, self.severity]:
                widget.currentTextChanged.connect(self.preview)
            self.wire_size.valueChanged.connect(self.preview)

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
                "A professional RFC 3164/5424 traffic generator for testing collectors, "
                "SIEM platforms and log pipelines.<br><br>"
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
