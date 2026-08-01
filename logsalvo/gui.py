from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

from .formatters import build_message
from .models import FACILITIES, SEVERITIES, MessageConfig, RunConfig, SenderConfig
from .sender import Sender


def main() -> int:
    try:
        from PySide6.QtCore import QObject, QThread, Signal, Slot
        from PySide6.QtWidgets import (
            QApplication,
            QCheckBox,
            QComboBox,
            QDoubleSpinBox,
            QFileDialog,
            QFormLayout,
            QGroupBox,
            QHBoxLayout,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMessageBox,
            QPlainTextEdit,
            QPushButton,
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
            self.setWindowTitle("LogSalvo 2.0")
            self.resize(980, 760)
            self.thread: QThread | None = None
            self.worker: Worker | None = None
            self._build()
            self.preview()

        def _line(self, value: str = "") -> QLineEdit:
            widget = QLineEdit(value)
            widget.textChanged.connect(self.preview)
            return widget

        def _build(self) -> None:
            root = QWidget()
            layout = QVBoxLayout(root)
            tabs = QTabWidget()
            layout.addWidget(tabs)

            connection = QWidget()
            connection_form = QFormLayout(connection)
            self.target = self._line("127.0.0.1")
            self.port = QSpinBox()
            self.port.setRange(1, 65535)
            self.port.setValue(514)
            self.transport = QComboBox()
            self.transport.addItems(["udp", "tcp"])
            self.tls = QCheckBox("Enable TLS")
            self.framing = QComboBox()
            self.framing.addItems(["octet", "lf"])
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
            tabs.addTab(connection, "Connection")

            message_tab = QWidget()
            message_layout = QVBoxLayout(message_tab)
            message_form = QFormLayout()
            self.format = QComboBox()
            self.format.addItems(["3164", "5424"])
            self.facility = QComboBox()
            self.facility.addItems(FACILITIES)
            self.severity = QComboBox()
            self.severity.addItems(SEVERITIES)
            self.severity.setCurrentText("info")
            self.hostname = self._line(socket.gethostname())
            self.app = self._line("logsalvo")
            self.procid = self._line("-")
            self.msgid = self._line("TEST")
            self.sd = self._line("-")
            self.wire_size = QSpinBox()
            self.wire_size.setRange(0, 65507)
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
            self.messages.textChanged.connect(self.preview)
            message_layout.addWidget(QLabel("Messages (one template per line)"))
            message_layout.addWidget(self.messages)
            import_button = QPushButton("Import message file")
            import_button.clicked.connect(self.import_messages)
            message_layout.addWidget(import_button)
            tabs.addTab(message_tab, "Message")

            run_tab = QWidget()
            run_form = QFormLayout(run_tab)
            self.count = QSpinBox()
            self.count.setRange(0, 10_000_000)
            self.count.setValue(10)
            self.duration = QDoubleSpinBox()
            self.duration.setRange(0, 86400)
            self.duration.setSuffix(" s")
            self.rate = QDoubleSpinBox()
            self.rate.setRange(0, 1_000_000)
            self.rate.setSuffix(" msg/s")
            self.delay = QDoubleSpinBox()
            self.delay.setRange(0, 3600)
            self.delay.setDecimals(3)
            self.delay.setSuffix(" s")
            self.retries = QSpinBox()
            self.retries.setRange(0, 20)
            self.retries.setValue(2)
            self.dry_run = QCheckBox("Build messages without sending")
            for label, widget in [
                ("Attempt count", self.count),
                ("Duration", self.duration),
                ("Rate", self.rate),
                ("Fixed delay", self.delay),
                ("Retries", self.retries),
                ("Dry run", self.dry_run),
            ]:
                run_form.addRow(label, widget)
            tabs.addTab(run_tab, "Run")

            preview_group = QGroupBox("Live preview")
            preview_layout = QVBoxLayout(preview_group)
            self.preview_box = QPlainTextEdit()
            self.preview_box.setReadOnly(True)
            self.preview_box.setMaximumHeight(100)
            preview_layout.addWidget(self.preview_box)
            layout.addWidget(preview_group)
            controls = QHBoxLayout()
            self.start_button = QPushButton("Start")
            self.start_button.clicked.connect(self.start)
            self.stop_button = QPushButton("Stop")
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
            layout.addWidget(self.status)
            self.log = QPlainTextEdit()
            self.log.setReadOnly(True)
            layout.addWidget(self.log)
            self.setCentralWidget(root)
            for widget in [self.format, self.facility, self.severity]:
                widget.currentTextChanged.connect(self.preview)
            self.wire_size.valueChanged.connect(self.preview)

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
            self.thread = QThread(self)
            self.worker = Worker(sender)
            self.worker.moveToThread(self.thread)
            self.thread.started.connect(self.worker.run)
            self.worker.log.connect(self.log.appendPlainText)
            self.worker.progress.connect(
                lambda attempted, sent, failed, rate: self.status.setText(
                    f"Attempted {attempted} | Sent {sent} | Failed {failed} | {rate:.1f} msg/s"
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
                self.status.setText("Stopping…")

        @Slot(object)
        def done(self, stats: object) -> None:
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status.setText(
                f"Complete: {stats.sent} sent, {stats.failed} failed in {stats.elapsed:.2f}s"
            )
            self.worker = None
            self.thread = None

        @Slot(str)
        def failed(self, error: str) -> None:
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status.setText("Failed")
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
    window = Window()
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
