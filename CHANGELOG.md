# Changelog

All notable changes to LogSalvo are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [2.3.1] - 2026-08-01

### Fixed

- UniFi CEF records prefixed with a BSD-style timestamp and hostname but no `<PRI>` header are now recognised and parsed.
- The timestamp and envelope hostname remain available when those records omit equivalent CEF extension values.

## [2.3.0] - 2026-08-01

### Added

- UniFi CEF/SIEM parsing, including CEF records wrapped in RFC 3164 envelopes.
- UniFi access-point and gateway device-log parsing for their distinct identity and process layouts.
- Generic CEF header and extension parsing with original CEF severity retained in structured data.

### Changed

- UniFi host, product, event ID, message, process, device identity, and severity fields now populate the receiver view and exports instead of appearing as an opaque raw message.

## [2.2.1] - 2026-08-01

### Fixed

- Raw PRI-prefixed payloads now decode priority, facility, and severity while showing only the message body in the message column.
- JSON syslog payloads now map common host, application, event, timestamp, facility, severity, and message aliases into receiver fields.
- Cisco IOS messages now extract their facility, numeric severity, mnemonic, timestamp, and message text.
- Leading whitespace, UTF-8 byte-order marks, and trailing NUL framing no longer prevent format detection.
- Invalid priority values are no longer reported as valid parsed priorities.

### Changed

- Recognised structured raw formats are no longer counted as malformed; their original payload is still retained for inspection and export.

## [2.2.0] - 2026-08-01

### Added

- User-configurable UDP and TCP syslog receiver for any port from 1 through 65535.
- Clear elevation guidance when the operating system denies a privileged port such as 514.
- IPv4/IPv6 bind-address selection and automatic, octet-counted, or newline TCP framing.
- Automatic RFC 3164/RFC 5424 parsing with raw-message fallback.
- Live severity-coloured message table, parsed/raw detail view, session counters, and bounded retention.
- Free-text, severity, facility, and protocol filtering.
- Pause/resume display queue, clear confirmation, and filtered CSV/JSONL/raw export.
- UDP/TCP integration tests and parser/export coverage.

### Changed

- Reorganized the desktop interface into dedicated Send and Receive workspaces.
- Updated product descriptions to reflect bidirectional syslog tooling.

## [2.1.1] - 2026-08-01

### Fixed

- Configuration fields now expand to use the available tab width instead of retaining compact Qt size hints.
- Increased input height, form margins, and row spacing for clearer scanning and easier interaction.
- Added responsive label wrapping and vertical scrolling for smaller windows.
- Increased message-editor and event-log working space.

## [2.1.0] - 2026-08-01

### Added

- The Tech Shed logo, application icon, and navy/cyan/teal visual identity.
- Branded application header, version badge, state-aware status display, footer, and About dialog.
- Centralized product name, semantic version, and copyright metadata.
- `logsalvo --version` CLI output.

### Changed

- Updated package, application, and documentation copyright to The Tech Shed for 2025-2026.
- Included the original high-resolution logo as packaged application data.

## [2.0.0] - 2026-08-01

### Added

- LogSalvo application name and `logsalvo` / `logsalvo-gui` entry points.
- Installable `logsalvo` package with shared CLI and GUI core.
- PySide6 desktop GUI with connection, TLS, message, and run configuration.
- Live encoded-message preview, event log, progress counters, cancellation, file import, and JSON profiles.
- Validated configuration dataclasses and clear CLI validation errors.
- TCP/TLS reconnect attempts with bounded exponential backoff.
- Family-aware IPv4/IPv6 source-address binding.
- Accurate minimum wire-payload sizing based on UTF-8 encoded bytes.
- RFC 5424 header-field and structured-data validation.
- Exit codes that distinguish success, runtime failure, invalid configuration, and interruption.
- Automated unit and local UDP integration tests.
- Ruff linting and GitHub Actions testing on Python 3.10 through 3.13.
- Modern `pyproject.toml` metadata and console entry points.

### Changed

- Reimplemented rate control using monotonic send deadlines. The previous implementation could transmit at approximately twice the requested rate.
- Counts now represent attempts so persistent send failures cannot create an infinite run.
- Empty file and standard-input sources are rejected immediately.
- A zero count now requires a positive duration; negative values are rejected.
- TCP framing, socket cleanup, error reporting, and TLS defaults are handled by reusable transport code.
- Documentation now covers installation, GUI and CLI operation, TLS, templates, exit codes, troubleshooting, testing, packaging, and migration.

### Removed

- Obsolete `syslog_sender.py` prototype.
- Standalone `syslog-pro.py`; its supported behavior is now available through the package entry points.
- Ambiguous `--size` option in favor of `--wire-size`.
- Undocumented infinite behavior from negative count values.

## [1.1.0] - 2025-08-15

### Added

- RFC 3164 and RFC 5424 output.
- UDP, TCP, TLS, RFC 6587 framing, templating, message-file input, source binding, and basic statistics in `syslog-pro.py`.
- Extended JSON example message corpus.

## [1.0.0] - 2025-04-25

### Added

- Initial UDP-based random syslog sender.

[2.3.1]: https://github.com/willcurtis/syslog-sender/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/willcurtis/syslog-sender/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/willcurtis/syslog-sender/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/willcurtis/syslog-sender/compare/a82f419...v2.2.0
[2.1.1]: https://github.com/willcurtis/syslog-sender/compare/4e255fd...a82f419
[2.1.0]: https://github.com/willcurtis/syslog-sender/compare/e10ab32...4e255fd
[2.0.0]: https://github.com/willcurtis/syslog-sender/compare/6d298f3c...e10ab32
[1.1.0]: https://github.com/willcurtis/syslog-sender/commits/6d298f3c
[1.0.0]: https://github.com/willcurtis/syslog-sender/commits/a760f95c
