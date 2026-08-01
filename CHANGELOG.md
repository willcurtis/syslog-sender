# Changelog

All notable changes to Syslog Sender are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-08-01

### Added

- Installable `syslog_sender` package with shared CLI and GUI core.
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

[2.0.0]: https://github.com/willcurtis/syslog-sender/compare/6d298f3c...v2.0.0
[1.1.0]: https://github.com/willcurtis/syslog-sender/commits/6d298f3c
[1.0.0]: https://github.com/willcurtis/syslog-sender/commits/a760f95c
