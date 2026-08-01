# LogSalvo

<img src="https://raw.githubusercontent.com/willcurtis/logsalvo/main/logsalvo/assets/tts-round-outline.png" alt="The Tech Shed logo" width="180">

LogSalvo is a cross-platform Python application for generating controlled syslog traffic when testing collectors, SIEM platforms, firewall rules, parsers, alerts, and log pipelines. Version 2 provides both a command-line interface and a PySide6 desktop GUI over the same tested sender core.

LogSalvo uses The Tech Shed visual identity: deep navy, cyan and teal. The supplied logo is packaged into the desktop application and used as its window icon and About artwork.

## Screenshots

### Send workspace

Configure the destination, transport, message format, templates, and run controls while reviewing the exact encoded message in the live preview.

![LogSalvo Send workspace showing connection settings, live preview, run status, and event log](docs/images/logsalvo-send.png)

### Receive workspace

Listen on a configurable address, port, and protocol; inspect incoming messages; filter the live table; and export the visible results.

![LogSalvo Receive workspace showing listener controls, message filters, parsed syslog table, and message detail](docs/images/logsalvo-receive.png)

## Highlights

- RFC 3164 and RFC 5424 message generation
- UDP, TCP, and TLS transports with IPv4 and IPv6 support
- RFC 6587 octet-counted or line-feed TCP framing
- Server certificate validation, custom CA, SNI override, and optional mTLS
- Facility and severity selection by name or number
- Reusable message templates and file-based message sets
- Accurate rate, delay, count, and duration controls
- TCP/TLS reconnects with configurable retries and backoff
- Binding to a chosen local source address
- Full encoded-payload padding for MTU and parser tests
- Dry-run mode, message preview, progress statistics, and meaningful exit codes
- Desktop GUI with profiles, live preview, message import, cancellation, and event log
- Built-in UDP/TCP receiver with live parsing, filtering, inspection, and export
- No third-party runtime dependencies for CLI use

> [!CAUTION]
> Only send test traffic to systems you own or are authorized to test. High message rates can overwhelm collectors, consume storage, or trigger production alerts.

## Requirements

- Python 3.10 or newer
- PySide6 only when using the GUI

The CLI works on Windows, macOS, and Linux using the Python standard library.

## Installation

Clone and install the CLI:

```bash
git clone https://github.com/willcurtis/logsalvo.git
cd logsalvo
python3 -m venv .venv
source .venv/bin/activate       # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .
```

Install the GUI as well:

```bash
python -m pip install '.[gui]'
```

For development:

```bash
python -m pip install -e '.[dev,gui]'
```

## First run

Send ten RFC 3164 messages over UDP:

```bash
logsalvo 192.0.2.10 --count 10 --message 'Test message {seq} {uuid}'
```

Preview without transmitting:

```bash
logsalvo 192.0.2.10 --dry-run --echo --count 3 \
  --format 5424 --facility local4 --severity notice \
  --message 'Configuration test {seq} at {timestamp}'
```

Start the desktop application:

```bash
logsalvo-gui
```

## Desktop GUI

The GUI separates configuration into Connection, Message, and Run tabs. Use the appearance switch beside the version badge to change between Dark and Light modes; LogSalvo remembers the selection for future launches.

1. Enter the collector address, port, and transport.
2. Configure TLS and certificates when required.
3. Choose RFC 3164 or RFC 5424 and set the header fields.
4. Enter one or more message templates, or import a text file.
5. Check the live encoded preview and byte count.
6. Choose count, duration, rate, delay, retry, and dry-run settings.
7. Select **Start**. Use **Stop** to cancel safely.

Live statistics show attempted, successful, and failed messages plus effective rate. Profiles can be saved to JSON and loaded later. Certificate and key paths are saved, but certificate or private-key contents are never copied into a profile.

The GUI warns before rates above 10,000 messages per second. Actual throughput depends on the operating system, transport, TLS, destination, and whether the live event log is displaying every message.

## Receiving syslog

Select the **Receive** workspace to run LogSalvo as a local syslog listener. The listener configuration is explicit because the operating system must know which local socket to open:

| Setting | Description |
| --- | --- |
| Bind address | `0.0.0.0` for all IPv4 interfaces, `::` for IPv6, `127.0.0.1` for local-only traffic, or a specific local address |
| Port | Any user-selected port from 1 through 65535; default 5514 |
| Protocol | UDP or TCP |
| TCP framing | Automatic detection, RFC 6587 octet-counting, or newline-delimited messages |
| Retention | Maximum number of messages kept in memory; default 10,000 |

Press **Start listening** after choosing the settings. LogSalvo reports permission errors, address conflicts, and invalid local addresses directly in the listener status and an explanatory dialog.

### Privileged ports and elevation

LogSalvo allows ports below 1024, including the standard syslog port 514. Some operating systems require administrator/root permission or a bind capability for these ports. LogSalvo never silently substitutes a different port. If the bind is refused, either:

- relaunch it with the elevation method appropriate to your operating system;
- grant the Python executable permission to bind privileged ports; or
- select an unprivileged port such as 5514 and configure senders accordingly.

Running an entire desktop application as root carries risk. Prefer a narrowly scoped operating-system bind capability or port redirection where your platform supports one.

### Live message view

Incoming RFC 3164 and RFC 5424 messages are parsed into received time, sender, transport, hostname, facility, severity, application, and message columns. LogSalvo also understands common raw payloads: PRI-prefixed message bodies, JSON objects with conventional syslog field names, Cisco IOS `%FACILITY-SEVERITY-MNEMONIC` messages, CEF events, and UniFi device logs. Severity values are colour-coded. Messages that cannot be recognised remain available unchanged as raw records and are included in the malformed counter.

For JSON payloads, common aliases such as `src`/`host`, `app`, `event`, `message`/`note`, `fac`/`fac_num`, `sev`/`sev_num`, and `ts` are mapped into the corresponding receiver fields. The complete JSON object remains available in the detail view and exports.

UniFi support includes current Ubiquiti CEF/SIEM exports, CEF wrapped in an RFC 3164 envelope, UniFi's timestamp-and-host CEF envelope without a PRI header, access-point `MAC,device-firmware: process[pid]: message` records, and gateway `hostname process[pid]: message` records. CEF extensions are retained as structured JSON in the detail view and exported data.

Select a row to inspect every parsed field and the original payload. The **Pause display** control keeps receiving into a bounded queue while holding the visible table steady; resume to add queued messages. **Clear** removes captured data from memory without stopping the listener.

### Filtering and export

The receiver can search message text, sender address, hostname, application, facility, and severity. Dedicated filters narrow the view by severity, facility, and UDP/TCP protocol.

**Export filtered…** exports exactly the currently visible result set in its displayed sort order:

- CSV for spreadsheets and reporting;
- JSON Lines for automation and data tools; or
- raw syslog text for replay and troubleshooting.

Retention is bounded to prevent long-running listeners from using unlimited memory. The received counter tracks the session total while the table contains only the retained messages.

## CLI reference

```text
usage: logsalvo [-h] [-p PORT] [--transport {udp,tcp}] [--tls]
                     [--cafile CAFILE] [--certfile CERTFILE] [--keyfile KEYFILE]
                     [--insecure] [--sni SNI] [--tcp-framing {octet,lf}]
                     [--bind-ip BIND_IP] [--timeout TIMEOUT] [--retries RETRIES]
                     [--format {3164,5424}] [--facility FACILITY]
                     [--severity SEVERITY] [--hostname HOSTNAME] [--app APP]
                     [--procid PROCID] [--msgid MSGID] [--sd SD]
                     [--wire-size WIRE_SIZE]
                     [-m MESSAGE | --from-file FROM_FILE | --stdin]
                     [-n COUNT] [--duration DURATION]
                     [--rate RATE | --delay DELAY] [--dry-run] [--echo]
                     target
```

Display the installed version and copyright information with:

```bash
logsalvo --version
```

### Connection options

| Option | Description |
| --- | --- |
| `target` | Collector IP address or DNS name |
| `-p`, `--port` | Destination port; defaults to 514, or 6514 with TLS |
| `--transport` | `udp` or `tcp` |
| `--tls` | Wrap a TCP connection in TLS |
| `--tcp-framing` | RFC 6587 `octet` framing or newline-delimited `lf` framing |
| `--bind-ip` | Bind to a specific local IPv4 or IPv6 source address |
| `--timeout` | Connection/socket timeout in seconds |
| `--retries` | Reconnect attempts per failed message; default 2 |

### TLS options

| Option | Description |
| --- | --- |
| `--cafile` | Custom trusted CA bundle or certificate |
| `--certfile` | Client certificate for mutual TLS |
| `--keyfile` | Private key associated with the client certificate |
| `--sni` | Override the TLS server name |
| `--insecure` | Disable certificate and hostname verification; testing only |

TLS requires TCP. An IP-address target does not automatically supply SNI; use `--sni` if the server certificate or virtual host requires a DNS name.

### Message options

| Option | Description |
| --- | --- |
| `--format` | `3164` or `5424` |
| `--facility` | Name such as `local4` or number 0–23 |
| `--severity` | Name such as `info`, `warn`, or number 0–7 |
| `--hostname` | Hostname placed in the syslog header |
| `--app` | RFC 5424 APP-NAME or RFC 3164 tag |
| `--procid` | Process identifier |
| `--msgid` | RFC 5424 message identifier |
| `--sd` | RFC 5424 structured-data string |
| `--wire-size` | Pad the complete UTF-8 encoded syslog payload to at least this many bytes |

RFC 5424 header fields are checked for permitted characters and maximum lengths. Structured data must be `-` or bracketed data such as:

```bash
--sd '[example@32473 site="lon1" environment="lab"]'
```

### Message sources

Sources are mutually exclusive:

- `--message` supplies one template.
- `--from-file` reads one template per line.
- `--stdin` reads templates from standard input.
- With no source option, the built-in examples are cycled.

An empty input is rejected instead of entering an unproductive loop. The included `msgs.txt` contains 1,500 JSON-style sample events and can be used directly:

```bash
logsalvo 192.0.2.10 --from-file msgs.txt --count 100 --rate 25
```

### Template variables

| Variable | Value |
| --- | --- |
| `{seq}` | Attempt sequence number |
| `{uuid}` | New UUID v4 |
| `{timestamp}` | ISO 8601 local timestamp with milliseconds |
| `{randint:a:b}` | Random integer in the inclusive range `a` to `b` |
| `{hostname}` | Configured hostname |
| `{app}` | Configured application name |
| `{facility}` | Numeric facility |
| `{severity}` | Numeric severity |

Example:

```bash
logsalvo logs.example.net --format 5424 --count 50 --rate 10 \
  --message 'probe={seq} correlation={uuid} cpu={randint:10:95}'
```

### Run controls

- `--count` is the number of send attempts, not successful deliveries. This guarantees termination when a collector is unavailable.
- `--count 0` is accepted only with a positive `--duration`.
- `--duration` stops the run after the specified seconds and takes precedence when reached first.
- `--rate` schedules an exact target messages-per-second cadence using a monotonic clock.
- `--delay` sleeps for a fixed period after each attempt.
- `--rate` and `--delay` cannot be combined.

## Examples

RFC 5424 over TCP using octet-counted framing:

```bash
logsalvo logs.example.net --transport tcp --port 10514 \
  --format 5424 --count 100 --rate 50 --msgid NETTEST \
  --sd '[example@32473 site="lon1"]'
```

TLS with a private CA:

```bash
logsalvo logs.example.net --transport tcp --tls --cafile ./lab-ca.pem \
  --format 5424 --count 20 --message 'TLS probe {seq}'
```

Mutual TLS:

```bash
logsalvo logs.example.net --transport tcp --tls \
  --cafile ./ca.pem --certfile ./client.pem --keyfile ./client-key.pem \
  --count 20
```

IPv6 with a selected source address:

```bash
logsalvo 2001:db8::50 --bind-ip 2001:db8::10 --count 5
```

Generate for 30 seconds regardless of count:

```bash
logsalvo 192.0.2.10 --count 0 --duration 30 --rate 100
```

Pipe messages from another program:

```bash
printf 'first {seq}\nsecond {seq}\n' | \
  logsalvo 192.0.2.10 --stdin --count 10 --delay 0.2
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All attempted messages were sent, or dry-run completed |
| `1` | Connection, TLS, formatting, or send failure |
| `2` | Invalid arguments, configuration, or input source |
| `130` | Interrupted from the CLI |

UDP success means that the local operating system accepted the datagram; UDP does not provide collector acknowledgements.

## Verification listeners

UDP on Linux:

```bash
nc -klu 514
```

TCP with LF framing:

```bash
nc -kl 10514
logsalvo 127.0.0.1 --transport tcp --tcp-framing lf --port 10514 --count 5
```

TLS test endpoint:

```bash
openssl s_server -accept 6514 -quiet -cert server.pem -key server-key.pem
```

## Troubleshooting

**The collector receives nothing**

- Confirm the correct destination port, firewall policy, and ingest listener.
- Use `--echo` to inspect locally generated payloads.
- Try a local `nc` listener to separate generator and network issues.
- Remember that binding a source address requires that address to exist locally.

**TCP connects but messages are not parsed**

- Match `--tcp-framing octet` or `--tcp-framing lf` to the collector configuration.
- Confirm whether the collector expects RFC 3164 or RFC 5424.

**TLS fails**

- Verify the CA chain and target hostname.
- Use `--sni` when connecting to an IP address or alternate DNS name.
- Use `--insecure` only to isolate verification problems in a controlled lab.

**The achieved rate is lower than requested**

- Disable `--echo` and avoid displaying every message in the GUI.
- TLS, message size, retries, operating-system buffers, and collector capacity limit throughput.
- UDP can be dropped silently under load.

## Development

Install development dependencies and run the checks:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
ruff check .
pytest
```

Tests include message formatting, field validation, template expansion, pacing, failure termination, duration control, and a real local UDP integration test. GitHub Actions runs linting and tests on Python 3.10–3.13.

The main components are:

```text
logsalvo/
├── cli.py          command-line adapter
├── gui.py          PySide6 desktop adapter
├── formatters.py   RFC 3164/5424 encoding
├── models.py       validated configuration and statistics
├── sender.py       pacing, retry, cancellation, and orchestration
├── templates.py    template expansion and examples
└── transports.py   UDP, TCP, TLS, framing, and address binding
```

## Building a desktop executable

PyInstaller can create a standalone executable. Install it alongside the GUI extra, then run:

```bash
python -m pip install '.[gui]' pyinstaller
pyinstaller --windowed --name logsalvo-gui \
  --collect-all PySide6 "$(command -v logsalvo-gui)"
```

PyInstaller options and signing/notarization requirements differ by operating system. Build and test on each target platform rather than cross-compiling.

## Migrating from the old scripts

The legacy `syslog_sender.py` and standalone `syslog-pro.py` have been removed. After installation:

- Replace `python syslog-pro.py HOST ...` with `logsalvo HOST ...`.
- Replace the pre-release `syslog-sender HOST ...` command with `logsalvo HOST ...`.
- Replace `--size` with the unambiguous `--wire-size`.
- Counts now measure attempts and always terminate despite send errors.
- Invalid negative values now fail rather than acting as undocumented infinite modes.
- Use `logsalvo-gui` for the desktop interface.

## License

LogSalvo is released under the [MIT License](LICENSE).

Copyright © 2025–2026 The Tech Shed. LogSalvo version 2.4.1.
