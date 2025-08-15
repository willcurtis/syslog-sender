# syslog-pro — Professional Syslog Traffic Generator

`syslog-pro.py` is a fast, dependency‑free CLI for generating syslog traffic to test and troubleshoot collectors, SIEMs, and log pipelines.

- **Formats:** RFC3164 (BSD) and RFC5424
- **Transports:** UDP, TCP, **TLS** (6514) with RFC6587 framing (`octet` or `lf`)
- **Controls:** Fixed delay or messages‑per‑second rate, total count or duration
- **Templating:** `{seq}`, `{uuid}`, `{timestamp}`, `{randint:a:b}`, `{hostname}`, `{app}`, `{facility}`, `{severity}`
- **Inputs:** Inline `-m`, file, or stdin
- **Ops‑friendly:** Bind source IP, IPv4/IPv6, payload padding, dry‑run, verbose echo, useful stats

> Goal: predictable, standards‑compliant test traffic for real‑world troubleshooting.

---

## Contents
- [Features](#features)
- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
- [Usage](#usage)
  - [CLI synopsis](#cli-synopsis)
  - [Key options](#key-options)
  - [Templating](#templating)
  - [Transports & framing](#transports--framing)
  - [TLS](#tls)
  - [Binding source IP](#binding-source-ip)
- [Examples](#examples)
- [Structured Data (RFC5424)](#structured-data-rfc5424)
- [Verification helpers](#verification-helpers)
- [Troubleshooting](#troubleshooting)
- [Exit status](#exit-status)
- [FAQ](#faq)
- [License](#license)

---

## Features
- RFC3164 and RFC5424 message building
- UDP or TCP transport; **TLS** on TCP with server verification, SNI, optional client certs
- RFC6587 framing for TCP: `--tcp-framing octet` (default) or `lf`
- Facilities/severities by **name** or number
- Message templating with runtime variables
- Rate limiting (`--rate`) or fixed delay (`--delay`)
- Stop by `--count` or `--duration`; repeat with `--interval`
- Bind to specific local IP (v4/v6)
- Payload padding (`--size`) to test MTU/fragmentation
- `--echo`, `--dry-run`, `-v/--verbose` for visibility
- No third‑party dependencies

## Requirements
- Python **3.8+** on macOS, Linux, or Windows.

## Install
Download the script and make it executable:
```bash
curl -L -o syslog-pro.py "<your source or repo URL>"
chmod +x syslog-pro.py
./syslog-pro.py --help
```
> Or place it on your PATH, e.g. `/usr/local/bin/syslog-pro`.

## Quick start
Send 10 RFC3164 messages via UDP 514:
```bash
python3 syslog-pro.py 192.0.2.10 -n 10 --format 3164 --app test --facility local4 --severity info   -m "Smoke test {seq} {uuid}"
```

Send 100 RFC5424 messages over TCP (octet framing) to port 10514 at 50 msg/s:
```bash
python3 syslog-pro.py loghost.example.com --transport tcp -p 10514 --format 5424   --msgid NETTEST --sd '[example@32473 site="UK" env="lab"]' -n 100 --rate 50
```

TLS (6514), verify server cert with custom CA:
```bash
python3 syslog-pro.py siem.company.tld --transport tcp --tls --cafile /path/ca.pem   --format 5424 -n 20 -m "TLS test {seq} at {timestamp}"
```

Pad to 1200 bytes and bind to a specific local IP:
```bash
python3 syslog-pro.py 198.51.100.5 --size 1200 --bind-ip 10.0.0.25 -n 5 --delay 0.2
```

Read messages from a file and repeat every 60s:
```bash
python3 syslog-pro.py 192.0.2.10 --from-file msgs.txt --interval 60 --format 5424
```

## Usage

### CLI synopsis
```text
usage: syslog-pro.py [-h] [-p PORT] [--transport {udp,tcp}] [--tls]
                     [--cafile CAFILE] [--certfile CERTFILE] [--keyfile KEYFILE]
                     [--insecure] [--sni SNI]
                     [--tcp-framing {octet,lf}] [--bind-ip BIND_IP]
                     [--format {3164,5424}] [--facility FACILITY]
                     [--severity SEVERITY] [--app APP] [--hostname HOSTNAME]
                     [--procid PROCID] [--msgid MSGID] [--sd SD]
                     [-m MESSAGE] [--from-file FROM_FILE] [--stdin]
                     [-n COUNT] [--duration DURATION] [--rate RATE] [--delay DELAY]
                     [--interval INTERVAL] [--size SIZE] [--echo] [--dry-run] [-v]
                     target
```

### Key options
- `target` — syslog server IP or hostname
- `-p/--port` — destination port (default **514**; defaults to **6514** when `--tls` if port not set)
- `--transport` — `udp` (default) or `tcp`
- `--tls` — enable TLS (TCP only)
- `--tcp-framing` — `octet` (default) or `lf`
- `--format` — `3164` (default) or `5424`
- `--facility` — name (`local0`, `auth`, `cron`, …) or number `0..23` (default `local0`)
- `--severity` — name (`info`, `err`, `debug`, …) or number `0..7` (default `info`)
- `--app` — app-name/tag (default `syslog-pro`)
- `--hostname` — override hostname in messages
- `--procid` — process ID (default: current PID)
- `--msgid` — RFC5424 MSGID (default `TEST`)
- `--sd` — RFC5424 Structured Data (see below)
- `-m/--message` — message template (see [Templating](#templating))
- `--from-file` / `--stdin` — message sources
- `-n/--count` or `--duration` — send limit(s)
- `--rate` or `--delay` — pacing (mutually exclusive)
- `--interval` — repeat whole batch periodically
- `--size` — minimum payload size (pads with spaces)
- `--echo`, `--dry-run`, `-v/--verbose` — visibility and diagnostics

### Templating
Variables you can embed in `-m`, file, or stdin lines:
- `{seq}` — sequence number (per run)
- `{uuid}` — random UUIDv4
- `{timestamp}` — ISO8601 with milliseconds
- `{randint:a:b}` — random integer in `[a, b]`
- `{hostname}` / `{app}` — as provided
- `{facility}` / `{severity}` — numeric values

Example:
```bash
-m 'fw={hostname} app={app} sev={severity} id={uuid} cnt={seq} cpu={randint:10:98}'
```

### Transports & framing
- **UDP 514:** simple, can drop under load. Good for quick checks.
- **TCP:** reliable. Use RFC6587 framing:
  - `--tcp-framing octet` → `"<length> <payload>"` (default)
  - `--tcp-framing lf` → payloads separated by `\n`
- **TLS 6514:** secure syslog over TCP. Use `--cafile` to verify the server.

### TLS
- `--cafile` — CA bundle or server cert for verification
- `--certfile` / `--keyfile` — client certificate/key (mTLS)
- `--insecure` — disable verification/hostname check (debug only)
- `--sni` — override SNI name (defaults to target hostname)

### Binding source IP
Use `--bind-ip <ip>` to pick a local address (useful on multi‑homed hosts or where collectors filter by sender IP).

## Examples

LF framing (legacy collectors):
```bash
python3 syslog-pro.py 192.0.2.10 --transport tcp --tcp-framing lf -n 20
```

Loop a probe every minute, printing each payload:
```bash
python3 syslog-pro.py 192.0.2.10 --interval 60 --echo -n 5 -m "probe {seq} {timestamp}"
```

Mix file and variables:
```bash
python3 syslog-pro.py 192.0.2.10 --from-file alarms.txt --format 5424   --sd '[example@32473 pop="lon1" severity="{severity}"]'
```

## Structured Data (RFC5424)
Pass raw SD with `--sd`. Example:
```bash
--sd '[example@32473 iut="3" eventSource="App" eventID="1011"][meta@9999 env="dev" site="lon"]'
```
If omitted, `-` is sent per RFC5424.

## Verification helpers
UDP listener (Linux/macOS):
```bash
nc -klu 0.0.0.0 514
```
TCP listener:
```bash
nc -kl 0.0.0.0 10514
```
OpenSSL TLS test server (for connectivity only):
```bash
openssl s_server -accept 6514 -quiet -cert server.pem -key server.key
```

## Troubleshooting
- **No ingestion over TCP:** framing mismatch. Align `--tcp-framing` with the collector.
- **Weird timestamps:** RFC3164 lacks year/timezone. Prefer `--format 5424`.
- **UDP drops:** expected under load. Use TCP/TLS to test reliability.
- **TLS handshake fails:** wrong CA or SNI. Provide `--cafile` and check `--sni`.
- **Nothing arrives:** check firewall/NAT; confirm the collector ingest port.
- **Filtered by source IP:** set `--bind-ip`.

## Exit status
The tool prints totals, errors, elapsed time, and effective rate. Current behavior uses exit code `0` regardless of send errors. For CI usage, you can modify the end of `main()` to exit non‑zero if `errors > 0`.

## FAQ
**Does it generate JSON automatically?**  
No. Use templates to embed JSON yourself.

**Randomize severity/facility per message?**  
Not built‑in. Provide multiple lines in a file and send at a rate/duration.

**IPv6?**  
Yes. Provide an IPv6 literal or a hostname with AAAA records.

**Windows?**  
Yes. Use `python syslog-pro.py ...` in PowerShell or CMD.

## License
TBD by the repository owner (e.g., MIT, BSD‑2‑Clause, Apache‑2.0).
