# Random Syslog Sender

A simple Python script to generate and send random syslog messages to a specified destination.

## Usage

```bash
python3 syslog_sender.py <destination_ip> --port 514 --count 10 --delay 0.5 --interval 0
```

### Options

- `destination_ip` (required): IP address to send the syslog messages to.
- `--port`: Syslog port (default: 514).
- `--count`: Number of messages to send (default: 10).
- `--delay`: Delay between messages in seconds (default: 0).
- `--interval`: Repeat the send every X seconds (default: 0 for no repeat).

### Example

```bash
python3 syslog_sender.py 192.168.1.100 --count 100 --delay 0.1 --interval 60
```

Sends 100 random messages every 60 seconds.

## License

MIT License
