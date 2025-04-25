#!/usr/bin/env python3
import socket
import random
import time
import argparse
from datetime import datetime

FACILITIES = list(range(0, 24))
SEVERITIES = list(range(0, 8))

EXAMPLE_MESSAGES = [
    "System rebooted",
    "User login successful",
    "Interface eth0 down",
    "Disk usage exceeded threshold",
    "Firewall rule matched",
    "Unexpected shutdown",
    "Temperature sensor alert",
    "Authentication failure",
    "Configuration changed",
    "Scheduled backup completed"
]

def generate_syslog_message():
    facility = random.choice(FACILITIES)
    severity = random.choice(SEVERITIES)
    priority = facility * 8 + severity
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    hostname = socket.gethostname()
    message = random.choice(EXAMPLE_MESSAGES)
    return f"<{priority}>{timestamp} {hostname} {message}"

def send_syslog(ip, port, count, delay):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(count):
        msg = generate_syslog_message()
        sock.sendto(msg.encode(), (ip, port))
        print(f"Sent: {msg}")
        if delay > 0:
            time.sleep(delay)
    sock.close()

def main():
    parser = argparse.ArgumentParser(description="Random Syslog Message Generator")
    parser.add_argument("ip", help="Destination IP address")
    parser.add_argument("--port", type=int, default=514, help="Syslog port (default: 514)")
    parser.add_argument("--count", type=int, default=10, help="Number of messages to send")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between messages (seconds)")
    parser.add_argument("--interval", type=float, default=0.0, help="Repeat sending every X seconds (0 to disable)")
    args = parser.parse_args()

    if args.interval > 0:
        print(f"Running in loop every {args.interval} seconds...")
        try:
            while True:
                send_syslog(args.ip, args.port, args.count, args.delay)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nStopped by user.")
    else:
        send_syslog(args.ip, args.port, args.count, args.delay)

if __name__ == "__main__":
    main()
