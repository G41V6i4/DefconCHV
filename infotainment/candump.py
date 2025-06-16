#!/usr/bin/env python3
import sys
import subprocess

if len(sys.argv) < 2:
    print("Usage: candump <interface>")
    sys.exit(1)

interface = sys.argv[1]
log_file = "/tmp/can_daemon/messages.log"

print(f"Listening on {interface}...")
subprocess.run(['tail', '-f', '-n', '0', log_file])