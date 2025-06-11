#!/bin/bash

# Main setup script for Automotive CTF

set -e

echo "================================"
echo "Automotive CTF Setup"
echo "================================"

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo "Warning: Running as root. This may cause permission issues."
fi

# Function to generate hints
generate_hints() {
    echo "Generating challenge hints..."
    
    # Level 1: Gateway Authentication
    cat > challenges/level1/description.md << 'EOF'
# Level 1: Gateway Authentication

Your first challenge is to authenticate with the CAN Gateway.

## Objective
Successfully authenticate with the gateway to send CAN messages.

## Points: 100

## Resources
- Gateway endpoint: ws://localhost:8080
- Authentication uses HMAC-SHA256
EOF

    cat > challenges/level1/hints.md << 'EOF'
# Hints for Level 1

1. Check the gateway source code for the authentication mechanism
2. The secret key might be hardcoded somewhere
3. Look for `auth_protocol.py`
4. HMAC requires a secret key and the challenge string
EOF

    # Level 2: UDS Communication
    cat > challenges/level2/description.md << 'EOF'
# Level 2: UDS Communication

Now that you're authenticated, communicate with the Engine ECU using UDS.

## Objective
Successfully establish a diagnostic session with the Engine ECU.

## Points: 200

## Resources
- Engine ECU ID: 0x7E0
- Response ID: 0x7E8
- UDS Service 0x10: Diagnostic Session Control
EOF

    # Level 3: Security Access
    cat > challenges/level3/description.md << 'EOF'
# Level 3: Security Access

Gain security access to the Engine ECU.

## Objective
Successfully complete security access level 2.

## Points: 300

## Resources
- Service 0x27: Security Access
- Multiple security levels available
- Each level uses different key algorithms
EOF

    # Level 4: Binary Exploitation
    cat > challenges/level4/description.md << 'EOF'
# Level 4: Binary Exploitation

The Engine ECU has vulnerable services. Exploit them!

## Objective
Achieve code execution on the Engine ECU.

## Points: 500

## Vulnerable Services
- 0xF0: Memory read
- 0xF1: Stack overflow
- 0xF2: Format string
- 0xF3: Heap overflow
EOF

    # Level 5: Flag Capture
    cat > challenges/level5/description.md << 'EOF'
# Level 5: Flag Capture

Retrieve the flag from the Engine ECU.

## Objective
Extract the secret flag using any method.

## Points: 600

## Methods
- Read from memory (0xF000)
- Execute hidden functions
- Bypass all security levels
- Use UDS service 0x22 with proper access
EOF
}

# Function to create example files
create_examples() {
    echo "Creating example files..."
    
    # Create simple client example
    cat > exploits/simple_client.py << 'EOF'
#!/usr/bin/env python3

import websocket
import json
import time

def main():
    # Connect to gateway
    ws = websocket.WebSocket()
    ws.connect("ws://localhost:8080")
    
    # Get welcome message
    welcome = json.loads(ws.recv())
    print(f"Welcome: {welcome}")
    
    # TODO: Authenticate here
    
    ws.close()

if __name__ == "__main__":
    main()
EOF

    chmod +x exploits/simple_client.py
}

# Function to check dependencies
check_dependencies() {
    echo "Checking dependencies..."
    
    # Check for Docker
    if ! command -v docker &> /dev/null; then
        echo "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    
    # Check for Python 3
    if ! command -v python3 &> /dev/null; then
        echo "Python 3 is not installed. Please install Python 3 first."
        exit 1
    fi
}

# Main setup
check_dependencies
generate_hints
create_examples

# Create necessary directories
mkdir -p logs/gateway logs/engine logs/exploits
mkdir -p tools/monitoring
mkdir -p config

# Create default config
cat > config/ctf_config.yaml << 'EOF'
ctf:
  name: "Automotive Security CTF"
  duration: 8  # hours
  teams_allowed: 50
  
scoring:
  level1: 100
  level2: 200
  level3: 300
  level4: 500
  level5: 600
  
services:
  gateway:
    port: 8080
    max_connections: 100
  engine:
    vulnerable: true
    protections: minimal
EOF

# Set permissions
chmod -R 755 scripts/
chmod -R 755 setup/
chmod -R 755 tools/

echo ""
echo "================================"
echo "Setup completed successfully!"
echo "================================"
echo ""
echo "Next steps:"
echo "1. Run: ./scripts/build_all.sh"
echo "2. Run: ./scripts/start_ctf.sh"
echo ""
echo "Happy hacking!"