#!/bin/bash

# Monitor Dynamic CAN Gateway

echo "🌉 Dynamic CAN Gateway Monitor"
echo "============================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to monitor vcan interfaces
monitor_vcans() {
    echo -e "${BLUE}[vcan Interfaces]${NC}"
    while true; do
        clear
        echo -e "${BLUE}Active vcan interfaces:${NC}"
        ip link show | grep vcan | awk '{print $2}' | sed 's/://' | sort
        
        echo -e "\n${YELLOW}Session bridges:${NC}"
        ps aux | grep "gateway_dynamic.py" | grep -v grep
        
        echo -e "\n${GREEN}Gateway logs:${NC}"
        docker logs gateway_ecu --tail 5
        
        sleep 2
    done
}

# Function to monitor specific vcan
monitor_single_vcan() {
    local vcan=$1
    echo -e "${BLUE}Monitoring $vcan${NC}"
    candump $vcan
}

# Main menu
echo "1. Monitor all vcan interfaces"
echo "2. Monitor vcan0 (Infotainment)"
echo "3. Monitor vcan1 (Engine)"
echo "4. Monitor session vcan (vcan2+)"
echo "5. Show gateway logs"
echo ""

read -p "Select option: " choice

case $choice in
    1)
        monitor_vcans
        ;;
    2)
        monitor_single_vcan vcan0
        ;;
    3)
        monitor_single_vcan vcan1
        ;;
    4)
        read -p "Enter vcan number (e.g., 2 for vcan2): " num
        monitor_single_vcan "vcan$num"
        ;;
    5)
        docker logs -f gateway_ecu
        ;;
    *)
        echo "Invalid option"
        ;;
esac