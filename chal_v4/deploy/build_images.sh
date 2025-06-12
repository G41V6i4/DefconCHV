#!/bin/bash
set -e

echo "Building ECU CTF Challenge images..."

# Base images
docker build -t ecu_ctf/can_bridge:latest ./can_bridge
docker build -t ecu_ctf/infotainment:latest ./infotainment
docker build -t ecu_ctf/gateway:latest ./gateway
docker build -t ecu_ctf/ecm:latest ./ecm

# Router
docker build -t ecu_ctf/router:latest ./router

echo "All images built successfully!"