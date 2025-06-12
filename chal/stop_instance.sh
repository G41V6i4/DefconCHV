#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <user_id>"
    exit 1
fi

USER_ID=$1

echo "Stopping CTF instance for user $USER_ID"
USER_ID=$USER_ID docker-compose down

echo "Instance stopped and cleaned up"
