#!/bin/bash

# Automatically switch to the script's own directory
cd "$(dirname "$0")" || {
  echo "Failed to switch to script directory"
  exit 1
}

# --- Configuration ---
WINDOWS_PARTITION_UUID="6840D17A40D150042" 
COMPOSE_OUTPUT_FILE="docker-compose.yml"

echo "--- Starting File Server Setup ---"

# Docker Compose Template
read -r -d '' DOCKER_COMPOSE_TEMPLATE <<EOF
version: '3.8'

services:
  file_server:
    build: .
    container_name: my_custom_file_server
    ports:
      - "5000:5000"
    volumes:
      - "/home/pawan/Downloads:/host_linux_home/Downloads:rw"
      - "/home/pawan/Documents:/host_linux_home/Documents:rw"
      - "WINDOWS_MOUNT_PATH_PLACEHOLDER:/host_windows_c:rw"
      - ./app.py:/app/app.py:ro
      - ./templates:/app/templates:ro
    environment:
      - FLASK_SECRET_KEY=fad62249097085110c14de2802459ce956cdfc37e123c315739a3399440be396
      - ADMIN_PASSWORD_HASH=scrypt:32768:8:1\$1M6p0ZUTlHCZgeQL\$5d9784132cbe39ced0aae82bcb68c9f72b19eb5bfa092b4cd797fffa12b23feffd56dfb6293b6ec9cddb26283149f643ec3167aaf59cb2116c83d0c2e97c57e6
EOF

echo "Searching for Windows partition (UUID: $WINDOWS_PARTITION_UUID)..."
MOUNT_POINT=$(mount | grep "$WINDOWS_PARTITION_UUID" | awk '{print $3}')

if [ -z "$MOUNT_POINT" ]; then
    echo "ERROR: Windows partition with UUID '$WINDOWS_PARTITION_UUID' is not currently mounted."
    echo "Please mount it manually first."
    exit 1
fi

echo "Windows partition found mounted at: $MOUNT_POINT"
echo "Generating $COMPOSE_OUTPUT_FILE..."
echo "$DOCKER_COMPOSE_TEMPLATE" > "$COMPOSE_OUTPUT_FILE"
sed -i "s|WINDOWS_MOUNT_PATH_PLACEHOLDER|$MOUNT_POINT|g" "$COMPOSE_OUTPUT_FILE"
echo "Updated $COMPOSE_OUTPUT_FILE with mount path: $MOUNT_POINT"

echo "Ensuring no previous container is running for this service..."
docker-compose down --remove-orphans

echo "Bringing up Docker container..."
docker-compose up -d

echo "--- File Server Setup Complete ---"
echo "Access it at: http://<your-ip>:5000"
