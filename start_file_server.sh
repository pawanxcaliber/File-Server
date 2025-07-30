#!/bin/bash

# start_file_server.sh
# This script finds the current mount point of your Windows partition,
# generates a docker-compose.yml file, and starts your Dockerized file server.

# --- Configuration ---
# IMPORTANT: Replace this with the actual UUID of your Windows partition.
# You can find it by running 'sudo blkid -o full' in your terminal and looking for your NTFS partition.
WINDOWS_PARTITION_UUID="6840D17A40D150042" 

# Name for the generated Docker Compose file
COMPOSE_OUTPUT_FILE="docker-compose.yml"

# --- Script Logic ---

echo "--- Starting File Server Setup ---"

# 1. Define the Docker Compose template inline
read -r -d '' DOCKER_COMPOSE_TEMPLATE <<EOF
version: '3.8'

services:
  file_server:
    build: .
    container_name: my_custom_file_server
    ports:
      - "5000:5000" # Host_Port:Container_Port
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

# 2. Check if the Windows partition is mounted and find its mount point
echo "Searching for Windows partition (UUID: $WINDOWS_PARTITION_UUID)..."

# Using 'mount' and 'awk' to extract the mount point.
MOUNT_POINT=$(mount | grep "$WINDOWS_PARTITION_UUID" | awk '{print $3}')

if [ -z "$MOUNT_POINT" ]; then
    echo "ERROR: Windows partition with UUID '$WINDOWS_PARTITION_UUID' is not currently mounted."
    echo "Please mount it manually first (e.g., by clicking on it in your file manager)."
    echo "To verify mount status, run: mount | grep \"$WINDOWS_PARTITION_UUID\""
    exit 1
fi

echo "Windows partition found mounted at: $MOUNT_POINT"

# 3. Write the template content to the output file
echo "Generating $COMPOSE_OUTPUT_FILE..."
echo "$DOCKER_COMPOSE_TEMPLATE" > "$COMPOSE_OUTPUT_FILE"

# 4. Replace the placeholder with the actual mount point
sed -i "s|WINDOWS_MOUNT_PATH_PLACEHOLDER|$MOUNT_POINT|g" "$COMPOSE_OUTPUT_FILE"

echo "Updated $COMPOSE_OUTPUT_FILE with mount path: $MOUNT_POINT"

# 5. Bring down any existing container to ensure fresh start with new config
echo "Ensuring no previous container is running for this service..."
# Changed 'docker compose' to 'docker-compose' for wider compatibility
docker-compose down --remove-orphans

# 6. Build (if necessary) and start the Docker container
echo "Bringing up Docker container..."
# Changed 'docker compose' to 'docker-compose' for wider compatibility
docker-compose up -d

echo "--- File Server Setup Complete ---"
echo "You can now access your file server via your browser."
echo "Remember to find your laptop's IP address on your current network (e.g., 'ip a' or 'hostname -I') and use it with port 5000."
echo "Example: http://YOUR_LAPTOP_IP:5000"