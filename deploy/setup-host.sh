#!/bin/bash
# setup-host.sh - Run on target server to install Docker, nginx, and configure firewall
set -e

echo "=== PEEK Host Setup ==="
echo "Running on: $(hostname)"
echo "Date: $(date)"

# Update system
echo ""
echo ">>> Updating system packages..."
sudo apt-get update
sudo apt-get upgrade -y

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo ""
    echo ">>> Installing Docker..."
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker $USER
    echo "Docker installed. You may need to log out and back in for group changes."
else
    echo ""
    echo ">>> Docker already installed: $(docker --version)"
fi

# Install Docker Compose plugin if not present
if ! docker compose version &> /dev/null; then
    echo ""
    echo ">>> Installing Docker Compose plugin..."
    sudo apt-get install -y docker-compose-plugin
else
    echo ""
    echo ">>> Docker Compose already installed: $(docker compose version)"
fi

# Install nginx if not present
if ! command -v nginx &> /dev/null; then
    echo ""
    echo ">>> Installing nginx..."
    sudo apt-get install -y nginx
else
    echo ""
    echo ">>> nginx already installed: $(nginx -v 2>&1)"
fi

# Configure UFW firewall
echo ""
echo ">>> Configuring firewall (UFW)..."
sudo ufw --force enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw reload
echo "Firewall configured. Allowed: SSH, HTTP (80)"

# Create app directory
echo ""
echo ">>> Creating /opt/peek directory..."
sudo mkdir -p /opt/peek
sudo chown $USER:$USER /opt/peek

# Start Docker service
echo ""
echo ">>> Ensuring Docker service is running..."
sudo systemctl enable docker
sudo systemctl start docker

echo ""
echo "=== Host setup complete ==="
echo "Ready for PEEK deployment to /opt/peek"
