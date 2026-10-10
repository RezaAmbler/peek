#!/bin/bash
# deploy.sh - Main deployment script (runs locally)
# Usage: ./deploy.sh <target-ip> [ssh-key-path]
set -e

# Configuration
TARGET_IP="${1:-}"
SSH_KEY="${2:-$HOME/.ssh/your-keypair.pem}"
SSH_USER="ubuntu"
REMOTE_DIR="/opt/peek"
LOCAL_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[DEPLOY]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Validate arguments
if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <target-ip> [ssh-key-path]"
    echo "Example: $0 203.0.113.10 ~/.ssh/your-keypair.pem"
    exit 1
fi

if [ ! -f "$SSH_KEY" ]; then
    error "SSH key not found: $SSH_KEY"
fi

if ! command -v openssl >/dev/null 2>&1; then
    error "openssl not found locally; required for SECRET_KEY generation"
fi

# SSH options
# Keepalives: the image build can be silent for minutes, and a dropped
# connection must fail the deploy rather than hang it.
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=30 -o ServerAliveCountMax=6 -i $SSH_KEY"
SSH_CMD="ssh $SSH_OPTS $SSH_USER@$TARGET_IP"
SCP_CMD="scp $SSH_OPTS"

echo ""
echo "=========================================="
echo "  PEEK Production Deployment"
echo "=========================================="
echo "Target: $SSH_USER@$TARGET_IP"
echo "SSH Key: $SSH_KEY"
echo "Local Dir: $LOCAL_DIR"
echo "Remote Dir: $REMOTE_DIR"
echo "=========================================="
echo ""

# Step 1: Test SSH connection
log "Step 1: Testing SSH connection..."
if $SSH_CMD "echo 'SSH connection successful'" 2>/dev/null; then
    log "SSH connection OK"
else
    error "Cannot connect to $TARGET_IP. Check IP and SSH key."
fi

# Step 2: Copy and run setup script
log "Step 2: Setting up host (Docker, nginx, ufw)..."
$SCP_CMD "$LOCAL_DIR/deploy/setup-host.sh" "$SSH_USER@$TARGET_IP:/tmp/setup-host.sh"
$SSH_CMD "chmod +x /tmp/setup-host.sh && /tmp/setup-host.sh"

# Step 3: Sync code to remote
log "Step 3: Syncing code to remote server..."
# Containers run as root and write runtime files into the tree (e.g.
# backend/app/data/kev_cache.json), leaving them root-owned. Reclaim ownership for
# the deploy user first so rsync (running as $SSH_USER) doesn't fail with
# "Permission denied" on a redeploy. root inside the containers can still write.
$SSH_CMD "sudo chown -R $SSH_USER:$SSH_USER $REMOTE_DIR 2>/dev/null || true"
rsync -avz --delete \
    --exclude '_analysis/' \
    --exclude '.git' \
    --exclude '.pytest_cache/' \
    --exclude 'backend/.pytest_cache/' \
    --exclude '.venv/' \
    --exclude 'artifacts/' \
    --exclude '/data/' \
    --exclude '.env' \
    --exclude 'frontend/coverage/' \
    --exclude 'frontend/dist/' \
    --exclude 'node_modules' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude 'tmp/' \
    --exclude 'venv/' \
    -e "ssh $SSH_OPTS" \
    "$LOCAL_DIR/" "$SSH_USER@$TARGET_IP:$REMOTE_DIR/"
log "Code synced to $REMOTE_DIR"

# Step 4: Create production .env file
log "Step 4: Creating production .env file..."
GENERATED_SECRET=$(openssl rand -hex 32)
if [ -z "$GENERATED_SECRET" ] || [ ${#GENERATED_SECRET} -lt 32 ]; then
    error "openssl rand returned empty or short value; aborting"
fi
$SSH_CMD "cat > $REMOTE_DIR/backend/.env << 'ENV_EOF'
DATABASE_URL=sqlite+aiosqlite:///./data/peek.db
SECRET_KEY=$GENERATED_SECRET
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440
ALLOWED_ORIGINS=[\"http://$TARGET_IP\",\"http://localhost:3000\"]
VERSION=2.2.1
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/0
ENV_EOF"

# Step 5: Create data directory
log "Step 5: Creating data directory..."
$SSH_CMD "mkdir -p $REMOTE_DIR/data && chmod 777 $REMOTE_DIR/data"

# Step 6: Build and start containers
log "Step 6: Building and starting Docker containers..."
$SSH_CMD "cd $REMOTE_DIR && sudo docker compose down 2>/dev/null || true"
$SSH_CMD "cd $REMOTE_DIR && sudo docker compose build"
$SSH_CMD "cd $REMOTE_DIR && sudo docker compose up -d"

# Step 7: Configure nginx reverse proxy
log "Step 7: Configuring nginx reverse proxy..."
$SSH_CMD "sudo tee /etc/nginx/sites-available/peek > /dev/null << 'NGINX_EOF'
server {
    listen 80;
    server_name _;

    # Frontend
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }

    # API
    location /api {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }
}
NGINX_EOF"

$SSH_CMD "sudo ln -sf /etc/nginx/sites-available/peek /etc/nginx/sites-enabled/peek"
$SSH_CMD "sudo rm -f /etc/nginx/sites-enabled/default"
$SSH_CMD "sudo nginx -t && sudo systemctl reload nginx"
log "nginx configured"

# Step 8: Wait for services to start
log "Step 8: Waiting for services to start..."
sleep 10

# Step 9: Health checks
log "Step 9: Running health checks..."
echo ""

# Check containers
log "Checking Docker containers..."
$SSH_CMD "cd $REMOTE_DIR && sudo docker compose ps"

# Check API health
log "Checking API health..."
API_HEALTH=$($SSH_CMD "curl -s http://localhost:8000/api/health" 2>/dev/null || echo "failed")
if echo "$API_HEALTH" | grep -q "ok"; then
    log "API health check: OK"
else
    warn "API health check failed: $API_HEALTH"
fi

# Check frontend
log "Checking frontend..."
FRONTEND_CHECK=$($SSH_CMD "curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/" 2>/dev/null || echo "000")
if [ "$FRONTEND_CHECK" = "200" ]; then
    log "Frontend health check: OK"
else
    warn "Frontend returned HTTP $FRONTEND_CHECK"
fi

# Check nginx proxy
log "Checking nginx proxy on port 80..."
NGINX_CHECK=$($SSH_CMD "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/" 2>/dev/null || echo "000")
if [ "$NGINX_CHECK" = "200" ]; then
    log "nginx proxy: OK"
else
    warn "nginx returned HTTP $NGINX_CHECK"
fi

echo ""
echo "=========================================="
echo "  Deployment Complete!"
echo "=========================================="
echo ""
log "PEEK is now accessible at: http://$TARGET_IP"
echo ""
echo "Useful commands:"
echo "  SSH:     ssh -i $SSH_KEY $SSH_USER@$TARGET_IP"
echo "  Logs:    ssh -i $SSH_KEY $SSH_USER@$TARGET_IP 'cd $REMOTE_DIR && sudo docker compose logs -f'"
echo "  Restart: ssh -i $SSH_KEY $SSH_USER@$TARGET_IP 'cd $REMOTE_DIR && sudo docker compose restart'"
echo ""
