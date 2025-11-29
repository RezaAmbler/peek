#!/bin/bash
# ============================================================================
#  Deliberately Insecure "Hellbox" for PEEK / Nmap / NSE / TLS testing
#
#  - Exposes a ton of services to the internet
#  - Weak TLS, self-signed short/weak cert (OpenSSL 3.x compatible)
#  - Anonymous FTP with write
#  - Open Redis / Memcached
#  - Weak DB users
#  - Lax SSH / Samba / mail / IMAP configs
#  - HTTP-layer vuln candy for Nikto / ZAP
#  - Nginx on standard ports (80, 443)
#  - Apache on non-standard ports (8888, 8443) with weak TLS
#
#  ONLY USE ON THROWAWAY LAB INSTANCES
#
#  Updated: 2024 - Fixed OpenSSL 3.x cipher compatibility
# ============================================================================

set -u -o pipefail
export DEBIAN_FRONTEND=noninteractive

echo "=== [1] Installing packages ==="
apt update -y

# Keep it big but not insane; some may already be installed
apt install -y \
  nginx apache2 apache2-bin \
  vsftpd \
  dovecot-imapd dovecot-pop3d \
  postfix \
  mysql-server postgresql \
  openssh-server \
  samba \
  redis-server memcached \
  xrdp \
  inetutils-inetd tftpd-hpa ftp || \
  echo "[WARN] Some packages failed to install; continuing."

# --------------------------------------------------------------------------
#  Weak TLS cert (short-lived, weak key, SHA1)
# --------------------------------------------------------------------------
echo
echo "=== [2] Generating weak, self-signed TLS cert ==="
BADCERT_DIR="/root/badcert"
mkdir -p "$BADCERT_DIR"

openssl req -x509 -newkey rsa:1024 \
  -keyout "$BADCERT_DIR/weak.key" \
  -out "$BADCERT_DIR/weak.crt" \
  -sha1 -days 90 \
  -nodes \
  -subj "/CN=hellbox.local" || \
  echo "[WARN] OpenSSL cert generation failed."

chmod 600 "$BADCERT_DIR/weak.key"

# --------------------------------------------------------------------------
#  Nginx: standard ports (80, 443) with weak TLS and autoindex
# --------------------------------------------------------------------------
echo
echo "=== [3] Nginx on standard ports (80, 443) with weak TLS and autoindex ==="

cat >/etc/nginx/sites-available/default <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    root /var/www/html;
    index index.html index.htm;

    # Directory listing (information disclosure)
    location / {
        autoindex on;
    }
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    ssl_certificate     /root/badcert/weak.crt;
    ssl_certificate_key /root/badcert/weak.key;

    # Allow old protocols (TLSv1, TLSv1.1 are weak)
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

    # Weak ciphers (OpenSSL 3.x compatible)
    ssl_ciphers DEFAULT:@SECLEVEL=0;
    ssl_prefer_server_ciphers on;

    root /var/www/html;
    index index.html index.htm;

    # Directory listing (information disclosure)
    location / {
        autoindex on;
    }
}
EOF

systemctl enable nginx >/dev/null 2>&1 || true

# --------------------------------------------------------------------------
#  Apache: non-standard ports (8888 HTTP, 8443 HTTPS) with weak TLS
# --------------------------------------------------------------------------
echo
echo "=== [4] Apache on non-standard ports (8888, 8443) with weak TLS ==="

# Configure Apache to listen on non-standard ports only
cat >/etc/apache2/ports.conf <<'EOF'
Listen 8888
Listen 8443
EOF

# Enable required modules
a2enmod ssl >/dev/null 2>&1 || true
a2enmod headers >/dev/null 2>&1 || true
a2enmod cgi >/dev/null 2>&1 || true

# Disable ALL default sites to avoid conflicts
a2dissite 000-default.conf >/dev/null 2>&1 || true
a2dissite default-ssl.conf >/dev/null 2>&1 || true
a2dissite 000-default-ssl.conf >/dev/null 2>&1 || true

# Remove old conflicting config files if they exist
rm -f /etc/apache2/sites-available/000-default-ssl.conf 2>/dev/null || true

# Fix global ssl.conf to allow weak ciphers (OpenSSL 3.x compatible)
if [ -f /etc/apache2/mods-available/ssl.conf ]; then
    sed -i 's/SSLCipherSuite HIGH:!aNULL/SSLCipherSuite DEFAULT:@SECLEVEL=0/' /etc/apache2/mods-available/ssl.conf || true
fi

# Create HTTP vhost on port 8888
cat >/etc/apache2/sites-available/hellbox-http.conf <<'EOF'
<VirtualHost *:8888>
    ServerName hellbox.local

    DocumentRoot /var/www/html
    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # CGI support for XSS testing
    ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
    <Directory "/usr/lib/cgi-bin">
        AllowOverride None
        Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
        Require all granted
    </Directory>

    # Enable TRACE method (vulnerability)
    TraceEnable On

    # Disable security headers (vulnerabilities for scanners to find)
    Header always unset X-Frame-Options
    Header always unset X-Content-Type-Options
    Header always unset X-XSS-Protection
</VirtualHost>
EOF

# Create HTTPS vhost on port 8443 with weak TLS
cat >/etc/apache2/sites-available/hellbox-ssl.conf <<'EOF'
<VirtualHost *:8443>
    ServerName hellbox.local

    SSLEngine on
    SSLCertificateFile /root/badcert/weak.crt
    SSLCertificateKeyFile /root/badcert/weak.key

    # Allow older TLS versions (weak)
    SSLProtocol all -TLSv1.3

    # Weak ciphers (OpenSSL 3.x compatible)
    SSLCipherSuite DEFAULT:@SECLEVEL=0
    SSLHonorCipherOrder on

    DocumentRoot /var/www/html
    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # CGI support for XSS testing
    ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
    <Directory "/usr/lib/cgi-bin">
        AllowOverride None
        Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
        Require all granted
    </Directory>

    # Enable TRACE method (vulnerability)
    TraceEnable On

    # Disable security headers (vulnerabilities for scanners to find)
    Header always unset X-Frame-Options
    Header always unset X-Content-Type-Options
    Header always unset X-XSS-Protection
</VirtualHost>
EOF

# Enable the new sites
a2ensite hellbox-http.conf >/dev/null 2>&1 || true
a2ensite hellbox-ssl.conf >/dev/null 2>&1 || true

systemctl enable apache2 >/dev/null 2>&1 || true

# --------------------------------------------------------------------------
#  HTTP-layer demo vulnerabilities for Nikto / ZAP
# --------------------------------------------------------------------------
echo
echo "=== [5] HTTP-layer demo vulnerabilities for scanners ==="

# Make sure web root exists
mkdir -p /var/www/html

# robots.txt leaking "hidden" paths
cat >/var/www/html/robots.txt <<'EOF'
User-agent: *
Disallow: /secret/
Disallow: /admin/
Disallow: /backup/
Disallow: /cgi-bin/
EOF

# Exposed backup/config-ish files
mkdir -p /var/www/html/secret
cat >/var/www/html/secret/config.php.bak <<'EOF'
<?php
// Fake old config file - DO NOT USE IN REAL LIFE
$db_host = "localhost";
$db_user = "root";
$db_pass = "root123";
$debug   = true;
$api_key = "sk-1234567890abcdef";
?>
EOF

cat >/var/www/html/backup.tar.gz <<'EOF'
This is not a real tarball, just a marker for scanners.
EOF

cat >/var/www/html/.htpasswd <<'EOF'
admin:$apr1$fake$hashedpasswordhere
EOF

cat >/var/www/html/readme.old <<'EOF'
Old deployment notes - should not be exposed.
Default credentials: admin / admin123
EOF

cat >/var/www/html/database.sql <<'EOF'
-- Fake database dump
CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(50));
INSERT INTO users VALUES (1, 'admin', 'admin123');
INSERT INTO users VALUES (2, 'test', 'test123');
EOF

mkdir -p /var/www/html/admin
cat >/var/www/html/admin/todo.txt <<'EOF'
- Remove default admin creds (admin / admin123)
- Move config.php.bak out of webroot
- Disable directory listing
- Enable security headers
EOF

cat >/var/www/html/admin/login.html <<'EOF'
<html>
<head><title>Admin Login</title></head>
<body>
<h1>Admin Panel</h1>
<form method="POST" action="/admin/login">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Login</button>
</form>
<!-- Default: admin / admin123 -->
</body>
</html>
EOF

mkdir -p /var/www/html/backup
cat >/var/www/html/backup/site-backup.zip <<'EOF'
Fake backup file marker
EOF

# Info-leaky index page with "credentials" in comments
cat >/var/www/html/index.html <<'EOF'
<!DOCTYPE html>
<html>
  <head>
    <title>Hellbox - Insecure Test Server</title>
    <meta name="generator" content="Hellbox CMS v0.1-dev">
  </head>
  <body>
    <h1>Welcome to Hellbox</h1>
    <!-- DEBUG: Application: Hellbox Admin Panel v0.1-dev -->
    <!-- TODO: Remove hardcoded credentials before going live -->
    <!-- user: admin / pass: admin123 -->
    <!-- API Key: sk-1234567890abcdef -->
    <p>This is a deliberately insecure demo system for security testing.</p>
    <p>Server: Apache/Nginx on Ubuntu</p>
    <a href="/admin/">Admin Panel</a> | 
    <a href="/secret/">Secret Files</a> |
    <a href="/cgi-bin/echo.sh?test=hello">CGI Test</a>
  </body>
</html>
EOF

# CGI script with reflected XSS vulnerability
mkdir -p /usr/lib/cgi-bin
cat >/usr/lib/cgi-bin/echo.sh <<'EOF'
#!/bin/bash
echo "Content-Type: text/html"
echo ""
echo "<html><head><title>Echo CGI</title></head><body>"
echo "<h1>Echo Service</h1>"
echo "<p>You sent: ${QUERY_STRING}</p>"
echo "<form method='GET'>"
echo "<input type='text' name='input' placeholder='Enter text'>"
echo "<button type='submit'>Echo</button>"
echo "</form>"
echo "</body></html>"
EOF
chmod +x /usr/lib/cgi-bin/echo.sh

# Another CGI with command injection potential (for scanner detection)
cat >/usr/lib/cgi-bin/ping.sh <<'EOF'
#!/bin/bash
echo "Content-Type: text/html"
echo ""
echo "<html><body>"
echo "<h1>Ping Test</h1>"
# Intentionally vulnerable - DO NOT USE IN PRODUCTION
if [ -n "$QUERY_STRING" ]; then
    HOST=$(echo "$QUERY_STRING" | sed 's/host=//')
    echo "<pre>"
    echo "Pinging: $HOST"
    echo "</pre>"
fi
echo "</body></html>"
EOF
chmod +x /usr/lib/cgi-bin/ping.sh

# --------------------------------------------------------------------------
#  Postfix: weak-ish TLS; still avoid full open relay
# --------------------------------------------------------------------------
echo
echo "=== [6] Postfix with weak TLS (no relay lock-down hardening) ==="

postconf -e "smtpd_tls_cert_file=/root/badcert/weak.crt"
postconf -e "smtpd_tls_key_file=/root/badcert/weak.key"
postconf -e "smtpd_tls_security_level=may"
postconf -e "smtpd_tls_mandatory_protocols=!TLSv1.3"
postconf -e "smtp_tls_mandatory_protocols=!TLSv1.3"
postconf -e "smtpd_tls_mandatory_ciphers=export"
postconf -e "smtp_use_tls=yes"
# Allow plain auth on non-TLS (bad)
postconf -e "smtpd_tls_auth_only=no"

systemctl enable postfix >/dev/null 2>&1 || true
systemctl restart postfix || echo "[WARN] Postfix restart failed."

# --------------------------------------------------------------------------
#  Dovecot: allow plaintext auth + weak TLS
# --------------------------------------------------------------------------
echo
echo "=== [7] Dovecot (IMAP/POP3) with plaintext auth and weak TLS ==="

DOVECOT_SSL_CONF="/etc/dovecot/conf.d/10-ssl.conf"
if [ -f "$DOVECOT_SSL_CONF" ]; then
  cp "$DOVECOT_SSL_CONF" "${DOVECOT_SSL_CONF}.bak.$(date +%s)" || true
fi

cat >"$DOVECOT_SSL_CONF" <<'EOF'
ssl = yes
ssl_cert = </root/badcert/weak.crt
ssl_key  = </root/badcert/weak.key

# Allow old protocols; disable TLS1.3
ssl_protocols = !TLSv1.3

# Weak ciphers (OpenSSL 3.x compatible)
ssl_cipher_list = DEFAULT:@SECLEVEL=0
EOF

# Allow plaintext auth (very bad)
AUTH_CONF="/etc/dovecot/conf.d/10-auth.conf"
if [ -f "$AUTH_CONF" ]; then
  sed -i 's/^#\?disable_plaintext_auth.*/disable_plaintext_auth = no/' "$AUTH_CONF" || true
fi

systemctl enable dovecot >/dev/null 2>&1 || true
systemctl restart dovecot || echo "[WARN] Dovecot restart failed."

# --------------------------------------------------------------------------
#  vsftpd: anonymous writeable FTP
# --------------------------------------------------------------------------
echo
echo "=== [8] vsftpd: anonymous writable FTP ==="

FTP_ROOT="/srv/ftp"
mkdir -p "$FTP_ROOT"
chmod 777 "$FTP_ROOT"

# Add some files for scanners to find
echo "FTP server readme - anonymous access enabled" > "$FTP_ROOT/readme.txt"
echo "Backup data - should not be public" > "$FTP_ROOT/backup.dat"

cat >/etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_other_write_enable=YES
anon_root=/srv/ftp
no_anon_password=YES
xferlog_std_format=YES
pasv_min_port=30000
pasv_max_port=30010
# Banner with version info (information disclosure)
ftpd_banner=Welcome to Hellbox FTP - vsftpd 3.0.3
EOF

systemctl enable vsftpd >/dev/null 2>&1 || true
systemctl restart vsftpd || echo "[WARN] vsftpd restart failed."

# --------------------------------------------------------------------------
#  SSH: allow root login + password auth
# --------------------------------------------------------------------------
echo
echo "=== [9] SSH: root login + password auth enabled ==="

SSHD_CFG="/etc/ssh/sshd_config"
cp "$SSHD_CFG" "${SSHD_CFG}.bak.$(date +%s)" || true

sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CFG" || true
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' "$SSHD_CFG" || true

systemctl enable ssh >/dev/null 2>&1 || true
systemctl restart ssh || echo "[WARN] SSH restart failed."

# --------------------------------------------------------------------------
#  MySQL: listen on 0.0.0.0; weak test user
# --------------------------------------------------------------------------
echo
echo "=== [10] MySQL: open bind + weak user ==="

MYCNF="/etc/mysql/mysql.conf.d/mysqld.cnf"
if [ -f "$MYCNF" ]; then
  sed -i 's/^\s*bind-address.*/bind-address = 0.0.0.0/' "$MYCNF" || \
    echo "[WARN] Could not update MySQL bind-address."
fi

systemctl enable mysql >/dev/null 2>&1 || true
systemctl restart mysql || echo "[WARN] MySQL restart failed."

mysql -u root <<'EOF' || echo "[WARN] MySQL user creation failed."
CREATE USER IF NOT EXISTS 'test'@'%' IDENTIFIED BY 'test123';
GRANT ALL PRIVILEGES ON *.* TO 'test'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF

# --------------------------------------------------------------------------
#  PostgreSQL: listen on 0.0.0.0; weak test user/db
# --------------------------------------------------------------------------
echo
echo "=== [11] PostgreSQL: open listen + weak user ==="

PG_VER=$(psql -V 2>/dev/null | awk '{print $3}' | cut -d. -f1 || echo "16")
PG_CONF="/etc/postgresql/${PG_VER}/main/postgresql.conf"
PG_HBA="/etc/postgresql/${PG_VER}/main/pg_hba.conf"

if [ -f "$PG_CONF" ]; then
  sed -i "s/^#\?listen_addresses.*/listen_addresses = '*'/" "$PG_CONF" || true
fi

if [ -f "$PG_HBA" ]; then
  cp "$PG_HBA" "${PG_HBA}.bak.$(date +%s)" || true
  # Remove existing entries to avoid duplicates
  grep -v "0.0.0.0/0" "$PG_HBA" > "${PG_HBA}.tmp" && mv "${PG_HBA}.tmp" "$PG_HBA"
  echo "host    all             all             0.0.0.0/0               md5" >> "$PG_HBA"
fi

systemctl enable postgresql >/dev/null 2>&1 || true
systemctl restart postgresql || echo "[WARN] PostgreSQL restart failed."

sudo -u postgres psql <<'EOF' || echo "[WARN] PostgreSQL user/db creation failed."
DO $$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'testuser') THEN
      CREATE ROLE testuser LOGIN PASSWORD 'test123';
   END IF;
END$$;
CREATE DATABASE IF NOT EXISTS testdb OWNER testuser;
EOF

# --------------------------------------------------------------------------
#  Redis: bind 0.0.0.0, protected-mode no
# --------------------------------------------------------------------------
echo
echo "=== [12] Redis: open to the world, no protected-mode ==="

REDIS_CONF="/etc/redis/redis.conf"
if [ -f "$REDIS_CONF" ]; then
  cp "$REDIS_CONF" "${REDIS_CONF}.bak.$(date +%s)" || true
  sed -i 's/^bind .*/bind 0.0.0.0/' "$REDIS_CONF" || true
  sed -i 's/^protected-mode .*/protected-mode no/' "$REDIS_CONF" || true
fi

systemctl enable redis-server >/dev/null 2>&1 || true
systemctl restart redis-server || echo "[WARN] Redis restart failed."

# --------------------------------------------------------------------------
#  Memcached: listen on 0.0.0.0
# --------------------------------------------------------------------------
echo
echo "=== [13] Memcached: open to the world ==="

MEMCACHED_CONF="/etc/memcached.conf"
if [ -f "$MEMCACHED_CONF" ]; then
  cp "$MEMCACHED_CONF" "${MEMCACHED_CONF}.bak.$(date +%s)" || true
  sed -i 's/^-l .*/-l 0.0.0.0/' "$MEMCACHED_CONF" || true
fi

systemctl enable memcached >/dev/null 2>&1 || true
systemctl restart memcached || echo "[WARN] Memcached restart failed."

# --------------------------------------------------------------------------
#  Samba: guest writable share
# --------------------------------------------------------------------------
echo
echo "=== [14] Samba: guest writable share ==="

SMB_CONF="/etc/samba/smb.conf"
if [ -f "$SMB_CONF" ]; then
  cp "$SMB_CONF" "${SMB_CONF}.bak.$(date +%s)" || true
fi

SHARE_DIR="/srv/samba/public"
mkdir -p "$SHARE_DIR"
chmod 777 "$SHARE_DIR"

# Add some files for scanners to find
echo "Public share - guest writable" > "$SHARE_DIR/readme.txt"
echo "Sensitive data - should not be public" > "$SHARE_DIR/secrets.txt"

cat >"$SMB_CONF" <<'EOF'
[global]
   workgroup = WORKGROUP
   server string = Hellbox Samba Server %v
   map to guest = Bad User
   dns proxy = no
   # Show version in banner (information disclosure)
   server min protocol = NT1

[public]
   path = /srv/samba/public
   browseable = yes
   writable = yes
   guest ok = yes
   read only = no
EOF

systemctl enable smbd nmbd >/dev/null 2>&1 || true
systemctl restart smbd nmbd || echo "[WARN] Samba restart failed."

# --------------------------------------------------------------------------
#  XRDP: default is enough (just ensure running)
# --------------------------------------------------------------------------
echo
echo "=== [15] XRDP: ensure running ==="

systemctl enable xrdp >/dev/null 2>&1 || true
systemctl restart xrdp || echo "[WARN] XRDP restart failed."

# --------------------------------------------------------------------------
#  TFTP: open, world-writable
# --------------------------------------------------------------------------
echo
echo "=== [16] TFTP: open, world-writable ==="

TFTP_ROOT="/srv/tftp"
mkdir -p "$TFTP_ROOT"
chmod 777 "$TFTP_ROOT"

# Add files for scanners
echo "TFTP root - world writable" > "$TFTP_ROOT/readme.txt"

cat >/etc/default/tftpd-hpa <<EOF
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="$TFTP_ROOT"
TFTP_ADDRESS="0.0.0.0:69"
TFTP_OPTIONS="--secure --create"
EOF

systemctl enable inetutils-inetd tftpd-hpa >/dev/null 2>&1 || true
systemctl restart inetutils-inetd tftpd-hpa || echo "[WARN] TFTP/inetd restart failed."

# --------------------------------------------------------------------------
#  Start web servers (Nginx first on 80/443, then Apache on 8888/8443)
# --------------------------------------------------------------------------
echo
echo "=== [17] Starting web servers ==="

# Stop both first to avoid conflicts
systemctl stop apache2 nginx >/dev/null 2>&1 || true

# Start Nginx (standard ports 80, 443)
echo "Starting Nginx on ports 80, 443..."
systemctl start nginx
if systemctl is-active --quiet nginx; then
    echo "[OK] Nginx started successfully"
else
    echo "[FAIL] Nginx failed to start"
    journalctl -xeu nginx.service --no-pager | tail -10
fi

# Start Apache (non-standard ports 8888, 8443)
echo "Starting Apache on ports 8888, 8443..."
systemctl start apache2
if systemctl is-active --quiet apache2; then
    echo "[OK] Apache started successfully"
else
    echo "[FAIL] Apache failed to start"
    journalctl -xeu apache2.service --no-pager | tail -10
fi

# Verify web server ports
echo
echo "Checking web server ports..."
netstat -tlnp 2>/dev/null | grep -E ':80|:443|:8888|:8443' || \
  ss -tlnp | grep -E ':80|:443|:8888|:8443' || \
  echo "[WARN] Could not verify web server ports."

# --------------------------------------------------------------------------
#  Summary
# --------------------------------------------------------------------------
echo
echo "=== [18] Summary for scanners ==="
PUBIP=$(curl -s ifconfig.me || echo "<public-ip>")

cat <<EOF

================================================================================
                        HELLBOX SETUP COMPLETE
================================================================================

Public IP: $PUBIP

--------------------------------------------------------------------------------
HTTP/HTTPS Services
--------------------------------------------------------------------------------
  Nginx (Standard Ports):
    - http://$PUBIP:80       → Directory listing, autoindex
    - https://$PUBIP:443     → Weak TLS (TLSv1, TLSv1.1, weak ciphers)

  Apache (Non-Standard Ports):
    - http://$PUBIP:8888     → Dir listing, CGI/XSS, TRACE enabled, backup files
    - https://$PUBIP:8443    → Weak TLS + same vulns as 8888

  Web Vulnerabilities:
    - /robots.txt            → Leaks hidden paths
    - /secret/config.php.bak → Exposed credentials
    - /admin/                → Admin panel with default creds in comments
    - /backup/               → Exposed backup files
    - /cgi-bin/echo.sh       → Reflected XSS
    - /cgi-bin/ping.sh       → Command injection pattern
    - /.htpasswd             → Exposed password file
    - /database.sql          → Exposed database dump
    - Missing security headers (X-Frame-Options, etc.)
    - TRACE method enabled

--------------------------------------------------------------------------------
Mail Services
--------------------------------------------------------------------------------
  - Postfix SMTP:  $PUBIP:25     (weak TLS, plain auth allowed)
  - Dovecot IMAP:  $PUBIP:143    (plaintext auth)
  - Dovecot IMAPS: $PUBIP:993    (weak TLS)
  - Dovecot POP3:  $PUBIP:110    (plaintext auth)
  - Dovecot POP3S: $PUBIP:995    (weak TLS)

--------------------------------------------------------------------------------
Database Services
--------------------------------------------------------------------------------
  - MySQL:      $PUBIP:3306   (user: test / pass: test123)
  - PostgreSQL: $PUBIP:5432   (user: testuser / pass: test123, db: testdb)

--------------------------------------------------------------------------------
Authentication Services
--------------------------------------------------------------------------------
  - SSH:  $PUBIP:22    (root login enabled, password auth enabled)
  - XRDP: $PUBIP:3389  (default config)

--------------------------------------------------------------------------------
File Services
--------------------------------------------------------------------------------
  - FTP (vsftpd):  $PUBIP:21    (anonymous writable)
  - Samba:         $PUBIP:445   (guest writable share: public)
  - TFTP:          $PUBIP:69    (world writable)

--------------------------------------------------------------------------------
Cache Services
--------------------------------------------------------------------------------
  - Redis:     $PUBIP:6379   (no auth, protected-mode disabled)
  - Memcached: $PUBIP:11211  (no auth, open to world)

--------------------------------------------------------------------------------
TLS Certificate
--------------------------------------------------------------------------------
  Location: /root/badcert/weak.crt
  Issues:   RSA 1024-bit key, SHA1 signature, 90-day validity

================================================================================
  This server is INTENTIONALLY INSECURE for security testing purposes.
  Perfect for: PEEK, Nmap, NSE, Nuclei, Nikto, ZAP, sslscan, ssh-audit
================================================================================
EOF

echo "=== Hellbox setup complete ==="