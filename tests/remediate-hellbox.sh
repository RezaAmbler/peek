#!/bin/bash
# Remediate the insecure hellbox by hardening services and cleaning test leaks
# without disabling the services. Intended to be run after the insecure setup.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

log() { echo "=== $1 ==="; }

reload_if_active() {
  local svc=$1
  if systemctl is-active --quiet "$svc"; then
    systemctl reload "$svc" >/dev/null 2>&1 || systemctl restart "$svc" >/dev/null 2>&1 || true
  fi
}

log "Refreshing package index quietly"
apt update -y >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Stronger TLS material for web/mail
# ---------------------------------------------------------------------------
log "Generating stronger TLS certificate"
CERT_DIR="/etc/ssl/hellbox-secure"
mkdir -p "$CERT_DIR"
openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
  -keyout "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.crt" \
  -subj "/CN=secure-hellbox.local" >/dev/null 2>&1 || true
chmod 600 "$CERT_DIR/server.key"

# ---------------------------------------------------------------------------
# Nginx hardening: drop autoindex, tighten TLS, add headers
# ---------------------------------------------------------------------------
if command -v nginx >/dev/null; then
  log "Hardening Nginx"
  cat >/etc/nginx/sites-available/default <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    root /var/www/html;
    index index.html;
    autoindex off;

    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;

    ssl_certificate     /etc/ssl/hellbox-secure/server.crt;
    ssl_certificate_key /etc/ssl/hellbox-secure/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    root /var/www/html;
    index index.html;
    autoindex off;
}
EOF
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Apache hardening: standard ports, disable TRACE/CGI, add headers, strong TLS
# ---------------------------------------------------------------------------
if command -v apache2 >/dev/null; then
  log "Hardening Apache"
  # Listen on standard ports
  cat >/etc/apache2/ports.conf <<'EOF'
Listen 80
<IfModule ssl_module>
    Listen 443
</IfModule>
EOF

  # Main HTTP vhost
  cat >/etc/apache2/sites-available/000-default.conf <<'EOF'
<VirtualHost *:80>
    ServerName secure-hellbox.local
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
    TraceEnable off
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
</VirtualHost>
EOF

  # HTTPS vhost
  cat >/etc/apache2/sites-available/default-ssl.conf <<'EOF'
<IfModule mod_ssl.c>
<VirtualHost _default_:443>
    ServerName secure-hellbox.local
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    SSLEngine on
    SSLCertificateFile    /etc/ssl/hellbox-secure/server.crt
    SSLCertificateKeyFile /etc/ssl/hellbox-secure/server.key
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5
    SSLHonorCipherOrder on
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    TraceEnable off
</VirtualHost>
</IfModule>
EOF

  a2dissite hellbox-http.conf hellbox-ssl.conf >/dev/null 2>&1 || true
  a2dismod cgi >/dev/null 2>&1 || true
  a2enmod ssl headers >/dev/null 2>&1 || true
  a2ensite 000-default.conf default-ssl.conf >/dev/null 2>&1 || true
  systemctl enable apache2 >/dev/null 2>&1 || true
  systemctl restart apache2 >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# SSH: disable password/root login
# ---------------------------------------------------------------------------
if [ -f /etc/ssh/sshd_config ]; then
  log "Hardening SSH"
  SSHD_CFG="/etc/ssh/sshd_config"
  cp "$SSHD_CFG" "${SSHD_CFG}.secure.bak.$(date +%s)" 2>/dev/null || true
  sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CFG" || true
  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' "$SSHD_CFG" || true
  systemctl restart ssh >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Databases: bind locally and remove weak users
# ---------------------------------------------------------------------------
if command -v mysql >/dev/null; then
  log "Hardening MySQL"
  MYCNF="/etc/mysql/mysql.conf.d/mysqld.cnf"
  if [ -f "$MYCNF" ]; then
    sed -i 's/^\s*bind-address.*/bind-address = 127.0.0.1/' "$MYCNF" || true
  fi
  systemctl enable mysql >/dev/null 2>&1 || true
  systemctl restart mysql >/dev/null 2>&1 || true
  mysql -u root <<'EOF' || true
DROP USER IF EXISTS 'test'@'%';
FLUSH PRIVILEGES;
EOF
fi

if command -v psql >/dev/null 2>&1; then
  log "Hardening PostgreSQL"
  PG_VER=$(psql -V 2>/dev/null | awk '{print $3}' | cut -d. -f1 || echo "16")
  PG_CONF="/etc/postgresql/${PG_VER}/main/postgresql.conf"
  PG_HBA="/etc/postgresql/${PG_VER}/main/pg_hba.conf"
  if [ -f "$PG_CONF" ]; then
    sed -i "s/^#\?listen_addresses.*/listen_addresses = 'localhost'/" "$PG_CONF" || true
  fi
  if [ -f "$PG_HBA" ]; then
    cp "$PG_HBA" "${PG_HBA}.secure.bak.$(date +%s)" 2>/dev/null || true
    grep -v "0.0.0.0/0" "$PG_HBA" | grep -v "all[[:space:]]*all[[:space:]]*md5" > "${PG_HBA}.tmp" || true
    mv "${PG_HBA}.tmp" "$PG_HBA" 2>/dev/null || true
    echo "host    all             all             127.0.0.1/32            md5" >> "$PG_HBA"
  fi
  systemctl enable postgresql >/dev/null 2>&1 || true
  systemctl restart postgresql >/dev/null 2>&1 || true
  sudo -u postgres psql <<'EOF' || true
DO $$
BEGIN
   IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'testuser') THEN
      REVOKE ALL PRIVILEGES ON DATABASE testdb FROM testuser;
      DROP OWNED BY testuser;
      DROP ROLE testuser;
   END IF;
END$$;
DROP DATABASE IF EXISTS testdb;
EOF
fi

# ---------------------------------------------------------------------------
# Caches: bind locally and enforce protections
# ---------------------------------------------------------------------------
if [ -f /etc/redis/redis.conf ]; then
  log "Hardening Redis"
  sed -i 's/^bind .*/bind 127.0.0.1/' /etc/redis/redis.conf || true
  sed -i 's/^protected-mode .*/protected-mode yes/' /etc/redis/redis.conf || true
  # Optional: set a requirepass; comment out if not desired
  if ! grep -q '^requirepass ' /etc/redis/redis.conf; then
    echo "requirepass changeMeStrong" >> /etc/redis/redis.conf
  else
    sed -i 's/^requirepass .*/requirepass changeMeStrong/' /etc/redis/redis.conf || true
  fi
  systemctl enable redis-server >/dev/null 2>&1 || true
  systemctl restart redis-server >/dev/null 2>&1 || true
fi

if [ -f /etc/memcached.conf ]; then
  log "Hardening Memcached"
  sed -i 's/^-l .*/-l 127.0.0.1/' /etc/memcached.conf || true
  systemctl enable memcached >/dev/null 2>&1 || true
  systemctl restart memcached >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Mail: enforce stronger TLS and disable cleartext auth on Postfix/Dovecot
# ---------------------------------------------------------------------------
if command -v postconf >/dev/null 2>&1; then
  log "Hardening Postfix"
  postconf -e "smtpd_tls_cert_file=/etc/ssl/hellbox-secure/server.crt"
  postconf -e "smtpd_tls_key_file=/etc/ssl/hellbox-secure/server.key"
  postconf -e "smtpd_tls_security_level=may"
  postconf -e "smtpd_tls_mandatory_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
  postconf -e "smtp_tls_mandatory_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
  postconf -e "smtpd_tls_mandatory_ciphers=high"
  postconf -e "smtp_use_tls=yes"
  postconf -e "smtpd_tls_auth_only=yes"
  reload_if_active postfix
fi

DOVECOT_SSL_CONF="/etc/dovecot/conf.d/10-ssl.conf"
if [ -f "$DOVECOT_SSL_CONF" ]; then
  log "Hardening Dovecot"
  cp "$DOVECOT_SSL_CONF" "${DOVECOT_SSL_CONF}.secure.bak.$(date +%s)" 2>/dev/null || true
  cat >"$DOVECOT_SSL_CONF" <<'EOF'
ssl = required
ssl_cert = </etc/ssl/hellbox-secure/server.crt
ssl_key  = </etc/ssl/hellbox-secure/server.key
ssl_protocols = !SSLv3 !TLSv1 !TLSv1.1
ssl_cipher_list = HIGH:!aNULL:!MD5
EOF
  AUTH_CONF="/etc/dovecot/conf.d/10-auth.conf"
  if [ -f "$AUTH_CONF" ]; then
    sed -i 's/^#\?disable_plaintext_auth.*/disable_plaintext_auth = yes/' "$AUTH_CONF" || true
  fi
  reload_if_active dovecot
fi

# ---------------------------------------------------------------------------
# Samba: remove guest writable share
# ---------------------------------------------------------------------------
if [ -f /etc/samba/smb.conf ]; then
  log "Cleaning Samba guest share"
  cp /etc/samba/smb.conf "/etc/samba/smb.conf.secure.bak.$(date +%s)" 2>/dev/null || true
  cat >/etc/samba/smb.conf <<'EOF'
[global]
   workgroup = WORKGROUP
   server string = Samba Server
   map to guest = Never
   disable netbios = yes
   smb ports = 445
EOF
  reload_if_active smbd
fi

# ---------------------------------------------------------------------------
# vsftpd: remove anonymous and write access, enforce chroot
# ---------------------------------------------------------------------------
if [ -f /etc/vsftpd.conf ]; then
  log "Hardening vsftpd"
  cat >/etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=NO
chroot_local_user=YES
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
pasv_min_port=30000
pasv_max_port=30010
EOF
  reload_if_active vsftpd
fi

# ---------------------------------------------------------------------------
# TFTP: set secure directory, disable creation
# ---------------------------------------------------------------------------
if [ -f /etc/default/tftpd-hpa ]; then
  log "Hardening TFTP"
  cat >/etc/default/tftpd-hpa <<'EOF'
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="/srv/tftp"
TFTP_ADDRESS="0.0.0.0:69"
TFTP_OPTIONS="--secure"
EOF
  reload_if_active tftpd-hpa
fi

# ---------------------------------------------------------------------------
# XRDP: keep default; ensure service reloads if active
# ---------------------------------------------------------------------------
reload_if_active xrdp

# ---------------------------------------------------------------------------
# Web root cleanup: remove intentionally leaked files/CGIs
# ---------------------------------------------------------------------------
log "Cleaning exposed web content"
rm -rf /var/www/html/secret /var/www/html/admin /var/www/html/backup /var/www/html/cgi-bin 2>/dev/null || true
rm -f /var/www/html/robots.txt /var/www/html/.htpasswd /var/www/html/database.sql \
      /var/www/html/backup.tar.gz /var/www/html/readme.old 2>/dev/null || true
rm -f /usr/lib/cgi-bin/echo.sh /usr/lib/cgi-bin/ping.sh 2>/dev/null || true
cat >/var/www/html/index.html <<'EOF'
<!DOCTYPE html>
<html>
  <head>
    <title>Hardened Hellbox</title>
    <meta charset="utf-8">
  </head>
  <body>
    <h1>Services hardened</h1>
    <p>Default credentials and intentionally exposed files were removed.</p>
  </body>
</html>
EOF

# ---------------------------------------------------------------------------
# Remove writable test roots
# ---------------------------------------------------------------------------
rm -rf /srv/ftp /srv/samba/public 2>/dev/null || true

log "Remediation complete"
