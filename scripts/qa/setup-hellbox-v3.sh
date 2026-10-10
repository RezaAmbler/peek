#!/bin/bash
# ============================================================================
#  HELLBOX v3 - Deliberately Insecure Lab Server for PEEK Testing
#
#  A comprehensive vulnerable environment for security scanner validation.
#  Includes KNOWN VULNERABLE VERSIONS with real CVEs for detection testing.
#
#  Target scanners: Nuclei, Nmap NSE, Nikto, ZAP, sslscan, ssh-audit,
#                   testssl.sh, httpx, Metasploit
#
#  ONLY USE ON THROWAWAY LAB INSTANCES - THIS SERVER WILL BE COMPROMISED
#
#  Version: 3.0
#  Updated: 2026-01
#  Recommended: t3.large or t3.xlarge (8GB+ RAM)
#
#  Changes from v2:
#    - Fixed inetutils-inetd/xinetd conflict (was breaking all apt installs)
#    - Split apt install into groups to isolate failures
#    - Added python3-pip to package list
#    - Use vulhub Docker images for more reliable CVE testing
#    - Better fallback handling for each vulnerable service
# ============================================================================

set -u -o pipefail
export DEBIAN_FRONTEND=noninteractive

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${GREEN}=== [$1] $2 ===${NC}"; }

# ============================================================================
#  SECTION 1: Base System Setup
# ============================================================================
log_section "1" "Installing base packages"

apt update -y
# Install packages in groups to isolate failures
# Group 1: Core utilities
apt install -y \
  curl wget git unzip build-essential python3-pip \
  || log_warn "Core utilities install had issues"

# Group 2: Web servers
apt install -y \
  nginx apache2 apache2-bin \
  php php-fpm php-mysql php-cli php-curl php-gd php-mbstring php-xml php-zip \
  || log_warn "Web server install had issues"

# Group 3: Mail services
apt install -y \
  dovecot-imapd dovecot-pop3d postfix \
  || log_warn "Mail services install had issues"

# Group 4: Databases
apt install -y \
  mysql-server postgresql \
  || log_warn "Database install had issues"

# Group 5: Network services
apt install -y \
  openssh-server \
  redis-server memcached \
  snmpd snmp \
  nfs-kernel-server \
  || log_warn "Network services install had issues"

# Group 6: Remote access (xinetd for telnet - DO NOT install inetutils-inetd, it conflicts!)
apt install -y \
  xrdp x11vnc \
  telnetd xinetd \
  tftpd-hpa ftp \
  || log_warn "Remote access install had issues"

# Group 7: Directory services (may require interaction, install separately)
DEBIAN_FRONTEND=noninteractive apt install -y \
  slapd ldap-utils \
  || log_warn "LDAP install had issues"

# Group 8: Misc services
apt install -y \
  finger fingerd \
  openjdk-11-jdk \
  || log_warn "Misc services install had issues"

# Group 9: Docker (critical - install last to ensure it works)
apt install -y \
  docker.io docker-compose \
  || log_warn "Docker install had issues"

log_info "Package installation complete - checking for critical packages..."

# Verify critical packages
for pkg in docker.io nginx openssh-server redis-server; do
  if dpkg -l | grep -q "^ii  $pkg"; then
    log_ok "$pkg installed"
  else
    log_error "$pkg MISSING - this will cause failures!"
  fi
done

# Enable and start Docker
systemctl enable docker
systemctl start docker

# ============================================================================
#  SECTION 2: Weak TLS Certificate
# ============================================================================
log_section "2" "Generating weak, self-signed TLS cert"

BADCERT_DIR="/root/badcert"
mkdir -p "$BADCERT_DIR"

openssl req -x509 -newkey rsa:1024 \
  -keyout "$BADCERT_DIR/weak.key" \
  -out "$BADCERT_DIR/weak.crt" \
  -sha1 -days 90 \
  -nodes \
  -subj "/CN=hellbox.local" || log_warn "OpenSSL cert generation failed."

chmod 600 "$BADCERT_DIR/weak.key"
log_ok "Weak TLS cert created (RSA 1024-bit, SHA1)"

# ============================================================================
#  SECTION 3: SSH - Weak Configuration (ssh-audit findings)
# ============================================================================
log_section "3" "Configuring SSH with weak algorithms and keys"

SSHD_CFG="/etc/ssh/sshd_config"
cp "$SSHD_CFG" "${SSHD_CFG}.bak.$(date +%s)" || true

# Generate weak host keys
log_info "Generating weak SSH host keys..."
rm -f /etc/ssh/ssh_host_*

# Weak DSA key (deprecated)
ssh-keygen -t dsa -b 1024 -f /etc/ssh/ssh_host_dsa_key -N "" || log_warn "DSA key generation failed"

# Weak RSA key (1024-bit)
ssh-keygen -t rsa -b 1024 -f /etc/ssh/ssh_host_rsa_weak_key -N "" || log_warn "Weak RSA key generation failed"

# Standard keys (but we'll enable weak algorithms)
ssh-keygen -t rsa -b 2048 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ecdsa -b 256 -f /etc/ssh/ssh_host_ecdsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

# Configure weak SSH settings
cat >"$SSHD_CFG" <<'EOF'
# Hellbox v2 - Intentionally Weak SSH Configuration
# For ssh-audit testing

Port 22
AddressFamily any
ListenAddress 0.0.0.0

# Host keys (including weak ones)
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_rsa_weak_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_dsa_key

# Weak Key Exchange Algorithms (ssh-audit will flag these)
KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,curve25519-sha256@libssh.org

# Weak Ciphers (ssh-audit will flag these)
Ciphers 3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com

# Weak MACs (ssh-audit will flag these)
MACs hmac-md5,hmac-md5-96,hmac-sha1,hmac-sha1-96,hmac-sha2-256,hmac-sha2-512,umac-64@openssh.com,umac-128@openssh.com

# Authentication
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Other weak settings
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Banner (information disclosure)
Banner /etc/ssh/banner
EOF

# Create SSH banner with version info
cat >/etc/ssh/banner <<'EOF'

==============================================
  HELLBOX - Insecure Test Server
  SSH Server: OpenSSH
  WARNING: This system is for testing only!
==============================================

EOF

systemctl enable ssh
systemctl restart ssh || log_warn "SSH restart failed"
log_ok "SSH configured with weak algorithms"

# ============================================================================
#  SECTION 4: SNMP - Default Community Strings
# ============================================================================
log_section "4" "Configuring SNMP with default community strings"

cat >/etc/snmp/snmpd.conf <<'EOF'
# Hellbox v2 - Insecure SNMP Configuration

# Listen on all interfaces
agentAddress udp:161,udp6:[::1]:161

# Default community strings (VERY BAD)
rocommunity public
rwcommunity private

# System information (information disclosure)
sysLocation    Hellbox Lab Server
sysContact     admin@hellbox.local
sysName        hellbox

# Full view access
view   all         included   .1
rouser authOnlyUser
rwuser authPrivUser

# Process monitoring
proc  mountd
proc  ntalkd    4
proc  sendmail 10 1

# Disk monitoring
disk  /     10000
disk  /var  5%

# Load monitoring
load  12 10 5
EOF

systemctl enable snmpd
systemctl restart snmpd || log_warn "SNMP restart failed"
log_ok "SNMP configured with public/private community strings"

# ============================================================================
#  SECTION 5: Telnet Service
# ============================================================================
log_section "5" "Enabling Telnet service"

cat >/etc/xinetd.d/telnet <<'EOF'
service telnet
{
    flags           = REUSE
    socket_type     = stream
    wait            = no
    user            = root
    server          = /usr/sbin/in.telnetd
    log_on_failure  += USERID
    disable         = no
}
EOF

systemctl enable xinetd
systemctl restart xinetd || log_warn "xinetd/telnet restart failed"
log_ok "Telnet service enabled on port 23"

# ============================================================================
#  SECTION 6: VNC Without Password
# ============================================================================
log_section "6" "Configuring VNC without password"

mkdir -p /root/.vnc
x11vnc -storepasswd "" /root/.vnc/passwd 2>/dev/null || true

# Create VNC startup script
cat >/usr/local/bin/start-vnc.sh <<'EOF'
#!/bin/bash
# Start VNC without password on display :0
x11vnc -display :0 -forever -shared -rfbport 5900 -noauth -o /var/log/x11vnc.log &
EOF
chmod +x /usr/local/bin/start-vnc.sh

# Create systemd service for VNC
cat >/etc/systemd/system/x11vnc.service <<'EOF'
[Unit]
Description=x11vnc VNC Server (No Auth)
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/bin/x11vnc -forever -shared -rfbport 5900 -noauth -create
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable x11vnc
systemctl start x11vnc || log_warn "VNC service start failed (may need display)"
log_ok "VNC configured without password on port 5900"

# ============================================================================
#  SECTION 7: NFS - World-Exportable Shares
# ============================================================================
log_section "7" "Configuring NFS with world-exportable shares"

NFS_SHARE="/srv/nfs/public"
mkdir -p "$NFS_SHARE"
chmod 777 "$NFS_SHARE"

# Add sensitive files
echo "NFS Share - Should not be world-readable" > "$NFS_SHARE/readme.txt"
echo "SECRET_API_KEY=sk-nfs-exposed-12345" > "$NFS_SHARE/secrets.env"
cat > "$NFS_SHARE/database-backup.sql" <<'EOF'
-- NFS Exposed Database Backup
CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(50));
INSERT INTO users VALUES (1, 'admin', 'admin123');
INSERT INTO users VALUES (2, 'root', 'toor');
EOF

# Export to world
cat >/etc/exports <<'EOF'
# Hellbox v2 - World-exportable NFS shares
/srv/nfs/public *(rw,sync,no_subtree_check,no_root_squash,insecure)
EOF

exportfs -ra
systemctl enable nfs-kernel-server
systemctl restart nfs-kernel-server || log_warn "NFS restart failed"
log_ok "NFS configured with world-exportable share"

# ============================================================================
#  SECTION 8: LDAP - Anonymous Bind
# ============================================================================
log_section "8" "Configuring LDAP with anonymous bind"

# Reconfigure slapd non-interactively
debconf-set-selections <<EOF
slapd slapd/internal/generated_adminpw password admin123
slapd slapd/password2 password admin123
slapd slapd/internal/adminpw password admin123
slapd slapd/password1 password admin123
slapd slapd/domain string hellbox.local
slapd shared/organization string Hellbox
slapd slapd/backend select MDB
slapd slapd/purge_database boolean true
slapd slapd/move_old_database boolean true
slapd slapd/allow_ldap_v2 boolean true
slapd slapd/no_configuration boolean false
EOF

dpkg-reconfigure -f noninteractive slapd || log_warn "LDAP reconfigure failed"

# Enable anonymous bind
cat >/tmp/anon-bind.ldif <<'EOF'
dn: cn=config
changetype: modify
replace: olcAllows
olcAllows: bind_anon_dn

dn: cn=config
changetype: modify
replace: olcRequires
olcRequires: none

dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: to * by * read
EOF

ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/anon-bind.ldif 2>/dev/null || log_warn "LDAP anon bind config failed"

# Add sample users
cat >/tmp/users.ldif <<'EOF'
dn: ou=users,dc=hellbox,dc=local
objectClass: organizationalUnit
ou: users

dn: cn=admin,ou=users,dc=hellbox,dc=local
objectClass: person
objectClass: organizationalPerson
cn: admin
sn: Administrator
userPassword: admin123

dn: cn=testuser,ou=users,dc=hellbox,dc=local
objectClass: person
objectClass: organizationalPerson
cn: testuser
sn: Test User
userPassword: test123
EOF

ldapadd -x -D "cn=admin,dc=hellbox,dc=local" -w admin123 -f /tmp/users.ldif 2>/dev/null || log_warn "LDAP user add failed"

systemctl enable slapd
systemctl restart slapd || log_warn "LDAP restart failed"
log_ok "LDAP configured with anonymous bind"

# ============================================================================
#  SECTION 9: Finger Service
# ============================================================================
log_section "9" "Enabling Finger service"

cat >/etc/xinetd.d/finger <<'EOF'
service finger
{
    socket_type     = stream
    wait            = no
    user            = nobody
    server          = /usr/sbin/in.fingerd
    disable         = no
}
EOF

systemctl restart xinetd || log_warn "Finger service restart failed"
log_ok "Finger service enabled on port 79"

# ============================================================================
#  SECTION 10: Docker API - Exposed Without Auth
# ============================================================================
log_section "10" "Exposing Docker API without authentication"

mkdir -p /etc/systemd/system/docker.service.d
cat >/etc/systemd/system/docker.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375
EOF

systemctl daemon-reload
systemctl restart docker || log_warn "Docker restart failed"
log_ok "Docker API exposed on port 2375 (no auth)"

# ============================================================================
#  SECTION 11: vsftpd 2.3.4 - Backdoor (CVE-2011-2523)
# ============================================================================
log_section "11" "Installing vsftpd 2.3.4 (CVE-2011-2523 - Backdoor)"

# FTP root for both Docker and native
FTP_ROOT="/srv/ftp"
mkdir -p "$FTP_ROOT"
chmod 777 "$FTP_ROOT"
echo "FTP server - anonymous access enabled" > "$FTP_ROOT/readme.txt"
echo "Backup data - should not be public" > "$FTP_ROOT/backup.dat"

# Method 1: Use vulhub's vulnerable vsftpd Docker image (PREFERRED - most reliable)
log_info "Attempting vulhub vsftpd 2.3.4 Docker image..."
docker run -d \
  --name vsftpd-vulnerable \
  --restart unless-stopped \
  -p 21:21 \
  -p 6200:6200 \
  -v "$FTP_ROOT:/var/ftp:ro" \
  vulhub/vsftpd:2.3.4 2>/dev/null

if docker ps | grep -q vsftpd-vulnerable; then
    log_ok "vsftpd 2.3.4 (CVE-2011-2523) running via Docker on port 21"
else
    log_warn "Docker vsftpd failed, attempting native compile..."
    
    # Method 2: Try to compile from source (fallback)
    cd /tmp
    wget -q https://github.com/nikdubois/vsftpd-2.3.4-infected/raw/master/vsftpd-2.3.4.tar.gz -O vsftpd-2.3.4.tar.gz || \
    wget -q https://security.appspot.com/downloads/vsftpd-2.3.4.tar.gz -O vsftpd-2.3.4.tar.gz || \
    log_warn "Could not download vsftpd 2.3.4"

    if [ -f vsftpd-2.3.4.tar.gz ]; then
        tar xzf vsftpd-2.3.4.tar.gz
        cd vsftpd-2.3.4
        
        make clean 2>/dev/null || true
        make -j$(nproc) 2>/dev/null || log_warn "vsftpd compile failed"
        
        if [ -f vsftpd ]; then
            cp vsftpd /usr/local/sbin/vsftpd-vulnerable
            log_ok "vsftpd 2.3.4 (vulnerable) compiled"
            
            cat >/etc/vsftpd-vulnerable.conf <<'VSFTPD_CONF'
listen=YES
listen_port=21
anonymous_enable=YES
local_enable=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_other_write_enable=YES
anon_root=/srv/ftp
no_anon_password=YES
ftpd_banner=Welcome to Hellbox FTP - vsftpd 2.3.4
pasv_min_port=30000
pasv_max_port=30010
VSFTPD_CONF

            cat >/etc/systemd/system/vsftpd-vulnerable.service <<'VSFTPD_SVC'
[Unit]
Description=vsftpd 2.3.4 (Vulnerable - CVE-2011-2523)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/vsftpd-vulnerable /etc/vsftpd-vulnerable.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
VSFTPD_SVC

            systemctl daemon-reload
            systemctl enable vsftpd-vulnerable
            systemctl start vsftpd-vulnerable || log_warn "vsftpd-vulnerable service failed"
        fi
    fi
    
    # Method 3: Fall back to standard vsftpd with anonymous access
    if ! netstat -tlnp 2>/dev/null | grep -q ":21 " && ! ss -tlnp | grep -q ":21 "; then
        log_warn "Using standard vsftpd as last resort (no backdoor CVE)"
        apt install -y vsftpd || true
        cat >/etc/vsftpd.conf <<'VSFTPD_STD'
listen=YES
anonymous_enable=YES
local_enable=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_root=/srv/ftp
no_anon_password=YES
ftpd_banner=Welcome to Hellbox FTP - vsftpd
pasv_min_port=30000
pasv_max_port=30010
VSFTPD_STD
        systemctl enable vsftpd
        systemctl start vsftpd
    fi
fi

log_ok "FTP service configured on port 21"

# ============================================================================
#  SECTION 12: ProFTPD 1.3.5 (CVE-2015-3306 - mod_copy) on port 2121
# ============================================================================
log_section "12" "Running ProFTPD 1.3.5 via Docker (CVE-2015-3306)"

# Try vulhub first (most reliable for CVE testing)
docker run -d \
  --name proftpd-vulnerable \
  --restart unless-stopped \
  -p 2121:21 \
  vulhub/proftpd:1.3.5 2>/dev/null || \
docker run -d \
  --name proftpd-vulnerable \
  --restart unless-stopped \
  -p 2121:21 \
  -p 30020-30030:30020-30030 \
  -e FTP_USER=admin \
  -e FTP_PASSWORD=admin123 \
  -v /srv/ftp:/home/admin \
  instantlinux/proftpd:1.3.5 2>/dev/null || \
  log_warn "ProFTPD container failed to start"

log_ok "ProFTPD 1.3.5 running on port 2121 (CVE-2015-3306)"

# ============================================================================
#  SECTION 13: Apache 2.4.49 (CVE-2021-41773 - Path Traversal RCE)
# ============================================================================
log_section "13" "Running Apache 2.4.49 via Docker (CVE-2021-41773)"

# Create vulnerable Apache content
mkdir -p /opt/apache-vulnerable/htdocs
echo "<html><body><h1>Apache 2.4.49 - Path Traversal Vulnerable</h1></body></html>" > /opt/apache-vulnerable/htdocs/index.html

# Try vulhub first (pre-configured for CVE-2021-41773)
docker run -d \
  --name apache-2.4.49 \
  --restart unless-stopped \
  -p 8080:80 \
  vulhub/httpd:2.4.49 2>/dev/null || \
docker run -d \
  --name apache-2.4.49 \
  --restart unless-stopped \
  -p 8080:80 \
  -v /opt/apache-vulnerable/htdocs:/usr/local/apache2/htdocs \
  httpd:2.4.49 2>/dev/null || log_warn "Apache 2.4.49 container failed"

log_ok "Apache 2.4.49 running on port 8080 (CVE-2021-41773)"

# ============================================================================
#  SECTION 14: Tomcat 7.0.79 (CVE-2017-12615 PUT RCE + Ghostcat)
# ============================================================================
log_section "14" "Running Tomcat 7.0.79 via Docker (CVE-2017-12615, CVE-2020-1938)"

# Create tomcat-users.xml with default creds
mkdir -p /opt/tomcat-vulnerable
cat >/opt/tomcat-vulnerable/tomcat-users.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users>
  <role rolename="manager-gui"/>
  <role rolename="manager-script"/>
  <role rolename="admin-gui"/>
  <role rolename="admin-script"/>
  <user username="tomcat" password="tomcat" roles="manager-gui,manager-script,admin-gui,admin-script"/>
  <user username="admin" password="admin" roles="manager-gui,manager-script,admin-gui,admin-script"/>
  <user username="root" password="root" roles="manager-gui,manager-script,admin-gui,admin-script"/>
</tomcat-users>
EOF

docker run -d \
  --name tomcat-vulnerable \
  --restart unless-stopped \
  -p 8009:8009 \
  -p 8180:8080 \
  -v /opt/tomcat-vulnerable/tomcat-users.xml:/usr/local/tomcat/conf/tomcat-users.xml \
  tomcat:7.0.79-jre8 2>/dev/null || \
docker run -d \
  --name tomcat-vulnerable \
  --restart unless-stopped \
  -p 8009:8009 \
  -p 8180:8080 \
  tomcat:7.0 2>/dev/null || log_warn "Tomcat container failed"

log_ok "Tomcat 7.0.79 running on port 8180 (HTTP) and 8009 (AJP/Ghostcat)"

# ============================================================================
#  SECTION 15: Webmin 1.890 (CVE-2019-15107 - Unauth RCE)
# ============================================================================
log_section "15" "Installing Webmin 1.890 (CVE-2019-15107)"

# Method 1: Try vulhub Docker image first (most reliable)
docker run -d \
  --name webmin-vulnerable \
  --restart unless-stopped \
  -p 10000:10000 \
  vulhub/webmin:1.910 2>/dev/null

if docker ps | grep -q webmin-vulnerable; then
    log_ok "Webmin 1.910 running via Docker on port 10000 (CVE-2019-15107)"
else
    # Method 2: Try native installation
    log_info "Docker Webmin failed, trying native install..."
    cd /tmp
    
    # Try multiple download sources
    wget -q --timeout=30 "https://sourceforge.net/projects/webadmin/files/webmin/1.890/webmin_1.890_all.deb/download" -O webmin_1.890.deb 2>/dev/null || \
    wget -q --timeout=30 "https://github.com/webmin/webmin/releases/download/1.890/webmin_1.890_all.deb" -O webmin_1.890.deb 2>/dev/null || \
    curl -sL --connect-timeout 30 "https://prdownloads.sourceforge.net/webadmin/webmin_1.890_all.deb" -o webmin_1.890.deb 2>/dev/null || \
    log_warn "Could not download Webmin 1.890"

    if [ -f webmin_1.890.deb ] && [ -s webmin_1.890.deb ]; then
        # Install dependencies first
        apt install -y perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python3 2>/dev/null || true
        
        dpkg -i webmin_1.890.deb 2>/dev/null || apt --fix-broken install -y 2>/dev/null
        
        # Configure Webmin for insecure access
        if [ -f /etc/webmin/miniserv.conf ]; then
            sed -i 's/ssl=1/ssl=0/' /etc/webmin/miniserv.conf
            echo "referers=" >> /etc/webmin/miniserv.conf
            systemctl restart webmin || log_warn "Webmin restart failed"
            log_ok "Webmin 1.890 installed on port 10000 (CVE-2019-15107)"
        else
            log_warn "Webmin config not found - installation may have failed"
        fi
    else
        log_warn "Webmin installation skipped - no valid package"
    fi
fi

# ============================================================================
#  SECTION 16: phpMyAdmin 4.8.1 (CVE-2018-12613 - LFI to RCE)
# ============================================================================
log_section "16" "Installing phpMyAdmin 4.8.1 (CVE-2018-12613)"

mkdir -p /var/www/phpmyadmin
cd /tmp
wget -q "https://files.phpmyadmin.net/phpMyAdmin/4.8.1/phpMyAdmin-4.8.1-all-languages.zip" -O phpmyadmin.zip || \
log_warn "Could not download phpMyAdmin 4.8.1"

if [ -f phpmyadmin.zip ]; then
    unzip -q phpmyadmin.zip
    mv phpMyAdmin-4.8.1-all-languages/* /var/www/phpmyadmin/
    
    # Configure phpMyAdmin
    cat >/var/www/phpmyadmin/config.inc.php <<'EOF'
<?php
$cfg['blowfish_secret'] = 'hellbox-insecure-secret-key-123456';
$i = 0;
$i++;
$cfg['Servers'][$i]['host'] = 'localhost';
$cfg['Servers'][$i]['auth_type'] = 'config';
$cfg['Servers'][$i]['user'] = 'test';
$cfg['Servers'][$i]['password'] = 'test123';
$cfg['Servers'][$i]['AllowNoPassword'] = true;
$cfg['Servers'][$i]['AllowRoot'] = true;
EOF
    
    chown -R www-data:www-data /var/www/phpmyadmin
    log_ok "phpMyAdmin 4.8.1 installed (CVE-2018-12613)"
else
    log_warn "phpMyAdmin installation skipped"
fi

# ============================================================================
#  SECTION 17: Elasticsearch 1.4.2 (CVE-2015-1427 - Groovy RCE)
# ============================================================================
log_section "17" "Running Elasticsearch 1.4.2 via Docker (CVE-2015-1427)"

# Note: The official elasticsearch:1.4.2 image is deprecated/removed
# Using vulhub's maintained vulnerable image instead
docker run -d \
  --name elasticsearch-vulnerable \
  --restart unless-stopped \
  -p 9200:9200 \
  -p 9300:9300 \
  vulhub/elasticsearch:1.4.2 2>/dev/null || \
docker run -d \
  --name elasticsearch-vulnerable \
  --restart unless-stopped \
  -p 9200:9200 \
  -p 9300:9300 \
  -e "discovery.type=single-node" \
  docker.elastic.co/elasticsearch/elasticsearch:1.4.2 2>/dev/null || \
  log_warn "Elasticsearch 1.4.2 container failed - CVE-2015-1427 won't be testable"

log_ok "Elasticsearch 1.4.2 running on port 9200 (CVE-2015-1427 Groovy RCE)"

# ============================================================================
#  SECTION 18: MongoDB 2.6 (No Auth Default)
# ============================================================================
log_section "18" "Running MongoDB 2.6 via Docker (No Auth)"

docker run -d \
  --name mongodb-vulnerable \
  --restart unless-stopped \
  -p 27017:27017 \
  mongo:2.6 2>/dev/null || log_warn "MongoDB 2.6 container failed"

log_ok "MongoDB 2.6 running on port 27017 (no authentication)"

# ============================================================================
#  SECTION 19: Samba 4.6.3 (CVE-2017-7494 - SambaCry)
# ============================================================================
log_section "19" "Running Samba 4.6.3 via Docker (CVE-2017-7494 SambaCry)"

# Create share directory
SAMBA_SHARE="/srv/samba/public"
mkdir -p "$SAMBA_SHARE"
chmod 777 "$SAMBA_SHARE"
echo "Samba share - guest writable" > "$SAMBA_SHARE/readme.txt"
echo "Sensitive data" > "$SAMBA_SHARE/secrets.txt"

# Use vulhub's vulnerable Samba image (4.6.3 is vulnerable to SambaCry)
docker run -d \
  --name samba-vulnerable \
  --restart unless-stopped \
  -p 139:139 \
  -p 445:445 \
  -v "$SAMBA_SHARE:/share" \
  vulhub/samba:4.6.3 2>/dev/null || \
docker run -d \
  --name samba-vulnerable \
  --restart unless-stopped \
  -p 139:139 \
  -p 445:445 \
  -v "$SAMBA_SHARE:/share" \
  dperson/samba:latest \
  -u "admin;admin123" \
  -s "public;/share;yes;no;yes;all" \
  -p 2>/dev/null || log_warn "Samba container failed"

# If docker fails, fall back to native Samba
if ! docker ps | grep -q samba-vulnerable; then
    log_warn "Using native Samba as fallback"
    
    cat >/etc/samba/smb.conf <<'EOF'
[global]
   workgroup = WORKGROUP
   server string = Hellbox Samba Server %v
   map to guest = Bad User
   dns proxy = no
   server min protocol = NT1

[public]
   path = /srv/samba/public
   browseable = yes
   writable = yes
   guest ok = yes
   read only = no
EOF
    
    systemctl enable smbd nmbd
    systemctl restart smbd nmbd
fi

log_ok "Samba running on ports 139/445"

# ============================================================================
#  SECTION 20: Drupal 7 (CVE-2018-7600 - Drupalgeddon2)
# ============================================================================
log_section "20" "Running Drupal 7.57 via Docker (CVE-2018-7600 Drupalgeddon2)"

# Try vulhub first (pre-configured for Drupalgeddon2)
docker run -d \
  --name drupal-vulnerable \
  --restart unless-stopped \
  -p 8081:80 \
  vulhub/drupal:8.5.0 2>/dev/null || \
docker run -d \
  --name drupal-vulnerable \
  --restart unless-stopped \
  -p 8081:80 \
  drupal:7.57 2>/dev/null || \
docker run -d \
  --name drupal-vulnerable \
  --restart unless-stopped \
  -p 8081:80 \
  drupal:7 2>/dev/null || log_warn "Drupal container failed"

log_ok "Drupal running on port 8081 (CVE-2018-7600 Drupalgeddon2)"

# ============================================================================
#  SECTION 21: Spring Boot Actuators (Exposed Endpoints)
# ============================================================================
log_section "21" "Creating Spring Boot Actuator simulation"

# We'll create a simple Python Flask app that simulates Spring Boot actuators
mkdir -p /opt/spring-actuator
cat >/opt/spring-actuator/app.py <<'EOF'
from flask import Flask, jsonify
import os
import json

app = Flask(__name__)

@app.route('/')
def index():
    return '<html><body><h1>Spring Boot Application</h1><a href="/actuator">Actuator</a></body></html>'

@app.route('/actuator')
def actuator():
    return jsonify({
        "_links": {
            "self": {"href": "/actuator"},
            "health": {"href": "/actuator/health"},
            "info": {"href": "/actuator/info"},
            "env": {"href": "/actuator/env"},
            "beans": {"href": "/actuator/beans"},
            "mappings": {"href": "/actuator/mappings"},
            "heapdump": {"href": "/actuator/heapdump"},
            "threaddump": {"href": "/actuator/threaddump"},
            "metrics": {"href": "/actuator/metrics"},
            "loggers": {"href": "/actuator/loggers"},
            "configprops": {"href": "/actuator/configprops"}
        }
    })

@app.route('/actuator/health')
def health():
    return jsonify({"status": "UP"})

@app.route('/actuator/info')
def info():
    return jsonify({
        "app": {"name": "hellbox-spring-app", "version": "1.0.0"},
        "java": {"version": "11.0.11"},
        "spring-boot": {"version": "2.3.4.RELEASE"}
    })

@app.route('/actuator/env')
def env():
    return jsonify({
        "activeProfiles": ["production"],
        "propertySources": [
            {
                "name": "systemEnvironment",
                "properties": {
                    "DATABASE_URL": {"value": "jdbc:mysql://localhost:3306/app"},
                    "DATABASE_USER": {"value": "admin"},
                    "DATABASE_PASSWORD": {"value": "******"},
                    "AWS_ACCESS_KEY_ID": {"value": "AKIAIOSFODNN7EXAMPLE"},
                    "AWS_SECRET_ACCESS_KEY": {"value": "******"},
                    "spring.datasource.password": {"value": "admin123"}
                }
            }
        ]
    })

@app.route('/actuator/beans')
def beans():
    return jsonify({"contexts": {"application": {"beans": {}}}})

@app.route('/actuator/mappings')
def mappings():
    return jsonify({"contexts": {"application": {"mappings": {}}}})

@app.route('/actuator/metrics')
def metrics():
    return jsonify({"names": ["jvm.memory.used", "http.server.requests", "process.cpu.usage"]})

@app.route('/actuator/configprops')
def configprops():
    return jsonify({
        "contexts": {
            "application": {
                "beans": {
                    "spring.datasource-org.springframework.boot.autoconfigure.jdbc.DataSourceProperties": {
                        "prefix": "spring.datasource",
                        "properties": {
                            "username": "admin",
                            "password": "******",
                            "url": "jdbc:mysql://localhost:3306/hellbox"
                        }
                    }
                }
            }
        }
    })

@app.route('/metrics')
def prometheus_metrics():
    return '''# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",path="/"} 1234
http_requests_total{method="POST",path="/api"} 567
# HELP jvm_memory_bytes_used JVM memory usage
# TYPE jvm_memory_bytes_used gauge
jvm_memory_bytes_used{area="heap"} 123456789
'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8082)
EOF

cat >/opt/spring-actuator/requirements.txt <<'EOF'
flask
EOF

# Create systemd service
cat >/etc/systemd/system/spring-actuator.service <<'EOF'
[Unit]
Description=Spring Boot Actuator Simulation
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/spring-actuator
ExecStart=/usr/bin/python3 /opt/spring-actuator/app.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

pip3 install flask --break-system-packages 2>/dev/null || pip3 install flask
systemctl daemon-reload
systemctl enable spring-actuator
systemctl start spring-actuator || log_warn "Spring actuator service failed"

log_ok "Spring Boot Actuators simulation running on port 8082"

# ============================================================================
#  SECTION 22: Nginx with Weak TLS (Standard ports 80, 443)
# ============================================================================
log_section "22" "Configuring Nginx on standard ports with weak TLS"

# Create comprehensive web vulnerability pages
mkdir -p /var/www/html/{secret,admin,backup,.git/objects,.svn/entries,api}

# robots.txt leaking hidden paths
cat >/var/www/html/robots.txt <<'EOF'
User-agent: *
Disallow: /secret/
Disallow: /admin/
Disallow: /backup/
Disallow: /cgi-bin/
Disallow: /.git/
Disallow: /.svn/
Disallow: /api/
Disallow: /actuator/
Disallow: /wp-admin/
EOF

# Exposed .git directory
cat >/var/www/html/.git/config <<'EOF'
[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallaliases = false
[remote "origin"]
    url = git@github.com:company/secret-project.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[user]
    email = admin@hellbox.local
    name = Admin User
[credential]
    helper = store
EOF

cat >/var/www/html/.git/HEAD <<'EOF'
ref: refs/heads/main
EOF

mkdir -p /var/www/html/.git/logs
cat >/var/www/html/.git/logs/HEAD <<'EOF'
0000000000000000000000000000000000000000 abc123def456 Admin <admin@hellbox.local> 1234567890 +0000	commit: Initial commit with secrets
EOF

# Exposed .svn directory
mkdir -p /var/www/html/.svn
cat >/var/www/html/.svn/entries <<'EOF'
10
dir
12345
https://svn.company.com/repos/secret-project
https://svn.company.com/repos
2024-01-01T00:00:00.000000Z
12345
admin
EOF

cat >/var/www/html/.svn/wc.db <<'EOF'
SQLite format 3 - This would be the working copy database
Contains paths, checksums, and metadata about the repository
EOF

# Exposed .env file
cat >/var/www/html/.env <<'EOF'
# Environment Configuration - SHOULD NOT BE EXPOSED
APP_ENV=production
APP_DEBUG=true
APP_KEY=base64:INSECURE_APP_KEY_12345678901234567890

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=hellbox_db
DB_USERNAME=admin
DB_PASSWORD=SuperSecret123!

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=hellbox-bucket

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=redis_password_123
REDIS_PORT=6379

MAIL_DRIVER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=hellbox_mail
MAIL_PASSWORD=mail_password_456

JWT_SECRET=jwt-super-secret-key-do-not-expose
API_KEY=sk-hellbox-api-key-1234567890abcdef
STRIPE_SECRET=sk_live_hellbox_stripe_secret_key
EOF

# Exposed config files
cat >/var/www/html/secret/config.php.bak <<'EOF'
<?php
// Database Configuration - DO NOT EXPOSE
$db_host = "localhost";
$db_user = "root";
$db_pass = "root123";
$db_name = "hellbox_db";
$debug   = true;
$api_key = "sk-1234567890abcdef";
$jwt_secret = "super-secret-jwt-key";
$admin_password = "admin123";
?>
EOF

# phpinfo page
cat >/var/www/html/phpinfo.php <<'EOF'
<?php
phpinfo();
?>
EOF

# Exposed database dump
cat >/var/www/html/database.sql <<'EOF'
-- Hellbox Database Dump
-- CONFIDENTIAL - DO NOT EXPOSE

CREATE DATABASE IF NOT EXISTS hellbox_db;
USE hellbox_db;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    api_key VARCHAR(64),
    role VARCHAR(20) DEFAULT 'user'
);

INSERT INTO users (username, password, email, api_key, role) VALUES
('admin', '$2y$10$hashed_admin_password', 'admin@hellbox.local', 'sk-admin-api-key-12345', 'admin'),
('root', 'root123', 'root@hellbox.local', 'sk-root-api-key-67890', 'superadmin'),
('test', 'test123', 'test@hellbox.local', 'sk-test-api-key-abcde', 'user'),
('backup', 'backup2024', 'backup@hellbox.local', NULL, 'backup');

CREATE TABLE api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_value VARCHAR(64) NOT NULL,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO api_keys (key_value, description) VALUES
('sk-live-production-key-1234567890', 'Production API Key'),
('sk-test-development-key-0987654321', 'Development API Key'),
('aws-AKIAIOSFODNN7EXAMPLE', 'AWS Access Key');
EOF

# .htpasswd exposure
cat >/var/www/html/.htpasswd <<'EOF'
admin:$apr1$xyz$hashedpasswordhere
root:$apr1$abc$anotherhashedpassword
backup:$apr1$def$backupuserpassword
EOF

# Backup files
cat >/var/www/html/backup.tar.gz <<'EOF'
Fake backup file - marker for scanners
Contains: database dumps, config files, source code
EOF

cat >/var/www/html/backup/site-backup.zip <<'EOF'
Fake site backup marker
EOF

cat >/var/www/html/backup/db-backup-2024.sql.gz <<'EOF'
Compressed database backup marker
EOF

# Admin panel
cat >/var/www/html/admin/index.html <<'EOF'
<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
<h1>Hellbox Admin Panel</h1>
<!-- Default credentials: admin / admin123 -->
<!-- API Key: sk-admin-1234567890 -->
<form method="POST" action="/admin/login">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Login</button>
</form>
</body>
</html>
EOF

cat >/var/www/html/admin/todo.txt <<'EOF'
Admin TODO:
- [ ] Remove default credentials (admin / admin123)
- [ ] Move config.php.bak out of webroot
- [ ] Disable directory listing
- [ ] Enable security headers
- [ ] Remove phpinfo.php
- [ ] Secure .git directory
- [ ] Update Drupal (Drupalgeddon2 vulnerable!)
- [ ] Patch Elasticsearch (Groovy RCE)
EOF

# WordPress-like structure (fake)
mkdir -p /var/www/html/wp-admin /var/www/html/wp-includes /var/www/html/wp-content/uploads
cat >/var/www/html/wp-login.php <<'EOF'
<!DOCTYPE html>
<html>
<head><title>WordPress Login</title></head>
<body>
<h1>WordPress</h1>
<!-- WordPress 4.9.8 - Multiple vulnerabilities -->
<form method="POST">
  <input type="text" name="log" placeholder="Username">
  <input type="password" name="pwd" placeholder="Password">
  <button type="submit">Log In</button>
</form>
</body>
</html>
EOF

cat >/var/www/html/wp-config.php.bak <<'EOF'
<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'wp_password_123');
define('DB_HOST', 'localhost');
define('AUTH_KEY', 'insecure-auth-key');
define('SECURE_AUTH_KEY', 'insecure-secure-auth-key');
define('LOGGED_IN_KEY', 'insecure-logged-in-key');
$table_prefix = 'wp_';
define('WP_DEBUG', true);
?>
EOF

# API endpoint simulation with Swagger
cat >/var/www/html/api/swagger.json <<'EOF'
{
  "swagger": "2.0",
  "info": {
    "title": "Hellbox API",
    "version": "1.0.0",
    "description": "Internal API - DO NOT EXPOSE"
  },
  "host": "api.hellbox.local",
  "basePath": "/v1",
  "paths": {
    "/users": {
      "get": {
        "summary": "List all users",
        "security": [{"api_key": []}]
      }
    },
    "/admin/config": {
      "get": {
        "summary": "Get system configuration",
        "description": "Returns sensitive configuration"
      }
    }
  },
  "securityDefinitions": {
    "api_key": {
      "type": "apiKey",
      "name": "X-API-Key",
      "in": "header"
    }
  }
}
EOF

cat >/var/www/html/api/openapi.yaml <<'EOF'
openapi: 3.0.0
info:
  title: Hellbox Internal API
  version: 1.0.0
  description: INTERNAL USE ONLY - Contains sensitive endpoints
servers:
  - url: https://api.hellbox.local/v1
paths:
  /admin/secrets:
    get:
      summary: Retrieve application secrets
      responses:
        200:
          description: Secret configuration data
EOF

# Main index page
cat >/var/www/html/index.html <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Hellbox v2 - Insecure Test Server</title>
    <meta name="generator" content="Hellbox CMS v2.0-dev">
</head>
<body>
    <h1>Welcome to Hellbox v2</h1>
    <!-- DEBUG: Application: Hellbox Admin Panel v2.0-dev -->
    <!-- TODO: Remove hardcoded credentials before going live -->
    <!-- Default user: admin / pass: admin123 -->
    <!-- API Key: sk-1234567890abcdef -->
    <!-- AWS Key: AKIAIOSFODNN7EXAMPLE -->
    
    <p>This is a deliberately insecure demo system for security testing.</p>
    <p>Server: Apache/Nginx on Ubuntu</p>
    
    <h2>Quick Links</h2>
    <ul>
        <li><a href="/admin/">Admin Panel</a></li>
        <li><a href="/secret/">Secret Files</a></li>
        <li><a href="/phpinfo.php">PHP Info</a></li>
        <li><a href="/wp-login.php">WordPress Login</a></li>
        <li><a href="/.git/config">Git Config</a></li>
        <li><a href="/.env">.env File</a></li>
        <li><a href="/api/swagger.json">API Docs</a></li>
        <li><a href=":8081/">Drupal (port 8081)</a></li>
        <li><a href=":8082/actuator">Spring Actuator (port 8082)</a></li>
        <li><a href=":8180/">Tomcat Manager (port 8180)</a></li>
        <li><a href=":9200/">Elasticsearch (port 9200)</a></li>
        <li><a href=":10000/">Webmin (port 10000)</a></li>
    </ul>
    
    <h2>Intentional Vulnerabilities</h2>
    <ul>
        <li>Directory listing enabled</li>
        <li>Weak TLS configuration</li>
        <li>Missing security headers</li>
        <li>Exposed backup/config files</li>
        <li>CVE-2011-2523 (vsftpd backdoor)</li>
        <li>CVE-2015-1427 (Elasticsearch Groovy RCE)</li>
        <li>CVE-2017-7494 (SambaCry)</li>
        <li>CVE-2017-12615 (Tomcat PUT RCE)</li>
        <li>CVE-2018-7600 (Drupalgeddon2)</li>
        <li>CVE-2018-12613 (phpMyAdmin LFI)</li>
        <li>CVE-2019-15107 (Webmin RCE)</li>
        <li>CVE-2020-1938 (Tomcat Ghostcat)</li>
        <li>CVE-2021-41773 (Apache Path Traversal)</li>
    </ul>
</body>
</html>
EOF

# CGI scripts for XSS/injection testing
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

cat >/usr/lib/cgi-bin/ping.sh <<'EOF'
#!/bin/bash
echo "Content-Type: text/html"
echo ""
echo "<html><body>"
echo "<h1>Ping Test</h1>"
if [ -n "$QUERY_STRING" ]; then
    HOST=$(echo "$QUERY_STRING" | sed 's/host=//')
    echo "<pre>"
    echo "Pinging: $HOST"
    echo "</pre>"
fi
echo "</body></html>"
EOF
chmod +x /usr/lib/cgi-bin/ping.sh

# Nginx configuration
cat >/etc/nginx/sites-available/default <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    root /var/www/html;
    index index.html index.htm index.php;

    # Directory listing (information disclosure)
    location / {
        autoindex on;
        try_files $uri $uri/ =404;
    }

    # PHP processing
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }

    # phpMyAdmin
    location /phpmyadmin {
        alias /var/www/phpmyadmin;
        index index.php;
        location ~ \.php$ {
            fastcgi_pass unix:/var/run/php/php-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $request_filename;
            include fastcgi_params;
        }
    }

    # Expose hidden files (bad practice)
    location ~ /\. {
        # Don't deny - expose .git, .svn, .env, etc.
    }

    # Server status (information disclosure)
    location /nginx_status {
        stub_status on;
        allow all;
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
    ssl_ciphers DEFAULT:@SECLEVEL=0;
    ssl_prefer_server_ciphers on;

    root /var/www/html;
    index index.html index.htm index.php;

    location / {
        autoindex on;
        try_files $uri $uri/ =404;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }

    location /phpmyadmin {
        alias /var/www/phpmyadmin;
        index index.php;
        location ~ \.php$ {
            fastcgi_pass unix:/var/run/php/php-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $request_filename;
            include fastcgi_params;
        }
    }

    location ~ /\. {
        # Expose hidden files
    }
}
EOF

systemctl enable nginx php*-fpm 2>/dev/null
# nginx loads the certificate before it applies ssl_ciphers, so the
# "@SECLEVEL=0" above does not stop OpenSSL 3 rejecting the 1024-bit key
# ("ee key too small") and nginx (ports 80 and 443) never starts. Lower the
# security level for the nginx process only, through its own OpenSSL config.
cat >/etc/nginx/openssl-weak.cnf <<'EOF'
openssl_conf = openssl_init
[openssl_init]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
MinProtocol = TLSv1
CipherString = DEFAULT:@SECLEVEL=0
EOF
mkdir -p /etc/systemd/system/nginx.service.d
cat >/etc/systemd/system/nginx.service.d/weak-tls.conf <<'EOF'
[Service]
Environment=OPENSSL_CONF=/etc/nginx/openssl-weak.cnf
EOF
systemctl daemon-reload

systemctl restart nginx php*-fpm 2>/dev/null || log_warn "Nginx/PHP restart failed"
log_ok "Nginx configured on ports 80/443 with weak TLS"

# ============================================================================
#  SECTION 23: Apache on Non-Standard Ports with server-status
# ============================================================================
log_section "23" "Configuring Apache on ports 8888/8443 with server-status"

cat >/etc/apache2/ports.conf <<'EOF'
Listen 8888
Listen 8443
EOF

a2enmod ssl headers cgi status >/dev/null 2>&1
a2dissite 000-default.conf default-ssl.conf >/dev/null 2>&1

cat >/etc/apache2/sites-available/hellbox-http.conf <<'EOF'
<VirtualHost *:8888>
    ServerName hellbox.local
    DocumentRoot /var/www/html

    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # Server status (information disclosure)
    <Location /server-status>
        SetHandler server-status
        Require all granted
    </Location>

    # Server info
    <Location /server-info>
        SetHandler server-info
        Require all granted
    </Location>

    ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
    <Directory "/usr/lib/cgi-bin">
        AllowOverride None
        Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
        Require all granted
    </Directory>

    TraceEnable On

    Header always unset X-Frame-Options
    Header always unset X-Content-Type-Options
    Header always unset X-XSS-Protection
</VirtualHost>
EOF

cat >/etc/apache2/sites-available/hellbox-ssl.conf <<'EOF'
<VirtualHost *:8443>
    ServerName hellbox.local

    SSLEngine on
    SSLCertificateFile /root/badcert/weak.crt
    SSLCertificateKeyFile /root/badcert/weak.key
    SSLProtocol all -TLSv1.3
    SSLCipherSuite DEFAULT:@SECLEVEL=0
    SSLHonorCipherOrder on

    DocumentRoot /var/www/html
    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    <Location /server-status>
        SetHandler server-status
        Require all granted
    </Location>

    ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
    <Directory "/usr/lib/cgi-bin">
        AllowOverride None
        Options +ExecCGI
        Require all granted
    </Directory>

    TraceEnable On
</VirtualHost>
EOF

a2ensite hellbox-http.conf hellbox-ssl.conf >/dev/null 2>&1
systemctl enable apache2
systemctl restart apache2 || log_warn "Apache restart failed"
log_ok "Apache configured on ports 8888/8443 with server-status"

# ============================================================================
#  SECTION 24: Mail Services (Postfix + Dovecot)
# ============================================================================
log_section "24" "Configuring mail services with weak TLS"

# Postfix
postconf -e "smtpd_tls_cert_file=/root/badcert/weak.crt"
postconf -e "smtpd_tls_key_file=/root/badcert/weak.key"
postconf -e "smtpd_tls_security_level=may"
postconf -e "smtpd_tls_mandatory_protocols=!TLSv1.3"
postconf -e "smtpd_tls_auth_only=no"
systemctl enable postfix
systemctl restart postfix || log_warn "Postfix restart failed"

# Dovecot
DOVECOT_SSL="/etc/dovecot/conf.d/10-ssl.conf"
cat >"$DOVECOT_SSL" <<'EOF'
ssl = yes
ssl_cert = </root/badcert/weak.crt
ssl_key  = </root/badcert/weak.key
ssl_min_protocol = SSLv3
ssl_cipher_list = DEFAULT:@SECLEVEL=0
EOF

AUTH_CONF="/etc/dovecot/conf.d/10-auth.conf"
[ -f "$AUTH_CONF" ] && sed -i 's/^#\?disable_plaintext_auth.*/disable_plaintext_auth = no/' "$AUTH_CONF"

systemctl enable dovecot
systemctl restart dovecot || log_warn "Dovecot restart failed"
log_ok "Mail services configured"

# ============================================================================
#  SECTION 25: Database Services
# ============================================================================
log_section "25" "Configuring MySQL and PostgreSQL"

# MySQL
MYCNF="/etc/mysql/mysql.conf.d/mysqld.cnf"
[ -f "$MYCNF" ] && sed -i 's/^\s*bind-address.*/bind-address = 0.0.0.0/' "$MYCNF"
systemctl enable mysql
systemctl restart mysql || log_warn "MySQL restart failed"

mysql -u root <<'EOF' 2>/dev/null || log_warn "MySQL user creation failed"
CREATE USER IF NOT EXISTS 'test'@'%' IDENTIFIED BY 'test123';
CREATE USER IF NOT EXISTS 'admin'@'%' IDENTIFIED BY 'admin123';
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY 'root';
GRANT ALL PRIVILEGES ON *.* TO 'test'@'%' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
CREATE DATABASE IF NOT EXISTS hellbox_db;
FLUSH PRIVILEGES;
EOF

# PostgreSQL
PG_VER=$(psql -V 2>/dev/null | awk '{print $3}' | cut -d. -f1 || echo "16")
PG_CONF="/etc/postgresql/${PG_VER}/main/postgresql.conf"
PG_HBA="/etc/postgresql/${PG_VER}/main/pg_hba.conf"

[ -f "$PG_CONF" ] && sed -i "s/^#\?listen_addresses.*/listen_addresses = '*'/" "$PG_CONF"
if [ -f "$PG_HBA" ]; then
    grep -v "0.0.0.0/0" "$PG_HBA" > "${PG_HBA}.tmp" && mv "${PG_HBA}.tmp" "$PG_HBA"
    echo "host    all             all             0.0.0.0/0               md5" >> "$PG_HBA"
fi

systemctl enable postgresql
systemctl restart postgresql || log_warn "PostgreSQL restart failed"

sudo -u postgres psql <<'EOF' 2>/dev/null || log_warn "PostgreSQL user creation failed"
DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'testuser') THEN CREATE ROLE testuser LOGIN PASSWORD 'test123'; END IF; END$$;
CREATE DATABASE testdb OWNER testuser;
EOF

log_ok "Database services configured"

# ============================================================================
#  SECTION 26: Redis and Memcached
# ============================================================================
log_section "26" "Configuring Redis and Memcached (no auth)"

REDIS_CONF="/etc/redis/redis.conf"
if [ -f "$REDIS_CONF" ]; then
    sed -i 's/^bind .*/bind 0.0.0.0/' "$REDIS_CONF"
    sed -i 's/^protected-mode .*/protected-mode no/' "$REDIS_CONF"
fi
systemctl enable redis-server
systemctl restart redis-server || log_warn "Redis restart failed"

MEMCACHED_CONF="/etc/memcached.conf"
[ -f "$MEMCACHED_CONF" ] && sed -i 's/^-l .*/-l 0.0.0.0/' "$MEMCACHED_CONF"
systemctl enable memcached
systemctl restart memcached || log_warn "Memcached restart failed"

log_ok "Redis/Memcached configured (no authentication)"

# ============================================================================
#  SECTION 27: TFTP and XRDP
# ============================================================================
log_section "27" "Configuring TFTP and XRDP"

TFTP_ROOT="/srv/tftp"
mkdir -p "$TFTP_ROOT"
chmod 777 "$TFTP_ROOT"
echo "TFTP root - world writable" > "$TFTP_ROOT/readme.txt"

cat >/etc/default/tftpd-hpa <<EOF
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="$TFTP_ROOT"
TFTP_ADDRESS="0.0.0.0:69"
TFTP_OPTIONS="--secure --create"
EOF

systemctl enable tftpd-hpa
systemctl restart tftpd-hpa || log_warn "TFTP restart failed"

systemctl enable xrdp
systemctl restart xrdp || log_warn "XRDP restart failed"

log_ok "TFTP and XRDP configured"

# ============================================================================
#  SECTION 28: Final Service Status Check
# ============================================================================
log_section "28" "Verifying services"

echo ""
echo "Checking native services..."
for svc in ssh nginx apache2 mysql postgresql redis-server memcached postfix dovecot snmpd xinetd slapd vsftpd-vulnerable vsftpd spring-actuator webmin nfs-kernel-server; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        log_ok "$svc is running"
    else
        log_warn "$svc is not running"
    fi
done

echo ""
echo "Checking Docker containers..."
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || log_warn "Docker not available"

# ============================================================================
#  SECTION 29: Summary
# ============================================================================
log_section "29" "HELLBOX v2 SETUP COMPLETE"

PUBIP=$(curl -s ifconfig.me 2>/dev/null || echo "<public-ip>")

cat <<EOF

================================================================================
                     HELLBOX v2 - VULNERABLE LAB SERVER
================================================================================

Public IP: $PUBIP

================================================================================
 SERVICES WITH KNOWN CVEs (Metasploit + Nuclei targets)
================================================================================

  vsftpd 2.3.4          $PUBIP:21        CVE-2011-2523 (Backdoor RCE)
  ProFTPD 1.3.5         $PUBIP:2121      CVE-2015-3306 (mod_copy RCE)
  Apache 2.4.49         $PUBIP:8080      CVE-2021-41773 (Path Traversal RCE)
  Tomcat 7.0.79         $PUBIP:8180      CVE-2017-12615 (PUT RCE)
  Tomcat AJP            $PUBIP:8009      CVE-2020-1938 (Ghostcat)
  Webmin 1.890          $PUBIP:10000     CVE-2019-15107 (Unauth RCE)
  phpMyAdmin 4.8.1      $PUBIP/phpmyadmin CVE-2018-12613 (LFI → RCE)
  Elasticsearch 1.4.2   $PUBIP:9200      CVE-2015-1427 (Groovy RCE)
  Samba                 $PUBIP:445       CVE-2017-7494 (SambaCry)
  Drupal 7.57           $PUBIP:8081      CVE-2018-7600 (Drupalgeddon2)

================================================================================
 WEB VULNERABILITIES (Nikto, ZAP, Nuclei targets)
================================================================================

  Nginx HTTP            $PUBIP:80        Dir listing, autoindex
  Nginx HTTPS           $PUBIP:443       Weak TLS (TLSv1, TLSv1.1)
  Apache HTTP           $PUBIP:8888      server-status, TRACE, CGI/XSS
  Apache HTTPS          $PUBIP:8443      Weak TLS + same vulns
  Spring Actuators      $PUBIP:8082      /actuator/env, /metrics

  Exposed Files:
    /.git/config        → Git repository info
    /.svn/entries       → SVN repository info
    /.env               → Environment secrets (AWS keys, DB creds)
    /phpinfo.php        → PHP configuration
    /server-status      → Apache status (port 8888)
    /robots.txt         → Disallowed paths
    /secret/config.php.bak → Backup credentials
    /database.sql       → Database dump
    /api/swagger.json   → API documentation
    /wp-login.php       → Fake WordPress

================================================================================
 NETWORK SERVICES (Nmap NSE, Metasploit targets)
================================================================================

  SSH (weak config)     $PUBIP:22        Weak KEX, MACs, ciphers, DSA key
  SNMP                  $PUBIP:161       Community: public/private
  Telnet                $PUBIP:23        Plaintext auth
  VNC                   $PUBIP:5900      No password
  Finger                $PUBIP:79        User enumeration
  NFS                   $PUBIP:2049      World-exportable /srv/nfs/public
  LDAP                  $PUBIP:389       Anonymous bind
  Docker API            $PUBIP:2375      Unauthenticated

================================================================================
 DATABASE SERVICES
================================================================================

  MySQL                 $PUBIP:3306      Users: test/test123, admin/admin123
  PostgreSQL            $PUBIP:5432      User: testuser/test123, db: testdb
  MongoDB               $PUBIP:27017     No authentication
  Redis                 $PUBIP:6379      No auth, protected-mode off
  Memcached             $PUBIP:11211     No auth

================================================================================
 MAIL SERVICES
================================================================================

  SMTP (Postfix)        $PUBIP:25        Weak TLS, plain auth allowed
  IMAP                  $PUBIP:143       Plaintext auth
  IMAPS                 $PUBIP:993       Weak TLS
  POP3                  $PUBIP:110       Plaintext auth
  POP3S                 $PUBIP:995       Weak TLS

================================================================================
 FILE SERVICES
================================================================================

  FTP (vsftpd)          $PUBIP:21        Anonymous writable
  FTP (ProFTPD)         $PUBIP:2121      mod_copy vulnerable
  Samba                 $PUBIP:445       Guest writable share: public
  TFTP                  $PUBIP:69        World writable
  NFS                   $PUBIP:2049      World readable/writable

================================================================================
 OTHER SERVICES
================================================================================

  XRDP                  $PUBIP:3389      Remote desktop
  Webmin                $PUBIP:10000     Admin panel (vulnerable)

================================================================================
 TEST CREDENTIALS
================================================================================

  MySQL:        test / test123, admin / admin123, root / root
  PostgreSQL:   testuser / test123
  LDAP:         cn=admin,dc=hellbox,dc=local / admin123
  Tomcat:       tomcat / tomcat, admin / admin
  Web Admin:    admin / admin123 (comments in HTML)
  phpMyAdmin:   test / test123

================================================================================
 TLS CERTIFICATE
================================================================================

  Location:     /root/badcert/weak.crt
  Issues:       RSA 1024-bit, SHA1 signature, 90-day validity, self-signed

================================================================================

  This server is INTENTIONALLY INSECURE for security testing purposes.

  Designed for testing with PEEK, Nmap, Nuclei, Nikto, ZAP, Metasploit,
  sslscan, testssl.sh, ssh-audit, and httpx.

  DO NOT expose to production networks!

================================================================================
EOF

log_ok "Hellbox v3 setup complete!"