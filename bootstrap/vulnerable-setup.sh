#!/bin/bash
# vulnerable-setup.sh
# Intentionally vulnerable EC2 target for ec2-vuln-lab (training lab, no internet path).
# Every block starts with its finding ID from vulns/manifest.yaml.
# Idempotent, so it can be re-run for re-break. No set -e on purpose: one failed step must not stop the rest.
set -u

LOG=/var/log/vuln-lab-setup.log
DONE=/var/log/vuln-lab-setup.done
OLD_RELEASE="2023.6.20240801"   # OS-10: verify this older AL2023 release exists for your region

exec > >(tee -a "$LOG") 2>&1
echo "=== vuln-lab setup start: $(date -u) ==="

section() { echo "--- $* ---"; }

section "swap (t3.micro has 1 GB RAM)"
if [ ! -f /swapfile ]; then
  dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
fi
swapon /swapfile 2>/dev/null || true
grep -q '^/swapfile ' /etc/fstab || echo '/swapfile swap swap defaults 0 0' >> /etc/fstab

section "packages from AL2023 repos (via S3 gateway endpoint)"
dnf install -y audit firewalld cronie mariadb105-server redis6 python3-dnf-plugin-versionlock

# OS-01, OS-02: password auth and root login over SSH.
# The 10- drop-in sorts before cloud-init's 50- file, so its values win.
section "OS-01 OS-02 sshd"
cat > /etc/ssh/sshd_config.d/10-vuln-lab.conf <<'EOF'
# Intentional findings OS-01 and OS-02.
PasswordAuthentication yes
PermitRootLogin yes
EOF
systemctl enable --now sshd
systemctl restart sshd

# OS-03: weak local account
section "OS-03 labadmin weak password"
id labadmin >/dev/null 2>&1 || useradd -m labadmin
echo 'labadmin:Password123!' | chpasswd

# OS-04: passwordless sudo
section "OS-04 passwordless sudo"
echo 'labadmin ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/labadmin
chmod 0440 /etc/sudoers.d/labadmin

# OS-05: SUID copy of find
section "OS-05 SUID find copy"
cp -f /usr/bin/find /usr/local/bin/find-suid
chmod 4755 /usr/local/bin/find-suid

# OS-06: world-writable script run hourly by cron
section "OS-06 world-writable cron script"
cat > /etc/cron.hourly/lab-cleanup <<'EOF'
#!/bin/bash
# Intentional finding OS-06: this file is world-writable.
find /tmp -type f -mtime +7 -delete 2>/dev/null
EOF
chmod 0777 /etc/cron.hourly/lab-cleanup
systemctl enable --now crond

# OS-07: shadow file readable by all users
section "OS-07 shadow permissions"
chmod 0644 /etc/shadow

# OS-08: auditd stopped and disabled
section "OS-08 auditd off"
systemctl stop auditd 2>/dev/null
systemctl disable auditd 2>/dev/null

# OS-09: host firewall stopped and disabled
section "OS-09 firewalld off"
systemctl stop firewalld 2>/dev/null
systemctl disable firewalld 2>/dev/null

# SVC-01: MariaDB on all interfaces, root with empty password
section "SVC-01 MariaDB"
cat > /etc/my.cnf.d/99-vuln-lab.cnf <<'EOF'
# Intentional finding SVC-01: listen on all interfaces.
[mysqld]
bind-address = 0.0.0.0
EOF
[ -d /var/lib/mysql/mysql ] || mariadb-install-db --user=mysql --datadir=/var/lib/mysql >/dev/null 2>&1
systemctl enable --now mariadb
systemctl restart mariadb
mysql -u root <<'SQL'
ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password USING PASSWORD('');
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
SQL

# SVC-02: Redis on all interfaces, protected mode off, no auth
section "SVC-02 Redis"
REDIS_CONF=$(ls /etc/redis6/redis6.conf /etc/redis6.conf /etc/redis.conf 2>/dev/null | head -n 1)
if [ -n "$REDIS_CONF" ]; then
  sed -i -e 's/^bind .*/bind 0.0.0.0/' \
         -e 's/^protected-mode .*/protected-mode no/' \
         -e 's/^requirepass /# requirepass /' "$REDIS_CONF"
  grep -q '^bind 0.0.0.0' "$REDIS_CONF" || echo 'bind 0.0.0.0' >> "$REDIS_CONF"
  grep -q '^protected-mode no' "$REDIS_CONF" || echo 'protected-mode no' >> "$REDIS_CONF"
else
  echo "SVC-02: redis config not found, check the redis6 package layout"
fi
systemctl enable --now redis6
systemctl restart redis6

# OS-10: outdated packages with known CVEs, pinned with versionlock.
# OS-10: outdated packages with known CVEs. Pinned to older AL2023 builds that exist in the
# default repos. openssl is intentionally left out: older builds conflict with the openssl-libs
# already installed on AL2023, and forcing it risks breaking TLS and dnf itself.
section "OS-10 old package versions"
dnf -y downgrade curl-minimal-7.88.1-1.amzn2023.0.1 libcurl-minimal-7.88.1-1.amzn2023.0.1 \
  || echo "OS-10: curl downgrade failed, check repo availability"
dnf -y downgrade sudo-1.9.13-1.p2.amzn2023.0.4 \
  || echo "OS-10: sudo downgrade failed, check repo availability"
dnf versionlock add curl-minimal libcurl-minimal sudo \
  || echo "OS-10: versionlock add failed"

section "done"
echo "=== vuln-lab setup finished: $(date -u) ==="
date -u > "$DONE"