#!/bin/bash
set -e

echo "=== Starting SSSD + SSH Server ==="

# Clean SSSD state
rm -rf /var/lib/sss/db/* /var/lib/sss/mc/* /run/sssd.pid 2>/dev/null || true

# Source pam-pocketid env vars
export $(grep -v '^#' /etc/environment | xargs 2>/dev/null) || true

# Start SSSD
echo "Starting SSSD..."
sssd -d 3 2>/dev/null &
sleep 5
echo "SSSD started."

# Start SSH server
echo "Starting SSH server on port 22..."
/usr/sbin/sshd -D -e -o LogLevel=DEBUG3 2>/var/log/sshd.log &
echo "SSH server started."

echo ""
echo "=== Ready ==="
echo "Run tests: docker compose exec sssd-client /test.sh"
echo "Test sudo: docker compose exec sssd-client su - <username>"
echo "           then: sudo whoami"
echo ""

exec tail -f /dev/null
