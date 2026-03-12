#!/bin/bash
set -e

echo "=== Starting SSSD + SSH Server ==="

# Clean SSSD state
rm -rf /var/lib/sss/db/* /var/lib/sss/mc/* /run/sssd.pid 2>/dev/null || true

# Start SSSD
echo "Starting SSSD..."
sssd -d 3 2>/dev/null &
sleep 5
echo "SSSD started."

# Start SSH server with debug logging to file
echo "Starting SSH server on port 22..."
/usr/sbin/sshd -D -e -o LogLevel=DEBUG3 2>/var/log/sshd.log &
echo $! > /run/sshd.pid
echo "SSH server started."

echo ""
echo "=== Ready ==="
echo "SSH: ssh -p 2222 jordan@localhost (key auth via SSSD)"
echo "Tests: docker exec <container> /test.sh"
echo "SSSD tests: docker exec <container> /test-sssd.sh"
echo ""

# Keep running regardless of sshd
exec tail -f /dev/null
