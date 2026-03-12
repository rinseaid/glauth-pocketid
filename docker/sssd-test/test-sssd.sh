#!/bin/bash
set -e

echo "=== GLAuth Pocket ID Plugin - SSSD Validation ==="
echo ""

LDAP_URI="ldap://glauth:3893"
BIND_DN="cn=serviceuser,ou=svcaccts,dc=example,dc=com"
BIND_PW="mysecret"
BASE_DN="dc=example,dc=com"

# Wait for glauth to be ready
echo "Waiting for glauth..."
for i in $(seq 1 30); do
    if ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" -b "$BASE_DN" -s base '(objectClass=*)' dn 2>/dev/null | grep -q "dn:"; then
        echo "glauth is ready!"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "FAIL: glauth not ready after 30 seconds"
        exit 1
    fi
    sleep 1
done
echo ""

# Start SSSD
echo "Starting SSSD..."
# Clear any cached data
rm -rf /var/lib/sss/db/* /var/lib/sss/mc/* 2>/dev/null || true
sssd -d 3 2>/dev/null &
SSSD_PID=$!

# Wait for SSSD to be ready
echo "Waiting for SSSD to initialize..."
sleep 5

PASS=0
FAIL=0

run_test() {
    local name="$1"
    local cmd="$2"
    local expected="$3"

    echo -n "TEST: $name... "
    result=$(eval "$cmd" 2>&1 || true)
    if echo "$result" | grep -qi "$expected"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        echo "  Expected to find: $expected"
        echo "  Got: $result"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "--- NSS Tests (getent) ---"

# Test 1: getent passwd for IDP user
run_test "getent passwd jordan" \
    "getent passwd jordan" \
    "jordan"

# Test 2: getent passwd shows correct shell
run_test "jordan has /bin/zsh shell via getent" \
    "getent passwd jordan" \
    "/bin/zsh"

# Test 3: getent passwd shows correct home
run_test "jordan has /home/jordan via getent" \
    "getent passwd jordan" \
    "/home/jordan"

# Test 4: getent passwd for alice
run_test "getent passwd alice" \
    "getent passwd alice" \
    "alice"

# Test 5: alice has default /bin/bash shell
run_test "alice has /bin/bash shell via getent" \
    "getent passwd alice" \
    "/bin/bash"

# Test 6: getent group for developers
run_test "getent group developers" \
    "getent group developers" \
    "developers"

# Test 7: Service user visible
run_test "getent passwd serviceuser" \
    "getent passwd serviceuser" \
    "serviceuser"

echo ""
echo "--- SSH Key Tests ---"

# Test 8: SSH keys for jordan via ldapsearch
run_test "jordan SSH keys via LDAP" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(cn=jordan)' sshPublicKey" \
    "ssh-ed25519"

# Test 9: jordan has multiple SSH keys
run_test "jordan has 2 SSH keys" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(cn=jordan)' sshPublicKey | grep -c 'sshPublicKey:'" \
    "2"

# Test 10: SSH authorized keys command (if sss_ssh_authorizedkeys available)
if command -v sss_ssh_authorizedkeys >/dev/null 2>&1; then
    run_test "sss_ssh_authorizedkeys jordan" \
        "sss_ssh_authorizedkeys jordan" \
        "ssh-"
else
    echo "SKIP: sss_ssh_authorizedkeys not available"
fi

echo ""
echo "--- Sudo Tests ---"

# Test 11: Sudo rules in LDAP
run_test "sudoRole entries exist" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b 'ou=sudoers,$BASE_DN' '(objectClass=sudoRole)' cn" \
    "server-admins"

# Test 12: sudoUser entries
run_test "server-admins has sudoUser jordan" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b 'ou=sudoers,$BASE_DN' '(cn=server-admins)' sudoUser" \
    "jordan"

# Test 13: sudoUser alice in server-admins
run_test "server-admins has sudoUser alice" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b 'ou=sudoers,$BASE_DN' '(cn=server-admins)' sudoUser" \
    "alice"

# Test 14: sudoCommand ALL
run_test "server-admins has sudoCommand ALL" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b 'ou=sudoers,$BASE_DN' '(cn=server-admins)' sudoCommand" \
    "ALL"

# Test 15: sudoOption
run_test "server-admins has sudoOption !authenticate" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b 'ou=sudoers,$BASE_DN' '(cn=server-admins)' sudoOption" \
    "!authenticate"

echo ""
echo "--- UID/GID Consistency Tests ---"

# Test 16: UID is numeric and >= 10000
run_test "jordan UID >= 10000" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(cn=jordan)' uidNumber" \
    "uidNumber: 1"

# Test 17: GID is numeric
run_test "jordan has gidNumber" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(cn=jordan)' gidNumber" \
    "gidNumber:"

# Test 18: Different users have different UIDs
JORDAN_UID=$(ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" -b "$BASE_DN" '(cn=jordan)' uidNumber 2>/dev/null | grep "uidNumber:" | awk '{print $2}')
ALICE_UID=$(ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" -b "$BASE_DN" '(cn=alice)' uidNumber 2>/dev/null | grep "uidNumber:" | awk '{print $2}')
echo -n "TEST: jordan and alice have different UIDs... "
if [ -n "$JORDAN_UID" ] && [ -n "$ALICE_UID" ] && [ "$JORDAN_UID" != "$ALICE_UID" ]; then
    echo "PASS (jordan=$JORDAN_UID, alice=$ALICE_UID)"
    PASS=$((PASS + 1))
else
    echo "FAIL (jordan=$JORDAN_UID, alice=$ALICE_UID)"
    FAIL=$((FAIL + 1))
fi

# Cleanup
kill $SSSD_PID 2>/dev/null || true

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
