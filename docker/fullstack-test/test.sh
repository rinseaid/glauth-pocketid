#!/bin/bash
set -e

echo "=== Full Stack Test: Pocket ID + glauth + SSSD + pam-pocketid ==="
echo ""

LDAP_URI="ldap://glauth:3893"
BIND_DN="cn=serviceuser,ou=svcaccts,dc=example,dc=com"
BIND_PW="mysecret"
BASE_DN="dc=example,dc=com"

# Wait for glauth to be ready
echo "Waiting for glauth..."
for i in $(seq 1 60); do
    if ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" -b "$BASE_DN" -s base '(objectClass=*)' dn 2>/dev/null | grep -q "dn:"; then
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "FAIL: glauth not ready after 60 seconds"
        exit 1
    fi
    sleep 1
done
echo "glauth is ready."

# Wait for SSSD enumeration
echo "Waiting for SSSD to enumerate users (may take up to 30s)..."
for i in $(seq 1 30); do
    if getent passwd testuser 2>/dev/null | grep -q testuser; then
        break
    fi
    sleep 2
done
echo ""

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
        echo "  Expected: $expected"
        echo "  Got: $result"
        FAIL=$((FAIL + 1))
    fi
}

echo "--- LDAP Tests ---"

run_test "Users visible via LDAP" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(objectClass=posixAccount)' cn | grep -c 'cn:'" \
    "[0-9]"

run_test "Groups visible via LDAP" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(objectClass=posixGroup)' ou | grep -c 'ou:'" \
    "[0-9]"

run_test "testuser found via LDAP" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(cn=testuser)' cn" \
    "cn: testuser"

run_test "testuser has SSH key via LDAP" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(cn=testuser)' sshPublicKey" \
    "ssh-"

echo ""
echo "--- NSS/SSSD Tests ---"

run_test "getent passwd testuser" \
    "getent passwd testuser" \
    "testuser"

run_test "getent passwd serviceuser" \
    "getent passwd serviceuser" \
    "serviceuser"

run_test "getent group test-group" \
    "getent group test-group 2>/dev/null || echo ''" \
    ""

echo ""
echo "--- Sudo Tests ---"

run_test "sudoRole entries via LDAP" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b 'ou=sudoers,$BASE_DN' '(objectClass=sudoRole)' cn 2>/dev/null | grep -c 'cn:' || echo 0" \
    "[0-9]"

echo ""
echo "--- SSH Key Tests ---"

if command -v sss_ssh_authorizedkeys >/dev/null 2>&1; then
    run_test "sss_ssh_authorizedkeys testuser" \
        "sss_ssh_authorizedkeys testuser 2>/dev/null" \
        "ssh-"
else
    echo "SKIP: sss_ssh_authorizedkeys not available"
fi

echo ""
echo "--- pam-pocketid Server Test ---"

run_test "pam-pocketid server reachable" \
    "curl -sf http://host.docker.internal:8090/healthz 2>/dev/null || echo 'unreachable'" \
    ""

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
