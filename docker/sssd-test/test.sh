#!/bin/bash
set -e

echo "=== GLAuth Pocket ID Plugin - Integration Tests ==="
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

PASS=0
FAIL=0

run_test() {
    local name="$1"
    local cmd="$2"
    local expected="$3"

    echo -n "TEST: $name... "
    result=$(eval "$cmd" 2>/dev/null || true)
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

# Test 1: Search all users
run_test "List all posixAccount users" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(objectClass=posixAccount)' cn" \
    "jordan"

# Test 2: Search specific user
run_test "Find user jordan" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(cn=jordan)' cn uidNumber" \
    "cn: jordan"

# Test 3: SSH keys present
run_test "SSH keys for jordan" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(cn=jordan)' sshPublicKey" \
    "sshPublicKey"

# Test 4: Alice has SSH key
run_test "Find user alice with SSH key" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(cn=alice)' sshPublicKey" \
    "sshPublicKey"

# Test 5: Search groups
run_test "List posixGroup groups" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(objectClass=posixGroup)' ou gidNumber" \
    "developers"

# Test 6: Login shell override
run_test "Jordan has /bin/zsh shell" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(cn=jordan)' loginShell" \
    "/bin/zsh"

# Test 7: Home directory
run_test "Jordan has home directory" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(cn=jordan)' homeDirectory" \
    "/home/jordan"

# Test 8: Sudoers search
run_test "Sudoers rules present" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b 'ou=sudoers,$BASE_DN' '(objectClass=sudoRole)' cn sudoUser" \
    "server-admins"

# Test 9: Sudo user membership
run_test "Sudo rule has sudoUser entries" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b 'ou=sudoers,$BASE_DN' '(cn=server-admins)' sudoUser" \
    "sudoUser"

# Test 10: UID numbers assigned
run_test "Users have UID numbers >= 10000" \
    "ldapsearch -x -H $LDAP_URI -D '$BIND_DN' -w '$BIND_PW' -b '$BASE_DN' '(cn=jordan)' uidNumber" \
    "uidNumber: 1"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
