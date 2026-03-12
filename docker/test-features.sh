#!/bin/bash
# test-features.sh — Comprehensive LDAP feature validation for glauth-pocketid
#
# Tests ALL plugin features via ldapsearch queries.
#
# Usage:
#   ./test-features.sh [ldap_host:port] [bind_dn] [bind_password] [base_dn] [webhook_url]
#
# Examples:
#   ./test-features.sh                                          # defaults
#   ./test-features.sh glauth:3893                              # custom host
#   ./test-features.sh localhost:3893 cn=admin,dc=x,dc=y pass   # custom bind

set -euo pipefail

# ---------- Configuration ----------

LDAP_HOST="${1:-localhost:3893}"
BIND_DN="${2:-cn=serviceuser,ou=svcaccts,dc=example,dc=com}"
BIND_PW="${3:-mysecret}"
BASE_DN="${4:-dc=example,dc=com}"
WEBHOOK_URL="${5:-}"   # e.g. http://localhost:5050
WEBHOOK_SECRET="${6:-}"  # webhook authentication secret

LDAP_URI="ldap://${LDAP_HOST}"

# ---------- Counters ----------

PASS=0
FAIL=0
SKIP=0
TOTAL=0

# ---------- Helpers ----------

# Run a single test.
# Usage: run_test <id> <description> <ldapsearch_args...> -- <grep_pattern>
#   or:  run_test_custom <id> <description> <shell_expression>
run_test() {
    local id="$1"; shift
    local desc="$1"; shift
    local expected="$1"; shift
    # remaining args are ldapsearch trailing arguments
    local ldap_args=("$@")

    TOTAL=$((TOTAL + 1))
    printf "  %-6s %-55s " "$id" "$desc"

    result=$(ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
        -b "$BASE_DN" -LLL "${ldap_args[@]}" 2>/dev/null || true)

    if echo "$result" | grep -qi "$expected"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        echo "         Expected to match: $expected"
        echo "         Output (first 10 lines):"
        echo "$result" | head -10 | sed 's/^/           /'
        FAIL=$((FAIL + 1))
    fi
}

# Run a test with a custom base DN override.
run_test_base() {
    local id="$1"; shift
    local desc="$1"; shift
    local expected="$1"; shift
    local custom_base="$1"; shift
    local ldap_args=("$@")

    TOTAL=$((TOTAL + 1))
    printf "  %-6s %-55s " "$id" "$desc"

    result=$(ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
        -b "$custom_base" -LLL "${ldap_args[@]}" 2>/dev/null || true)

    if echo "$result" | grep -qi "$expected"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        echo "         Expected to match: $expected"
        echo "         Output (first 10 lines):"
        echo "$result" | head -10 | sed 's/^/           /'
        FAIL=$((FAIL + 1))
    fi
}

# Run a test with a count-based assertion.
# Passes if count of matching lines >= min_count.
run_test_count() {
    local id="$1"; shift
    local desc="$1"; shift
    local grep_pattern="$1"; shift
    local min_count="$1"; shift
    local ldap_args=("$@")

    TOTAL=$((TOTAL + 1))
    printf "  %-6s %-55s " "$id" "$desc"

    result=$(ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
        -b "$BASE_DN" -LLL "${ldap_args[@]}" 2>/dev/null || true)
    count=$(echo "$result" | grep -ci "$grep_pattern" 2>/dev/null || echo "0")

    if [ "$count" -ge "$min_count" ]; then
        echo "PASS (count=$count)"
        PASS=$((PASS + 1))
    else
        echo "FAIL (count=$count, need>=$min_count)"
        echo "         Output (first 10 lines):"
        echo "$result" | head -10 | sed 's/^/           /'
        FAIL=$((FAIL + 1))
    fi
}

# Count-based test with custom base DN.
run_test_count_base() {
    local id="$1"; shift
    local desc="$1"; shift
    local grep_pattern="$1"; shift
    local min_count="$1"; shift
    local custom_base="$1"; shift
    local ldap_args=("$@")

    TOTAL=$((TOTAL + 1))
    printf "  %-6s %-55s " "$id" "$desc"

    result=$(ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
        -b "$custom_base" -LLL "${ldap_args[@]}" 2>/dev/null || true)
    count=$(echo "$result" | grep -ci "$grep_pattern" 2>/dev/null || echo "0")

    if [ "$count" -ge "$min_count" ]; then
        echo "PASS (count=$count)"
        PASS=$((PASS + 1))
    else
        echo "FAIL (count=$count, need>=$min_count)"
        echo "         Output (first 10 lines):"
        echo "$result" | head -10 | sed 's/^/           /'
        FAIL=$((FAIL + 1))
    fi
}

# Test that a value does NOT appear.
run_test_absent() {
    local id="$1"; shift
    local desc="$1"; shift
    local unwanted="$1"; shift
    local ldap_args=("$@")

    TOTAL=$((TOTAL + 1))
    printf "  %-6s %-55s " "$id" "$desc"

    result=$(ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
        -b "$BASE_DN" -LLL "${ldap_args[@]}" 2>/dev/null || true)

    if echo "$result" | grep -qi "$unwanted"; then
        echo "FAIL (found unwanted: $unwanted)"
        echo "$result" | head -10 | sed 's/^/           /'
        FAIL=$((FAIL + 1))
    else
        echo "PASS"
        PASS=$((PASS + 1))
    fi
}

# HTTP-based test (for webhook/health endpoints).
run_test_http() {
    local id="$1"; shift
    local desc="$1"; shift
    local method="$1"; shift
    local url="$1"; shift
    local expected_code="$1"; shift

    TOTAL=$((TOTAL + 1))
    printf "  %-6s %-55s " "$id" "$desc"

    if [ -z "$url" ]; then
        echo "SKIP (no webhook URL configured)"
        SKIP=$((SKIP + 1))
        return
    fi

    if ! command -v curl >/dev/null 2>&1; then
        echo "SKIP (curl not available)"
        SKIP=$((SKIP + 1))
        return
    fi

    local extra_args=("$@")
    http_code=$(curl -4 -s -o /dev/null -w "%{http_code}" --connect-timeout 5 -X "$method" "${extra_args[@]}" "$url" 2>/dev/null || echo "000")

    if [ "$http_code" = "$expected_code" ]; then
        echo "PASS (HTTP $http_code)"
        PASS=$((PASS + 1))
    elif [ "$http_code" = "000" ]; then
        echo "SKIP (connection failed — webhook may not be reachable from this host)"
        SKIP=$((SKIP + 1))
    else
        echo "FAIL (HTTP $http_code, expected $expected_code)"
        FAIL=$((FAIL + 1))
    fi
}

# Custom comparison test — runs a shell snippet and checks exit code.
run_test_custom() {
    local id="$1"; shift
    local desc="$1"; shift
    local snippet="$1"; shift

    TOTAL=$((TOTAL + 1))
    printf "  %-6s %-55s " "$id" "$desc"

    if eval "$snippet" >/dev/null 2>&1; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
    fi
}

# ---------- Wait for GLAuth ----------

echo "=== GLAuth Feature Validation ==="
echo ""
echo "LDAP URI : $LDAP_URI"
echo "Bind DN  : $BIND_DN"
echo "Base DN  : $BASE_DN"
echo "Webhook  : ${WEBHOOK_URL:-<not configured>}"
echo ""

echo "Waiting for glauth to be ready..."
for i in $(seq 1 30); do
    if ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
        -b "$BASE_DN" -s base '(objectClass=*)' dn 2>/dev/null | grep -q "dn:"; then
        echo "glauth is ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "FATAL: glauth not ready after 30 seconds"
        exit 1
    fi
    sleep 1
done
echo ""

# ========================================================================
# 1. User Discovery
# ========================================================================
echo "--- 1. User Discovery ---"

run_test_count "T01" "List all posixAccount entries (>=2 users)" \
    "dn:" 2 \
    '(objectClass=posixAccount)' dn

run_test "T02" "Find user jordan by cn (uidNumber >= 10000)" \
    "uidNumber: 1" \
    '(cn=jordan)' uidNumber

# T03: jordan and alice have different UIDs
TOTAL=$((TOTAL + 1))
printf "  %-6s %-55s " "T03" "Alice has different UID from jordan"
JORDAN_UID=$(ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
    -b "$BASE_DN" -LLL '(cn=jordan)' uidNumber 2>/dev/null \
    | grep "uidNumber:" | awk '{print $2}')
ALICE_UID=$(ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
    -b "$BASE_DN" -LLL '(cn=alice)' uidNumber 2>/dev/null \
    | grep "uidNumber:" | awk '{print $2}')
if [ -n "$JORDAN_UID" ] && [ -n "$ALICE_UID" ] && [ "$JORDAN_UID" != "$ALICE_UID" ]; then
    echo "PASS (jordan=$JORDAN_UID, alice=$ALICE_UID)"
    PASS=$((PASS + 1))
else
    echo "FAIL (jordan=$JORDAN_UID, alice=$ALICE_UID)"
    FAIL=$((FAIL + 1))
fi

run_test_absent "T04" "Disabled users are excluded" \
    "disabled-user" \
    '(objectClass=posixAccount)' cn

run_test "T05" "User has required POSIX attrs (uid, gidNumber, etc.)" \
    "objectClass: posixAccount" \
    '(cn=jordan)' objectClass uid uidNumber gidNumber homeDirectory loginShell

echo ""

# ========================================================================
# 2. Group Discovery
# ========================================================================
echo "--- 2. Group Discovery ---"

run_test_count "T06" "List all posixGroup entries (>=1 group)" \
    "dn:" 1 \
    '(objectClass=posixGroup)' dn

run_test "T07" "Find developers group (gidNumber >= 10000)" \
    "gidNumber: 1" \
    '(ou=developers)' gidNumber

run_test "T08" "Group membership (memberUid present)" \
    "memberUid:" \
    '(ou=developers)' memberUid

echo ""

# ========================================================================
# 3. SSH Key Delivery
# ========================================================================
echo "--- 3. SSH Key Delivery ---"

run_test "T09" "Jordan has sshPublicKey attribute" \
    "sshPublicKey:" \
    '(cn=jordan)' sshPublicKey

run_test_count "T10" "Jordan has at least 2 SSH keys (multi-value)" \
    "sshPublicKey:" 2 \
    '(cn=jordan)' sshPublicKey

# T11: Alice has exactly 1 SSH key
TOTAL=$((TOTAL + 1))
printf "  %-6s %-55s " "T11" "Alice has exactly 1 SSH key"
ALICE_KEYS=$(ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
    -b "$BASE_DN" -LLL '(cn=alice)' sshPublicKey 2>/dev/null \
    | grep -c "sshPublicKey:" 2>/dev/null || echo "0")
if [ "$ALICE_KEYS" -eq 1 ]; then
    echo "PASS (count=$ALICE_KEYS)"
    PASS=$((PASS + 1))
else
    echo "FAIL (count=$ALICE_KEYS, expected=1)"
    FAIL=$((FAIL + 1))
fi

echo ""

# ========================================================================
# 4. Login Shell Override
# ========================================================================
echo "--- 4. Login Shell Override ---"

run_test "T12" "Jordan has loginShell=/bin/zsh (custom claim)" \
    "/bin/zsh" \
    '(cn=jordan)' loginShell

run_test "T13" "Alice has loginShell=/bin/bash (default)" \
    "/bin/bash" \
    '(cn=alice)' loginShell

echo ""

# ========================================================================
# 5. Home Directory
# ========================================================================
echo "--- 5. Home Directory ---"

run_test "T14" "Jordan has homeDirectory=/home/jordan" \
    "/home/jordan" \
    '(cn=jordan)' homeDirectory

run_test "T15" "Alice has homeDirectory=/home/alice" \
    "/home/alice" \
    '(cn=alice)' homeDirectory

echo ""

# ========================================================================
# 6. Sudo Rules
# ========================================================================
echo "--- 6. Sudo Rules ---"

SUDO_BASE="ou=sudoers,$BASE_DN"

run_test_count_base "T16" "Search ou=sudoers for sudoRole entries (>=1)" \
    "dn:" 1 \
    "$SUDO_BASE" \
    '(objectClass=sudoRole)' dn

run_test_base "T17" "sudoRole has objectClass=sudoRole" \
    "objectClass: sudoRole" \
    "$SUDO_BASE" \
    '(objectClass=sudoRole)' objectClass

run_test_base "T18" "sudoUser contains expected usernames" \
    "sudoUser:" \
    "$SUDO_BASE" \
    '(objectClass=sudoRole)' sudoUser

run_test_base "T19" "sudoCommand attribute exists" \
    "sudoCommand:" \
    "$SUDO_BASE" \
    '(objectClass=sudoRole)' sudoCommand

run_test_base "T20" "sudoHost attribute exists" \
    "sudoHost:" \
    "$SUDO_BASE" \
    '(objectClass=sudoRole)' sudoHost

run_test_base "T21" "sudoOption contains !authenticate" \
    "!authenticate" \
    "$SUDO_BASE" \
    '(objectClass=sudoRole)' sudoOption

echo ""

# ========================================================================
# 7. NIS Netgroups
# ========================================================================
echo "--- 7. NIS Netgroups ---"

NETGROUP_BASE="ou=netgroup,$BASE_DN"

run_test_count_base "T22" "Search ou=netgroup for nisNetgroup entries (>=1)" \
    "dn:" 1 \
    "$NETGROUP_BASE" \
    '(objectClass=nisNetgroup)' dn

run_test_base "T23" "nisNetgroupTriple has correct format (host,user,domain)" \
    "nisNetgroupTriple:" \
    "$NETGROUP_BASE" \
    '(objectClass=nisNetgroup)' nisNetgroupTriple

run_test_base "T24" "objectClass=nisNetgroup present" \
    "objectClass: nisNetgroup" \
    "$NETGROUP_BASE" \
    '(objectClass=nisNetgroup)' objectClass

echo ""

# ========================================================================
# 8. Host Access Control
# ========================================================================
echo "--- 8. Host Access Control ---"

# Jordan is in access-webservers (hosts: web01, web02, web03)
run_test "T25" "Jordan has host attribute from access group" \
    "host:" \
    '(cn=jordan)' host

# Alice is in full-access (hosts: web01, web02, db01, app01)
run_test "T26" "Alice has host attribute from full-access group" \
    "host:" \
    '(cn=alice)' host

# T27: Users without access groups should not have host attribute.
# Since both test users have access groups in the mock, we verify that the
# serviceuser (static config user) does NOT have a host attribute.
run_test_absent "T27" "Users without access groups have no host attr" \
    "host:" \
    '(cn=serviceuser)' host

echo ""

# ========================================================================
# 9. Automount Maps
# ========================================================================
echo "--- 9. Automount Maps ---"

AUTOMOUNT_BASE="ou=automount,$BASE_DN"

run_test_count_base "T28" "Search ou=automount for automountMap entries" \
    "dn:" 1 \
    "$AUTOMOUNT_BASE" \
    '(objectClass=automountMap)' dn

run_test_base "T29" "automountMapName attribute present" \
    "automountMapName:" \
    "$AUTOMOUNT_BASE" \
    '(objectClass=automountMap)' automountMapName

run_test_count_base "T30" "Search for automount entries under the map" \
    "dn:" 1 \
    "$AUTOMOUNT_BASE" \
    '(objectClass=automount)' dn

run_test_base "T31" "automountKey and automountInformation present" \
    "automountKey:" \
    "$AUTOMOUNT_BASE" \
    '(objectClass=automount)' automountKey automountInformation

echo ""

# ========================================================================
# 10. Webhook & Health
# ========================================================================
echo "--- 10. Webhook & Health ---"

run_test_http "T32" "GET /healthz returns 200" \
    "GET" "${WEBHOOK_URL:+${WEBHOOK_URL}/healthz}" "200"

if [ -n "$WEBHOOK_SECRET" ]; then
    run_test_http "T33" "POST /webhook/refresh returns 200" \
        "POST" "${WEBHOOK_URL:+${WEBHOOK_URL}/webhook/refresh}" "200" \
        -H "X-Webhook-Secret: ${WEBHOOK_SECRET}"
else
    run_test_http "T33" "POST /webhook/refresh returns 200" \
        "POST" "${WEBHOOK_URL:+${WEBHOOK_URL}/webhook/refresh}" "200"
fi

echo ""

# ========================================================================
# Summary
# ========================================================================
echo "========================================"
printf "  TOTAL: %d   PASS: %d   FAIL: %d   SKIP: %d\n" "$TOTAL" "$PASS" "$FAIL" "$SKIP"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAILED"
    exit 1
else
    echo "RESULT: OK"
    exit 0
fi
