#!/bin/bash
set -e

# Seed a real Pocket ID instance with test data for the full-stack test.
# This script:
# 1. Creates an admin user + API key directly in the database
# 2. Uses the REST API to create test users, groups, and an OIDC client

POCKET_ID_URL="${1:-http://localhost:1411}"
API_KEY="test-api-key-for-fullstack"
API_KEY_HASH=$(echo -n "$API_KEY" | sha256sum | awk '{print $1}')

echo "=== Seeding Pocket ID at $POCKET_ID_URL ==="

# Wait for Pocket ID to be ready
echo "Waiting for Pocket ID..."
for i in $(seq 1 60); do
    if curl -sf "$POCKET_ID_URL/" >/dev/null 2>&1; then
        echo "Pocket ID is ready."
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "FAIL: Pocket ID not ready after 60 seconds"
        exit 1
    fi
    sleep 1
done

# Step 1: Seed admin user and API key via database
echo ""
echo "--- Step 1: Creating admin user and API key in database ---"

docker compose exec -T pocket-id-db psql -U pocketid -d pocketid <<SQL
INSERT INTO users (id, username, email, first_name, last_name, display_name, is_admin, created_at, updated_at, email_verified)
VALUES ('a0000001-0000-0000-0000-000000000001', 'admin', 'admin@example.com', 'Admin', 'User', 'Admin User', true, NOW(), NOW(), true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO api_keys (id, name, key, user_id, expires_at, created_at, expiration_email_sent)
VALUES ('a0000002-0000-0000-0000-000000000002', 'test-key', '$API_KEY_HASH', 'a0000001-0000-0000-0000-000000000001', NOW() + INTERVAL '10 years', NOW(), false)
ON CONFLICT (id) DO NOTHING;
SQL

echo "Admin user and API key created."

# Helper: create user, return ID on stdout, status on stderr
create_user() {
    local username="$1" email="$2" first="$3" last="$4"
    resp=$(curl -sf -X POST "$POCKET_ID_URL/api/users" \
        -H "X-API-KEY: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$username\",\"email\":\"$email\",\"firstName\":\"$first\",\"lastName\":\"$last\"}" 2>&1) || true
    if echo "$resp" | grep -q '"id"'; then
        local uid=$(echo "$resp" | jq -r '.id')
        echo "  Created user $username ($uid)" >&2
        echo "$uid"
        return
    fi
    # User might already exist
    existing=$(curl -sf "$POCKET_ID_URL/api/users?pagination[page]=1&pagination[limit]=100" \
        -H "X-API-KEY: $API_KEY" | jq -r ".data[] | select(.username==\"$username\") | .id" 2>/dev/null)
    if [ -n "$existing" ]; then
        echo "  User $username already exists ($existing)" >&2
        echo "$existing"
    else
        echo "  FAILED to create user $username: $resp" >&2
    fi
}

# Helper: create group, return ID on stdout
create_group() {
    local name="$1"
    local friendly="${2:-$1}"
    resp=$(curl -sf -X POST "$POCKET_ID_URL/api/user-groups" \
        -H "X-API-KEY: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"$name\",\"friendlyName\":\"$friendly\"}" 2>&1) || true
    if echo "$resp" | grep -q '"id"'; then
        local gid=$(echo "$resp" | jq -r '.id')
        echo "  Created group $name ($gid)" >&2
        echo "$gid"
        return
    fi
    # Group might already exist
    existing=$(curl -sf "$POCKET_ID_URL/api/user-groups?pagination[page]=1&pagination[limit]=100" \
        -H "X-API-KEY: $API_KEY" | jq -r ".data[] | select(.name==\"$name\") | .id" 2>/dev/null)
    if [ -n "$existing" ]; then
        echo "  Group $name already exists ($existing)" >&2
        echo "$existing"
    else
        echo "  FAILED to create group $name: $resp" >&2
    fi
}

add_members() {
    local group_id="$1"
    shift
    local user_ids=("$@")
    local json_ids=$(printf '"%s",' "${user_ids[@]}" | sed 's/,$//')
    curl -sf -X PUT "$POCKET_ID_URL/api/user-groups/$group_id/users" \
        -H "X-API-KEY: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"userIds\":[$json_ids]}" >/dev/null 2>&1 && echo "  Members added to group $group_id" || echo "  Failed to add members to $group_id"
}

set_claims() {
    local type="$1" id="$2"
    shift 2
    local claims="$@"
    curl -sf -X PUT "$POCKET_ID_URL/api/custom-claims/$type/$id" \
        -H "X-API-KEY: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$claims" >/dev/null 2>&1 && echo "  Claims set for $type $id" || echo "  Failed to set claims for $type $id"
}

# Step 2: Create test users
echo ""
echo "--- Step 2: Creating test users ---"
TESTUSER_ID=$(create_user "testuser" "testuser@example.com" "Test" "User")
ALICE_ID=$(create_user "alice" "alice@example.com" "Alice" "Smith")
BOB_ID=$(create_user "bob" "bob@example.com" "Bob" "Jones")

# Step 3: Set custom claims (SSH keys)
echo ""
echo "--- Step 3: Setting SSH keys via custom claims ---"
[ -n "$TESTUSER_ID" ] && set_claims "user" "$TESTUSER_ID" '[
    {"key":"sshPublicKey","value":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyForFullStackTestEnvironment testuser@test"},
    {"key":"loginShell","value":"/bin/zsh"}
]'
[ -n "$ALICE_ID" ] && set_claims "user" "$ALICE_ID" '[
    {"key":"sshPublicKey","value":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceTestKeyForFullStackTest alice@test"}
]'

# Step 4: Create groups and add members
echo ""
echo "--- Step 4: Creating groups ---"
DEVS_ID=$(create_group "developers" "Developers")
SUDO_ALL_ID=$(create_group "sudo-all" "Sudo ALL")
SERVER_ACCESS_ID=$(create_group "server-access" "Server Access")

echo ""
echo "--- Adding members to groups ---"
[ -n "$DEVS_ID" ] && [ -n "$TESTUSER_ID" ] && [ -n "$ALICE_ID" ] && [ -n "$BOB_ID" ] && \
    add_members "$DEVS_ID" "$TESTUSER_ID" "$ALICE_ID" "$BOB_ID"
[ -n "$SUDO_ALL_ID" ] && [ -n "$TESTUSER_ID" ] && [ -n "$ALICE_ID" ] && \
    add_members "$SUDO_ALL_ID" "$TESTUSER_ID" "$ALICE_ID"
[ -n "$SERVER_ACCESS_ID" ] && [ -n "$TESTUSER_ID" ] && \
    add_members "$SERVER_ACCESS_ID" "$TESTUSER_ID"

# Set sudo claims
echo ""
echo "--- Setting sudo claims ---"
[ -n "$SUDO_ALL_ID" ] && set_claims "user-group" "$SUDO_ALL_ID" '[
    {"key":"sudoCommands","value":"ALL"},
    {"key":"sudoHosts","value":"ALL"},
    {"key":"sudoRunAsUser","value":"ALL"}
]'

# Step 5: Create OIDC client for pam-pocketid
echo ""
echo "--- Step 5: Creating OIDC client for pam-pocketid ---"

OIDC_CLIENT_SECRET="test-client-secret-for-fullstack"

OIDC_RESP=$(curl -sf -X POST "$POCKET_ID_URL/api/oidc/clients" \
    -H "X-API-KEY: $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "pam-pocketid",
        "callbackURLs": ["http://localhost:8090/callback"],
        "logoutCallbackURLs": [],
        "isPublic": false
    }' 2>&1) || true

if echo "$OIDC_RESP" | grep -q '"id"'; then
    OIDC_CLIENT_ID=$(echo "$OIDC_RESP" | jq -r '.id')
    echo "  OIDC client created: $OIDC_CLIENT_ID"

    # Set the client secret in DB (Pocket ID stores OIDC secrets as bcrypt hashes)
    OIDC_SECRET_HASH=$(docker run --rm python:3-alpine sh -c \
        "pip install bcrypt -q 2>/dev/null && python -c \"import bcrypt; print(bcrypt.hashpw(b'$OIDC_CLIENT_SECRET', bcrypt.gensalt()).decode())\"" 2>/dev/null)
    docker compose exec -T pocket-id-db psql -U pocketid -d pocketid -c \
        "UPDATE oidc_clients SET secret = '$OIDC_SECRET_HASH' WHERE id = '$OIDC_CLIENT_ID';" >/dev/null 2>&1
    echo "  Client secret set: $OIDC_CLIENT_SECRET"

    # Update docker-compose.yml with the client ID
    if [ -f "$COMPOSE_FILE" ]; then
        sed -i '' "s|PAM_POCKETID_CLIENT_ID:.*|PAM_POCKETID_CLIENT_ID: \"$OIDC_CLIENT_ID\"|" "$COMPOSE_FILE"
        echo "  Updated docker-compose.yml with client ID"
    fi
else
    echo "  OIDC client creation response: $OIDC_RESP"
    echo "  You may need to create the OIDC client manually in Pocket ID admin UI"
fi

echo ""
echo "=== Seed complete ==="
echo ""
echo "Next steps:"
echo "  1. Wait ~30s for glauth to sync"
echo "  2. Run: docker compose exec sssd-client /test.sh"
echo ""
echo "  To restart pam-pocketid with OIDC credentials:"
echo "    docker compose up -d pam-pocketid"
echo ""
echo "  To test sudo with pam-pocketid:"
echo "    docker compose exec sssd-client su - testuser"
echo "    testuser$ sudo whoami"
