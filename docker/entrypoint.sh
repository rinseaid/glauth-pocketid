#!/bin/sh
set -e

CONFIG_PATH="/etc/glauth/glauth.cfg"
TEMPLATE_PATH="/etc/glauth/glauth.cfg.tmpl"

# If the user wants to use a mounted config file, skip templating.
if [ "$GLAUTH_SKIP_TEMPLATE" = "true" ]; then
    exec /app/glauth -c "$CONFIG_PATH"
fi

# Apply defaults for optional variables
export GLAUTH_DEBUG="${GLAUTH_DEBUG:-false}"
export GLAUTH_LDAP_PORT="${GLAUTH_LDAP_PORT:-3893}"
export GLAUTH_BASEDN="${GLAUTH_BASEDN:-dc=example,dc=com}"
export GLAUTH_SERVICE_USER="${GLAUTH_SERVICE_USER:-serviceuser}"
export GLAUTH_SERVICE_GROUP="${GLAUTH_SERVICE_GROUP:-svcaccts}"
export GLAUTH_SERVICE_UIDNUMBER="${GLAUTH_SERVICE_UIDNUMBER:-9000}"
export GLAUTH_SERVICE_GIDNUMBER="${GLAUTH_SERVICE_GIDNUMBER:-9000}"

# Validate env vars to prevent TOML injection via newlines or quotes.
# envsubst does raw text substitution with no escaping — a newline or quote
# in any variable can inject arbitrary TOML directives.
for var in GLAUTH_DEBUG GLAUTH_LDAP_PORT GLAUTH_BASEDN GLAUTH_SERVICE_USER \
           GLAUTH_SERVICE_GROUP GLAUTH_SERVICE_UIDNUMBER GLAUTH_SERVICE_GIDNUMBER; do
    val=$(eval echo "\"\$$var\"")
    case "$val" in
        *"
"*|*'"'*|*'\\'*)
            echo "ERROR: $var contains newline, quote, or backslash — rejected to prevent config injection" >&2
            exit 1
            ;;
    esac
done

# Validate boolean
case "$GLAUTH_DEBUG" in
    true|false) ;;
    *) echo "ERROR: GLAUTH_DEBUG must be 'true' or 'false', got '$GLAUTH_DEBUG'" >&2; exit 1 ;;
esac

# Validate integers
for var in GLAUTH_LDAP_PORT GLAUTH_SERVICE_UIDNUMBER GLAUTH_SERVICE_GIDNUMBER; do
    val=$(eval echo "\"\$$var\"")
    case "$val" in
        ''|*[!0-9]*) echo "ERROR: $var must be a positive integer, got '$val'" >&2; exit 1 ;;
    esac
done

# Handle service account password
if [ -z "$GLAUTH_SERVICE_PASSWORD_SHA256" ]; then
    if [ -n "$GLAUTH_SERVICE_PASSWORD" ]; then
        GLAUTH_SERVICE_PASSWORD_SHA256=$(printf '%s' "$GLAUTH_SERVICE_PASSWORD" | sha256sum | awk '{print $1}')
        export GLAUTH_SERVICE_PASSWORD_SHA256
    else
        echo "ERROR: Set GLAUTH_SERVICE_PASSWORD_SHA256 (or GLAUTH_SERVICE_PASSWORD) for the LDAP service account" >&2
        exit 1
    fi
fi

# Validate SHA256 hash is hex-only
case "$GLAUTH_SERVICE_PASSWORD_SHA256" in
    *[!0-9a-fA-F]*) echo "ERROR: GLAUTH_SERVICE_PASSWORD_SHA256 must be a hex string" >&2; exit 1 ;;
esac

# Generate config from template with restricted umask and explicit variable list
umask 0077
envsubst '${GLAUTH_DEBUG} ${GLAUTH_LDAP_PORT} ${GLAUTH_BASEDN} ${GLAUTH_SERVICE_USER} ${GLAUTH_SERVICE_GROUP} ${GLAUTH_SERVICE_UIDNUMBER} ${GLAUTH_SERVICE_GIDNUMBER} ${GLAUTH_SERVICE_PASSWORD_SHA256}' \
    < "$TEMPLATE_PATH" > "$CONFIG_PATH"

# Clear plaintext password from environment before exec
unset GLAUTH_SERVICE_PASSWORD

exec /app/glauth -c "$CONFIG_PATH"
