# glauth-pocketid

A [GLAuth](https://github.com/glauth/glauth) plugin backend that bridges [Pocket ID](https://github.com/pocket-id/pocket-id) to LDAP, enabling sssd-based Linux host authentication with SSH key delivery, sudo rule synthesis, and more.

## Features

- **SSH key delivery** — Public keys from Pocket ID custom claims via `sshPublicKey` LDAP attribute (up to 99 keys per user)
- **Sudo rules** — Claims-based `sudoRole` synthesis from group attributes
- **NIS netgroups** — Claims-based `nisNetgroup` entries for host/user grouping
- **Host access control** — Claims-based `host` attribute for sssd access restrictions
- **Automount maps** — Claims-based `automountMap`/`automount` entries for NFS mounts
- **Login time windows** — Per-user schedule restrictions via `allowedLoginHours`
- **Stable UID/GID** — Persisted UUID-to-integer mapping survives restarts
- **Webhook refresh** — HTTP endpoint for instant sync triggers
- **Prometheus metrics** — Sync duration, error counts, entity totals
- **No passwords** — Designed for passkey/MFA-only authentication at the IDP layer

## Architecture

```
+-----------------+                +------------------------------+             +---------------+
|                 |   REST API     |                              |    LDAP     |               |
| Pocket ID       |<===============|  GLAuth + pocketid.so        |<============| Linux hosts   |
|                 |  sync every Ns |                              |  port 3893  | (sssd)        |
|                 |                |                              |             |               |
|  /api/users     |                |  Users  --> posixAccount     |             | getent        |
|  /api/user-     |                |  Groups --> posixGroup       |             | ssh keys      |
|    groups       |                |  Claims --> sudoRole         |             | sudo rules    |
|                 |                |  Claims --> nisNetgroup      |             | netgroups     |
|                 |                |  Claims --> automount        |             | automount     |
|                 |                |                              |             | host access   |
+-----------------+                +------------------------------+             +---------------+
```

## Quick start

Pull the pre-built container from GitHub Container Registry:

```yaml
services:
  glauth:
    image: ghcr.io/rinseaid/glauth-pocketid:latest
    ports:
      - "3893:3893"
      - "8080:8080"
    environment:
      GLAUTH_BASEDN: "dc=example,dc=com"
      GLAUTH_SERVICE_PASSWORD: "your-service-password"
      POCKETID_BASE_URL: "https://id.example.com"
      POCKETID_API_KEY: "your-pocket-id-api-key"
      POCKETID_WEBHOOK_PORT: "8080"
    volumes:
      - glauth-data:/var/lib/glauth
    restart: unless-stopped

volumes:
  glauth-data:
```

```bash
docker compose up -d
```

The container generates `glauth.cfg` from environment variables at startup. To use a custom config file instead, mount it at `/etc/glauth/glauth.cfg` and set `GLAUTH_SKIP_TEMPLATE=true`.

### Verify it works

```bash
ldapsearch -x -H ldap://localhost:3893 \
  -D "cn=serviceuser,ou=svcaccts,dc=example,dc=com" \
  -w 'your-service-password' \
  -b "dc=example,dc=com" "(objectClass=posixAccount)"
```

## GLAuth configuration

The container includes a default [`glauth.cfg.example`](glauth.cfg.example). Mount your own config at `/etc/glauth/glauth.cfg`. Key settings:

```toml
[backend]
  datastore     = "plugin"
  plugin        = "/app/pocketid.so"
  pluginhandler = "NewPocketIDHandler"
  baseDN        = "dc=example,dc=com"
  nameformat    = "cn"
  groupformat   = "ou"
  sshkeyattr    = "sshPublicKey"
  anonymousdse  = true

[behaviors]
  IgnoreCapabilities = false
```

### Environment variables

#### GLAuth config

The container generates `glauth.cfg` from these variables at startup. Set `GLAUTH_SKIP_TEMPLATE=true` to use a mounted config file instead.

| Variable | Default | Description |
|---|---|---|
| `GLAUTH_BASEDN` | `dc=example,dc=com` | LDAP base DN |
| `GLAUTH_SERVICE_PASSWORD` | *(required\*)* | Service account password (plaintext, hashed at startup) |
| `GLAUTH_SERVICE_PASSWORD_SHA256` | *(required\*)* | Service account password (pre-hashed SHA-256) |
| `GLAUTH_SERVICE_USER` | `serviceuser` | Service account username |
| `GLAUTH_SERVICE_GROUP` | `svcaccts` | Service account group name |
| `GLAUTH_SERVICE_UIDNUMBER` | `9000` | Service account UID |
| `GLAUTH_SERVICE_GIDNUMBER` | `9000` | Service account GID |
| `GLAUTH_LDAP_PORT` | `3893` | LDAP listen port |
| `GLAUTH_DEBUG` | `false` | Enable debug logging |
| `GLAUTH_SKIP_TEMPLATE` | `false` | Skip config generation, use mounted file |

\* Provide either `GLAUTH_SERVICE_PASSWORD` or `GLAUTH_SERVICE_PASSWORD_SHA256`.

#### Plugin config

| Variable | Default | Description |
|---|---|---|
| `POCKETID_BASE_URL` | *(required)* | Pocket ID base URL |
| `POCKETID_API_KEY` | *(required)* | Pocket ID admin API key |
| `POCKETID_REFRESH_SEC` | `300` | Seconds between syncs |
| `POCKETID_UID_BASE` | `10000` | Starting UID for auto-assignment |
| `POCKETID_GID_BASE` | `10000` | Starting GID for auto-assignment |
| `POCKETID_DEFAULT_SHELL` | `/bin/bash` | Default login shell |
| `POCKETID_DEFAULT_HOME` | `/home/{username}` | Home directory template |
| `POCKETID_PERSIST_PATH` | `/var/lib/glauth/uidmap.json` | Path to UID/GID persistence file |
| `POCKETID_WEBHOOK_PORT` | `0` (disabled) | Port for webhook/metrics HTTP server |
| `POCKETID_WEBHOOK_SECRET` | *(empty)* | Shared secret for webhook authentication |
| `POCKETID_SUDO_NO_AUTHENTICATE` | `false` | Sudo auth policy: `false` / `true` / `claims` (see [Sudo authentication](#sudo-authentication)) |

## Configuring Linux hosts

Install sssd and configure it to use GLAuth as the LDAP backend. See [`sssd.conf.example`](sssd.conf.example) for a complete configuration.

```bash
sudo cp sssd.conf.example /etc/sssd/sssd.conf
sudo chmod 0600 /etc/sssd/sssd.conf
# Edit ldap_uri, ldap_search_base, bind DN, and password
sudo systemctl restart sssd
```

Key sssd settings for GLAuth compatibility:
- `ldap_schema = rfc2307`
- `ldap_group_name = ou`
- `ldap_group_member = memberUid`
- `auth_provider = none` (Pocket ID handles authentication)

### SSH key delivery

Add to `/etc/ssh/sshd_config`:
```
AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys %u
AuthorizedKeysCommandUser root
PubkeyAuthentication yes
PasswordAuthentication no
```

### NSS and PAM

`/etc/nsswitch.conf`:
```
passwd:  files sss
group:   files sss
shadow:  files sss
sudoers: files sss
```

Auto-create home directories — add to `/etc/pam.d/common-session`:
```
session optional pam_mkhomedir.so skel=/etc/skel umask=0077
```

## Pocket ID setup

1. Create an admin API key in Pocket ID (Settings > Admin API, or set `STATIC_API_KEY` env var)
2. Add custom claims to users for SSH keys (`sshPublicKey`, `sshPublicKey2`, etc.)
3. Add custom claims to groups for sudo rules, netgroups, access control, etc.

> **Note**: Pocket ID custom claims are arrays of `{key, value}` objects.

## Custom claims reference

All features are **claims-based** — any group with the relevant custom claims is automatically recognized regardless of its name.

### User claims

| Claim key | Description |
|---|---|
| `sshPublicKey`, `sshPublicKey1` ... `sshPublicKey99` | SSH public keys |
| `loginShell` | Override default login shell |
| `uidNumber` | Override auto-assigned UID |
| `allowedLoginHours` | Login time windows (see below) |

### Sudo rules

Any group with a `sudoCommands` claim becomes a `sudoRole` LDAP entry. The `sudoCommands` claim is **required** — groups without it are skipped to prevent accidentally granting unrestricted access.

| Claim key | Default | Required | Description |
|---|---|---|---|
| `sudoCommands` | *(none)* | **Yes** | Allowed commands (comma-separated) |
| `sudoHosts` | `ALL` | No | Hosts where the rule applies |
| `sudoRunAsUser` | `root` | No | Target user |
| `sudoRunAsGroup` | *(omitted)* | No | Target group |
| `sudoOptions` | *(none)* | No | Additional sudo options (see below) |

**Example — full sudo:**
```
Group: full-admins     Claims: sudoCommands=ALL, sudoHosts=ALL, sudoRunAsUser=ALL
```

**Example — restricted:**
```
Group: ops-team        Claims: sudoCommands=/usr/bin/systemctl restart *,/usr/bin/journalctl
```

### Sudo authentication

When a user runs `sudo`, the sudo rules define *what* they can do. But sudo also needs to verify *who they are* before proceeding. This is controlled by the `!authenticate` sudo option and the `POCKETID_SUDO_NO_AUTHENTICATE` env var.

**How sudo authentication works:**

1. sssd delivers `sudoRole` entries from GLAuth to the host
2. sudo checks if the user matches a rule (commands, hosts, run-as user)
3. If the rule has `!authenticate`, sudo runs the command immediately — no verification
4. If the rule does NOT have `!authenticate`, sudo invokes the PAM auth stack

**What this means in practice:**

| `POCKETID_SUDO_NO_AUTHENTICATE` | What happens when user runs `sudo` | Best for |
|---|---|---|
| `false` (default) | Sudo invokes PAM. Install [pam-pocketid](https://github.com/rinseaid/pam-pocketid) for browser-based passkey approval, or another PAM module. | **Recommended** — per-invocation user verification via passkey |
| `true` | Sudo runs immediately, no authentication. `!authenticate` is added to every rule. | Convenience / non-interactive automation (less secure) |
| `claims` | Per-group control. Groups with `sudoOptions=!authenticate` skip auth; groups without it invoke PAM. | Mixed environments — some groups need quick access, others need verification |

**With `false` + pam-pocketid (recommended):**

The user runs `sudo`, sees a URL and approval code, opens it in a browser, taps their passkey, and sudo proceeds. No passwords anywhere — but the user explicitly authenticates each time. This is the most secure option because it provides per-invocation identity verification.

**With `claims` (per-group):**

```
Group: automation-bots   Claims: sudoCommands=ALL, sudoOptions=!authenticate
Group: full-admins       Claims: sudoCommands=ALL
```

Here `automation-bots` skips authentication (for CI/CD or scripts), while `full-admins` still requires passkey approval via PAM. The `sudoOptions=!authenticate` claim is only accepted when `POCKETID_SUDO_NO_AUTHENTICATE=claims` — otherwise it is silently stripped for security.

> **Security note:** The `sudoOptions` claim is filtered through a blocklist that prevents dangerous options like `env_keep+=LD_PRELOAD`, `setenv`, `!env_reset`, etc. The `!authenticate` option is special-cased: it is only allowed when the server operator explicitly enables it via `POCKETID_SUDO_NO_AUTHENTICATE`.

### NIS netgroups

| Claim key | Description |
|---|---|
| `netgroupHosts` | Comma-separated hostnames |
| `netgroupDomain` | Override NIS domain (default: derived from baseDN) |

### Host-based access control

| Claim key | Description |
|---|---|
| `accessHosts` | Comma-separated hostnames or `ALL` |

Use with sssd: `access_provider = ldap`, `ldap_access_order = host`.

### Automount maps

All three claims are required:

| Claim key | Description | Example |
|---|---|---|
| `automountMapName` | Map name | `auto.home` |
| `automountKey` | Mount key | `*` |
| `automountInformation` | Mount options and source | `-fstype=nfs4 nas:/home/&` |

### Login time windows

User claim `allowedLoginHours`. Format: `HH:MM-HH:MM,Day-Day` (semicolons for multiple windows).

```
08:00-18:00,Mon-Fri          Business hours, weekdays
22:00-06:00                   Night shift, any day
```

## Webhooks and metrics

Set `POCKETID_WEBHOOK_PORT` to enable the HTTP server.

| Endpoint | Method | Description |
|---|---|---|
| `/webhook/refresh` | POST | Trigger immediate sync (requires `X-Webhook-Secret` if configured) |
| `/healthz` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |

## Running tests

```bash
make test
```

## Building from source

The plugin `.so` must be compiled with the **same Go toolchain version** and **same `github.com/glauth/glauth/v2` module** as your GLAuth binary. Go plugins require CGO, so the build host must have a C compiler (`gcc`). Pre-built GLAuth release binaries will not work with this plugin.

The Makefile handles cloning GLAuth at the pinned version into `.glauth-source/`.

```bash
make plugin
```

This produces `bin/linuxamd64/pocketid.so`. To target other platforms:

```bash
make plugin PLUGIN_OS=linux PLUGIN_ARCH=arm64
make plugin PLUGIN_OS=darwin PLUGIN_ARCH=arm64
```

To build a matching GLAuth binary from source:

```bash
make glauth-bin
```

To build the Docker image locally instead of pulling from GHCR:

```bash
docker build -f docker/Dockerfile -t glauth-pocketid .
```

## Example files

| File | Description |
|---|---|
| [`glauth.cfg.example`](glauth.cfg.example) | GLAuth server configuration |
| [`sssd.conf.example`](sssd.conf.example) | sssd client configuration for Linux hosts |
| [`docker-compose.example.yml`](docker-compose.example.yml) | Docker Compose stack |

## Integration with pam-pocketid

[pam-pocketid](https://github.com/rinseaid/pam-pocketid) adds browser-based passkey authentication for `sudo`. The two projects complement each other:

- **glauth-pocketid** defines *what* users can sudo (which commands, on which hosts, as which user) by synthesizing `sudoRole` LDAP entries from Pocket ID group claims
- **pam-pocketid** defines *how* they authenticate when sudo is invoked — via a browser-based passkey flow instead of a password

Without pam-pocketid, you have three options:
1. `POCKETID_SUDO_NO_AUTHENTICATE=false` (default) + another PAM module for authentication
2. `POCKETID_SUDO_NO_AUTHENTICATE=true` to skip authentication entirely (convenient but less secure)
3. `POCKETID_SUDO_NO_AUTHENTICATE=claims` for per-group control via the `sudoOptions` claim

pam-pocketid fills option 1 — sudo invokes PAM, PAM calls pam-pocketid, and the user authenticates with a passkey in their browser. No passwords needed, but each sudo invocation is explicitly approved.

### Running both services together

```yaml
# docker-compose.yml — full stack with LDAP + sudo auth
services:
  glauth:
    image: ghcr.io/rinseaid/glauth-pocketid:latest
    ports:
      - "3893:3893"
      - "8080:8080"
    environment:
      GLAUTH_BASEDN: "dc=example,dc=com"
      GLAUTH_SERVICE_PASSWORD: "your-service-password"
      POCKETID_BASE_URL: "https://id.example.com"
      POCKETID_API_KEY: "your-pocket-id-api-key"
      POCKETID_WEBHOOK_PORT: "8080"
      # Do NOT set POCKETID_SUDO_NO_AUTHENTICATE — let PAM handle auth
    volumes:
      - glauth-data:/var/lib/glauth
    restart: unless-stopped

  pam-pocketid:
    image: ghcr.io/rinseaid/pam-pocketid:latest
    ports:
      - "8090:8090"
    environment:
      PAM_POCKETID_ISSUER_URL: "https://id.example.com"
      PAM_POCKETID_CLIENT_ID: "your-oidc-client-id"
      PAM_POCKETID_CLIENT_SECRET: "your-oidc-client-secret"
      PAM_POCKETID_EXTERNAL_URL: "https://sudo.example.com"
      PAM_POCKETID_SHARED_SECRET: "your-shared-secret"
    restart: unless-stopped

volumes:
  glauth-data:
```

### Pocket ID group setup

Create groups with `sudoCommands` claims but do **not** set `sudoOptions=!authenticate` — instead let PAM invoke pam-pocketid for browser-based approval:

```
Group: full-admins     Claims: sudoCommands=ALL, sudoHosts=ALL, sudoRunAsUser=ALL
Group: ops-team        Claims: sudoCommands=/usr/bin/systemctl restart *,/usr/bin/journalctl
```

### Linux host setup

On each managed host, install the pam-pocketid binary and configure both sssd and PAM:

```bash
# 1. Install the PAM helper
curl -L -o /usr/local/bin/pam-pocketid \
  https://github.com/rinseaid/pam-pocketid/releases/latest/download/pam-pocketid-linux-amd64
chmod +x /usr/local/bin/pam-pocketid

# 2. Configure the helper
cat > /etc/environment.d/pam-pocketid.conf <<EOF
PAM_POCKETID_SERVER_URL=https://sudo.example.com
PAM_POCKETID_SHARED_SECRET=your-shared-secret
EOF

# 3. Configure PAM for sudo — /etc/pam.d/sudo
cat > /etc/pam.d/sudo <<EOF
auth    required    pam_exec.so    expose_authtok stdout /usr/local/bin/pam-pocketid
account required    pam_unix.so
session required    pam_limits.so
EOF
```

sssd configuration remains the same as described in [Configuring Linux hosts](#configuring-linux-hosts) above — sssd handles user/group resolution and sudo rule delivery via LDAP, while PAM handles the authentication step via pam-pocketid.

## Version compatibility

| Component | Version |
|---|---|
| Go | 1.21 (must match between GLAuth and plugin) |
| GLAuth | v2.4.0 (pinned in Makefile and go.mod) |
| Base image | Debian Bookworm (CGO required for plugin support) |
