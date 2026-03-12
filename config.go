package main

import (
	"log"
	"os"
	"strconv"
	"strings"
)

// PluginConfig holds all plugin-specific configuration loaded from environment variables.
type PluginConfig struct {
	BaseURL      string
	APIKey       string
	RefreshSec   int
	UIDBase      int
	GIDBase      int
	DefaultShell string
	DefaultHome  string
	SudoPrefix   string // Deprecated: sudo rules are now claims-based. Kept for backward compat.
	PersistPath  string
	BaseDN       string

	// Feature prefixes (deprecated: features are now claims-based)
	NetgroupPrefix  string
	AccessPrefix    string
	AutomountPrefix string

	// Webhook/metrics
	WebhookPort   int
	WebhookSecret string
	WebhookListen string // bind address for webhook server (default: 127.0.0.1)

	// SudoNoAuthenticate controls the !authenticate sudoOption, which tells
	// sudo to skip PAM authentication entirely (no password, no passkey, nothing).
	//
	// Without !authenticate, sudo invokes the PAM auth stack. If pam-pocketid
	// is installed, this means browser-based passkey approval — no password needed,
	// but the user still explicitly authenticates each sudo invocation.
	//
	// Values:
	//   "false"  (default) — !authenticate blocked; sudo always invokes PAM.
	//                         Use with pam-pocketid for passkey-based sudo auth.
	//   "true"   — !authenticate added to ALL sudo rules; PAM is never invoked.
	//              Convenient but less secure (no per-invocation user verification).
	//   "claims" — !authenticate allowed per-group via the sudoOptions custom claim.
	//              IDP admins can set sudoOptions=!authenticate on specific groups.
	//              Groups without it still require PAM auth.
	SudoNoAuthenticate string
}

func LoadConfig() PluginConfig {
	// Default UID/GID base at 200000 to avoid collisions with:
	// - System accounts (0-999)
	// - Regular local users (1000-60000)
	// - Container/nobody conventions (65534)
	// - Rootless container subuid/subgid ranges (typically 100000-165535)
	// Range 200000+ is safe for directory-provided users in all deployment scenarios.
	uidBase := envOrDefaultInt("POCKETID_UID_BASE", 200000)
	if uidBase < 10000 {
		uidBase = 10000 // prevent overlap with system (0-999) and typical local users (1000-9999)
	}
	gidBase := envOrDefaultInt("POCKETID_GID_BASE", 200000)
	if gidBase < 10000 {
		gidBase = 10000 // prevent overlap with system (0-999) and typical local groups (1000-9999)
	}

	refreshSec := envOrDefaultInt("POCKETID_REFRESH_SEC", 300)
	if refreshSec < 10 {
		refreshSec = 10 // minimum 10 seconds; prevents time.NewTicker panic on <=0
	}
	if refreshSec > 86400 {
		refreshSec = 86400 // cap at 1 day to prevent time.Duration overflow
	}

	cfg := PluginConfig{
		BaseURL:      envOrDefault("POCKETID_BASE_URL", ""),
		APIKey:       envOrDefault("POCKETID_API_KEY", ""),
		RefreshSec:   refreshSec,
		UIDBase:      uidBase,
		GIDBase:      gidBase,
		DefaultShell: validatedShell(envOrDefault("POCKETID_DEFAULT_SHELL", "/bin/bash")),
		DefaultHome:  envOrDefault("POCKETID_DEFAULT_HOME", "/home/{username}"),
		SudoPrefix:   envOrDefault("POCKETID_SUDO_PREFIX", "sudo-"),
		PersistPath:  envOrDefault("POCKETID_PERSIST_PATH", "/var/lib/glauth/uidmap.json"),

		NetgroupPrefix:  envOrDefault("POCKETID_NETGROUP_PREFIX", "netgroup-"),
		AccessPrefix:    envOrDefault("POCKETID_ACCESS_PREFIX", "access-"),
		AutomountPrefix: envOrDefault("POCKETID_AUTOMOUNT_PREFIX", "automount-"),

		WebhookPort:   clampInt(envOrDefaultInt("POCKETID_WEBHOOK_PORT", 0), 0, 65535),
		WebhookSecret: envOrDefault("POCKETID_WEBHOOK_SECRET", ""),
		WebhookListen: envOrDefault("POCKETID_WEBHOOK_LISTEN", "127.0.0.1"),

		SudoNoAuthenticate: envOrDefault("POCKETID_SUDO_NO_AUTHENTICATE", "false"),
	}

	// Validate SudoNoAuthenticate to catch typos like "True", "yes", "claim"
	switch cfg.SudoNoAuthenticate {
	case "true", "false", "claims":
		// valid
	default:
		log.Printf("[pocketid] WARNING: invalid POCKETID_SUDO_NO_AUTHENTICATE=%q, defaulting to \"false\"", cfg.SudoNoAuthenticate)
		cfg.SudoNoAuthenticate = "false"
	}

	// Clear secrets from environment to prevent leakage via child processes
	// or /proc/PID/environ. The values are now stored in the returned struct.
	os.Unsetenv("POCKETID_API_KEY")
	os.Unsetenv("POCKETID_WEBHOOK_SECRET")

	return cfg
}

// HomeDir returns the home directory for a given username, substituting {username} in the template.
func (c PluginConfig) HomeDir(username string) string {
	return strings.ReplaceAll(c.DefaultHome, "{username}", username)
}

// validatedShell returns the shell path if it passes ValidateLoginShell,
// otherwise falls back to /bin/bash. Prevents unsafe default shells from
// env vars (e.g., paths with spaces or shell metacharacters).
func validatedShell(shell string) string {
	if ValidateLoginShell(shell) {
		return shell
	}
	return "/bin/bash"
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func clampInt(val, min, max int) int {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}

func envOrDefaultInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
