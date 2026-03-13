package main

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	ldap "github.com/glauth/ldap"
)

// validSudoHostOrUser matches safe values for sudoHost, sudoRunAsUser, sudoRunAsGroup:
// alphanumeric, hyphens, dots, underscores, or the literal "ALL".
var validSudoHostOrUser = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// sudoClaimKeys are the custom claim keys that indicate a group defines sudo permissions.
var sudoClaimKeys = []string{"sudoCommands", "sudoHosts", "sudoRunAsUser", "sudoRunAsGroup", "sudoOptions"}

// dangerousSudoOptions are sudo options that enable privilege escalation
// beyond what the allowed commands grant. These are blocked from claims input.
var dangerousSudoOptions = map[string]bool{
	"!env_reset":  true, // preserves attacker's environment
	"setenv":      true, // allows setting arbitrary env vars
	"!requiretty": true, // enables cron/scripted exploitation
	"!env_check":  true, // disables env var sanitization
	"!env_delete": true, // prevents removal of dangerous env vars
	"!log_output": true, // hides attacker activity from audit
	"!log_input":  true, // hides attacker activity from audit
	"!noexec":        true, // disables noexec protection, allows shared library calls
	"!use_pty":       true, // disables PTY allocation, aids TTY-based attacks
	"!closefrom":     true, // prevents closing extra file descriptors (info leak)
	"!authenticate":  true, // disables password prompt — must only be set via SudoNoAuthenticate config
	"authenticate":   true, // block explicit setting too — use SudoNoAuthenticate config instead
	"!syslog":        true, // disables syslog logging of sudo commands
	"!pam_session":   true, // disables PAM session management (bypasses session audit/limits)
}

// dangerousSudoOptionPrefixes are prefixes of sudo options that are blocked.
var dangerousSudoOptionPrefixes = []string{
	"env_keep+=LD_PRELOAD",      // LD_PRELOAD injection
	"env_keep+=LD_LIBRARY_PATH", // library path injection
	"env_keep+=PYTHONPATH",      // Python import injection
	"env_keep+=PERL5LIB",        // Perl import injection
	"env_keep+=RUBYLIB",         // Ruby import injection
	"env_keep+=NODE_PATH",       // Node.js module injection
	"env_keep+=CLASSPATH",       // Java classpath injection
	"env_keep+=GOPATH",          // Go path injection
	"env_keep+=BASH_ENV",        // Bash startup injection
	"env_keep+=ENV",             // sh startup injection
	"env_keep+=DYLD_",           // macOS dynamic linker injection
	"env_keep+=PERL5OPT",        // Perl option injection
	"env_keep+=PYTHONSTARTUP",   // Python startup script injection
	"env_keep+=JAVA_TOOL_OPTIONS", // Java agent injection
	"env_keep+=http_proxy",      // MITM via proxy injection
	"env_keep+=https_proxy",     // MITM via proxy injection
	"env_keep+=CARGO_HOME",      // Rust build path injection
	"env_keep+=GEM_PATH",        // Ruby gem path injection
	"env_keep+=PATH",            // command lookup path override
	"env_keep+=HOME",            // home directory override (affects dotfile loading)
	"env_keep+=EDITOR",          // editor override (used by visudo, crontab -e, etc.)
	"env_keep+=VISUAL",          // editor override (used by visudo, crontab -e, etc.)
	"env_keep+=SUDO_EDITOR",    // editor override for sudoedit
	"env_keep+=TMPDIR",          // temp directory override (symlink attacks)
	"env_keep+=IFS",             // internal field separator — classic shell privilege escalation
	"env_keep+=LD_AUDIT",        // glibc audit library injection (similar to LD_PRELOAD)
	"env_keep+=LD_PROFILE",      // glibc profiling — code execution via profiling library
	"env_keep+=PROMPT_COMMAND",  // Bash executes this before every prompt display
	"env_keep+=SHELLOPTS",       // Bash shell option injection
	"env_keep+=BASHOPTS",        // additional Bash option injection
	"env_keep+=CDPATH",          // causes unexpected directory changes in scripts
	"env_keep+=GLOBIGNORE",      // alters glob behavior in shell scripts
	"env_keep+=_JAVA_OPTIONS",   // alternative Java agent injection vector
	"secure_path",               // overrides safe command PATH
	"mailerpath",                // specifies arbitrary program for sudo to execute
	"logfile",                   // allows writing to arbitrary file paths
	"lecture_file",              // allows probing arbitrary file paths
	"timestamp_timeout",         // can extend sudo ticket lifetime indefinitely
	"env_check+=",               // weakens environment sanitization rules
	"env_delete+=",              // prevents removal of specific env vars
}

// isNoAuthOption returns true if the option is !authenticate or authenticate
// (with any whitespace/casing variation).
func isNoAuthOption(opt string) bool {
	normalized := strings.ToLower(strings.TrimSpace(opt))
	normalized = strings.ReplaceAll(normalized, " ", "")
	return normalized == "!authenticate" || normalized == "authenticate"
}

// normalizeSudoOption strips all whitespace (including Unicode whitespace like
// non-breaking space U+00A0) and quotes from a sudo option string so that
// "env_keep += LD_PRELOAD", env_keep+="LD_PRELOAD", and variations with Unicode
// spaces are all compared identically to "env_keep+=LD_PRELOAD".
func normalizeSudoOption(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) || r == '"' || r == '\'' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isSafeSudoOption returns true if the sudo option is safe to pass through.
func isSafeSudoOption(opt string) bool {
	lower := strings.ToLower(strings.TrimSpace(opt))
	if lower == "" {
		return false
	}
	// Reject embedded newlines/carriage returns that could be interpreted as
	// separate directives by some LDAP clients or sudoers parsers
	if strings.ContainsAny(lower, "\n\r") {
		return false
	}
	if dangerousSudoOptions[lower] {
		return false
	}
	// Normalize whitespace before prefix comparison to prevent bypass via
	// "env_keep += LD_PRELOAD" (with spaces) evading "env_keep+=LD_PRELOAD"
	normalized := normalizeSudoOption(lower)
	if dangerousSudoOptions[normalized] {
		return false
	}
	for _, prefix := range dangerousSudoOptionPrefixes {
		if strings.HasPrefix(normalized, strings.ToLower(normalizeSudoOption(prefix))) {
			return false
		}
	}
	return true
}

// validSudoCommand checks that a sudo command value is safe.
// Rejects negation patterns, sudoedit, empty values, and non-absolute paths
// (except the literal "ALL").
func validSudoCommand(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	// Reject null bytes (could cause truncation in C-based sudo)
	if strings.ContainsRune(cmd, 0) {
		return false
	}
	// Reject newlines/carriage returns that could inject additional directives
	if strings.ContainsAny(cmd, "\n\r") {
		return false
	}
	if cmd == "ALL" {
		return true
	}
	// Reject negation patterns (e.g., "!/usr/bin/su")
	if strings.HasPrefix(cmd, "!") {
		return false
	}
	// Reject sudoedit (allows editing arbitrary files as root)
	if strings.EqualFold(cmd, "sudoedit") || strings.HasPrefix(strings.ToLower(cmd), "sudoedit ") {
		return false
	}
	// Must start with / (absolute path)
	if !strings.HasPrefix(cmd, "/") {
		return false
	}
	// Reject path traversal (e.g., /usr/bin/../bin/su)
	if strings.Contains(cmd, "..") {
		return false
	}
	return true
}

// hasSudoClaims returns true if the group has any sudo-related custom claims.
func hasSudoClaims(claims map[string]string) bool {
	for _, key := range sudoClaimKeys {
		if v, ok := claims[key]; ok && v != "" {
			return true
		}
	}
	return false
}

// BuildSudoRules synthesizes sudoRole LDAP entries from groups that have sudo-related
// custom claims (sudoCommands, sudoHosts, sudoRunAsUser, sudoRunAsGroup, sudoOptions).
// Any group with at least one sudo claim becomes a sudoRole entry.
func BuildSudoRules(groups []IDPGroup, memberMap map[string][]string, baseDN string, noAuthenticate string) []*ldap.Entry {
	var entries []*ldap.Entry
	for _, g := range groups {
		if !isValidGroupName(g.Name) {
			continue // skip groups with unsafe names
		}
		claims := ClaimsMap(g.CustomClaims)
		if !hasSudoClaims(claims) {
			continue
		}

		attrs := []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"sudoRole", "top"}},
			{Name: "cn", Values: []string{g.Name}},
		}

		// All members as multi-valued sudoUser attribute — skip rule entirely if no members
		members := memberMap[g.ID]
		if len(members) == 0 {
			continue
		}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "sudoUser", Values: members})

		sudoHosts := validatedSudoHostOrUser(claims, "sudoHosts", "ALL")
		if len(sudoHosts) == 0 {
			continue // all explicit sudoHosts values were invalid — fail-closed
		}
		attrs = append(attrs, &ldap.EntryAttribute{
			Name:   "sudoHost",
			Values: sudoHosts,
		})

		// sudoCommand has no default — must be explicitly set.
		// If sudoCommands claim triggered hasSudoClaims but this specific claim is empty,
		// other claims (sudoHosts, sudoRunAsUser, etc.) triggered it instead.
		if rawCmds := splitClaim(claims, "sudoCommands"); len(rawCmds) > 0 {
			var cmds []string
			for _, c := range rawCmds {
				if validSudoCommand(c) {
					cmds = append(cmds, c)
				}
			}
			if len(cmds) == 0 {
				continue // all commands were invalid
			}
			attrs = append(attrs, &ldap.EntryAttribute{
				Name:   "sudoCommand",
				Values: cmds,
			})
		} else {
			// No commands specified — skip this rule entirely to avoid granting ALL
			continue
		}

		sudoRunAsUser := validatedSudoHostOrUser(claims, "sudoRunAsUser", "root")
		if len(sudoRunAsUser) == 0 {
			continue // all explicit sudoRunAsUser values were invalid — fail-closed
		}
		attrs = append(attrs, &ldap.EntryAttribute{
			Name:   "sudoRunAsUser",
			Values: sudoRunAsUser,
		})

		// sudoRunAsGroup is optional — only emit if set (validate values)
		if vals := splitClaim(claims, "sudoRunAsGroup"); len(vals) > 0 {
			var safeVals []string
			for _, v := range vals {
				if v == "ALL" || validSudoHostOrUser.MatchString(v) {
					safeVals = append(safeVals, v)
				}
			}
			if len(safeVals) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{
					Name:   "sudoRunAsGroup",
					Values: safeVals,
				})
			}
		}

		// Merge sudo options: optionally include !authenticate
		// noAuthenticate modes: "true" = add to all rules, "claims" = allow per-group via claim, "false" = block
		var sudoOptions []string
		if noAuthenticate == "true" {
			sudoOptions = append(sudoOptions, "!authenticate")
		}
		if extra := splitClaim(claims, "sudoOptions"); len(extra) > 0 {
			for _, opt := range extra {
				// When noAuthenticate == "claims", allow !authenticate from claim input
				if isNoAuthOption(opt) {
					if noAuthenticate == "claims" {
						sudoOptions = append(sudoOptions, strings.TrimSpace(opt))
					}
					continue // skip blocklist check — handled above
				}
				if isSafeSudoOption(opt) {
					sudoOptions = append(sudoOptions, opt)
				}
			}
		}
		if len(sudoOptions) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{
				Name:   "sudoOption",
				Values: sudoOptions,
			})
		}

		dn := fmt.Sprintf("cn=%s,ou=sudoers,%s", EscapeDNValue(g.Name), baseDN)
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}
	return entries
}

func getClaimOrDefault(claims map[string]string, key, def string) string {
	if v, ok := claims[key]; ok && v != "" {
		return v
	}
	return def
}

// splitClaim splits a comma-separated claim value into trimmed, non-empty values.
func splitClaim(claims map[string]string, key string) []string {
	v, ok := claims[key]
	if !ok || v == "" {
		return nil
	}
	var vals []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			vals = append(vals, s)
		}
	}
	return vals
}

// splitClaimOrDefault splits a comma-separated claim value, falling back to a default.
func splitClaimOrDefault(claims map[string]string, key, def string) []string {
	if vals := splitClaim(claims, key); len(vals) > 0 {
		return vals
	}
	return []string{def}
}

// validatedSudoHostOrUser filters a claim's comma-separated values, keeping only
// safe entries (alphanumeric + hyphens/dots/underscores, or "ALL").
// Returns nil if a claim was explicitly set but ALL values were rejected —
// callers should skip the sudo rule entirely (fail-closed) rather than
// falling back to the default, which could silently grant broader access.
func validatedSudoHostOrUser(claims map[string]string, key, def string) []string {
	// Check if claim was explicitly set
	explicit := splitClaim(claims, key)
	if len(explicit) == 0 {
		// No claim set — use default
		return []string{def}
	}
	// Claim was explicitly set — filter values
	var safe []string
	for _, v := range explicit {
		if v == "ALL" || validSudoHostOrUser.MatchString(v) {
			safe = append(safe, v)
		}
	}
	// If all explicit values were rejected, return nil (fail-closed).
	// Caller must check for nil and skip the rule.
	return safe
}
