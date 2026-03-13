package main

import (
	"fmt"
	"regexp"
	"strings"

	ldap "github.com/glauth/ldap"
)

var validAutomountKey = regexp.MustCompile(`^[a-zA-Z0-9_.*/-]+$`)
var validAutomountMapName = regexp.MustCompile(`^auto\.[a-zA-Z0-9_-]+$`)

// dangerousAutomountMapNames are map names that control the automount master
// map or other system-level mount configuration. Allowing these from IDP claims
// would let an attacker define mount points at arbitrary filesystem locations.
var dangerousAutomountMapNames = map[string]bool{
	"auto.master":  true,
	"auto_master":  true,
	"auto.direct":  true,
	"auto_direct":  true,
}

// unsafeMountOptions are mount options that allow privilege escalation.
var unsafeMountOptions = map[string]bool{
	"suid": true,
	"dev":  true,
	"exec": true, // could override noexec policies on attacker-controlled NFS
}

// hasUnsafeMountOption parses NFS/automount option strings and returns true if any
// dangerous option (suid, dev) is present. Options can appear in the mount info
// after the server:path, typically as -fstype=nfs,opt1,opt2.
func hasUnsafeMountOption(info string) bool {
	// automount info format: "-fstype=nfs,suid,rw server:/path" or just options
	lower := strings.ToLower(info)
	// Split on whitespace to find option segments
	for _, part := range strings.Fields(lower) {
		// Options start with - or are comma-separated lists
		// Strip leading -fstype=nfs, prefix if present
		if idx := strings.Index(part, ","); idx >= 0 {
			// Could be "-fstype=nfs,suid,rw" — parse after first comma too
			optStr := part
			if strings.HasPrefix(optStr, "-") {
				// e.g. "-fstype=nfs,suid" — the part before first comma is fstype
				optStr = part[idx+1:]
			}
			for _, opt := range strings.Split(optStr, ",") {
				opt = strings.TrimSpace(opt)
				opt = strings.TrimLeft(opt, "-")
				// Check both exact match and key portion before '='
				// to catch variants like suid=1 or dev=true
				if unsafeMountOptions[opt] {
					return true
				}
				if eqIdx := strings.Index(opt, "="); eqIdx >= 0 {
					if unsafeMountOptions[opt[:eqIdx]] {
						return true
					}
				}
			}
		} else {
			key := strings.TrimLeft(part, "-")
			if unsafeMountOptions[key] {
				return true
			}
			if eqIdx := strings.Index(key, "="); eqIdx >= 0 {
				if unsafeMountOptions[key[:eqIdx]] {
					return true
				}
			}
		}
	}
	return false
}

// shellMetachars are characters that could enable command injection if values
// are processed through a shell (backtick, $, pipe, semicolon, braces, etc.).
// Note: & (ampersand) is intentionally NOT included — it is used in automount
// for key substitution (e.g., "nas:/home/&" expands to "nas:/home/<key>").
var shellMetachars = regexp.MustCompile("[`$|;<>\\\\(){}\n\r]")

// hasShellMetachars returns true if the string contains shell metacharacters.
func hasShellMetachars(s string) bool {
	return shellMetachars.MatchString(s)
}

// automountClaimKeys are the custom claim keys that indicate a group defines an automount entry.
var automountClaimKeys = []string{"automountMapName", "automountKey", "automountInformation"}

// hasAutomountClaims returns true if the group has any automount-related custom claims.
func hasAutomountClaims(claims map[string]string) bool {
	for _, key := range automountClaimKeys {
		if v, ok := claims[key]; ok && v != "" {
			return true
		}
	}
	return false
}

// BuildAutomountEntries synthesizes automountMap and automount LDAP entries from groups
// that have automount-related custom claims (automountMapName, automountKey,
// automountInformation). Each matching group with all three required claims becomes
// an automount entry under the corresponding map container.
func BuildAutomountEntries(groups []IDPGroup, baseDN string) []*ldap.Entry {
	var entries []*ldap.Entry
	seenMaps := make(map[string]*ldap.Entry)

	for _, g := range groups {
		if !isValidGroupName(g.Name) {
			continue // skip groups with unsafe names
		}
		claims := ClaimsMap(g.CustomClaims)
		if !hasAutomountClaims(claims) {
			continue
		}

		mapName, ok := claims["automountMapName"]
		if !ok || mapName == "" {
			continue
		}
		// Validate automountMapName format (must be auto.<name>)
		if !validAutomountMapName.MatchString(mapName) {
			continue
		}
		// Block master/direct maps — these control mount point definitions
		// and could be used to mount attacker-controlled NFS at arbitrary paths
		if dangerousAutomountMapNames[strings.ToLower(mapName)] {
			continue
		}
		key, ok := claims["automountKey"]
		if !ok || key == "" {
			continue
		}
		info, ok := claims["automountInformation"]
		if !ok || info == "" {
			continue
		}

		// Validate automountKey: must be a simple name, no path traversal
		if !validAutomountKey.MatchString(key) || strings.Contains(key, "..") {
			continue
		}

		// Reject dangerous mount options (suid/dev allow privilege escalation)
		if hasUnsafeMountOption(info) {
			continue
		}

		// Reject shell metacharacters that could enable command injection
		// if automount info is ever processed through a shell
		if hasShellMetachars(info) {
			continue
		}

		// Create the map container entry if we haven't seen this mapName yet.
		if _, exists := seenMaps[mapName]; !exists {
			mapDN := fmt.Sprintf("automountMapName=%s,ou=automount,%s", EscapeDNValue(mapName), baseDN)
			mapEntry := &ldap.Entry{
				DN: mapDN,
				Attributes: []*ldap.EntryAttribute{
					{Name: "objectClass", Values: []string{"automountMap", "top"}},
					{Name: "automountMapName", Values: []string{mapName}},
				},
			}
			seenMaps[mapName] = mapEntry
			entries = append(entries, mapEntry)
		}

		// Create the automount entry underneath the map.
		mountDN := fmt.Sprintf("automountKey=%s,automountMapName=%s,ou=automount,%s", EscapeDNValue(key), EscapeDNValue(mapName), baseDN)
		mountEntry := &ldap.Entry{
			DN: mountDN,
			Attributes: []*ldap.EntryAttribute{
				{Name: "objectClass", Values: []string{"automount", "top"}},
				{Name: "automountKey", Values: []string{key}},
				{Name: "automountInformation", Values: []string{info}},
				{Name: "description", Values: []string{g.Name}},
			},
		}
		entries = append(entries, mountEntry)
	}

	return entries
}
