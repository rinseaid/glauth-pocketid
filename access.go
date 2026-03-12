package main

import (
	"regexp"
	"sort"
	"strings"
)

// validHostname matches safe hostnames: alphanumeric, dots, hyphens, or the literal "ALL".
var validHostname = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// accessClaimKeys are the custom claim keys that indicate a group defines host access control.
var accessClaimKeys = []string{"accessHosts"}

// hasAccessClaims returns true if the group has any access-related custom claims.
func hasAccessClaims(claims map[string]string) bool {
	for _, key := range accessClaimKeys {
		if v, ok := claims[key]; ok && v != "" {
			return true
		}
	}
	return false
}

// BuildUserHostMap builds a map of username -> []hostnames from groups that have
// access-related custom claims (accessHosts). The result is intended to be stored
// and used by FindPosixAccounts() to populate the "host" LDAP attribute on user entries.
func BuildUserHostMap(groups []IDPGroup, memberMap map[string][]string) map[string][]string {
	userHosts := make(map[string][]string)

	for _, g := range groups {
		if !isValidGroupName(g.Name) {
			continue // skip groups with unsafe names
		}
		claims := ClaimsMap(g.CustomClaims)
		if !hasAccessClaims(claims) {
			continue
		}

		// Parse and validate hosts from the accessHosts custom claim.
		rawHosts := splitClaim(claims, "accessHosts")
		var hosts []string
		for _, h := range rawHosts {
			// Reject "ALL" — could be misinterpreted as wildcard by downstream
			// access control systems (pam_access, custom scripts).
			if strings.EqualFold(h, "ALL") {
				continue
			}
			// Reject leading-dot hostnames (e.g., ".example.com") which act as
			// domain wildcards in pam_access, matching any host in that domain.
			if strings.HasPrefix(h, ".") {
				continue
			}
			if validHostname.MatchString(h) {
				hosts = append(hosts, h)
			}
		}
		if len(hosts) == 0 {
			continue
		}

		for _, member := range memberMap[g.ID] {
			userHosts[member] = append(userHosts[member], hosts...)
		}
	}

	// Deduplicate and sort each user's host list.
	for user, hosts := range userHosts {
		seen := make(map[string]struct{}, len(hosts))
		deduped := make([]string, 0, len(hosts))
		for _, h := range hosts {
			if _, ok := seen[h]; !ok {
				seen[h] = struct{}{}
				deduped = append(deduped, h)
			}
		}
		sort.Strings(deduped)
		userHosts[user] = deduped
	}

	return userHosts
}
