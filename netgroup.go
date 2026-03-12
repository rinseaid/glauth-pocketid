package main

import (
	"fmt"
	"strings"

	ldap "github.com/glauth/ldap"
)

// netgroupClaimKeys are the custom claim keys that indicate a group defines a netgroup.
var netgroupClaimKeys = []string{"netgroupHosts", "netgroupDomain"}

// hasNetgroupClaims returns true if the group has any netgroup-related custom claims.
func hasNetgroupClaims(claims map[string]string) bool {
	for _, key := range netgroupClaimKeys {
		if v, ok := claims[key]; ok && v != "" {
			return true
		}
	}
	return false
}

// BuildNetgroupEntries synthesizes nisNetgroup LDAP entries from groups that have
// netgroup-related custom claims (netgroupHosts, netgroupDomain). Each matching group
// becomes one nisNetgroup entry with nisNetgroupTriple values for each host x member combination.
func BuildNetgroupEntries(groups []IDPGroup, memberMap map[string][]string, baseDN string) []*ldap.Entry {
	var entries []*ldap.Entry
	for _, g := range groups {
		if !isValidGroupName(g.Name) {
			continue // skip groups with unsafe names
		}
		claims := ClaimsMap(g.CustomClaims)
		if !hasNetgroupClaims(claims) {
			continue
		}

		// Determine the domain from the custom claim or derive from baseDN.
		domain := getClaimOrDefault(claims, "netgroupDomain", baseDNToDomain(baseDN))

		// Parse hosts from comma-separated claim; may be empty.
		hosts := splitClaim(claims, "netgroupHosts")

		// Build nisNetgroupTriple values: (host,user,domain)
		// Sanitize all fields to prevent triple injection via special characters
		members := memberMap[g.ID]
		sanitizedDomain := SanitizeNetgroupField(domain)
		var triples []string
		if len(hosts) == 0 {
			// No hosts specified: use empty host field.
			for _, user := range members {
				triples = append(triples, fmt.Sprintf("(,%s,%s)", SanitizeNetgroupField(user), sanitizedDomain))
			}
		} else {
			for _, host := range hosts {
				sanitizedHost := SanitizeNetgroupField(host)
				for _, user := range members {
					triples = append(triples, fmt.Sprintf("(%s,%s,%s)", sanitizedHost, SanitizeNetgroupField(user), sanitizedDomain))
				}
			}
		}

		attrs := []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"nisNetgroup", "top"}},
			{Name: "cn", Values: []string{g.Name}},
		}

		if len(triples) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{
				Name:   "nisNetgroupTriple",
				Values: triples,
			})
		}

		dn := fmt.Sprintf("cn=%s,ou=netgroup,%s", EscapeDNValue(g.Name), baseDN)
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}
	return entries
}

// baseDNToDomain converts a base DN like "dc=example,dc=com" to "example.com"
// by extracting the values of all dc= components and joining them with dots.
func baseDNToDomain(baseDN string) string {
	var parts []string
	for _, component := range strings.Split(baseDN, ",") {
		component = strings.TrimSpace(component)
		lower := strings.ToLower(component)
		if strings.HasPrefix(lower, "dc=") {
			parts = append(parts, component[3:])
		}
	}
	return strings.Join(parts, ".")
}
