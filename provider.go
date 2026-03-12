package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Provider is the interface for fetching users and groups from an identity provider.
// The implementation is PocketIDClient which queries the Pocket ID REST API.
type Provider interface {
	ListAllUsers(ctx context.Context) ([]IDPUser, error)
	ListAllGroups(ctx context.Context) ([]IDPGroup, error)
}

// IDPUser represents a user from any identity provider.
type IDPUser struct {
	ID           string
	Username     string
	Email        string
	FirstName    string
	LastName     string
	Disabled     bool
	CustomClaims []CustomClaim
}

// IDPGroup represents a group from any identity provider, including its members.
type IDPGroup struct {
	ID           string
	Name         string
	CustomClaims []CustomClaim
	Users        []IDPUser
}

// CustomClaim represents a single key-value custom claim.
// Used across all providers as the canonical claim format.
type CustomClaim struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ClaimsMap converts a slice of CustomClaim into a map for easier lookup.
// Null bytes are stripped from all values to prevent truncation attacks
// in downstream C-based consumers (sudo, automount, NIS).
func ClaimsMap(claims []CustomClaim) map[string]string {
	m := make(map[string]string, len(claims))
	for _, c := range claims {
		m[stripNullBytes(c.Key)] = stripNullBytes(c.Value)
	}
	return m
}

// stripNullBytes removes all null bytes from a string.
func stripNullBytes(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

// APIError is returned when an API returns a non-2xx status code.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Message)
}

// EscapeDNValue escapes special characters in an LDAP DN value per RFC 4514.
func EscapeDNValue(val string) string {
	var b strings.Builder
	for i, r := range val {
		switch {
		case r == ',' || r == '+' || r == '"' || r == '\\' || r == '<' || r == '>' || r == ';':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '#' && i == 0:
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == ' ' && (i == 0 || i == len(val)-1):
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == 0:
			b.WriteString("\\00")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// validLoginShell matches absolute paths with no spaces or shell metacharacters.
var validLoginShell = regexp.MustCompile(`^/[a-zA-Z0-9/_.-]+$`)

// ValidateLoginShell returns true if the shell path is safe to use.
func ValidateLoginShell(shell string) bool {
	if !validLoginShell.MatchString(shell) {
		return false
	}
	// Reject path traversal (e.g., /bin/bash/../../etc/passwd)
	if strings.Contains(shell, "..") {
		return false
	}
	return true
}

// SanitizeNetgroupField strips characters that could break NIS netgroup triple format.
func SanitizeNetgroupField(s string) string {
	replacer := strings.NewReplacer("(", "", ")", "", ",", "", "\n", "", "\r", "", "\x00", "")
	return replacer.Replace(s)
}
