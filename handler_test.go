package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glauth/glauth/v2/pkg/config"
	ldap "github.com/glauth/ldap"
)

// testStore creates a Store wired to the Pocket ID mock server for handler-level tests.
func testStore(t *testing.T) (*Store, Provider, func()) {
	t.Helper()
	return pocketIDTestStore(t)
}

func TestUIDAssignment(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// jordan and alice should have UIDs assigned (bob is disabled)
	found, jordan, _ := store.FindUser("jordan", false)
	if !found {
		t.Fatal("jordan not found")
	}
	if jordan.UIDNumber < 200000 {
		t.Errorf("expected UID >= 200000, got %d", jordan.UIDNumber)
	}

	found, alice, _ := store.FindUser("alice", false)
	if !found {
		t.Fatal("alice not found")
	}
	if alice.UIDNumber < 200000 {
		t.Errorf("expected UID >= 200000, got %d", alice.UIDNumber)
	}

	// UIDs should be different
	if jordan.UIDNumber == alice.UIDNumber {
		t.Error("jordan and alice should have different UIDs")
	}

	// Disabled user should not be present
	found, _, _ = store.FindUser("bob", false)
	if found {
		t.Error("disabled user bob should not be found")
	}

	// Persist and reload - UIDs should be stable
	jordanUID := jordan.UIDNumber
	aliceUID := alice.UIDNumber

	store2 := NewStore(store.cfg)
	if err := store2.Refresh(provider); err != nil {
		t.Fatalf("Second refresh failed: %v", err)
	}

	_, jordan2, _ := store2.FindUser("jordan", false)
	_, alice2, _ := store2.FindUser("alice", false)

	if jordan2.UIDNumber != jordanUID {
		t.Errorf("jordan UID changed: %d -> %d", jordanUID, jordan2.UIDNumber)
	}
	if alice2.UIDNumber != aliceUID {
		t.Errorf("alice UID changed: %d -> %d", aliceUID, alice2.UIDNumber)
	}
}

func TestSSHKeyMapping(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// jordan has 2 SSH keys
	_, jordan, _ := store.FindUser("jordan", false)
	if len(jordan.SSHKeys) != 2 {
		t.Errorf("expected 2 SSH keys for jordan, got %d", len(jordan.SSHKeys))
	}
	if jordan.SSHKeys[0] != "ssh-rsa AAAA jordan@laptop" {
		t.Errorf("unexpected first SSH key: %s", jordan.SSHKeys[0])
	}
	if jordan.SSHKeys[1] != "ssh-ed25519 BBBB jordan@desktop" {
		t.Errorf("unexpected second SSH key: %s", jordan.SSHKeys[1])
	}

	// alice has 1 SSH key
	_, alice, _ := store.FindUser("alice", false)
	if len(alice.SSHKeys) != 1 {
		t.Errorf("expected 1 SSH key for alice, got %d", len(alice.SSHKeys))
	}
}

func TestSudoRuleSynthesis(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	rules := store.GetSudoRules()

	// Should have 2 sudo rules (server-admins and service-restarters have sudo claims)
	if len(rules) != 2 {
		t.Errorf("expected 2 sudo rules, got %d", len(rules))
		for _, r := range rules {
			t.Logf("  rule: %s", r.DN)
		}
	}

	var serverAdmins *sudoRuleInfo
	var serviceRestarters *sudoRuleInfo
	for _, r := range rules {
		info := parseSudoRule(r)
		if info.cn == "server-admins" {
			serverAdmins = info
		}
		if info.cn == "service-restarters" {
			serviceRestarters = info
		}
	}

	if serverAdmins == nil {
		t.Fatal("server-admins rule not found")
	}
	if len(serverAdmins.sudoUsers) != 2 {
		t.Errorf("expected 2 sudoUsers in server-admins, got %d", len(serverAdmins.sudoUsers))
	}

	if serviceRestarters == nil {
		t.Fatal("service-restarters rule not found")
	}
}

func TestSudoCustomClaims(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	rules := store.GetSudoRules()

	for _, r := range rules {
		info := parseSudoRule(r)
		if info.cn == "service-restarters" {
			if len(info.sudoCommands) != 1 || info.sudoCommands[0] != "/usr/bin/systemctl restart *" {
				t.Errorf("expected custom sudoCommand, got %q", info.sudoCommands)
			}
			if len(info.sudoRunAsUsers) != 1 || info.sudoRunAsUsers[0] != "root" {
				t.Errorf("expected sudoRunAsUser=root, got %q", info.sudoRunAsUsers)
			}
			return
		}
	}
	t.Error("service-restarters rule not found")
}

func TestFindUser(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// By username
	found, u, _ := store.FindUser("jordan", false)
	if !found {
		t.Fatal("jordan not found by username")
	}
	if u.Name != "jordan" {
		t.Errorf("expected name jordan, got %s", u.Name)
	}

	// Case insensitive
	found, _, _ = store.FindUser("Jordan", false)
	if !found {
		t.Error("jordan not found with capital R")
	}

	// By UPN (email)
	found, u, _ = store.FindUser("alice@example.com", true)
	if !found {
		t.Fatal("alice not found by UPN")
	}
	if u.Name != "alice" {
		t.Errorf("expected name alice, got %s", u.Name)
	}

	// Non-existent
	found, _, _ = store.FindUser("nobody", false)
	if found {
		t.Error("nobody should not be found")
	}
}

func TestFindGroup(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	found, g, _ := store.FindGroup("developers")
	if !found {
		t.Fatal("developers group not found")
	}
	if g.Name != "developers" {
		t.Errorf("expected name developers, got %s", g.Name)
	}
	if g.GIDNumber < 200000 {
		t.Errorf("expected GID >= 200000, got %d", g.GIDNumber)
	}

	found, _, _ = store.FindGroup("nonexistent")
	if found {
		t.Error("nonexistent group should not be found")
	}
}

func TestLoginShellOverride(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	_, jordan, _ := store.FindUser("jordan", false)
	if jordan.LoginShell != "/bin/zsh" {
		t.Errorf("expected /bin/zsh for jordan, got %s", jordan.LoginShell)
	}

	_, alice, _ := store.FindUser("alice", false)
	if alice.LoginShell != "/bin/bash" {
		t.Errorf("expected /bin/bash for alice, got %s", alice.LoginShell)
	}
}

func TestHomeDirectory(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	_, jordan, _ := store.FindUser("jordan", false)
	if jordan.Homedir != "/home/jordan" {
		t.Errorf("expected /home/jordan, got %s", jordan.Homedir)
	}
}

func TestFindPosixAccounts(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	backend := config.Backend{
		BaseDN:             "dc=example,dc=com",
		NameFormat:         "cn",
		NameFormatAsArray:  []string{"cn"},
		GroupFormat:        "ou",
		GroupFormatAsArray: []string{"ou"},
		SSHKeyAttr:         "sshPublicKey",
	}

	entries, err := store.FindPosixAccounts(backend, "ou=users")
	if err != nil {
		t.Fatalf("FindPosixAccounts failed: %v", err)
	}

	// Should have jordan and alice (bob is disabled)
	if len(entries) != 2 {
		t.Errorf("expected 2 posix accounts, got %d", len(entries))
	}

	// Check that SSH keys are present in entries
	for _, entry := range entries {
		if getAttr(entry, "cn") == "jordan" {
			sshKeys := getAttrValues(entry, "sshPublicKey")
			if len(sshKeys) != 2 {
				t.Errorf("expected 2 SSH keys for jordan entry, got %d", len(sshKeys))
			}
		}
	}
}

func TestDirtyTracking(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	// First refresh should write (new UIDs assigned)
	if err := store.Refresh(provider); err != nil {
		t.Fatalf("First refresh failed: %v", err)
	}

	info1, err := os.Stat(store.cfg.PersistPath)
	if err != nil {
		t.Fatalf("uidmap.json should exist after first refresh: %v", err)
	}
	modTime1 := info1.ModTime()

	// Small delay to ensure filesystem timestamp granularity
	time.Sleep(10 * time.Millisecond)

	// Second refresh with same data should NOT write
	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Second refresh failed: %v", err)
	}

	info2, err := os.Stat(store.cfg.PersistPath)
	if err != nil {
		t.Fatalf("uidmap.json should still exist: %v", err)
	}
	modTime2 := info2.ModTime()

	if !modTime2.Equal(modTime1) {
		t.Errorf("uidmap.json should not have been rewritten on second refresh (no new UIDs)")
	}
}

func TestClaimsMap(t *testing.T) {
	claims := []CustomClaim{
		{Key: "foo", Value: "bar"},
		{Key: "baz", Value: "qux"},
	}

	m := ClaimsMap(claims)
	if m["foo"] != "bar" {
		t.Errorf("expected foo=bar, got foo=%s", m["foo"])
	}
	if m["baz"] != "qux" {
		t.Errorf("expected baz=qux, got baz=%s", m["baz"])
	}
}

func TestUIDPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	persistPath := filepath.Join(tmpDir, "uidmap.json")

	// Write a persisted map
	p := persistedMap{
		UIDs:    map[string]int{"uuid-1": 200005, "uuid-2": 200006},
		GIDs:    map[string]int{"gid-1": 200005},
		NextUID: 200007,
		NextGID: 200006,
	}
	data, _ := json.Marshal(p)
	os.WriteFile(persistPath, data, 0644)

	cfg := PluginConfig{
		UIDBase:     200000,
		GIDBase:     200000,
		PersistPath: persistPath,
	}

	store := NewStore(cfg)
	if store.nextUID != 200007 {
		t.Errorf("expected nextUID=200007, got %d", store.nextUID)
	}
	if store.uidMap["uuid-1"] != 200005 {
		t.Errorf("expected uuid-1 UID=200005, got %d", store.uidMap["uuid-1"])
	}
}

// --- helpers ---

type sudoRuleInfo struct {
	cn             string
	sudoUsers      []string
	sudoHosts      []string
	sudoCommands   []string
	sudoRunAsUsers []string
	sudoRunAsGroup []string
	sudoOptions    []string
}

func parseSudoRule(entry interface{ GetAttributeValues(string) []string }) *sudoRuleInfo {
	return &sudoRuleInfo{
		cn:             first(entry.GetAttributeValues("cn")),
		sudoUsers:      entry.GetAttributeValues("sudoUser"),
		sudoHosts:      entry.GetAttributeValues("sudoHost"),
		sudoCommands:   entry.GetAttributeValues("sudoCommand"),
		sudoRunAsUsers: entry.GetAttributeValues("sudoRunAsUser"),
		sudoRunAsGroup: entry.GetAttributeValues("sudoRunAsGroup"),
		sudoOptions:    entry.GetAttributeValues("sudoOption"),
	}
}

func first(vals []string) string {
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// Helper to get attribute values from an ldap.Entry
func getAttr(entry interface{}, name string) string {
	switch e := entry.(type) {
	case interface{ GetAttributeValue(string) string }:
		return e.GetAttributeValue(name)
	default:
		_ = e
		return ""
	}
}

func getAttrValues(entry interface{}, name string) []string {
	switch e := entry.(type) {
	case interface{ GetAttributeValues(string) []string }:
		return e.GetAttributeValues(name)
	default:
		_ = e
		return nil
	}
}

func TestExtractSSHKeys(t *testing.T) {
	// Unnumbered sshPublicKey + numbered keys
	claims := map[string]string{
		"sshPublicKey":  "ssh-dss AAAAB3NzaC1kc3MAAA user0@host",
		"sshPublicKey1": "ssh-rsa AAAAB3NzaC1yc2EAAA user1@host",
		"sshPublicKey2": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA user2@host",
		"sshPublicKey3": "ecdsa-sha2-nistp256 AAAA user3@host",
	}

	keys := extractSSHKeys(claims)
	if len(keys) != 4 {
		t.Errorf("expected 4 keys, got %d", len(keys))
	}
	if len(keys) > 0 && keys[0] != "ssh-dss AAAAB3NzaC1kc3MAAA user0@host" {
		t.Errorf("first key should be unnumbered sshPublicKey, got %s", keys[0])
	}

	// Invalid keys should be rejected
	invalidClaims := map[string]string{
		"sshPublicKey1": `command="/bin/evil" ssh-rsa AAAA`,
		"sshPublicKey2": "not-a-valid-key",
	}
	invalidKeys := extractSSHKeys(invalidClaims)
	if len(invalidKeys) != 0 {
		t.Errorf("expected 0 valid keys from invalid claims, got %d", len(invalidKeys))
	}

	// No keys
	empty := extractSSHKeys(map[string]string{})
	if len(empty) != 0 {
		t.Errorf("expected 0 keys, got %d", len(empty))
	}
}

func TestBuildSudoRules(t *testing.T) {
	groups := []IDPGroup{
		{
			ID:   "g1",
			Name: "sudo-ALL",
			CustomClaims: []CustomClaim{
				{Key: "sudoCommands", Value: "ALL"},
				{Key: "sudoHosts", Value: "ALL"},
			},
		},
		{
			ID:   "g2",
			Name: "developers",
		},
	}
	memberMap := map[string][]string{
		"g1": {"jordan", "alice"},
		"g2": {"jordan"},
	}

	rules := BuildSudoRules(groups, memberMap, "dc=example,dc=com", "true")

	// Only sudo-ALL has sudo claims; developers has none
	if len(rules) != 1 {
		t.Fatalf("expected 1 sudo rule, got %d", len(rules))
	}

	rule := rules[0]
	if rule.DN != "cn=sudo-ALL,ou=sudoers,dc=example,dc=com" {
		t.Errorf("unexpected DN: %s", rule.DN)
	}

	// Check sudoUser attribute
	for _, attr := range rule.Attributes {
		if attr.Name == "sudoUser" {
			if len(attr.Values) != 2 {
				t.Errorf("expected 2 sudoUsers, got %d", len(attr.Values))
			}
		}
		if attr.Name == "sudoOption" {
			if attr.Values[0] != "!authenticate" {
				t.Errorf("expected sudoOption=!authenticate, got %s", attr.Values[0])
			}
		}
	}
}

func TestSudoMultiValueClaims(t *testing.T) {
	groups := []IDPGroup{
		{
			ID:   "g1",
			Name: "sudo-ops",
			CustomClaims: []CustomClaim{
				{Key: "sudoCommands", Value: "/usr/bin/systemctl restart *, /usr/bin/journalctl, /usr/bin/top"},
				{Key: "sudoHosts", Value: "web01, web02, db01"},
				{Key: "sudoRunAsUser", Value: "root, www-data"},
				{Key: "sudoRunAsGroup", Value: "www-data, adm"},
				{Key: "sudoOptions", Value: "env_keep+=SSH_AUTH_SOCK, log_output"},
			},
		},
	}
	memberMap := map[string][]string{
		"g1": {"jordan"},
	}

	rules := BuildSudoRules(groups, memberMap, "dc=example,dc=com", "true")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	info := parseSudoRule(rules[0])

	// Commands
	if len(info.sudoCommands) != 3 {
		t.Errorf("expected 3 sudoCommands, got %d: %v", len(info.sudoCommands), info.sudoCommands)
	}
	if info.sudoCommands[0] != "/usr/bin/systemctl restart *" {
		t.Errorf("unexpected first command: %q", info.sudoCommands[0])
	}

	// Hosts
	if len(info.sudoHosts) != 3 {
		t.Errorf("expected 3 sudoHosts, got %d: %v", len(info.sudoHosts), info.sudoHosts)
	}

	// RunAsUser
	if len(info.sudoRunAsUsers) != 2 {
		t.Errorf("expected 2 sudoRunAsUsers, got %d: %v", len(info.sudoRunAsUsers), info.sudoRunAsUsers)
	}

	// RunAsGroup
	if len(info.sudoRunAsGroup) != 2 {
		t.Errorf("expected 2 sudoRunAsGroup, got %d: %v", len(info.sudoRunAsGroup), info.sudoRunAsGroup)
	}

	// Options - should include !authenticate plus the 2 custom options
	if len(info.sudoOptions) != 3 {
		t.Errorf("expected 3 sudoOptions, got %d: %v", len(info.sudoOptions), info.sudoOptions)
	}
	if info.sudoOptions[0] != "!authenticate" {
		t.Errorf("first sudoOption should be !authenticate, got %q", info.sudoOptions[0])
	}
}

func TestGetClaimOrDefault(t *testing.T) {
	claims := map[string]string{
		"sudoCommands": "/usr/bin/foo",
	}

	if v := getClaimOrDefault(claims, "sudoCommands", "ALL"); v != "/usr/bin/foo" {
		t.Errorf("expected /usr/bin/foo, got %s", v)
	}
	if v := getClaimOrDefault(claims, "sudoHosts", "ALL"); v != "ALL" {
		t.Errorf("expected ALL, got %s", v)
	}
}

func TestAPIError(t *testing.T) {
	err := &APIError{StatusCode: 401, Message: "unauthorized"}
	expected := "API error 401: unauthorized"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestPluginConfig(t *testing.T) {
	// Test defaults
	cfg := LoadConfig()
	if cfg.RefreshSec != 300 {
		t.Errorf("expected default refresh=300, got %d", cfg.RefreshSec)
	}
	if cfg.UIDBase != 200000 {
		t.Errorf("expected default UID base=200000, got %d", cfg.UIDBase)
	}
	if cfg.DefaultShell != "/bin/bash" {
		t.Errorf("expected default shell=/bin/bash, got %s", cfg.DefaultShell)
	}

	// Test HomeDir template
	if cfg.HomeDir("testuser") != "/home/testuser" {
		t.Errorf("expected /home/testuser, got %s", cfg.HomeDir("testuser"))
	}
}

func TestConfigEnvOverrides(t *testing.T) {
	t.Setenv("POCKETID_BASE_URL", "https://id.test.com")
	t.Setenv("POCKETID_API_KEY", "my-api-key")
	t.Setenv("POCKETID_REFRESH_SEC", "60")
	t.Setenv("POCKETID_UID_BASE", "20000")
	t.Setenv("POCKETID_DEFAULT_SHELL", "/bin/fish")
	t.Setenv("POCKETID_SUDO_PREFIX", "admin-")

	cfg := LoadConfig()
	if cfg.BaseURL != "https://id.test.com" {
		t.Errorf("expected base URL from env, got %s", cfg.BaseURL)
	}
	if cfg.APIKey != "my-api-key" {
		t.Errorf("expected API key from env, got %s", cfg.APIKey)
	}
	if cfg.RefreshSec != 60 {
		t.Errorf("expected refresh=60, got %d", cfg.RefreshSec)
	}
	if cfg.UIDBase != 20000 {
		t.Errorf("expected UID base=20000, got %d", cfg.UIDBase)
	}
	if cfg.DefaultShell != "/bin/fish" {
		t.Errorf("expected /bin/fish, got %s", cfg.DefaultShell)
	}
	if cfg.SudoPrefix != "admin-" {
		t.Errorf("expected admin-, got %s", cfg.SudoPrefix)
	}
}

// --- Netgroup tests ---

func TestNetgroupSynthesis(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	entries := store.GetNetgroupEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 netgroup entry, got %d", len(entries))
	}

	e := entries[0]
	if !strings.Contains(e.DN, "web-team") {
		t.Errorf("unexpected DN: %s", e.DN)
	}

	triples := e.GetAttributeValues("nisNetgroupTriple")
	// web-team has 2 hosts and members (including disabled bob via group membership)
	if len(triples) < 4 {
		t.Errorf("expected at least 4 nisNetgroupTriple values, got %d: %v", len(triples), triples)
	}

	// Verify triple format contains host and user
	foundJordanWeb01 := false
	for _, tr := range triples {
		if strings.Contains(tr, "web01") && strings.Contains(tr, "jordan") {
			foundJordanWeb01 = true
		}
	}
	if !foundJordanWeb01 {
		t.Error("expected to find triple with web01 and jordan")
	}
}

func TestBaseDNToDomain(t *testing.T) {
	tests := []struct {
		baseDN   string
		expected string
	}{
		{"dc=example,dc=com", "example.com"},
		{"dc=sub,dc=example,dc=com", "sub.example.com"},
		{"dc=test", "test"},
	}

	for _, tt := range tests {
		got := baseDNToDomain(tt.baseDN)
		if got != tt.expected {
			t.Errorf("baseDNToDomain(%q) = %q, want %q", tt.baseDN, got, tt.expected)
		}
	}
}

// --- Access control tests ---

func TestHostBasedAccessControl(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	backend := config.Backend{
		BaseDN:             "dc=example,dc=com",
		NameFormat:         "cn",
		NameFormatAsArray:  []string{"cn"},
		GroupFormat:        "ou",
		GroupFormatAsArray: []string{"ou"},
		SSHKeyAttr:         "sshPublicKey",
	}

	entries, err := store.FindPosixAccounts(backend, "ou=users")
	if err != nil {
		t.Fatalf("FindPosixAccounts failed: %v", err)
	}

	for _, entry := range entries {
		name := getAttr(entry, "cn")
		hosts := getAttrValues(entry, "host")

		switch name {
		case "jordan":
			// jordan is in web-access -> web01, web02, web03
			if len(hosts) != 3 {
				t.Errorf("expected 3 hosts for jordan, got %d: %v", len(hosts), hosts)
			}
		case "alice":
			// alice is in full-access -> web01, web02, db01, app01
			if len(hosts) != 4 {
				t.Errorf("expected 4 hosts for alice, got %d: %v", len(hosts), hosts)
			}
		}
	}
}

func TestBuildUserHostMap(t *testing.T) {
	groups := []IDPGroup{
		{
			ID:   "g1",
			Name: "access-web",
			CustomClaims: []CustomClaim{
				{Key: "accessHosts", Value: "web01, web02"},
			},
		},
		{
			ID:   "g2",
			Name: "access-db",
			CustomClaims: []CustomClaim{
				{Key: "accessHosts", Value: "db01"},
			},
		},
		{
			ID:   "g3",
			Name: "all-servers",
			CustomClaims: []CustomClaim{
				{Key: "accessHosts", Value: "app01"},
			},
		},
		{
			ID:   "g4",
			Name: "developers",
			// No access claims -> not an access group
		},
	}
	memberMap := map[string][]string{
		"g1": {"jordan", "alice"},
		"g2": {"jordan"},
		"g3": {"alice"},
		"g4": {"jordan"},
	}

	result := BuildUserHostMap(groups, memberMap)

	if len(result["jordan"]) != 3 {
		t.Errorf("expected 3 hosts for jordan, got %d: %v", len(result["jordan"]), result["jordan"])
	}
	// alice: web01, web02 (from g1) + app01 (from g3) = 3
	if len(result["alice"]) != 3 {
		t.Errorf("expected 3 hosts for alice, got %d: %v", len(result["alice"]), result["alice"])
	}
}

// --- Automount tests ---

func TestAutomountSynthesis(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	entries := store.GetAutomountEntries()
	// Should have 2 entries: 1 automountMap + 1 automount
	if len(entries) != 2 {
		t.Fatalf("expected 2 automount entries, got %d", len(entries))
	}

	// First should be the map container
	mapEntry := entries[0]
	if mapEntry.GetAttributeValue("automountMapName") != "auto.home" {
		t.Errorf("expected automountMapName=auto.home, got %s", mapEntry.GetAttributeValue("automountMapName"))
	}

	// Second should be the mount entry
	mountEntry := entries[1]
	if mountEntry.GetAttributeValue("automountKey") != "*" {
		t.Errorf("expected automountKey=*, got %s", mountEntry.GetAttributeValue("automountKey"))
	}
	if mountEntry.GetAttributeValue("automountInformation") != "-fstype=nfs4 nas:/home/&" {
		t.Errorf("unexpected automountInformation: %s", mountEntry.GetAttributeValue("automountInformation"))
	}
}

func TestBuildAutomountEntries(t *testing.T) {
	groups := []IDPGroup{
		{
			ID:   "g1",
			Name: "automount-home",
			CustomClaims: []CustomClaim{
				{Key: "automountMapName", Value: "auto.home"},
				{Key: "automountKey", Value: "*"},
				{Key: "automountInformation", Value: "-fstype=nfs4 nas:/home/&"},
			},
		},
		{
			ID:   "g2",
			Name: "automount-shared",
			CustomClaims: []CustomClaim{
				{Key: "automountMapName", Value: "auto.home"},
				{Key: "automountKey", Value: "/shared"},
				{Key: "automountInformation", Value: "-fstype=nfs4 nas:/shared"},
			},
		},
		{
			ID:   "g3",
			Name: "automount-missing",
			// Missing required claims -> should be skipped
			CustomClaims: []CustomClaim{
				{Key: "automountMapName", Value: "auto.other"},
			},
		},
	}

	entries := BuildAutomountEntries(groups, "dc=example,dc=com")

	// 1 map (auto.home) + 2 mount entries = 3
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (1 map + 2 mounts), got %d", len(entries))
	}

	// Verify map container is first
	if entries[0].GetAttributeValue("objectClass") != "automountMap" {
		t.Error("first entry should be automountMap")
	}
}

// --- Time window tests ---

func TestParseTimeWindows(t *testing.T) {
	tests := []struct {
		spec    string
		wantErr bool
		count   int
	}{
		{"09:00-17:00", false, 1},
		{"09:00-17:00,Mon-Fri", false, 1},
		{"09:00-17:00,Mon-Fri;18:00-22:00,Sat-Sun", false, 2},
		{"22:00-06:00", false, 1},
		{"", false, 0},
		{"invalid", true, 0},
	}

	for _, tt := range tests {
		windows, err := ParseTimeWindows(tt.spec)
		if tt.wantErr && err == nil {
			t.Errorf("ParseTimeWindows(%q): expected error", tt.spec)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("ParseTimeWindows(%q): unexpected error: %v", tt.spec, err)
		}
		if !tt.wantErr && len(windows) != tt.count {
			t.Errorf("ParseTimeWindows(%q): expected %d windows, got %d", tt.spec, tt.count, len(windows))
		}
	}
}

func TestIsWithinWindow(t *testing.T) {
	businessHours, _ := ParseTimeWindows("09:00-17:00,Mon-Fri")
	nightShift, _ := ParseTimeWindows("22:00-06:00")
	weekendOnly, _ := ParseTimeWindows("00:00-23:59,Sat-Sun")

	// Tuesday at 10:00 — within business hours
	tue10 := time.Date(2026, 3, 10, 10, 0, 0, 0, time.UTC)
	if !IsWithinWindow(businessHours, tue10) {
		t.Error("Tuesday 10:00 should be within business hours")
	}

	// Tuesday at 20:00 — outside business hours
	tue20 := time.Date(2026, 3, 10, 20, 0, 0, 0, time.UTC)
	if IsWithinWindow(businessHours, tue20) {
		t.Error("Tuesday 20:00 should be outside business hours")
	}

	// Saturday at 10:00 — outside business hours (wrong day)
	sat10 := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	if IsWithinWindow(businessHours, sat10) {
		t.Error("Saturday 10:00 should be outside business hours")
	}

	// Night shift: 23:00 should be within
	at23 := time.Date(2026, 3, 10, 23, 0, 0, 0, time.UTC)
	if !IsWithinWindow(nightShift, at23) {
		t.Error("23:00 should be within night shift (22:00-06:00)")
	}

	// Night shift: 03:00 should be within
	at03 := time.Date(2026, 3, 10, 3, 0, 0, 0, time.UTC)
	if !IsWithinWindow(nightShift, at03) {
		t.Error("03:00 should be within night shift (22:00-06:00)")
	}

	// Night shift: 12:00 should be outside
	at12 := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	if IsWithinWindow(nightShift, at12) {
		t.Error("12:00 should be outside night shift (22:00-06:00)")
	}

	// Weekend only: Saturday
	if !IsWithinWindow(weekendOnly, sat10) {
		t.Error("Saturday should be within weekend-only window")
	}

	// Weekend only: Tuesday
	if IsWithinWindow(weekendOnly, tue10) {
		t.Error("Tuesday should be outside weekend-only window")
	}

	// Empty windows = no restriction
	if !IsWithinWindow(nil, tue10) {
		t.Error("nil windows should allow access")
	}

	// Midnight-crossing with day restriction: "22:00-06:00,Mon-Fri"
	// This window means shifts starting Mon-Fri evenings, extending into the next morning.
	nightShiftWeekdays, _ := ParseTimeWindows("22:00-06:00,Mon-Fri")

	// Friday 23:00 — within (Friday is in Mon-Fri, pre-midnight portion)
	fri23 := time.Date(2026, 3, 13, 23, 0, 0, 0, time.UTC) // Friday
	if !IsWithinWindow(nightShiftWeekdays, fri23) {
		t.Error("Friday 23:00 should be within 22:00-06:00,Mon-Fri (pre-midnight, Friday is allowed)")
	}

	// Saturday 02:00 — within (post-midnight portion of Friday's shift; yesterday=Friday is in Mon-Fri)
	sat02 := time.Date(2026, 3, 14, 2, 0, 0, 0, time.UTC) // Saturday
	if !IsWithinWindow(nightShiftWeekdays, sat02) {
		t.Error("Saturday 02:00 should be within 22:00-06:00,Mon-Fri (post-midnight, yesterday=Friday is allowed)")
	}

	// Saturday 23:00 — outside (Saturday is NOT in Mon-Fri, pre-midnight portion)
	sat23 := time.Date(2026, 3, 14, 23, 0, 0, 0, time.UTC) // Saturday
	if IsWithinWindow(nightShiftWeekdays, sat23) {
		t.Error("Saturday 23:00 should be outside 22:00-06:00,Mon-Fri (Saturday not allowed)")
	}

	// Sunday 02:00 — outside (post-midnight, yesterday=Saturday is NOT in Mon-Fri)
	sun02 := time.Date(2026, 3, 15, 2, 0, 0, 0, time.UTC) // Sunday
	if IsWithinWindow(nightShiftWeekdays, sun02) {
		t.Error("Sunday 02:00 should be outside 22:00-06:00,Mon-Fri (yesterday=Saturday not allowed)")
	}

	// Monday 02:00 — outside (post-midnight, yesterday=Sunday is NOT in Mon-Fri)
	mon02 := time.Date(2026, 3, 16, 2, 0, 0, 0, time.UTC) // Monday
	if IsWithinWindow(nightShiftWeekdays, mon02) {
		t.Error("Monday 02:00 should be outside 22:00-06:00,Mon-Fri (yesterday=Sunday not allowed)")
	}

	// Monday 23:00 — within (Monday is in Mon-Fri, pre-midnight portion)
	mon23 := time.Date(2026, 3, 16, 23, 0, 0, 0, time.UTC) // Monday
	if !IsWithinWindow(nightShiftWeekdays, mon23) {
		t.Error("Monday 23:00 should be within 22:00-06:00,Mon-Fri (pre-midnight, Monday is allowed)")
	}

	// Tuesday 02:00 — within (post-midnight, yesterday=Monday is in Mon-Fri)
	tue02 := time.Date(2026, 3, 17, 2, 0, 0, 0, time.UTC) // Tuesday
	if !IsWithinWindow(nightShiftWeekdays, tue02) {
		t.Error("Tuesday 02:00 should be within 22:00-06:00,Mon-Fri (post-midnight, yesterday=Monday is allowed)")
	}
}

// --- Webhook tests ---

func TestWebhookRefresh(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	ws := NewWebhookServer(0, "test-secret", store, provider, nil, &sync.Mutex{}, "127.0.0.1")

	// Test refresh endpoint with correct secret
	req := httptest.NewRequest(http.MethodPost, "/webhook/refresh", nil)
	req.Header.Set("X-Webhook-Secret", "test-secret")
	rr := httptest.NewRecorder()
	ws.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify data was loaded
	found, _, _ := store.FindUser("jordan", false)
	if !found {
		t.Error("jordan should be found after webhook refresh")
	}
}

func TestWebhookNoSecret(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	ws := NewWebhookServer(0, "", store, provider, nil, &sync.Mutex{}, "127.0.0.1")

	// Without secret configured, endpoint should reject with 503
	req := httptest.NewRequest(http.MethodPost, "/webhook/refresh", nil)
	rr := httptest.NewRecorder()
	ws.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 without secret configured, got %d", rr.Code)
	}
}

func TestWebhookSecretAuth(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	ws := NewWebhookServer(0, "my-secret", store, provider, nil, &sync.Mutex{}, "127.0.0.1")

	// Without secret -> 401
	req := httptest.NewRequest(http.MethodPost, "/webhook/refresh", nil)
	rr := httptest.NewRecorder()
	ws.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without secret, got %d", rr.Code)
	}

	// With wrong secret -> 401
	req = httptest.NewRequest(http.MethodPost, "/webhook/refresh", nil)
	req.Header.Set("X-Webhook-Secret", "wrong")
	rr = httptest.NewRecorder()
	ws.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong secret, got %d", rr.Code)
	}

	// With correct secret -> 200
	req = httptest.NewRequest(http.MethodPost, "/webhook/refresh", nil)
	req.Header.Set("X-Webhook-Secret", "my-secret")
	rr = httptest.NewRecorder()
	ws.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with correct secret, got %d", rr.Code)
	}
}

func TestWebhookMethodNotAllowed(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	ws := NewWebhookServer(0, "test-secret", store, provider, nil, &sync.Mutex{}, "127.0.0.1")

	req := httptest.NewRequest(http.MethodGet, "/webhook/refresh", nil)
	rr := httptest.NewRecorder()
	ws.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", rr.Code)
	}
}

// --- Metrics tests ---

func TestMetricsRecording(t *testing.T) {
	m := &Metrics{}

	m.RecordSync(100*time.Millisecond, nil, 5, 3, 2, 1, 1, 2)

	if m.usersTotal != 5 {
		t.Errorf("expected usersTotal=5, got %d", m.usersTotal)
	}
	if m.syncSuccesses != 1 {
		t.Errorf("expected syncSuccesses=1, got %d", m.syncSuccesses)
	}
	if !m.lastSyncSuccess {
		t.Error("expected lastSyncSuccess=true")
	}

	// Record an error
	m.RecordSync(50*time.Millisecond, fmt.Errorf("test error"), 0, 0, 0, 0, 0, 0)
	if m.syncErrors != 1 {
		t.Errorf("expected syncErrors=1, got %d", m.syncErrors)
	}
	if m.lastSyncSuccess {
		t.Error("expected lastSyncSuccess=false after error")
	}
	// Users total should not have changed (error doesn't update counts)
	if m.usersTotal != 5 {
		t.Errorf("expected usersTotal still 5 after error, got %d", m.usersTotal)
	}
}

func TestMetricsHandler(t *testing.T) {
	m := &Metrics{}
	m.RecordSync(100*time.Millisecond, nil, 10, 5, 3, 2, 1, 4)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	m.Handler()(rr, req)

	body := rr.Body.String()

	if !strings.Contains(body, "glauth_pocketid_users_total") {
		t.Error("metrics should contain glauth_pocketid_users_total")
	}
	if !strings.Contains(body, "glauth_pocketid_sync_successes_total") {
		t.Error("metrics should contain glauth_pocketid_sync_successes_total")
	}
	if !strings.Contains(body, "glauth_pocketid_netgroups_total") {
		t.Error("metrics should contain glauth_pocketid_netgroups_total")
	}
	if rr.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("unexpected content type: %s", rr.Header().Get("Content-Type"))
	}
}

// --- Config tests for new features ---

func TestConfigNewDefaults(t *testing.T) {
	cfg := LoadConfig()
	if cfg.NetgroupPrefix != "netgroup-" {
		t.Errorf("expected netgroup prefix 'netgroup-', got %q", cfg.NetgroupPrefix)
	}
	if cfg.AccessPrefix != "access-" {
		t.Errorf("expected access prefix 'access-', got %q", cfg.AccessPrefix)
	}
	if cfg.AutomountPrefix != "automount-" {
		t.Errorf("expected automount prefix 'automount-', got %q", cfg.AutomountPrefix)
	}
	if cfg.WebhookPort != 0 {
		t.Errorf("expected webhook port 0, got %d", cfg.WebhookPort)
	}
}

// --- DN structure and membership tests ---

func TestFlatDNStructure(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	backend := config.Backend{
		BaseDN:             "dc=example,dc=com",
		NameFormat:         "cn",
		NameFormatAsArray:  []string{"cn"},
		GroupFormat:        "ou",
		GroupFormatAsArray: []string{"ou"},
		SSHKeyAttr:         "sshPublicKey",
	}

	// Check user DNs: should be cn=<username>,dc=example,dc=com (no OU)
	accounts, err := store.FindPosixAccounts(backend, "ou=users")
	if err != nil {
		t.Fatalf("FindPosixAccounts failed: %v", err)
	}

	for _, entry := range accounts {
		name := getAttr(entry, "cn")
		expectedDN := fmt.Sprintf("cn=%s,dc=example,dc=com", name)
		if entry.DN != expectedDN {
			t.Errorf("user %s: expected DN %q, got %q", name, expectedDN, entry.DN)
		}
		// Must NOT contain ou=users or ou=people in the DN
		if strings.Contains(entry.DN, "ou=") {
			t.Errorf("user %s: DN should not contain OU hierarchy, got %q", name, entry.DN)
		}
	}

	// Check group DNs: should be ou=<groupname>,dc=example,dc=com (no hierarchy)
	groups, err := store.FindPosixGroups(backend, "")
	if err != nil {
		t.Fatalf("FindPosixGroups failed: %v", err)
	}

	for _, entry := range groups {
		name := getAttr(entry, "ou")
		expectedDN := fmt.Sprintf("ou=%s,dc=example,dc=com", name)
		if entry.DN != expectedDN {
			t.Errorf("group %s: expected DN %q, got %q", name, expectedDN, entry.DN)
		}
		// Must NOT contain ou=groups hierarchy
		if strings.Contains(entry.DN, "ou=groups") {
			t.Errorf("group %s: DN should not contain ou=groups hierarchy, got %q", name, entry.DN)
		}
	}
}

func TestUserGroupMembership(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Get group GIDs for verification
	groupGIDs := make(map[string]int)
	for _, groupName := range []string{"developers", "server-admins", "service-restarters", "web-team", "web-access", "full-access", "nfs-homes"} {
		found, g, _ := store.FindGroup(groupName)
		if !found {
			t.Fatalf("group %s not found", groupName)
		}
		groupGIDs[groupName] = g.GIDNumber
	}

	// Jordan should be in: developers, server-admins, service-restarters, web-team, web-access (5 groups)
	found, jordan, _ := store.FindUser("jordan", false)
	if !found {
		t.Fatal("jordan not found")
	}

	jordanExpected := map[int]string{
		groupGIDs["developers"]:          "developers",
		groupGIDs["server-admins"]:       "server-admins",
		groupGIDs["service-restarters"]:  "service-restarters",
		groupGIDs["web-team"]:            "web-team",
		groupGIDs["web-access"]:          "web-access",
	}
	jordanOther := make(map[int]bool)
	for _, gid := range jordan.OtherGroups {
		jordanOther[gid] = true
	}
	for gid, name := range jordanExpected {
		if !jordanOther[gid] {
			t.Errorf("jordan missing group %s (GID %d) in OtherGroups", name, gid)
		}
	}
	if len(jordan.OtherGroups) != 5 {
		t.Errorf("jordan: expected 5 OtherGroups, got %d: %v", len(jordan.OtherGroups), jordan.OtherGroups)
	}

	// Alice should be in: developers, server-admins, web-team, full-access (4 groups)
	found, alice, _ := store.FindUser("alice", false)
	if !found {
		t.Fatal("alice not found")
	}

	aliceExpected := map[int]string{
		groupGIDs["developers"]:    "developers",
		groupGIDs["server-admins"]: "server-admins",
		groupGIDs["web-team"]:      "web-team",
		groupGIDs["full-access"]:   "full-access",
	}
	aliceOther := make(map[int]bool)
	for _, gid := range alice.OtherGroups {
		aliceOther[gid] = true
	}
	for gid, name := range aliceExpected {
		if !aliceOther[gid] {
			t.Errorf("alice missing group %s (GID %d) in OtherGroups", name, gid)
		}
	}
	if len(alice.OtherGroups) != 4 {
		t.Errorf("alice: expected 4 OtherGroups, got %d: %v", len(alice.OtherGroups), alice.OtherGroups)
	}

	// User private group pattern: PrimaryGroup == UIDNumber
	if jordan.PrimaryGroup != jordan.UIDNumber {
		t.Errorf("jordan: PrimaryGroup (%d) != UIDNumber (%d), expected user private group pattern",
			jordan.PrimaryGroup, jordan.UIDNumber)
	}
	if alice.PrimaryGroup != alice.UIDNumber {
		t.Errorf("alice: PrimaryGroup (%d) != UIDNumber (%d), expected user private group pattern",
			alice.PrimaryGroup, alice.UIDNumber)
	}
}

func TestMemberOfAttribute(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	backend := config.Backend{
		BaseDN:             "dc=example,dc=com",
		NameFormat:         "cn",
		NameFormatAsArray:  []string{"cn"},
		GroupFormat:        "ou",
		GroupFormatAsArray: []string{"ou"},
		SSHKeyAttr:         "sshPublicKey",
	}

	entries, err := store.FindPosixAccounts(backend, "ou=users")
	if err != nil {
		t.Fatalf("FindPosixAccounts failed: %v", err)
	}

	// Find jordan's entry
	var jordanEntry *struct {
		memberOf []string
	}
	for _, entry := range entries {
		if getAttr(entry, "cn") == "jordan" {
			jordanEntry = &struct{ memberOf []string }{
				memberOf: getAttrValues(entry, "memberOf"),
			}
			break
		}
	}
	if jordanEntry == nil {
		t.Fatal("jordan entry not found in FindPosixAccounts")
	}

	// Jordan is in 5 groups; memberOf should contain DNs for all of them
	// (plus potentially the user private group DN, which won't resolve to a named group)
	jordanGroups := []string{"developers", "server-admins", "service-restarters", "web-team", "web-access"}
	for _, groupName := range jordanGroups {
		expectedDN := fmt.Sprintf("ou=%s,dc=example,dc=com", groupName)
		found := false
		for _, dn := range jordanEntry.memberOf {
			if dn == expectedDN {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("jordan memberOf missing DN for group %s (expected %s)", groupName, expectedDN)
			t.Logf("  actual memberOf: %v", jordanEntry.memberOf)
		}
	}

	// No memberOf should contain "ou=groups" hierarchy
	for _, dn := range jordanEntry.memberOf {
		if strings.Contains(dn, "ou=groups") {
			t.Errorf("memberOf DN contains ou=groups hierarchy: %s", dn)
		}
	}
}

func TestGroupMemberUid(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	backend := config.Backend{
		BaseDN:             "dc=example,dc=com",
		NameFormat:         "cn",
		NameFormatAsArray:  []string{"cn"},
		GroupFormat:        "ou",
		GroupFormatAsArray: []string{"ou"},
		SSHKeyAttr:         "sshPublicKey",
	}

	// Use empty hierarchy (not "ou=groups") to get posixGroup with memberUid
	groups, err := store.FindPosixGroups(backend, "")
	if err != nil {
		t.Fatalf("FindPosixGroups failed: %v", err)
	}

	groupByName := make(map[string]*ldap.Entry)
	for _, entry := range groups {
		name := getAttr(entry, "ou")
		groupByName[name] = entry
	}

	// developers: jordan, alice, bob in IDP — but bob is disabled, so memberUid should be jordan, alice
	devEntry, ok := groupByName["developers"]
	if !ok {
		t.Fatal("developers group not found in posix groups")
	}
	devMembers := getAttrValues(devEntry, "memberUid")
	sort.Strings(devMembers)
	if len(devMembers) != 2 {
		t.Errorf("developers: expected 2 memberUid (bob excluded as disabled), got %d: %v", len(devMembers), devMembers)
	} else {
		if devMembers[0] != "alice" || devMembers[1] != "jordan" {
			t.Errorf("developers memberUid: expected [alice jordan], got %v", devMembers)
		}
	}

	// server-admins: jordan, alice
	adminsEntry, ok := groupByName["server-admins"]
	if !ok {
		t.Fatal("server-admins group not found in posix groups")
	}
	adminMembers := getAttrValues(adminsEntry, "memberUid")
	sort.Strings(adminMembers)
	if len(adminMembers) != 2 {
		t.Errorf("server-admins: expected 2 memberUid, got %d: %v", len(adminMembers), adminMembers)
	} else {
		if adminMembers[0] != "alice" || adminMembers[1] != "jordan" {
			t.Errorf("server-admins memberUid: expected [alice jordan], got %v", adminMembers)
		}
	}
}

func TestUserPrivateGroup(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	backend := config.Backend{
		BaseDN:             "dc=example,dc=com",
		NameFormat:         "cn",
		NameFormatAsArray:  []string{"cn"},
		GroupFormat:        "ou",
		GroupFormatAsArray: []string{"ou"},
		SSHKeyAttr:         "sshPublicKey",
	}

	// Check via FindUser that PrimaryGroup == UIDNumber for all users
	for _, username := range []string{"jordan", "alice"} {
		found, u, _ := store.FindUser(username, false)
		if !found {
			t.Fatalf("%s not found", username)
		}
		if u.PrimaryGroup != u.UIDNumber {
			t.Errorf("%s: PrimaryGroup (%d) != UIDNumber (%d)", username, u.PrimaryGroup, u.UIDNumber)
		}
	}

	// Check that the ou attribute on user entries is "users", not a group name
	entries, err := store.FindPosixAccounts(backend, "ou=users")
	if err != nil {
		t.Fatalf("FindPosixAccounts failed: %v", err)
	}

	for _, entry := range entries {
		name := getAttr(entry, "cn")
		ou := getAttr(entry, "ou")
		if ou != "users" {
			t.Errorf("%s: expected ou=users, got ou=%s", name, ou)
		}
	}

	// Check that FindPosixGroups includes user private groups
	groups, err := store.FindPosixGroups(backend, "")
	if err != nil {
		t.Fatalf("FindPosixGroups failed: %v", err)
	}

	for _, username := range []string{"jordan", "alice"} {
		found, u, _ := store.FindUser(username, false)
		if !found {
			t.Fatalf("%s not found", username)
		}
		var upg *ldap.Entry
		for _, g := range groups {
			if getAttr(g, "ou") == username {
				upg = g
				break
			}
		}
		if upg == nil {
			t.Errorf("%s: no user private group found in FindPosixGroups", username)
			continue
		}
		gid := getAttr(upg, "gidNumber")
		if gid != fmt.Sprintf("%d", u.UIDNumber) {
			t.Errorf("%s: UPG gidNumber = %s, want %d", username, gid, u.UIDNumber)
		}
	}

	// Check that FindGroup resolves user private groups
	for _, username := range []string{"jordan", "alice"} {
		found, g, err := store.FindGroup(username)
		if err != nil {
			t.Fatalf("FindGroup(%s): %v", username, err)
		}
		if !found {
			t.Errorf("FindGroup(%s): not found, expected UPG", username)
			continue
		}
		_, u, _ := store.FindUser(username, false)
		if g.GIDNumber != u.UIDNumber {
			t.Errorf("FindGroup(%s): GIDNumber = %d, want %d", username, g.GIDNumber, u.UIDNumber)
		}
	}
}

func TestUIDValidation(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := PluginConfig{
		UIDBase:     200000,
		GIDBase:     200000,
		DefaultShell: "/bin/bash",
		DefaultHome: "/home/{username}",
		PersistPath: filepath.Join(tmpDir, "uidmap.json"),
		BaseDN:      "dc=example,dc=com",
	}

	store := NewStore(cfg)

	// Test uidNumber=0 gets auto-assigned
	uid0 := store.assignUID("user-zero", map[string]string{"uidNumber": "0"})
	if uid0 < cfg.UIDBase {
		t.Errorf("uidNumber=0 should be rejected and auto-assigned >= %d, got %d", cfg.UIDBase, uid0)
	}

	// Test uidNumber=500 (below UIDBase) gets auto-assigned
	uid500 := store.assignUID("user-500", map[string]string{"uidNumber": "500"})
	if uid500 < cfg.UIDBase {
		t.Errorf("uidNumber=500 should be rejected (below UIDBase=%d) and auto-assigned, got %d", cfg.UIDBase, uid500)
	}

	// Test valid uidNumber is accepted
	uid220000 := store.assignUID("user-valid", map[string]string{"uidNumber": "220000"})
	if uid220000 != 220000 {
		t.Errorf("uidNumber=220000 should be accepted, got %d", uid220000)
	}

	// Test collision detection: different user claiming same UID
	uidCollision := store.assignUID("user-collision", map[string]string{"uidNumber": "220000"})
	if uidCollision == 220000 {
		t.Errorf("uidNumber=220000 should be rejected due to collision with user-valid, got %d", uidCollision)
	}
	if uidCollision < cfg.UIDBase {
		t.Errorf("collision fallback should auto-assign >= %d, got %d", cfg.UIDBase, uidCollision)
	}
}

func TestLoginShellValidation(t *testing.T) {
	tests := []struct {
		shell    string
		valid    bool
		desc     string
	}{
		{"/bin/bash", true, "standard bash"},
		{"/bin/zsh", true, "zsh"},
		{"/usr/bin/fish", true, "fish shell"},
		{"/bin/bash -c evil", false, "shell with arguments (space)"},
		{"not-absolute", false, "relative path"},
		{"", false, "empty string"},
		{"/bin/bash;rm -rf /", false, "shell injection with semicolon"},
		{"/bin/bash\nrm -rf /", false, "shell injection with newline"},
		{"/usr/local/bin/my-shell", true, "custom absolute path"},
	}

	for _, tt := range tests {
		result := ValidateLoginShell(tt.shell)
		if result != tt.valid {
			t.Errorf("ValidateLoginShell(%q) [%s]: expected %v, got %v", tt.shell, tt.desc, tt.valid, result)
		}
	}

	// Integration test: verify that invalid loginShell falls back to default
	srv := mockPocketIDServer(t)
	defer srv.Close()

	tmpDir := t.TempDir()
	cfg := PluginConfig{
		BaseURL:         srv.URL,
		APIKey:          testAPIKey,
		RefreshSec:      300,
		UIDBase:         200000,
		GIDBase:         200000,
		DefaultShell:    "/bin/bash",
		DefaultHome:     "/home/{username}",
		SudoPrefix:      "sudo-",
		PersistPath:     filepath.Join(tmpDir, "uidmap.json"),
		BaseDN:          "dc=example,dc=com",
		NetgroupPrefix:  "netgroup-",
		AccessPrefix:    "access-",
		AutomountPrefix: "automount-",
	}

	provider := NewPocketIDClient(srv.URL, testAPIKey)
	store := NewStore(cfg)

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Jordan has loginShell="/bin/zsh" which is valid
	_, jordan, _ := store.FindUser("jordan", false)
	if jordan.LoginShell != "/bin/zsh" {
		t.Errorf("jordan: expected /bin/zsh, got %s", jordan.LoginShell)
	}

	// Alice has no loginShell claim, should get default
	_, alice, _ := store.FindUser("alice", false)
	if alice.LoginShell != "/bin/bash" {
		t.Errorf("alice: expected default /bin/bash, got %s", alice.LoginShell)
	}
}

func TestHasUnsafeMountOption(t *testing.T) {
	tests := []struct {
		info   string
		unsafe bool
		desc   string
	}{
		{"-fstype=nfs,rw,nosuid,nodev,noexec server:/export/home/&", false, "safe NFS mount"},
		{"-fstype=nfs,rw,suid server:/export/home/&", true, "suid option"},
		{"-fstype=nfs,rw,dev server:/export/home/&", true, "dev option"},
		{"-fstype=nfs,rw,exec server:/export/home/&", true, "exec option"},
		{"-fstype=nfs,rw,nosuid server:/path", false, "nosuid is safe"},
		{"-fstype=nfs,rw,nodev server:/path", false, "nodev is safe"},
		{"-fstype=nfs,rw,noexec server:/path", false, "noexec is safe"},
		{"-fstype=nfs,suid,nodev server:/path", true, "suid with nodev"},
		{"-fstype=nfs,nosuid,dev server:/path", true, "dev with nosuid"},
		{"-fstype=nfs,rw server:/path", false, "no suid/dev/exec options"},
		{"suid", true, "bare suid option"},
		{"dev", true, "bare dev option"},
		{"exec", true, "bare exec option"},
		{"-fstype=nfs,SUID server:/path", true, "case insensitive suid"},
		{"-fstype=nfs,DEV server:/path", true, "case insensitive dev"},
		{"-fstype=nfs,EXEC server:/path", true, "case insensitive exec"},
		{"-fstype=nfs,nonosuid server:/path", false, "nonosuid is not suid"},
	}

	for _, tt := range tests {
		result := hasUnsafeMountOption(tt.info)
		if result != tt.unsafe {
			t.Errorf("hasUnsafeMountOption(%q) [%s]: expected %v, got %v", tt.info, tt.desc, tt.unsafe, result)
		}
	}
}

func TestIDPUserBindDisabled(t *testing.T) {
	store, provider, cleanup := testStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// IDP users must have PassSHA256 set to "!" to prevent LDAP bind
	_, jordan, _ := store.FindUser("jordan", false)
	if jordan.PassSHA256 != "!" {
		t.Errorf("jordan PassSHA256 should be '!' (bind disabled), got %q", jordan.PassSHA256)
	}

	_, alice, _ := store.FindUser("alice", false)
	if alice.PassSHA256 != "!" {
		t.Errorf("alice PassSHA256 should be '!' (bind disabled), got %q", alice.PassSHA256)
	}
}

func TestSudoCommandValidation(t *testing.T) {
	tests := []struct {
		cmd   string
		valid bool
		desc  string
	}{
		{"/usr/bin/systemctl restart *", true, "absolute path with glob"},
		{"/usr/bin/top", true, "simple absolute path"},
		{"ALL", true, "ALL keyword"},
		{"", false, "empty string"},
		{"!/usr/bin/su", false, "negation pattern"},
		{"sudoedit /etc/sudoers", false, "sudoedit"},
		{"SUDOEDIT /etc/passwd", false, "sudoedit case insensitive"},
		{"relative/path", false, "relative path"},
		{"sudoedit", false, "bare sudoedit"},
		{"/usr/bin/../bin/su", false, "path traversal with .."},
		{"/usr/bin/../../etc/shadow", false, "deep path traversal"},
		{"/usr/..hidden/bin", false, "dot-dot in directory name"},
	}

	for _, tt := range tests {
		result := validSudoCommand(tt.cmd)
		if result != tt.valid {
			t.Errorf("validSudoCommand(%q) [%s]: expected %v, got %v", tt.cmd, tt.desc, tt.valid, result)
		}
	}

	// Integration: negated commands should be filtered from sudo rules
	groups := []IDPGroup{
		{
			ID:   "g1",
			Name: "tricky-sudo",
			CustomClaims: []CustomClaim{
				{Key: "sudoCommands", Value: "/usr/bin/*, !/usr/bin/su"},
			},
		},
	}
	memberMap := map[string][]string{"g1": {"attacker"}}
	rules := BuildSudoRules(groups, memberMap, "dc=example,dc=com", "true")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	for _, attr := range rules[0].Attributes {
		if attr.Name == "sudoCommand" {
			for _, v := range attr.Values {
				if strings.HasPrefix(v, "!") {
					t.Errorf("negation pattern %q should have been filtered", v)
				}
			}
			if len(attr.Values) != 1 || attr.Values[0] != "/usr/bin/*" {
				t.Errorf("expected only '/usr/bin/*', got %v", attr.Values)
			}
		}
	}
}

func TestSudoOptionValidation(t *testing.T) {
	tests := []struct {
		opt  string
		safe bool
		desc string
	}{
		{"log_output", true, "safe option"},
		{"log_input", true, "safe option"},
		{"env_keep+=SSH_AUTH_SOCK", true, "safe env_keep"},
		{"!env_reset", false, "dangerous: disables env reset"},
		{"setenv", false, "dangerous: allows setting env"},
		{"!requiretty", false, "dangerous: no tty required"},
		{"env_keep+=LD_PRELOAD", false, "dangerous: LD_PRELOAD injection"},
		{"env_keep+=LD_LIBRARY_PATH", false, "dangerous: library path injection"},
		{"env_keep+=PYTHONPATH", false, "dangerous: Python import injection"},
		// Whitespace bypass attempts
		{"env_keep += LD_PRELOAD", false, "whitespace bypass: LD_PRELOAD with spaces"},
		{"env_keep +=\tLD_LIBRARY_PATH", false, "whitespace bypass: tab in env_keep"},
		{"!authenticate", false, "dangerous: disables PAM auth"},
		{"! authenticate", false, "whitespace bypass: !authenticate with space"},
		{"authenticate", false, "dangerous: explicit authenticate toggle"},
	}

	for _, tt := range tests {
		result := isSafeSudoOption(tt.opt)
		if result != tt.safe {
			t.Errorf("isSafeSudoOption(%q) [%s]: expected %v, got %v", tt.opt, tt.desc, tt.safe, result)
		}
	}

	// Integration: dangerous options should be stripped from sudo rules
	groups := []IDPGroup{
		{
			ID:   "g1",
			Name: "evil-sudo",
			CustomClaims: []CustomClaim{
				{Key: "sudoCommands", Value: "/usr/bin/systemctl restart *"},
				{Key: "sudoOptions", Value: "!env_reset, env_keep+=LD_PRELOAD, log_output"},
			},
		},
	}
	memberMap := map[string][]string{"g1": {"attacker"}}
	rules := BuildSudoRules(groups, memberMap, "dc=example,dc=com", "false")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	for _, attr := range rules[0].Attributes {
		if attr.Name == "sudoOption" {
			if len(attr.Values) != 1 || attr.Values[0] != "log_output" {
				t.Errorf("expected only 'log_output' after filtering, got %v", attr.Values)
			}
		}
	}
}

// --- SudoNoAuthenticate Three-Mode Tests ---

func TestSudoNoAuthenticateClaimsMode(t *testing.T) {
	groups := []IDPGroup{
		{
			ID:   "g1",
			Name: "automation-bots",
			CustomClaims: []CustomClaim{
				{Key: "sudoCommands", Value: "ALL"},
				{Key: "sudoOptions", Value: "!authenticate, log_output"},
			},
		},
		{
			ID:   "g2",
			Name: "full-admins",
			CustomClaims: []CustomClaim{
				{Key: "sudoCommands", Value: "ALL"},
				{Key: "sudoOptions", Value: "log_output"},
			},
		},
	}
	memberMap := map[string][]string{
		"g1": {"bot1"},
		"g2": {"admin1"},
	}

	// claims mode: !authenticate allowed per-group
	rules := BuildSudoRules(groups, memberMap, "dc=example,dc=com", "claims")
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	// g1 should have !authenticate + log_output
	var g1Opts, g2Opts []string
	for _, r := range rules {
		for _, attr := range r.Attributes {
			if attr.Name == "cn" && attr.Values[0] == "automation-bots" {
				for _, a := range r.Attributes {
					if a.Name == "sudoOption" {
						g1Opts = a.Values
					}
				}
			}
			if attr.Name == "cn" && attr.Values[0] == "full-admins" {
				for _, a := range r.Attributes {
					if a.Name == "sudoOption" {
						g2Opts = a.Values
					}
				}
			}
		}
	}

	if len(g1Opts) != 2 {
		t.Errorf("automation-bots: expected 2 sudoOptions, got %d: %v", len(g1Opts), g1Opts)
	}
	if len(g2Opts) != 1 || g2Opts[0] != "log_output" {
		t.Errorf("full-admins: expected [log_output], got %v", g2Opts)
	}

	// false mode: !authenticate blocked even from claims
	rules = BuildSudoRules(groups, memberMap, "dc=example,dc=com", "false")
	for _, r := range rules {
		for _, attr := range r.Attributes {
			if attr.Name == "cn" && attr.Values[0] == "automation-bots" {
				for _, a := range r.Attributes {
					if a.Name == "sudoOption" {
						for _, v := range a.Values {
							if v == "!authenticate" {
								t.Error("false mode: !authenticate should be blocked from claims")
							}
						}
					}
				}
			}
		}
	}

	// true mode: !authenticate added globally (even without claim)
	rules = BuildSudoRules(groups, memberMap, "dc=example,dc=com", "true")
	for _, r := range rules {
		for _, attr := range r.Attributes {
			if attr.Name == "sudoOption" {
				found := false
				for _, v := range attr.Values {
					if v == "!authenticate" {
						found = true
					}
				}
				if !found {
					cn := ""
					for _, a := range r.Attributes {
						if a.Name == "cn" {
							cn = a.Values[0]
						}
					}
					t.Errorf("true mode: %s should have !authenticate", cn)
				}
			}
		}
	}
}

func TestSudoNoAuthenticateWhitespaceBypass(t *testing.T) {
	// Test that whitespace variations of !authenticate are caught
	groups := []IDPGroup{
		{
			ID:   "g1",
			Name: "tricky",
			CustomClaims: []CustomClaim{
				{Key: "sudoCommands", Value: "ALL"},
				{Key: "sudoOptions", Value: "! authenticate"},
			},
		},
	}
	memberMap := map[string][]string{"g1": {"user1"}}

	rules := BuildSudoRules(groups, memberMap, "dc=example,dc=com", "false")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	for _, attr := range rules[0].Attributes {
		if attr.Name == "sudoOption" {
			for _, v := range attr.Values {
				if v == "! authenticate" || v == "!authenticate" {
					t.Error("false mode: whitespace variant of !authenticate should be blocked")
				}
			}
		}
	}
}

// --- SSH Key Validation Tests ---

func TestSSHKeyValidation(t *testing.T) {
	tests := []struct {
		key   string
		valid bool
	}{
		// Valid keys
		{"ssh-rsa AAAAB3NzaC1yc2EAAA user@host", true},
		{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA user@host", true},
		{"ecdsa-sha2-nistp256 AAAAE2VjZHNh user@host", true},
		{"ssh-dss AAAAB3NzaC1kc3MAAA user@host", true},
		{"sk-ssh-ed25519@openssh.com AAAAG user@host", true},
		{"sk-ecdsa-sha2-nistp256@openssh.com AAAAG user@host", true},
		{"  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA user@host  ", true}, // trimmed

		// ATTACK: authorized_keys options injection
		{`command="/bin/evil" ssh-rsa AAAA`, false},
		{`no-pty ssh-ed25519 AAAA`, false},
		{`restrict,command="/bin/bash -c 'cat /etc/shadow'" ssh-rsa AAAA`, false},
		{`environment="PATH=/evil" ssh-rsa AAAA`, false},
		{`from="attacker.com" ssh-ed25519 AAAA`, false},
		{`permitopen="0.0.0.0:0" ssh-rsa AAAA`, false},

		// Invalid
		{"", false},
		{"not-a-key", false},
		{"ssh-rsa", false},       // no space + data
		{"ssh-rsaAAAA", false},   // no space
		{"SSH-RSA AAAA", false},  // wrong case
	}

	for _, tc := range tests {
		result := isValidSSHKey(tc.key)
		if result != tc.valid {
			t.Errorf("isValidSSHKey(%q) = %v, want %v", tc.key, result, tc.valid)
		}
	}
}

func TestSSHKeyInjectionBlocked(t *testing.T) {
	// Verify extractSSHKeys rejects injected keys
	claims := map[string]string{
		"sshPublicKey1": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA valid@key",
		"sshPublicKey2": `command="/bin/evil" ssh-rsa AAAA injected@key`,
		"sshPublicKey3": "ssh-rsa AAAAB3NzaC1yc2EAAA also-valid@key",
	}

	keys := extractSSHKeys(claims)
	if len(keys) != 2 {
		t.Fatalf("expected 2 valid keys, got %d: %v", len(keys), keys)
	}
	for _, k := range keys {
		if strings.Contains(k, "command=") {
			t.Errorf("injected key should have been rejected: %s", k)
		}
	}
}

// --- UID 0 Prevention Tests ---

func TestUID0Prevention(t *testing.T) {
	cfg := PluginConfig{
		UIDBase:     1000, // LoadConfig enforces >= 1000
		GIDBase:     1000,
		PersistPath: t.TempDir() + "/test.json",
		DefaultShell: "/bin/bash",
		DefaultHome:  "/home/{username}",
	}

	store := NewStore(cfg)

	// Claim UID 0 — should be rejected
	uid := store.assignUID("user-wants-root", map[string]string{"uidNumber": "0"})
	if uid == 0 {
		t.Fatal("CRITICAL: assignUID returned UID 0 (root)")
	}
	if uid < 1000 {
		t.Fatalf("assignUID returned system UID %d, expected >= 1000", uid)
	}

	// Claim UID -1
	uid = store.assignUID("user-wants-neg", map[string]string{"uidNumber": "-1"})
	if uid <= 0 {
		t.Fatalf("assignUID returned invalid UID %d for claim -1", uid)
	}

	// Claim UID 2^32 overflow
	uid = store.assignUID("user-wants-overflow", map[string]string{"uidNumber": "4294967296"})
	if uid == 0 {
		t.Fatal("CRITICAL: assignUID returned UID 0 from overflow")
	}
}

func TestUIDBaseMinimum(t *testing.T) {
	// Verify LoadConfig enforces minimum base
	t.Setenv("POCKETID_UID_BASE", "0")
	t.Setenv("POCKETID_GID_BASE", "500")
	cfg := LoadConfig()
	if cfg.UIDBase < 1000 {
		t.Errorf("UIDBase should be >= 1000, got %d", cfg.UIDBase)
	}
	if cfg.GIDBase < 1000 {
		t.Errorf("GIDBase should be >= 1000, got %d", cfg.GIDBase)
	}
}

func TestAutoAssignUIDCollisionPrevention(t *testing.T) {
	cfg := PluginConfig{
		UIDBase:     200000,
		GIDBase:     200000,
		PersistPath: t.TempDir() + "/test.json",
		DefaultShell: "/bin/bash",
		DefaultHome:  "/home/{username}",
	}

	store := NewStore(cfg)

	// User A claims UID 200000 (which is also where nextUID starts)
	uidA := store.assignUID("user-A", map[string]string{"uidNumber": "200000"})
	if uidA != 200000 {
		t.Fatalf("expected user-A to get UID 200000, got %d", uidA)
	}

	// User B auto-assigned — should NOT get 200000 (collision)
	uidB := store.assignUID("user-B", map[string]string{})
	if uidB == 200000 {
		t.Fatal("CRITICAL: user-B got same UID as user-A (collision)")
	}
	if uidB < 200000 {
		t.Fatalf("user-B got UID %d, expected >= 200000", uidB)
	}
}

// --- Null Byte Handling Tests ---

func TestNullByteStripping(t *testing.T) {
	claims := []CustomClaim{
		{Key: "sudoCommands", Value: "/bin/bash\x00extra"},
		{Key: "loginShell", Value: "/bin/zsh\x00"},
		{Key: "sshPublicKey1", Value: "ssh-rsa AAAA\x00injected"},
	}

	m := ClaimsMap(claims)

	for key, val := range m {
		if strings.Contains(val, "\x00") {
			t.Errorf("ClaimsMap(%s) still contains null byte: %q", key, val)
		}
	}

	// sudoCommands should be "/bin/bashextra" after null stripping
	if m["sudoCommands"] != "/bin/bashextra" {
		t.Errorf("expected '/bin/bashextra', got %q", m["sudoCommands"])
	}
}

func TestSudoCommandNullByteRejection(t *testing.T) {
	// Even after ClaimsMap strips nulls, verify validSudoCommand rejects them
	if validSudoCommand("/bin/bash\x00") {
		t.Error("validSudoCommand should reject null bytes")
	}
	if validSudoCommand("/bin/bash\x00/evil") {
		t.Error("validSudoCommand should reject embedded null bytes")
	}
}

// --- Automount Shell Metachar Tests ---

func TestAutomountShellMetachars(t *testing.T) {
	tests := []struct {
		info   string
		reject bool
	}{
		{"-fstype=nfs server:/path", false},
		{"-fstype=nfs,rw server:/path", false},
		{"`whoami`:/path", true},
		{"$(id):/path", true},
		{"-fstype=nfs server:/path | tee /tmp/evil", true},
		{"-fstype=nfs server:/path; rm -rf /", true},
	}

	for _, tc := range tests {
		result := hasShellMetachars(tc.info)
		if result != tc.reject {
			t.Errorf("hasShellMetachars(%q) = %v, want %v", tc.info, result, tc.reject)
		}
	}
}

// --- SSRF Prevention Tests ---

func TestSSRFRedirectBlocked(t *testing.T) {
	// The client should block redirects to different hosts
	client := NewPocketIDClient("http://legitimate-idp.example.com", "test-key")
	if client == nil {
		t.Fatal("NewPocketIDClient returned nil")
	}
	// The CheckRedirect function is tested implicitly through the HTTP client
	// configuration — we verify it's set up correctly
	if client.http.CheckRedirect == nil {
		t.Fatal("CheckRedirect should be configured to block cross-origin redirects")
	}
}

// --- Hostname ALL Rejection Tests ---

func TestHostnameALLRejected(t *testing.T) {
	groups := []IDPGroup{
		{
			ID:   "g1",
			Name: "access-all",
			CustomClaims: []CustomClaim{
				{Key: "accessHosts", Value: "ALL"},
			},
		},
		{
			ID:   "g2",
			Name: "access-mixed",
			CustomClaims: []CustomClaim{
				{Key: "accessHosts", Value: "web01, ALL, db01"},
			},
		},
	}
	memberMap := map[string][]string{
		"g1": {"alice"},
		"g2": {"jordan"},
	}

	result := BuildUserHostMap(groups, memberMap)

	// alice: group has only "ALL" which is rejected -> no hosts
	if hosts, ok := result["alice"]; ok && len(hosts) > 0 {
		t.Errorf("alice should have no hosts (ALL rejected), got %v", hosts)
	}

	// jordan: "web01, ALL, db01" -> ALL rejected, left with web01, db01
	if len(result["jordan"]) != 2 {
		t.Errorf("expected 2 hosts for jordan (ALL filtered), got %d: %v", len(result["jordan"]), result["jordan"])
	}
}

// TestSudoOptionQuotingBypass verifies that quotes in sudo options are stripped
// during normalization, preventing bypass of the blocklist via env_keep+="LD_PRELOAD".
func TestSudoOptionQuotingBypass(t *testing.T) {
	cases := []struct {
		opt  string
		safe bool
	}{
		{`env_keep+="LD_PRELOAD"`, false},
		{`env_keep+='LD_PRELOAD'`, false},
		{`env_keep += "LD_PRELOAD"`, false},
		{`env_keep+="LD_LIBRARY_PATH"`, false},
		{`env_keep+="PYTHONPATH"`, false},
		{`env_keep+="PATH"`, false},
		{`env_keep+="HOME"`, false},
		{`env_keep+="EDITOR"`, false},
	}
	for _, c := range cases {
		if got := isSafeSudoOption(c.opt); got != c.safe {
			t.Errorf("isSafeSudoOption(%q) = %v, want %v", c.opt, got, c.safe)
		}
	}
}

// TestSudoOptionSyslogPamSession verifies !syslog and !pam_session are blocked.
func TestSudoOptionSyslogPamSession(t *testing.T) {
	cases := []string{"!syslog", "!pam_session", "!SYSLOG", "!PAM_SESSION"}
	for _, opt := range cases {
		if isSafeSudoOption(opt) {
			t.Errorf("isSafeSudoOption(%q) = true, want false", opt)
		}
	}
}

// TestSudoCommandNewlineRejection verifies that newlines in sudo commands are rejected.
func TestSudoCommandNewlineRejection(t *testing.T) {
	cases := []string{
		"/usr/bin/foo\n/usr/bin/bar",
		"/usr/bin/foo\r\n/usr/bin/bar",
		"ALL\n!/usr/bin/su",
	}
	for _, cmd := range cases {
		if validSudoCommand(cmd) {
			t.Errorf("validSudoCommand(%q) = true, want false", cmd)
		}
	}
}

// TestSudoRuleSkippedWithNoMembers verifies that sudo rules with zero validated
// members are not emitted (prevents memberless sudoRole entries).
func TestSudoRuleSkippedWithNoMembers(t *testing.T) {
	groups := []IDPGroup{
		{
			ID:   "g1",
			Name: "has-members",
			CustomClaims: []CustomClaim{
				{Key: "sudoCommands", Value: "/usr/bin/systemctl"},
			},
		},
		{
			ID:   "g2",
			Name: "no-members",
			CustomClaims: []CustomClaim{
				{Key: "sudoCommands", Value: "/usr/bin/systemctl"},
			},
		},
	}
	memberMap := map[string][]string{
		"g1": {"alice"},
		"g2": {}, // empty
	}
	rules := BuildSudoRules(groups, memberMap, "dc=example,dc=com", "false")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (empty-member rule should be skipped), got %d", len(rules))
	}
	if rules[0].DN != "cn=has-members,ou=sudoers,dc=example,dc=com" {
		t.Errorf("unexpected rule DN: %s", rules[0].DN)
	}
}

// TestAutomountMapNameValidation verifies that dangerous map names are blocked.
func TestAutomountMapNameValidation(t *testing.T) {
	groups := []IDPGroup{
		{
			ID:   "g1",
			Name: "mount-master",
			CustomClaims: []CustomClaim{
				{Key: "automountMapName", Value: "auto.master"},
				{Key: "automountKey", Value: "/home"},
				{Key: "automountInformation", Value: "-fstype=nfs,rw nas:/home"},
			},
		},
		{
			ID:   "g2",
			Name: "mount-direct",
			CustomClaims: []CustomClaim{
				{Key: "automountMapName", Value: "auto.direct"},
				{Key: "automountKey", Value: "/mnt/evil"},
				{Key: "automountInformation", Value: "-fstype=nfs,rw evil:/pwn"},
			},
		},
		{
			ID:   "g3",
			Name: "mount-invalid-format",
			CustomClaims: []CustomClaim{
				{Key: "automountMapName", Value: "../../etc/auto.master"},
				{Key: "automountKey", Value: "/home"},
				{Key: "automountInformation", Value: "-fstype=nfs,rw nas:/home"},
			},
		},
		{
			ID:   "g4",
			Name: "mount-valid",
			CustomClaims: []CustomClaim{
				{Key: "automountMapName", Value: "auto.home"},
				{Key: "automountKey", Value: "*"},
				{Key: "automountInformation", Value: "-fstype=nfs,rw,nosuid,nodev nas:/home/&"},
			},
		},
	}
	entries := BuildAutomountEntries(groups, "dc=example,dc=com")

	// Only the valid entry (auto.home) should be present
	if len(entries) != 2 { // 1 map container + 1 mount entry
		t.Errorf("expected 2 entries (1 valid map + 1 mount), got %d", len(entries))
		for _, e := range entries {
			t.Logf("  entry: %s", e.DN)
		}
	}
}

// TestLeadingDotHostnameRejected verifies that leading-dot hostnames are blocked
// to prevent pam_access domain wildcard bypass.
func TestLeadingDotHostnameRejected(t *testing.T) {
	groups := []IDPGroup{
		{
			ID:   "g1",
			Name: "dot-access",
			CustomClaims: []CustomClaim{
				{Key: "accessHosts", Value: ".example.com, web01, .evil.com"},
			},
		},
	}
	memberMap := map[string][]string{
		"g1": {"testuser"},
	}

	result := BuildUserHostMap(groups, memberMap)

	// Only "web01" should pass — leading-dot entries should be stripped
	hosts := result["testuser"]
	if len(hosts) != 1 || hosts[0] != "web01" {
		t.Errorf("expected only [web01], got %v", hosts)
	}
}

// TestReservedGroupNameRejection verifies that system group names are blocked.
func TestReservedGroupNameRejection(t *testing.T) {
	reserved := []string{"root", "wheel", "sudo", "admin", "docker", "sshd", "all"}
	for _, name := range reserved {
		if isValidGroupName(name) {
			t.Errorf("isValidGroupName(%q) = true, want false (reserved)", name)
		}
	}
	// Valid group names should still pass
	valid := []string{"developers", "server-admins", "web-team", "ops_team"}
	for _, name := range valid {
		if !isValidGroupName(name) {
			t.Errorf("isValidGroupName(%q) = false, want true", name)
		}
	}
}

// TestSudoOptionUnicodeWhitespaceBypass verifies that Unicode whitespace characters
// (non-breaking space, etc.) are stripped during normalization.
func TestSudoOptionUnicodeWhitespaceBypass(t *testing.T) {
	cases := []struct {
		opt  string
		safe bool
	}{
		{"env_keep+=\u00A0LD_PRELOAD", false},  // non-breaking space
		{"env_keep+=\u2000LD_PRELOAD", false},   // en quad
		{"env_keep+=\u3000LD_PRELOAD", false},   // ideographic space
		{"!\u00A0authenticate", false},           // NBSP in !authenticate
	}
	for _, c := range cases {
		if got := isSafeSudoOption(c.opt); got != c.safe {
			t.Errorf("isSafeSudoOption(%q) = %v, want %v", c.opt, got, c.safe)
		}
	}
}

// suppress unused import warning
var _ = fmt.Sprintf
