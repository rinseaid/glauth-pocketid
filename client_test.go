package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glauth/glauth/v2/pkg/config"
)

const testAPIKey = "test-api-key"

// pocketIDResponse builds a Pocket ID list API response with pagination.
func pocketIDResponse(data interface{}, currentPage, totalPages, totalItems int) []byte {
	resp := map[string]interface{}{
		"data": data,
		"pagination": map[string]interface{}{
			"currentPage": currentPage,
			"totalPages":  totalPages,
			"totalItems":  totalItems,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// mockPocketIDServer creates an httptest.Server simulating the Pocket ID REST API.
// It serves 3 users and 7 groups with X-API-KEY authentication.
func mockPocketIDServer(t *testing.T) *httptest.Server {
	t.Helper()

	users := []map[string]interface{}{
		{
			"id":        "a0000000-0000-0000-0000-000000000001",
			"username":  "jordan",
			"email":     "jordan@example.com",
			"firstName": "Jordan",
			"lastName":  "Smith",
			"disabled":  false,
			"customClaims": []map[string]string{
				{"key": "sshPublicKey1", "value": "ssh-rsa AAAA jordan@laptop"},
				{"key": "sshPublicKey2", "value": "ssh-ed25519 BBBB jordan@desktop"},
				{"key": "loginShell", "value": "/bin/zsh"},
			},
		},
		{
			"id":        "a0000000-0000-0000-0000-000000000002",
			"username":  "alice",
			"email":     "alice@example.com",
			"firstName": "Alice",
			"lastName":  "Jones",
			"disabled":  false,
			"customClaims": []map[string]string{
				{"key": "sshPublicKey1", "value": "ssh-rsa CCCC alice@laptop"},
			},
		},
		{
			"id":        "a0000000-0000-0000-0000-000000000003",
			"username":  "bob",
			"email":     "bob@example.com",
			"firstName": "Bob",
			"lastName":  "Brown",
			"disabled":  true,
			"customClaims": []map[string]string{},
		},
	}

	// Groups include their members inline (Pocket ID returns users with groups)
	groups := []map[string]interface{}{
		{
			"id":           "b0000000-0000-0000-0000-000000000001",
			"name":         "developers",
			"customClaims": []map[string]string{},
			"users":        []map[string]interface{}{users[0], users[1], users[2]},
		},
		{
			"id":   "b0000000-0000-0000-0000-000000000002",
			"name": "server-admins",
			"customClaims": []map[string]string{
				{"key": "sudoCommands", "value": "ALL"},
				{"key": "sudoHosts", "value": "ALL"},
				{"key": "sudoRunAsUser", "value": "ALL"},
			},
			"users": []map[string]interface{}{users[0], users[1]},
		},
		{
			"id":   "b0000000-0000-0000-0000-000000000003",
			"name": "service-restarters",
			"customClaims": []map[string]string{
				{"key": "sudoCommands", "value": "/usr/bin/systemctl restart *"},
				{"key": "sudoRunAsUser", "value": "root"},
			},
			"users": []map[string]interface{}{users[0]},
		},
		{
			"id":   "b0000000-0000-0000-0000-000000000004",
			"name": "web-team",
			"customClaims": []map[string]string{
				{"key": "netgroupHosts", "value": "web01, web02"},
			},
			"users": []map[string]interface{}{users[0], users[1]},
		},
		{
			"id":   "b0000000-0000-0000-0000-000000000005",
			"name": "web-access",
			"customClaims": []map[string]string{
				{"key": "accessHosts", "value": "web01, web02, web03"},
			},
			"users": []map[string]interface{}{users[0]},
		},
		{
			"id":   "b0000000-0000-0000-0000-000000000006",
			"name": "full-access",
			"customClaims": []map[string]string{
				{"key": "accessHosts", "value": "web01, web02, db01, app01"},
			},
			"users": []map[string]interface{}{users[1]},
		},
		{
			"id":   "b0000000-0000-0000-0000-000000000007",
			"name": "nfs-homes",
			"customClaims": []map[string]string{
				{"key": "automountMapName", "value": "auto.home"},
				{"key": "automountKey", "value": "*"},
				{"key": "automountInformation", "value": "-fstype=nfs4 nas:/home/&"},
			},
			"users": []map[string]interface{}{},
		},
	}

	// Index groups by ID for individual lookup
	groupByID := make(map[string]map[string]interface{})
	for _, g := range groups {
		groupByID[g["id"].(string)] = g
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate API key
		apiKey := r.Header.Get("X-API-KEY")
		if apiKey != testAPIKey {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/users":
			w.Write(pocketIDResponse(users, 1, 1, len(users)))

		case r.URL.Path == "/api/user-groups":
			w.Write(pocketIDResponse(groups, 1, 1, len(groups)))

		case strings.HasPrefix(r.URL.Path, "/api/user-groups/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/user-groups/")
			if g, ok := groupByID[id]; ok {
				json.NewEncoder(w).Encode(g)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// pocketIDTestStore creates a Store wired to a mock Pocket ID server.
func pocketIDTestStore(t *testing.T) (*Store, Provider, func()) {
	t.Helper()
	srv := mockPocketIDServer(t)

	tmpDir := t.TempDir()
	persistPath := filepath.Join(tmpDir, "uidmap.json")

	cfg := PluginConfig{
		BaseURL:         srv.URL,
		APIKey:          testAPIKey,
		RefreshSec:      300,
		UIDBase:         200000,
		GIDBase:         200000,
		DefaultShell:    "/bin/bash",
		DefaultHome:     "/home/{username}",
		SudoPrefix:      "sudo-",
		PersistPath:     persistPath,
		BaseDN:          "dc=example,dc=com",
		NetgroupPrefix:  "netgroup-",
		AccessPrefix:    "access-",
		AutomountPrefix: "automount-",
	}

	provider := NewPocketIDClient(srv.URL, testAPIKey)
	store := NewStore(cfg)

	return store, provider, srv.Close
}

// --- User Discovery ---

func TestPocketIDListUsers(t *testing.T) {
	_, provider, cleanup := pocketIDTestStore(t)
	defer cleanup()

	users, err := provider.ListAllUsers(context.Background())
	if err != nil {
		t.Fatalf("ListAllUsers failed: %v", err)
	}

	if len(users) != 3 {
		t.Fatalf("expected 3 users, got %d", len(users))
	}

	userMap := make(map[string]IDPUser)
	for _, u := range users {
		userMap[u.Username] = u
	}

	jordan := userMap["jordan"]
	if jordan.ID != "a0000000-0000-0000-0000-000000000001" {
		t.Errorf("expected ID a0000000-0000-0000-0000-000000000001, got %s", jordan.ID)
	}
	if jordan.FirstName != "Jordan" || jordan.LastName != "Smith" {
		t.Errorf("unexpected name: %s %s", jordan.FirstName, jordan.LastName)
	}
	if jordan.Email != "jordan@example.com" {
		t.Errorf("unexpected email: %s", jordan.Email)
	}
	if jordan.Disabled {
		t.Error("jordan should not be disabled")
	}

	bob := userMap["bob"]
	if !bob.Disabled {
		t.Error("bob should be disabled")
	}
}

func TestPocketIDDisabledUser(t *testing.T) {
	store, provider, cleanup := pocketIDTestStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	found, _, _ := store.FindUser("bob", false)
	if found {
		t.Error("disabled user bob should not be in the store")
	}

	found, _, _ = store.FindUser("jordan", false)
	if !found {
		t.Error("jordan should be found in store")
	}
	found, _, _ = store.FindUser("alice", false)
	if !found {
		t.Error("alice should be found in store")
	}
}

func TestPocketIDUserCustomClaims(t *testing.T) {
	_, provider, cleanup := pocketIDTestStore(t)
	defer cleanup()

	users, err := provider.ListAllUsers(context.Background())
	if err != nil {
		t.Fatalf("ListAllUsers failed: %v", err)
	}

	userMap := make(map[string]IDPUser)
	for _, u := range users {
		userMap[u.Username] = u
	}

	// Jordan should have SSH keys and loginShell from custom claims
	jordan := userMap["jordan"]
	claims := ClaimsMap(jordan.CustomClaims)
	if claims["sshPublicKey1"] != "ssh-rsa AAAA jordan@laptop" {
		t.Errorf("unexpected sshPublicKey1: %q", claims["sshPublicKey1"])
	}
	if claims["sshPublicKey2"] != "ssh-ed25519 BBBB jordan@desktop" {
		t.Errorf("unexpected sshPublicKey2: %q", claims["sshPublicKey2"])
	}
	if claims["loginShell"] != "/bin/zsh" {
		t.Errorf("unexpected loginShell: %q", claims["loginShell"])
	}

	// Alice should have one SSH key
	alice := userMap["alice"]
	aliceClaims := ClaimsMap(alice.CustomClaims)
	if aliceClaims["sshPublicKey1"] != "ssh-rsa CCCC alice@laptop" {
		t.Errorf("unexpected alice sshPublicKey1: %q", aliceClaims["sshPublicKey1"])
	}

	// Bob has no custom claims
	bob := userMap["bob"]
	if len(bob.CustomClaims) != 0 {
		t.Errorf("expected no custom claims for bob, got %d", len(bob.CustomClaims))
	}
}

// --- Group Discovery ---

func TestPocketIDListGroups(t *testing.T) {
	_, provider, cleanup := pocketIDTestStore(t)
	defer cleanup()

	groups, err := provider.ListAllGroups(context.Background())
	if err != nil {
		t.Fatalf("ListAllGroups failed: %v", err)
	}

	if len(groups) != 7 {
		t.Fatalf("expected 7 groups, got %d", len(groups))
	}

	groupMap := make(map[string]IDPGroup)
	for _, g := range groups {
		groupMap[g.Name] = g
	}

	devs := groupMap["developers"]
	if len(devs.Users) != 3 {
		t.Errorf("developers: expected 3 members, got %d", len(devs.Users))
	}

	admins := groupMap["server-admins"]
	if len(admins.Users) != 2 {
		t.Errorf("server-admins: expected 2 members, got %d", len(admins.Users))
	}

	nfsHomes := groupMap["nfs-homes"]
	if len(nfsHomes.Users) != 0 {
		t.Errorf("nfs-homes: expected 0 members, got %d", len(nfsHomes.Users))
	}
}

func TestPocketIDGroupCustomClaims(t *testing.T) {
	_, provider, cleanup := pocketIDTestStore(t)
	defer cleanup()

	groups, err := provider.ListAllGroups(context.Background())
	if err != nil {
		t.Fatalf("ListAllGroups failed: %v", err)
	}

	groupMap := make(map[string]IDPGroup)
	for _, g := range groups {
		groupMap[g.Name] = g
	}

	// server-admins: sudo claims
	adminClaims := ClaimsMap(groupMap["server-admins"].CustomClaims)
	if adminClaims["sudoCommands"] != "ALL" {
		t.Errorf("expected sudoCommands=ALL, got %q", adminClaims["sudoCommands"])
	}

	// service-restarters: restricted sudo
	restartClaims := ClaimsMap(groupMap["service-restarters"].CustomClaims)
	if restartClaims["sudoCommands"] != "/usr/bin/systemctl restart *" {
		t.Errorf("unexpected sudoCommands: %q", restartClaims["sudoCommands"])
	}

	// nfs-homes: automount claims
	nfsClaims := ClaimsMap(groupMap["nfs-homes"].CustomClaims)
	if nfsClaims["automountMapName"] != "auto.home" {
		t.Errorf("unexpected automountMapName: %q", nfsClaims["automountMapName"])
	}
}

// --- Auth ---

func TestPocketIDAuthFailure(t *testing.T) {
	srv := mockPocketIDServer(t)
	defer srv.Close()

	provider := NewPocketIDClient(srv.URL, "wrong-key")
	_, err := provider.ListAllUsers(context.Background())
	if err == nil {
		t.Fatal("expected error with wrong API key")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 error, got: %v", err)
	}
}

func TestPocketIDNoAuth(t *testing.T) {
	srv := mockPocketIDServer(t)
	defer srv.Close()

	provider := NewPocketIDClient(srv.URL, "")
	_, err := provider.ListAllUsers(context.Background())
	if err == nil {
		t.Fatal("expected error with empty API key")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 in error, got: %v", err)
	}
}

// --- Pagination ---

func TestPocketIDPagination(t *testing.T) {
	users := []map[string]interface{}{
		{"id": "c0000000-0000-0000-0000-000000000001", "username": "user1", "email": "u1@test.com", "firstName": "User", "lastName": "One", "disabled": false, "customClaims": []map[string]string{}},
		{"id": "c0000000-0000-0000-0000-000000000002", "username": "user2", "email": "u2@test.com", "firstName": "User", "lastName": "Two", "disabled": false, "customClaims": []map[string]string{}},
		{"id": "c0000000-0000-0000-0000-000000000003", "username": "user3", "email": "u3@test.com", "firstName": "User", "lastName": "Three", "disabled": false, "customClaims": []map[string]string{}},
	}

	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != testAPIKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/users" {
			requestCount++
			page := r.URL.Query().Get("pagination[page]")
			switch page {
			case "", "1":
				w.Write(pocketIDResponse(users[:2], 1, 2, 3))
			case "2":
				w.Write(pocketIDResponse(users[2:], 2, 2, 3))
			default:
				w.Write(pocketIDResponse([]interface{}{}, 3, 2, 3))
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	provider := NewPocketIDClient(srv.URL, testAPIKey)
	result, err := provider.ListAllUsers(context.Background())
	if err != nil {
		t.Fatalf("ListAllUsers failed: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("expected 3 users across 2 pages, got %d", len(result))
	}

	if requestCount != 2 {
		t.Errorf("expected 2 API requests (2 pages), got %d", requestCount)
	}

	names := make(map[string]bool)
	for _, u := range result {
		names[u.Username] = true
	}
	for _, expected := range []string{"user1", "user2", "user3"} {
		if !names[expected] {
			t.Errorf("user %s not found in paginated results", expected)
		}
	}
}

// --- Full Store Integration ---

func TestPocketIDStoreRefresh(t *testing.T) {
	store, provider, cleanup := pocketIDTestStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	users := store.GetUsers()
	if len(users) != 2 {
		t.Errorf("expected 2 active users, got %d", len(users))
	}

	groups := store.GetGroups()
	if len(groups) != 7 {
		t.Errorf("expected 7 groups, got %d", len(groups))
	}

	rules := store.GetSudoRules()
	if len(rules) != 2 {
		t.Errorf("expected 2 sudo rules, got %d", len(rules))
	}

	netgroups := store.GetNetgroupEntries()
	if len(netgroups) != 1 {
		t.Errorf("expected 1 netgroup entry, got %d", len(netgroups))
	}

	automounts := store.GetAutomountEntries()
	if len(automounts) != 2 {
		t.Errorf("expected 2 automount entries, got %d", len(automounts))
	}
}

func TestPocketIDSudoRules(t *testing.T) {
	store, provider, cleanup := pocketIDTestStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	rules := store.GetSudoRules()

	var serverAdmins, serviceRestarters *sudoRuleInfo
	for _, r := range rules {
		info := parseSudoRule(r)
		switch info.cn {
		case "server-admins":
			serverAdmins = info
		case "service-restarters":
			serviceRestarters = info
		}
	}

	if serverAdmins == nil {
		t.Fatal("server-admins sudo rule not found")
	}
	if len(serverAdmins.sudoUsers) != 2 {
		t.Errorf("expected 2 sudoUsers in server-admins, got %d: %v", len(serverAdmins.sudoUsers), serverAdmins.sudoUsers)
	}
	if len(serverAdmins.sudoCommands) != 1 || serverAdmins.sudoCommands[0] != "ALL" {
		t.Errorf("expected sudoCommand=ALL, got %v", serverAdmins.sudoCommands)
	}

	if serviceRestarters == nil {
		t.Fatal("service-restarters sudo rule not found")
	}
	if len(serviceRestarters.sudoUsers) != 1 || serviceRestarters.sudoUsers[0] != "jordan" {
		t.Errorf("expected [jordan] as sudoUsers, got %v", serviceRestarters.sudoUsers)
	}
}

func TestPocketIDNetgroups(t *testing.T) {
	store, provider, cleanup := pocketIDTestStore(t)
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
	if len(triples) < 4 {
		t.Errorf("expected at least 4 nisNetgroupTriple values, got %d: %v", len(triples), triples)
	}
}

func TestPocketIDAccessControl(t *testing.T) {
	store, provider, cleanup := pocketIDTestStore(t)
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
			if len(hosts) != 3 {
				t.Errorf("expected 3 hosts for jordan, got %d: %v", len(hosts), hosts)
			}
		case "alice":
			if len(hosts) != 4 {
				t.Errorf("expected 4 hosts for alice, got %d: %v", len(hosts), hosts)
			}
		}
	}
}

func TestPocketIDAutomount(t *testing.T) {
	store, provider, cleanup := pocketIDTestStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	entries := store.GetAutomountEntries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 automount entries (1 map + 1 mount), got %d", len(entries))
	}

	mapEntry := entries[0]
	if mapEntry.GetAttributeValue("automountMapName") != "auto.home" {
		t.Errorf("expected automountMapName=auto.home, got %s", mapEntry.GetAttributeValue("automountMapName"))
	}

	mountEntry := entries[1]
	if mountEntry.GetAttributeValue("automountKey") != "*" {
		t.Errorf("expected automountKey=*, got %s", mountEntry.GetAttributeValue("automountKey"))
	}
}

func TestPocketIDSSHKeys(t *testing.T) {
	store, provider, cleanup := pocketIDTestStore(t)
	defer cleanup()

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

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

	_, alice, _ := store.FindUser("alice", false)
	if len(alice.SSHKeys) != 1 {
		t.Errorf("expected 1 SSH key for alice, got %d", len(alice.SSHKeys))
	}

	if jordan.LoginShell != "/bin/zsh" {
		t.Errorf("expected /bin/zsh for jordan, got %s", jordan.LoginShell)
	}
	if alice.LoginShell != "/bin/bash" {
		t.Errorf("expected /bin/bash (default) for alice, got %s", alice.LoginShell)
	}
}

// --- Error Handling ---

func TestPocketIDServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer srv.Close()

	provider := NewPocketIDClient(srv.URL, testAPIKey)

	_, err := provider.ListAllUsers(context.Background())
	if err == nil {
		t.Fatal("expected error from 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected 500 in error message, got: %v", err)
	}

	_, err = provider.ListAllGroups(context.Background())
	if err == nil {
		t.Fatal("expected error from 500 response for groups")
	}
}

func TestPocketIDEmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != testAPIKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(pocketIDResponse([]interface{}{}, 1, 1, 0))
	}))
	defer srv.Close()

	provider := NewPocketIDClient(srv.URL, testAPIKey)

	users, err := provider.ListAllUsers(context.Background())
	if err != nil {
		t.Fatalf("ListAllUsers failed: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected 0 users, got %d", len(users))
	}

	groups, err := provider.ListAllGroups(context.Background())
	if err != nil {
		t.Fatalf("ListAllGroups failed: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(groups))
	}

	tmpDir := t.TempDir()
	cfg := PluginConfig{
		UIDBase:      200000,
		GIDBase:      200000,
		DefaultShell: "/bin/bash",
		DefaultHome:  "/home/{username}",
		PersistPath:  filepath.Join(tmpDir, "uidmap.json"),
		BaseDN:       "dc=example,dc=com",
	}
	store := NewStore(cfg)
	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh with empty data failed: %v", err)
	}
	if len(store.GetUsers()) != 0 {
		t.Error("expected empty user store after empty refresh")
	}
}

// --- Large-scale membership test (reproduces real Pocket ID setup) ---

// TestLargeScaleMembership creates 62+ groups matching a real Pocket ID deployment
// to verify that all group memberships are correctly reflected in LDAP memberOf.
// This reproduces the bug where rinseaid showed 18/60 groups and bert appeared
// in netbootxyz-users incorrectly.
func TestLargeScaleMembership(t *testing.T) {
	// Define users
	rinseaid := map[string]interface{}{
		"id": "d0000000-0000-0000-0000-000000000001", "username": "rinseaid", "email": "rinseaid@example.com",
		"firstName": "Rinse", "lastName": "Aid", "disabled": false, "customClaims": []map[string]string{},
	}
	eljaric := map[string]interface{}{
		"id": "d0000000-0000-0000-0000-000000000002", "username": "eljaric", "email": "eljaric@example.com",
		"firstName": "Eljaric", "lastName": "User", "disabled": false, "customClaims": []map[string]string{},
	}
	bert := map[string]interface{}{
		"id": "d0000000-0000-0000-0000-000000000003", "username": "bert", "email": "bert@example.com",
		"firstName": "Bert", "lastName": "User", "disabled": false, "customClaims": []map[string]string{},
	}
	allUsers := []map[string]interface{}{rinseaid, eljaric, bert}

	// Define all 62 groups with exact membership matching real setup
	type groupDef struct {
		name    string
		members []map[string]interface{} // subset of allUsers
	}
	groupDefs := []groupDef{
		{"gitea-admins", []map[string]interface{}{rinseaid}},
		{"guacamole-users", []map[string]interface{}{rinseaid}},
		{"harbor-admins", []map[string]interface{}{rinseaid}},
		{"pocket-id-admins", []map[string]interface{}{rinseaid}},
		{"pve-admins", []map[string]interface{}{rinseaid}},
		{"pbs-admins", []map[string]interface{}{rinseaid}},
		{"pocket-id-users", []map[string]interface{}{rinseaid, eljaric, bert}},
		{"lidarr-users", []map[string]interface{}{rinseaid}},
		{"radarr-users", []map[string]interface{}{rinseaid}},
		{"sonarr-users", []map[string]interface{}{rinseaid}},
		{"bazarr-users", []map[string]interface{}{rinseaid}},
		{"readarr-users", []map[string]interface{}{rinseaid, eljaric}},
		{"meshcentral-users", []map[string]interface{}{rinseaid}},
		{"meshcentral-admins", []map[string]interface{}{rinseaid}},
		{"homeassistant-users", []map[string]interface{}{rinseaid}},
		{"calibre-users", []map[string]interface{}{rinseaid, eljaric}},
		{"netbootxyz-users", []map[string]interface{}{rinseaid}}, // bert NOT a member
		{"nextcloud-users", []map[string]interface{}{rinseaid}},
		{"prowlarr-users", []map[string]interface{}{rinseaid}},
		{"qbittorrent-users", []map[string]interface{}{rinseaid}},
		{"portainer-users", []map[string]interface{}{rinseaid}},
		{"readarr-audio-users", []map[string]interface{}{rinseaid, eljaric}},
		{"recyclarr-users", []map[string]interface{}{rinseaid}},
		{"sabnzbd-users", []map[string]interface{}{rinseaid}},
		{"scrutiny-users", []map[string]interface{}{rinseaid}},
		{"scrypted-users", []map[string]interface{}{rinseaid}},
		{"tandoor-users", []map[string]interface{}{rinseaid, eljaric}},
		{"tautulli-users", []map[string]interface{}{rinseaid}},
		{"audiobookshelf-users", []map[string]interface{}{rinseaid, eljaric}},
		{"server-login", []map[string]interface{}{rinseaid}},
		{"sudo-all", []map[string]interface{}{rinseaid}},
		{"jellyfin-users", []map[string]interface{}{rinseaid, eljaric}},
		{"jellyfin-admins", []map[string]interface{}{rinseaid}},
		{"omni-users", []map[string]interface{}{rinseaid}},
		{"gitea-users", []map[string]interface{}{rinseaid}},
		{"forgejo-users", []map[string]interface{}{rinseaid}},
		{"forgejo-admins", []map[string]interface{}{rinseaid}},
		{"komodo-users", []map[string]interface{}{rinseaid}},
		{"code-server-users", []map[string]interface{}{rinseaid}},
		{"seafile-users", []map[string]interface{}{rinseaid}},
		{"qui-users", []map[string]interface{}{rinseaid}},
		{"booklore-users", []map[string]interface{}{rinseaid, eljaric}},
		{"karakeep-users", []map[string]interface{}{rinseaid}},
		{"readmeabook-users", []map[string]interface{}{rinseaid, eljaric}},
		{"readmeabook-admins", []map[string]interface{}{rinseaid}},
		{"chaptarr-users", []map[string]interface{}{rinseaid, eljaric}},
		{"kasm-admins", []map[string]interface{}{rinseaid}},
		{"shelfmark-admins", []map[string]interface{}{rinseaid}},
		{"shelfmark-users", []map[string]interface{}{rinseaid, eljaric}},
		{"uptime-kuma-users", []map[string]interface{}{rinseaid}},
		{"technitium-users", []map[string]interface{}{rinseaid}},
		{"maintainerr-users", []map[string]interface{}{rinseaid}},
		{"backrest-users", []map[string]interface{}{rinseaid}},
		{"portabase-users", []map[string]interface{}{rinseaid}},
		{"valetudo-users", []map[string]interface{}{rinseaid}},
		{"hubitat-users", []map[string]interface{}{rinseaid}},
		{"grafana-admins", []map[string]interface{}{rinseaid}},
		{"grafana-users", []map[string]interface{}{rinseaid}},
		{"booklore-admins", []map[string]interface{}{rinseaid}},
		{"kopia-users", []map[string]interface{}{rinseaid}},
		{"pocket-id-power-users", []map[string]interface{}{eljaric}},
	}

	// Build JSON groups with IDs
	groups := make([]map[string]interface{}, 0, len(groupDefs))
	groupByID := make(map[string]map[string]interface{})
	for i, gd := range groupDefs {
		g := map[string]interface{}{
			"id":           fmt.Sprintf("e0000000-0000-0000-0000-%012d", i),
			"name":         gd.name,
			"customClaims": []map[string]string{},
			"users":        gd.members,
		}
		groups = append(groups, g)
		groupByID[g["id"].(string)] = g
	}

	totalGroups := len(groups)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != testAPIKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/users":
			w.Write(pocketIDResponse(allUsers, 1, 1, len(allUsers)))

		case r.URL.Path == "/api/user-groups":
			// Return groups WITHOUT users (matching real Pocket ID list behavior)
			strippedGroups := make([]map[string]interface{}, 0, len(groups))
			for _, g := range groups {
				stripped := map[string]interface{}{
					"id":           g["id"],
					"name":         g["name"],
					"customClaims": g["customClaims"],
				}
				strippedGroups = append(strippedGroups, stripped)
			}
			w.Write(pocketIDResponse(strippedGroups, 1, 1, totalGroups))

		case strings.HasPrefix(r.URL.Path, "/api/user-groups/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/user-groups/")
			if g, ok := groupByID[id]; ok {
				json.NewEncoder(w).Encode(g)
			} else {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error":"not found"}`))
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	cfg := PluginConfig{
		BaseURL:      srv.URL,
		APIKey:       testAPIKey,
		UIDBase:      200000,
		GIDBase:      200000,
		DefaultShell: "/bin/bash",
		DefaultHome:  "/home/{username}",
		PersistPath:  filepath.Join(tmpDir, "uidmap.json"),
		BaseDN:       "dc=example,dc=com",
	}
	provider := NewPocketIDClient(srv.URL, testAPIKey)
	store := NewStore(cfg)

	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Verify all users exist
	storeUsers := store.GetUsers()
	if len(storeUsers) != 3 {
		t.Fatalf("expected 3 users, got %d", len(storeUsers))
	}

	// Verify all groups exist
	storeGroups := store.GetGroups()
	if len(storeGroups) != totalGroups {
		t.Fatalf("expected %d groups, got %d", totalGroups, len(storeGroups))
	}

	// Check rinseaid's group memberships via OtherGroups
	_, rinseaidUser, _ := store.FindUser("rinseaid", false)
	rinseaidExpectedGroups := 0
	for _, gd := range groupDefs {
		for _, m := range gd.members {
			if m["username"] == "rinseaid" {
				rinseaidExpectedGroups++
				break
			}
		}
	}
	if len(rinseaidUser.OtherGroups) != rinseaidExpectedGroups {
		t.Errorf("rinseaid: expected %d OtherGroups, got %d", rinseaidExpectedGroups, len(rinseaidUser.OtherGroups))
	}

	// Check eljaric's group memberships
	_, eljaricUser, _ := store.FindUser("eljaric", false)
	eljaricExpectedGroups := 0
	for _, gd := range groupDefs {
		for _, m := range gd.members {
			if m["username"] == "eljaric" {
				eljaricExpectedGroups++
				break
			}
		}
	}
	if len(eljaricUser.OtherGroups) != eljaricExpectedGroups {
		t.Errorf("eljaric: expected %d OtherGroups, got %d", eljaricExpectedGroups, len(eljaricUser.OtherGroups))
	}

	// Check bert should only be in pocket-id-users
	_, bertUser, _ := store.FindUser("bert", false)
	if len(bertUser.OtherGroups) != 1 {
		t.Errorf("bert: expected 1 OtherGroup (pocket-id-users), got %d", len(bertUser.OtherGroups))
	}

	// Verify memberOf via LDAP entries
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
		memberOf := getAttrValues(entry, "memberOf")

		switch name {
		case "rinseaid":
			if len(memberOf) != rinseaidExpectedGroups {
				t.Errorf("rinseaid memberOf: expected %d, got %d", rinseaidExpectedGroups, len(memberOf))
				// List missing groups for debugging
				memberOfSet := make(map[string]bool)
				for _, dn := range memberOf {
					memberOfSet[dn] = true
				}
				for _, gd := range groupDefs {
					for _, m := range gd.members {
						if m["username"] == "rinseaid" {
							dn := fmt.Sprintf("ou=%s,dc=example,dc=com", gd.name)
							if !memberOfSet[dn] {
								t.Errorf("  MISSING: %s", gd.name)
							}
						}
					}
				}
			}

			// Verify bert is NOT shown as member of netbootxyz-users group
			for _, dn := range memberOf {
				if strings.Contains(dn, "netbootxyz") && name == "bert" {
					t.Error("bert should NOT be in netbootxyz-users")
				}
			}

		case "eljaric":
			if len(memberOf) != eljaricExpectedGroups {
				t.Errorf("eljaric memberOf: expected %d, got %d", eljaricExpectedGroups, len(memberOf))
			}

		case "bert":
			if len(memberOf) != 1 {
				t.Errorf("bert memberOf: expected 1 (pocket-id-users), got %d", len(memberOf))
				for _, dn := range memberOf {
					t.Errorf("  bert memberOf: %s", dn)
				}
			}
			// Specifically check bert is NOT in netbootxyz-users
			for _, dn := range memberOf {
				if strings.Contains(dn, "netbootxyz") {
					t.Error("bert incorrectly appears in netbootxyz-users")
				}
			}
		}
	}

	// Verify group member lists are correct
	groupEntries, err := store.FindPosixGroups(backend, "")
	if err != nil {
		t.Fatalf("FindPosixGroups failed: %v", err)
	}

	for _, entry := range groupEntries {
		name := getAttr(entry, "ou")
		if name == "netbootxyz-users" {
			memberUids := getAttrValues(entry, "memberUid")
			for _, uid := range memberUids {
				if uid == "bert" {
					t.Error("netbootxyz-users group incorrectly lists bert as memberUid")
				}
			}
			if len(memberUids) != 1 || memberUids[0] != "rinseaid" {
				t.Errorf("netbootxyz-users: expected [rinseaid], got %v", memberUids)
			}
		}
	}
}

// TestPaginatedGroupFetch tests that groups are correctly fetched across multiple pages.
func TestPaginatedGroupFetch(t *testing.T) {
	// Create 150 groups to force pagination (limit=100 per page)
	allGroups := make([]map[string]interface{}, 150)
	groupByID := make(map[string]map[string]interface{})
	testUser := map[string]interface{}{
		"id": "f0000000-0000-0000-0000-000000000001", "username": "testuser", "email": "test@example.com",
		"firstName": "Test", "lastName": "User", "disabled": false, "customClaims": []map[string]string{},
	}

	for i := 0; i < 150; i++ {
		g := map[string]interface{}{
			"id":           fmt.Sprintf("f2000000-0000-0000-0000-%012d", i),
			"name":         fmt.Sprintf("group-%03d", i),
			"customClaims": []map[string]string{},
			"users":        []map[string]interface{}{testUser},
		}
		allGroups[i] = g
		groupByID[g["id"].(string)] = g
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != testAPIKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/users":
			w.Write(pocketIDResponse([]map[string]interface{}{testUser}, 1, 1, 1))

		case r.URL.Path == "/api/user-groups":
			page := 1
			if p := r.URL.Query().Get("pagination[page]"); p != "" {
				fmt.Sscanf(p, "%d", &page)
			}
			limit := 100
			offset := (page - 1) * limit
			end := offset + limit
			if end > len(allGroups) {
				end = len(allGroups)
			}

			// Strip users from list response (matches real Pocket ID behavior)
			pageData := make([]map[string]interface{}, 0)
			if offset < len(allGroups) {
				for _, g := range allGroups[offset:end] {
					stripped := map[string]interface{}{
						"id":           g["id"],
						"name":         g["name"],
						"customClaims": g["customClaims"],
					}
					pageData = append(pageData, stripped)
				}
			}

			totalPages := (len(allGroups) + limit - 1) / limit
			w.Write(pocketIDResponse(pageData, page, totalPages, len(allGroups)))

		case strings.HasPrefix(r.URL.Path, "/api/user-groups/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/user-groups/")
			if g, ok := groupByID[id]; ok {
				json.NewEncoder(w).Encode(g)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	provider := NewPocketIDClient(srv.URL, testAPIKey)
	groups, err := provider.ListAllGroups(context.Background())
	if err != nil {
		t.Fatalf("ListAllGroups failed: %v", err)
	}

	if len(groups) != 150 {
		t.Errorf("expected 150 groups, got %d", len(groups))
	}

	// Verify all groups have their member
	for _, g := range groups {
		if len(g.Users) != 1 {
			t.Errorf("group %s: expected 1 member, got %d", g.Name, len(g.Users))
		}
	}

	// Now test full store refresh
	tmpDir := t.TempDir()
	cfg := PluginConfig{
		UIDBase:      200000,
		GIDBase:      200000,
		DefaultShell: "/bin/bash",
		DefaultHome:  "/home/{username}",
		PersistPath:  filepath.Join(tmpDir, "uidmap.json"),
		BaseDN:       "dc=example,dc=com",
	}
	store := NewStore(cfg)
	if err := store.Refresh(provider); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	_, testU, _ := store.FindUser("testuser", false)
	if len(testU.OtherGroups) != 150 {
		t.Errorf("testuser: expected 150 OtherGroups, got %d", len(testU.OtherGroups))
	}
}

// suppress unused import warning
var _ = fmt.Sprintf
var _ = config.Backend{}
