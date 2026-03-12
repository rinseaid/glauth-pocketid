// mock-pocketid: A mock Pocket ID REST API server for integration testing.
// Serves users and groups with custom claims matching the Pocket ID API format.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

const apiKey = "test-api-key"

type CustomClaim struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type User struct {
	ID           string        `json:"id"`
	Username     string        `json:"username"`
	Email        string        `json:"email"`
	FirstName    string        `json:"firstName"`
	LastName     string        `json:"lastName"`
	Disabled     bool          `json:"disabled"`
	CustomClaims []CustomClaim `json:"customClaims"`
}

type Group struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	CustomClaims []CustomClaim `json:"customClaims"`
	Users        []User        `json:"users"`
}

type ListResponse struct {
	Data       interface{} `json:"data"`
	Pagination Pagination  `json:"pagination"`
}

type Pagination struct {
	CurrentPage int `json:"currentPage"`
	TotalPages  int `json:"totalPages"`
	TotalItems  int `json:"totalItems"`
}

var users = []User{
	{
		ID:        "uuid-jordan",
		Username:  "jordan",
		Email:     "jordan@example.com",
		FirstName: "Jordan",
		LastName:  "Smith",
		Disabled:  false,
		CustomClaims: []CustomClaim{
			{Key: "sshPublicKey1", Value: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyJordan jordan@laptop"},
			{Key: "sshPublicKey2", Value: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQTestKeyJordan2 jordan@desktop"},
			{Key: "loginShell", Value: "/bin/zsh"},
		},
	},
	{
		ID:        "uuid-alice",
		Username:  "alice",
		Email:     "alice@example.com",
		FirstName: "Alice",
		LastName:  "Jones",
		Disabled:  false,
		CustomClaims: []CustomClaim{
			{Key: "sshPublicKey1", Value: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyAlice alice@laptop"},
		},
	},
	{
		ID:           "uuid-bob",
		Username:     "bob",
		Email:        "bob@example.com",
		FirstName:    "Bob",
		LastName:     "Brown",
		Disabled:     true,
		CustomClaims: []CustomClaim{},
	},
}

var groups []Group

func init() {
	groups = []Group{
		{
			ID:           "gid-developers",
			Name:         "developers",
			CustomClaims: []CustomClaim{},
			Users:        []User{users[0], users[1], users[2]},
		},
		{
			ID:   "gid-server-admins",
			Name: "server-admins",
			CustomClaims: []CustomClaim{
				{Key: "sudoCommands", Value: "ALL"},
				{Key: "sudoHosts", Value: "ALL"},
				{Key: "sudoRunAsUser", Value: "ALL"},
			},
			Users: []User{users[0], users[1]},
		},
		{
			ID:   "gid-service-restarters",
			Name: "service-restarters",
			CustomClaims: []CustomClaim{
				{Key: "sudoCommands", Value: "/usr/bin/systemctl restart *"},
				{Key: "sudoHosts", Value: "ALL"},
				{Key: "sudoRunAsUser", Value: "root"},
			},
			Users: []User{users[0]},
		},
		{
			ID:   "gid-web-team",
			Name: "web-team",
			CustomClaims: []CustomClaim{
				{Key: "netgroupHosts", Value: "web01, web02"},
				{Key: "netgroupDomain", Value: "example.com"},
			},
			Users: []User{users[0], users[1]},
		},
		{
			ID:   "gid-web-access",
			Name: "web-access",
			CustomClaims: []CustomClaim{
				{Key: "accessHosts", Value: "web01, web02, web03"},
			},
			Users: []User{users[0]},
		},
		{
			ID:   "gid-full-access",
			Name: "full-access",
			CustomClaims: []CustomClaim{
				{Key: "accessHosts", Value: "web01, web02, db01, app01"},
			},
			Users: []User{users[1]},
		},
		{
			ID:   "gid-nfs-homes",
			Name: "nfs-homes",
			CustomClaims: []CustomClaim{
				{Key: "automountMapName", Value: "auto.home"},
				{Key: "automountKey", Value: "*"},
				{Key: "automountInformation", Value: "-fstype=nfs4 nas:/home/&"},
			},
			Users: []User{},
		},
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-KEY")
		if key != apiKey {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func parseIntParam(r *http.Request, name string, defaultVal int) int {
	s := r.URL.Query().Get(name)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 1 {
		return defaultVal
	}
	return v
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.String())

	page := parseIntParam(r, "pagination[page]", 1)
	limit := parseIntParam(r, "pagination[limit]", 100)

	offset := (page - 1) * limit
	total := len(users)
	totalPages := (total + limit - 1) / limit

	var pageData []User
	for i := offset; i < total && i < offset+limit; i++ {
		pageData = append(pageData, users[i])
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ListResponse{
		Data: pageData,
		Pagination: Pagination{
			CurrentPage: page,
			TotalPages:  totalPages,
			TotalItems:  total,
		},
	})
}

func handleGroups(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.String())

	page := parseIntParam(r, "pagination[page]", 1)
	limit := parseIntParam(r, "pagination[limit]", 100)

	offset := (page - 1) * limit
	total := len(groups)
	totalPages := (total + limit - 1) / limit

	var pageData []Group
	for i := offset; i < total && i < offset+limit; i++ {
		pageData = append(pageData, groups[i])
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ListResponse{
		Data: pageData,
		Pagination: Pagination{
			CurrentPage: page,
			TotalPages:  totalPages,
			TotalItems:  total,
		},
	})
}

func handleGroupByID(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.String())

	// Extract group ID from URL path: /api/user-groups/{id}
	path := r.URL.Path
	id := path[len("/api/user-groups/"):]

	for _, g := range groups {
		if g.ID == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(g)
			return
		}
	}

	http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", authMiddleware(handleUsers))
	mux.HandleFunc("/api/user-groups/", authMiddleware(handleGroupByID)) // /api/user-groups/{id}
	mux.HandleFunc("/api/user-groups", authMiddleware(handleGroups))     // /api/user-groups (list)
	// Health check endpoint (no auth)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	fmt.Println("Mock Pocket ID server listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", mux))
}
