package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// validIDPattern matches UUID-like identifiers (hex + hyphens).
// Prevents path traversal in Phase 2 group URL construction.
var validIDPattern = regexp.MustCompile(`^[a-fA-F0-9-]{1,128}$`)

const (
	maxResponseBytes = 10 * 1024 * 1024 // 10 MB
	maxPages         = 1000
	maxTotalItems    = 100000 // cap total users/groups to prevent memory exhaustion
)

// PocketIDClient fetches users and groups from the Pocket ID REST API.
type PocketIDClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewPocketIDClient creates a new Pocket ID API client.
func NewPocketIDClient(baseURL, apiKey string) *PocketIDClient {
	if u, err := url.Parse(baseURL); err != nil || u.Host == "" {
		log.Printf("[pocketid] WARNING: POCKETID_BASE_URL is invalid or missing host component")
	}

	return &PocketIDClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		http: &http.Client{
			Timeout: 30 * time.Second,
			// Block all redirects. Go's default redirect follower would strip the
			// API key header, but re-attaching it risks leaking the key to
			// unintended endpoints on the same host. Pocket ID's API endpoints
			// should not redirect; if they do, we want to know about it.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// WarnInsecureURL returns a warning message if the base URL is not HTTPS.
func WarnInsecureURL(baseURL string) string {
	if strings.HasPrefix(strings.ToLower(baseURL), "http://") {
		return "POCKETID_BASE_URL uses plain HTTP — API key will be sent in cleartext. Use HTTPS in production."
	}
	return ""
}

var _ Provider = (*PocketIDClient)(nil)

func (c *PocketIDClient) doRequest(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Sanitize error body: a compromised or misconfigured API server could
		// reflect the X-API-KEY header in error responses. Since these errors
		// are logged, we redact the body to prevent API key leakage in logs.
		msg := strings.ReplaceAll(string(body), "\n", " ")
		msg = strings.ReplaceAll(msg, "\r", " ")
		if len(msg) > 512 {
			msg = msg[:512] + "... (truncated)"
		}
		// Redact anything that looks like it could contain the API key
		if c.apiKey != "" && len(c.apiKey) >= 8 && strings.Contains(msg, c.apiKey) {
			msg = "[response body redacted — contained API key]"
		}
		return nil, &APIError{StatusCode: resp.StatusCode, Message: msg}
	}
	return body, nil
}

// Pocket ID API response types

type pocketIDListResponse struct {
	Data       json.RawMessage `json:"data"`
	Pagination struct {
		CurrentPage int `json:"currentPage"`
		TotalPages  int `json:"totalPages"`
		TotalItems  int `json:"totalItems"`
	} `json:"pagination"`
}

type pocketIDUser struct {
	ID           string        `json:"id"`
	Username     string        `json:"username"`
	Email        string        `json:"email"`
	FirstName    string        `json:"firstName"`
	LastName     string        `json:"lastName"`
	Disabled     bool          `json:"disabled"`
	CustomClaims []CustomClaim `json:"customClaims"`
}

type pocketIDGroup struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	CustomClaims []CustomClaim `json:"customClaims"`
}

type pocketIDGroupWithMembers struct {
	pocketIDGroup
	Users []pocketIDUser `json:"users"`
}

func (c *PocketIDClient) ListAllUsers(ctx context.Context) ([]IDPUser, error) {
	var allUsers []IDPUser
	page := 1

	for page <= maxPages {
		url := fmt.Sprintf("%s/api/users?pagination[page]=%d&pagination[limit]=100", c.baseURL, page)
		body, err := c.doRequest(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("listing users at page %d: %w", page, err)
		}

		var resp pocketIDListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decoding users response: %w", err)
		}

		var users []pocketIDUser
		if err := json.Unmarshal(resp.Data, &users); err != nil {
			return nil, fmt.Errorf("decoding users data: %w", err)
		}

		log.Printf("[pocketid] Users page %d: got %d users (totalPages=%d, totalItems=%d)",
			page, len(users), resp.Pagination.TotalPages, resp.Pagination.TotalItems)

		if len(users) == 0 {
			break
		}

		for _, u := range users {
			if !validIDPattern.MatchString(u.ID) {
				log.Printf("[pocketid] WARNING: skipping user %q with invalid ID format", u.Username)
				continue
			}
			allUsers = append(allUsers, IDPUser{
				ID:           u.ID,
				Username:     stripNullBytes(u.Username),
				Email:        stripNullBytes(u.Email),
				FirstName:    stripNullBytes(u.FirstName),
				LastName:     stripNullBytes(u.LastName),
				Disabled:     u.Disabled,
				CustomClaims: u.CustomClaims,
			})
		}

		if len(allUsers) >= maxTotalItems {
			break
		}
		if page >= resp.Pagination.TotalPages && len(users) < 100 {
			break
		}
		page++
	}

	log.Printf("[pocketid] Total users fetched: %d", len(allUsers))
	return allUsers, nil
}

func (c *PocketIDClient) ListAllGroups(ctx context.Context) ([]IDPGroup, error) {
	// Phase 1: Collect all group IDs from the paginated list endpoint.
	// The list endpoint does not include members — only the single-group endpoint does.
	type groupIDName struct {
		ID   string
		Name string
	}
	var groupIDs []groupIDName
	page := 1

	for page <= maxPages {
		url := fmt.Sprintf("%s/api/user-groups?pagination[page]=%d&pagination[limit]=100", c.baseURL, page)
		body, err := c.doRequest(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("listing groups at page %d: %w", page, err)
		}

		var resp pocketIDListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decoding groups response: %w", err)
		}

		var groups []pocketIDGroup
		if err := json.Unmarshal(resp.Data, &groups); err != nil {
			return nil, fmt.Errorf("decoding groups data: %w", err)
		}

		log.Printf("[pocketid] Groups page %d: got %d groups (totalPages=%d, totalItems=%d)",
			page, len(groups), resp.Pagination.TotalPages, resp.Pagination.TotalItems)

		if len(groups) == 0 {
			break
		}

		for _, g := range groups {
			// Validate ID format before storing — prevents path traversal
			// in Phase 2 URL construction (e.g., "../../admin" as group ID)
			if !validIDPattern.MatchString(g.ID) {
				log.Printf("[pocketid] WARNING: skipping group %q with invalid ID format: %q", g.Name, g.ID)
				continue
			}
			groupIDs = append(groupIDs, groupIDName{ID: g.ID, Name: g.Name})
		}

		if len(groupIDs) >= maxTotalItems {
			break
		}
		// Stop if the API says we've reached the last page AND we got fewer
		// than a full page of results (belt-and-suspenders against wrong totalPages)
		if page >= resp.Pagination.TotalPages && len(groups) < 100 {
			break
		}
		page++
	}

	log.Printf("[pocketid] Phase 1 complete: collected %d group IDs", len(groupIDs))

	// Phase 2: Fetch each group individually to get members and claims.
	// Skip individual groups that fail (e.g., deleted between phases, transient errors)
	// rather than aborting the entire sync.
	var allGroups []IDPGroup
	for _, ginfo := range groupIDs {
		groupURL := fmt.Sprintf("%s/api/user-groups/%s", c.baseURL, url.PathEscape(ginfo.ID))
		body, err := c.doRequest(ctx, groupURL)
		if err != nil {
			log.Printf("[pocketid] WARNING: skipping group %q (%q): %v", ginfo.Name, ginfo.ID, err)
			continue
		}

		var g pocketIDGroupWithMembers
		if err := json.Unmarshal(body, &g); err != nil {
			log.Printf("[pocketid] WARNING: skipping group %q (%q): decode error: %v", ginfo.Name, ginfo.ID, err)
			continue
		}

		var members []IDPUser
		for _, u := range g.Users {
			members = append(members, IDPUser{
				ID:           u.ID,
				Username:     stripNullBytes(u.Username),
				Email:        stripNullBytes(u.Email),
				FirstName:    stripNullBytes(u.FirstName),
				LastName:     stripNullBytes(u.LastName),
				Disabled:     u.Disabled,
				CustomClaims: u.CustomClaims,
			})
		}

		log.Printf("[pocketid] Group %q (%q): %d members", g.Name, ginfo.ID, len(members))

		allGroups = append(allGroups, IDPGroup{
			ID:           g.ID,
			Name:         g.Name,
			CustomClaims: g.CustomClaims,
			Users:        members,
		})
	}

	log.Printf("[pocketid] Phase 2 complete: %d groups with members fetched", len(allGroups))
	return allGroups, nil
}
