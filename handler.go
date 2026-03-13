package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/glauth/glauth/v2/pkg/stats"
	ldap "github.com/glauth/ldap"
)

type pluginHandler struct {
	backend     config.Backend
	log         *zerolog.Logger
	cfg         *config.Config
	yubikeyAuth *yubigo.YubiAuth
	ldohelper   handler.LDAPOpsHelper

	store     *Store
	provider  Provider
	pluginCfg PluginConfig
	cancel    context.CancelFunc
	closeOnce sync.Once
	webhook   *WebhookServer

	// refreshMu serializes refresh cycles between the background loop and
	// webhook-triggered refreshes. Without this, two concurrent refreshes
	// could fetch from the API simultaneously and produce non-deterministic
	// UID assignments for newly added users.
	refreshMu sync.Mutex
}

// NewPocketIDHandler is the exported plugin constructor. It must match:
// func(...handler.Option) handler.Handler
func NewPocketIDHandler(opts ...handler.Option) handler.Handler {
	options := handler.NewOptions(opts...)

	// Guard against nil logger — glauth's LDAPOpsHelper dereferences GetLog()
	// without nil checks. A nil logger would panic on every LDAP Bind/Search.
	if options.Logger == nil {
		nop := zerolog.Nop()
		options.Logger = &nop
	}

	// Guard against empty format arrays — glauth normally populates these from
	// config, but direct construction (tests, custom integrations) may leave
	// them nil/empty, causing index-out-of-bounds panics.
	if len(options.Backend.NameFormatAsArray) == 0 {
		options.Backend.NameFormatAsArray = []string{"cn"}
	}
	if len(options.Backend.GroupFormatAsArray) == 0 {
		options.Backend.GroupFormatAsArray = []string{"ou"}
	}

	pluginCfg := LoadConfig()

	// Allow the glauth database field to override the base URL if env not set
	if pluginCfg.BaseURL == "" && options.Backend.Database != "" {
		pluginCfg.BaseURL = options.Backend.Database
	}

	// Store baseDN from glauth backend config
	pluginCfg.BaseDN = options.Backend.BaseDN

	// Warn if using insecure HTTP
	if warn := WarnInsecureURL(pluginCfg.BaseURL); warn != "" && options.Logger != nil {
		options.Logger.Warn().Msg(warn)
	}

	// Warn if webhook port is set without a secret
	if pluginCfg.WebhookPort > 0 && pluginCfg.WebhookSecret == "" && options.Logger != nil {
		options.Logger.Warn().Msg("POCKETID_WEBHOOK_PORT is set but POCKETID_WEBHOOK_SECRET is empty — webhook endpoint will reject all requests")
	}

	provider := NewPocketIDClient(pluginCfg.BaseURL, pluginCfg.APIKey)

	store := NewStore(pluginCfg)

	h := &pluginHandler{
		backend:     options.Backend,
		log:         options.Logger,
		cfg:         options.Config,
		yubikeyAuth: options.YubiAuth,
		ldohelper:   options.LDAPHelper,
		store:       store,
		provider:    provider,
		pluginCfg:   pluginCfg,
	}

	// Initial data load
	if err := store.Refresh(provider); err != nil {
		if h.log != nil {
			h.log.Error().Err(err).Msg("Initial IDP sync failed")
		}
	} else {
		if h.log != nil {
			h.log.Info().Msg("Initial IDP sync completed")
		}
	}

	// Start background refresh
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go h.refreshLoop(ctx)

	// Start webhook/metrics server if configured
	if pluginCfg.WebhookPort > 0 {
		h.webhook = NewWebhookServer(pluginCfg.WebhookPort, pluginCfg.WebhookSecret, store, provider, h.log, &h.refreshMu, pluginCfg.WebhookListen)
		h.webhook.Mux().HandleFunc("/metrics", globalMetrics.Handler())
		h.webhook.Start()
	}

	return h
}

func (h *pluginHandler) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(h.pluginCfg.RefreshSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if h.webhook != nil {
				h.webhook.Stop()
			}
			return
		case <-ticker.C:
			h.doRefresh()
		}
	}
}

// doRefresh performs a single sync cycle with panic recovery.
// Without recovery, a panic in Refresh kills the goroutine silently,
// stopping all future syncs with no alerting.
// Uses TryLock to skip if a webhook-triggered refresh is already running.
func (h *pluginHandler) doRefresh() {
	if !h.refreshMu.TryLock() {
		if h.log != nil {
			h.log.Debug().Msg("Skipping background refresh — another refresh is in progress")
		}
		return
	}
	defer h.refreshMu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			if h.log != nil {
				h.log.Error().Interface("panic", r).Msg("PANIC in IDP sync — recovered, will retry next cycle")
			}
		}
	}()

	if err := h.store.Refresh(h.provider); err != nil {
		if h.log != nil {
			h.log.Error().Err(err).Msg("IDP sync failed")
		}
	} else {
		if h.log != nil {
			h.log.Debug().Msg("IDP sync completed")
		}
	}
}

// --- LDAPOpsHandler interface ---

func (h *pluginHandler) GetBackend() config.Backend    { return h.backend }
func (h *pluginHandler) GetLog() *zerolog.Logger       { return h.log }
func (h *pluginHandler) GetCfg() *config.Config        { return h.cfg }
func (h *pluginHandler) GetYubikeyAuth() *yubigo.YubiAuth { return h.yubikeyAuth }

func (h *pluginHandler) FindUser(ctx context.Context, userName string, searchByUPN bool) (bool, config.User, error) {
	// Check IDP users first
	found, user, err := h.store.FindUser(userName, searchByUPN)
	if found {
		return found, user, err
	}
	// Fall back to static config users (e.g., service accounts).
	// Deep-copy to prevent glauth's filterAttributes from mutating static config.
	if h.cfg != nil {
		for _, u := range h.cfg.Users {
			if searchByUPN {
				if strings.EqualFold(u.Mail, userName) {
					return true, h.store.deepCopyUser(u), nil
				}
			} else {
				if strings.EqualFold(u.Name, userName) {
					return true, h.store.deepCopyUser(u), nil
				}
			}
		}
	}
	return false, config.User{}, nil
}

func (h *pluginHandler) FindGroup(ctx context.Context, groupName string) (bool, config.Group, error) {
	// Check IDP groups first
	found, group, err := h.store.FindGroup(groupName)
	if found {
		return found, group, err
	}
	// Fall back to static config groups.
	// Deep-copy to prevent glauth's filterAttributes from mutating static config.
	if h.cfg != nil {
		for _, g := range h.cfg.Groups {
			if strings.EqualFold(g.Name, groupName) {
				return true, deepCopyGroup(g), nil
			}
		}
	}
	return false, config.Group{}, nil
}

func (h *pluginHandler) FindPosixAccounts(ctx context.Context, hierarchy string) ([]*ldap.Entry, error) {
	entries, err := h.store.FindPosixAccounts(h.backend, hierarchy)
	if err != nil {
		return nil, err
	}
	// Include static config users (service accounts)
	if h.cfg != nil {
		for _, u := range h.cfg.Users {
			attrs := []*ldap.EntryAttribute{}
			for _, nameAttr := range h.backend.NameFormatAsArray {
				attrs = append(attrs, &ldap.EntryAttribute{Name: nameAttr, Values: []string{u.Name}})
			}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{"users"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uidNumber", Values: []string{fmt.Sprintf("%d", u.UIDNumber)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount", "shadowAccount"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{"/bin/bash"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{"/home/" + u.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{u.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gecos", Values: []string{u.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", u.PrimaryGroup)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"active"}})

			dn := fmt.Sprintf("%s=%s,%s", h.backend.NameFormatAsArray[0], EscapeDNValue(u.Name), h.backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	}
	return entries, nil
}

func (h *pluginHandler) FindPosixGroups(ctx context.Context, hierarchy string) ([]*ldap.Entry, error) {
	entries, err := h.store.FindPosixGroups(h.backend, hierarchy)
	if err != nil {
		return nil, err
	}
	// Include static config groups
	if h.cfg != nil {
		for _, g := range h.cfg.Groups {
			attrs := []*ldap.EntryAttribute{}
			for _, groupAttr := range h.backend.GroupFormatAsArray {
				attrs = append(attrs, &ldap.EntryAttribute{Name: groupAttr, Values: []string{g.Name}})
			}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{g.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", g.GIDNumber)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup", "top"}})
			dn := fmt.Sprintf("%s=%s,%s", h.backend.GroupFormatAsArray[0], EscapeDNValue(g.Name), h.backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	}
	return entries, nil
}

// --- Handler interface (ldap.Binder, ldap.Searcher, ldap.Closer, etc.) ---

func (h *pluginHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	ctx := context.Background()
	return h.ldohelper.Bind(ctx, h, bindDN, bindSimplePw, conn)
}

func (h *pluginHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	ctx := context.Background()

	// Reject unauthenticated searches on synthesized OUs
	if bindDN == "" {
		return h.ldohelper.Search(ctx, h, bindDN, searchReq, conn)
	}

	baseDNLower := strings.ToLower(searchReq.BaseDN)
	sudoersOU := "ou=sudoers," + strings.ToLower(h.backend.BaseDN)
	netgroupOU := "ou=netgroup," + strings.ToLower(h.backend.BaseDN)
	automountOU := "ou=automount," + strings.ToLower(h.backend.BaseDN)

	// Intercept sudoers searches (exact OU match)
	if baseDNLower == sudoersOU || strings.HasSuffix(baseDNLower, ","+sudoersOU) {
		return h.searchEntries(h.store.GetSudoRules(), searchReq)
	}

	// Intercept netgroup searches
	if baseDNLower == netgroupOU || strings.HasSuffix(baseDNLower, ","+netgroupOU) {
		return h.searchEntries(h.store.GetNetgroupEntries(), searchReq)
	}

	// Intercept automount searches
	if baseDNLower == automountOU || strings.HasSuffix(baseDNLower, ","+automountOU) {
		return h.searchEntries(h.store.GetAutomountEntries(), searchReq)
	}

	return h.ldohelper.Search(ctx, h, bindDN, searchReq, conn)
}

func (h *pluginHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h *pluginHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h *pluginHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (ldap.LDAPResultCode, error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h *pluginHandler) Close(boundDn string, conn net.Conn) error {
	stats.Frontend.Add("closes", 1)
	// Note: Close() is called on every LDAP connection close, NOT just at shutdown.
	// We cannot reliably distinguish shutdown from connection close, so we do NOT
	// cancel the refresh loop here. The refresh goroutine and webhook server are
	// stopped via context cancellation when the process exits.
	// If a graceful shutdown hook becomes available in glauth, call h.Shutdown().
	return nil
}

// Shutdown cancels the background refresh loop and stops the webhook server.
// This should be called during graceful shutdown (not on every connection close).
func (h *pluginHandler) Shutdown() {
	h.closeOnce.Do(func() {
		if h.cancel != nil {
			h.cancel()
		}
	})
}

// searchEntries handles LDAP searches for synthesized entries (sudoers, netgroups, automount).
// Returns deep copies to prevent glauth's filterAttributes from mutating stored data.
func (h *pluginHandler) searchEntries(entries []*ldap.Entry, searchReq ldap.SearchRequest) (ldap.ServerSearchResult, error) {
	var filtered []*ldap.Entry
	baseDNLower := strings.ToLower(searchReq.BaseDN)

	for _, entry := range entries {
		dnLower := strings.ToLower(entry.DN)
		// Match exact DN or proper subtree (comma-prefixed suffix).
		// Bare HasSuffix without comma prefix could match partial RDN components
		// (e.g., search for "sudoers,dc=example,dc=com" matching "ou=sudoers,...").
		if dnLower == baseDNLower || strings.HasSuffix(dnLower, ","+baseDNLower) {
			attrs := make([]*ldap.EntryAttribute, len(entry.Attributes))
			for i, a := range entry.Attributes {
				vals := make([]string, len(a.Values))
				copy(vals, a.Values)
				attrs[i] = &ldap.EntryAttribute{Name: a.Name, Values: vals}
			}
			filtered = append(filtered, &ldap.Entry{DN: entry.DN, Attributes: attrs})
		}
	}

	return ldap.ServerSearchResult{
		Entries:    filtered,
		Referrals:  []string{},
		Controls:   []ldap.Control{},
		ResultCode: ldap.LDAPResultSuccess,
	}, nil
}

// refreshTimeout is the maximum time allowed for a full sync cycle (all API calls).
const refreshTimeout = 5 * time.Minute

// contextWithRefreshTimeout returns a context with a timeout for sync operations.
// The caller MUST call the returned cancel function to release timer resources.
func contextWithRefreshTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), refreshTimeout)
}

// Ensure pluginHandler implements the required interfaces at compile time.
var _ handler.Handler = (*pluginHandler)(nil)
var _ handler.LDAPOpsHandler = (*pluginHandler)(nil)

// MaybeDecode is needed to match the glauth handler package's function signature.
// It's used by the configHandler for base64 decoding but we pass through as-is.
func MaybeDecode(value string) string {
	return value
}

func main() {
	fmt.Println("This is a GLAuth plugin. Build with -buildmode=plugin")
}
