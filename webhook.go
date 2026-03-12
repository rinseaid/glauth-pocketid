package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// constantTimeSecretEqual compares two secrets in constant time without leaking
// length information. It hashes both values with SHA-256 before comparing, so
// the comparison time is independent of input lengths.
func constantTimeSecretEqual(provided, expected string) bool {
	h1 := sha256.Sum256([]byte(provided))
	h2 := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(h1[:], h2[:]) == 1
}

const webhookMinCooldown = 30 * time.Second

// WebhookServer provides an HTTP server for webhook-triggered sync and optional metrics.
type WebhookServer struct {
	server *http.Server
	store  *Store
	provider Provider
	secret string
	log    *zerolog.Logger
	mux    *http.ServeMux

	// refreshMu is shared with the handler's background refresh loop to
	// prevent concurrent refreshes that could produce non-deterministic
	// UID assignments. Pointer to the handler's mutex.
	refreshMu    *sync.Mutex
	lastRefresh  time.Time
	lastRefreshMu sync.Mutex
}

// NewWebhookServer creates a new webhook server. The refreshMu is shared with
// the background refresh loop to prevent concurrent refreshes.
func NewWebhookServer(port int, secret string, store *Store, provider Provider, log *zerolog.Logger, refreshMu *sync.Mutex, listenAddr string) *WebhookServer {
	if listenAddr == "" {
		listenAddr = "127.0.0.1"
	}
	mux := http.NewServeMux()
	ws := &WebhookServer{
		server: &http.Server{
			Addr:              fmt.Sprintf("%s:%d", listenAddr, port),
			Handler:           mux,
			ReadTimeout:       10 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second, // prevent indefinite keep-alive connections
		},
		store:     store,
		provider:  provider,
		secret:    secret,
		log:       log,
		mux:       mux,
		refreshMu: refreshMu,
	}

	mux.HandleFunc("/webhook/refresh", ws.handleRefresh)
	mux.HandleFunc("/healthz", ws.handleHealth)

	return ws
}

// Start begins listening in a goroutine.
func (ws *WebhookServer) Start() {
	ln, err := net.Listen("tcp", ws.server.Addr)
	if err != nil {
		if ws.log != nil {
			ws.log.Error().Err(err).Str("addr", ws.server.Addr).Msg("Webhook server failed to listen")
		}
		return
	}
	if ws.log != nil {
		ws.log.Info().Str("addr", ws.server.Addr).Msg("Webhook server started")
	}
	go func() {
		if err := ws.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			if ws.log != nil {
				ws.log.Error().Err(err).Msg("Webhook server error")
			}
		}
	}()
}

// Stop gracefully shuts down the server.
func (ws *WebhookServer) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws.server.Shutdown(ctx)
}

// Mux returns the HTTP mux so additional handlers (e.g., /metrics) can be registered.
func (ws *WebhookServer) Mux() *http.ServeMux {
	return ws.mux
}

func (ws *WebhookServer) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Require authentication: webhook secret must be configured and provided
	if ws.secret == "" {
		http.Error(w, "webhook secret not configured", http.StatusServiceUnavailable)
		return
	}
	provided := r.Header.Get("X-Webhook-Secret")
	if !constantTimeSecretEqual(provided, ws.secret) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Prevent concurrent refreshes — acquire refresh lock first
	if !ws.refreshMu.TryLock() {
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, "refresh already in progress")
		return
	}
	defer ws.refreshMu.Unlock()

	// Rate limit: check cooldown while holding refresh lock to prevent TOCTOU bypass
	ws.lastRefreshMu.Lock()
	if time.Since(ws.lastRefresh) < webhookMinCooldown {
		ws.lastRefreshMu.Unlock()
		http.Error(w, "too many requests, try again later", http.StatusTooManyRequests)
		return
	}
	// Set lastRefresh optimistically before refresh to close the TOCTOU window
	ws.lastRefresh = time.Now()
	ws.lastRefreshMu.Unlock()

	start := time.Now()
	err := ws.store.Refresh(ws.provider)
	duration := time.Since(start)

	if err != nil {
		if ws.log != nil {
			ws.log.Error().Err(err).Dur("duration", duration).Msg("Webhook-triggered sync failed")
		}
		http.Error(w, "sync failed", http.StatusInternalServerError)
		return
	}

	if ws.log != nil {
		ws.log.Info().Dur("duration", duration).Msg("Webhook-triggered sync completed")
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "sync completed in %s", duration)
}

func (ws *WebhookServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// AuthenticatedHandler wraps an HTTP handler with webhook secret authentication.
// Used for endpoints like /metrics that should not be publicly accessible.
func (ws *WebhookServer) AuthenticatedHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ws.secret == "" {
			http.Error(w, "webhook secret not configured", http.StatusServiceUnavailable)
			return
		}
		provided := r.Header.Get("X-Webhook-Secret")
		if !constantTimeSecretEqual(provided, ws.secret) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
