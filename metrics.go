package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Metrics tracks plugin sync statistics.
// Uses a simple custom implementation to avoid conflicts with glauth's
// prometheus global registry (Go plugins share global state).
type Metrics struct {
	mu sync.RWMutex

	syncDurationMs  float64
	syncErrors      int64
	syncSuccesses   int64
	lastSyncTime    time.Time
	lastSyncSuccess bool
	usersTotal      int
	groupsTotal     int
	sudoRulesTotal  int

	netgroupsTotal  int
	automountsTotal int
	accessRules     int
}

var globalMetrics = &Metrics{}

// RecordSync records the result of a sync operation.
func (m *Metrics) RecordSync(duration time.Duration, err error, users, groups, sudoRules, netgroups, automounts, accessRules int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.syncDurationMs = float64(duration.Milliseconds())
	m.lastSyncTime = time.Now()

	if err != nil {
		m.syncErrors++
		m.lastSyncSuccess = false
	} else {
		m.syncSuccesses++
		m.lastSyncSuccess = true
		m.usersTotal = users
		m.groupsTotal = groups
		m.sudoRulesTotal = sudoRules
		m.netgroupsTotal = netgroups
		m.automountsTotal = automounts
		m.accessRules = accessRules
	}
}

// Handler returns an HTTP handler that serves Prometheus-compatible metrics.
func (m *Metrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.RLock()
		defer m.mu.RUnlock()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		promGauge(w, "glauth_pocketid_sync_duration_milliseconds", "Duration of last sync in milliseconds", m.syncDurationMs)
		promCounter(w, "glauth_pocketid_sync_errors_total", "Total number of sync errors", float64(m.syncErrors))
		promCounter(w, "glauth_pocketid_sync_successes_total", "Total number of successful syncs", float64(m.syncSuccesses))
		promGauge(w, "glauth_pocketid_sync_last_success", "Whether the last sync was successful (1=yes, 0=no)", boolToFloat(m.lastSyncSuccess))

		if !m.lastSyncTime.IsZero() {
			promGauge(w, "glauth_pocketid_sync_last_timestamp_seconds", "Unix timestamp of last sync", float64(m.lastSyncTime.Unix()))
		}

		promGauge(w, "glauth_pocketid_users_total", "Total number of active users", float64(m.usersTotal))
		promGauge(w, "glauth_pocketid_groups_total", "Total number of groups", float64(m.groupsTotal))
		promGauge(w, "glauth_pocketid_sudo_rules_total", "Total number of sudo rules", float64(m.sudoRulesTotal))
		promGauge(w, "glauth_pocketid_netgroups_total", "Total number of netgroup entries", float64(m.netgroupsTotal))
		promGauge(w, "glauth_pocketid_automounts_total", "Total number of automount entries", float64(m.automountsTotal))
		promGauge(w, "glauth_pocketid_access_rules_total", "Total number of host access rules", float64(m.accessRules))
	}
}

func promGauge(w http.ResponseWriter, name, help string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, value)
}

func promCounter(w http.ResponseWriter, name, help string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %g\n", name, help, name, name, value)
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
