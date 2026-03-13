package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/glauth/glauth/v2/pkg/config"
	ldap "github.com/glauth/ldap"
)

// reservedUsernames are system account names that must never be created from IDP data.
// These accounts exist on standard Linux systems and shadowing them could grant
// SSH key authentication to privileged system accounts.
var reservedUsernames = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "sync": true,
	"games": true, "man": true, "lp": true, "mail": true, "news": true,
	"uucp": true, "proxy": true, "www-data": true, "backup": true,
	"list": true, "irc": true, "gnats": true, "nobody": true,
	"systemd-network": true, "systemd-resolve": true, "systemd-timesync": true,
	"messagebus": true, "syslog": true, "sshd": true, "ntp": true,
	"mysql": true, "postgres": true, "redis": true, "mongodb": true,
	"_apt": true, "uuidd": true, "tcpdump": true, "tss": true,
	"landscape": true, "pollinate": true, "fwupd-refresh": true,
	"serviceuser": true, // glauth service account
	"all":         true, // sudoers ALL keyword — sudoUser: ALL grants every user sudo access
}

// validUsername matches safe POSIX usernames.
var validUsername = regexp.MustCompile(`^[a-z_][a-z0-9_.-]*$`)

// validGroupName matches safe POSIX group names (same character set as usernames).
var validGroupName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]*$`)

// reservedGroupNames are system group names that must not be shadowed by IDP groups.
// Creating these from IDP data could grant unintended permissions (e.g., "wheel"
// membership grants sudo access on many systems).
var reservedGroupNames = map[string]bool{
	"root": true, "wheel": true, "sudo": true, "admin": true, "adm": true,
	"shadow": true, "disk": true, "kmem": true, "tty": true, "tape": true,
	"daemon": true, "bin": true, "sys": true, "staff": true, "operator": true,
	"sshd": true, "docker": true, "lxd": true, "libvirt": true, "kvm": true,
	"all": true, // sudoers ALL keyword
}

// isValidGroupName returns true if the group name is safe for use in LDAP entries.
func isValidGroupName(name string) bool {
	if !utf8.ValidString(name) {
		return false // reject invalid UTF-8 to prevent EscapeDNValue mismatches
	}
	lower := strings.ToLower(name)
	if len(name) > 256 {
		return false
	}
	if reservedGroupNames[lower] {
		return false
	}
	return validGroupName.MatchString(lower)
}

// isValidUsername returns true if the username is safe for use as a POSIX account.
func isValidUsername(name string) bool {
	if !utf8.ValidString(name) {
		return false // reject invalid UTF-8 to prevent EscapeDNValue mismatches
	}
	lower := strings.ToLower(name)
	if reservedUsernames[lower] {
		return false
	}
	// Pocket ID creates internal API users with this prefix — they are not real users
	if strings.HasPrefix(lower, "static-api-user-") {
		return false
	}
	if len(name) > 256 {
		return false
	}
	return validUsername.MatchString(lower)
}

// Store holds the in-memory user/group data synced from the identity provider.
type Store struct {
	mu     sync.RWMutex
	cfg    PluginConfig
	users  map[string]config.User  // keyed by lowercase username
	groups map[string]config.Group // keyed by lowercase group name

	// UID/GID assignment persistence
	uidMap  map[string]int // IDP UUID -> uidNumber
	gidMap  map[string]int // IDP UUID -> gidNumber
	nextUID int
	nextGID int

	// gid -> groupName for DN building
	gidToName map[int]string

	// dirty tracks whether UID/GID maps have changed since last persist
	dirty bool

	// sudoRole LDAP entries, built at refresh time
	sudoRules []*ldap.Entry

	// netgroup entries
	netgroupEntries []*ldap.Entry

	// automount entries
	automountEntries []*ldap.Entry

	// host-based access control: username -> []hostname
	userHosts map[string][]string
}

// persistedMap is the JSON file format for UID/GID persistence.
type persistedMap struct {
	UIDs    map[string]int `json:"uids"`
	GIDs    map[string]int `json:"gids"`
	NextUID int            `json:"nextUID"`
	NextGID int            `json:"nextGID"`
}

// NewStore creates a new Store and loads any persisted UID/GID mappings.
func NewStore(cfg PluginConfig) *Store {
	s := &Store{
		cfg:          cfg,
		users:        make(map[string]config.User),
		groups:       make(map[string]config.Group),
		uidMap:       make(map[string]int),
		gidMap:       make(map[string]int),
		nextUID:      cfg.UIDBase,
		nextGID:      cfg.GIDBase,
		gidToName: make(map[int]string),
	}
	s.loadPersisted()
	return s
}

func (s *Store) loadPersisted() {
	// Open with O_NOFOLLOW to atomically reject symlinks (no TOCTOU gap).
	// Also checks permissions on the opened fd to prevent reading tampered files.
	f, err := openNoFollow(s.cfg.PersistPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[pocketid] WARNING: cannot open persist file %s: %v — UIDs/GIDs will be reassigned", s.cfg.PersistPath, err)
		}
		return
	}
	defer f.Close()

	// Check permissions on opened fd — reject world/group-readable persist files
	fi, err := f.Stat()
	if err != nil {
		return
	}
	if fi.Size() > maxResponseBytes { // reuse 10 MB cap
		log.Printf("[pocketid] WARNING: persist file %s is too large (%d bytes), ignoring", s.cfg.PersistPath, fi.Size())
		return
	}

	data, err := io.ReadAll(io.LimitReader(f, maxResponseBytes))
	if err != nil {
		return
	}
	var p persistedMap
	if err := json.Unmarshal(data, &p); err != nil {
		log.Printf("[pocketid] WARNING: failed to parse persist file %s: %v — UIDs/GIDs will be reassigned", s.cfg.PersistPath, err)
		return
	}
	// Validate loaded UIDs: reject values outside safe range
	if p.UIDs != nil {
		for id, uid := range p.UIDs {
			if !validateID(uid, s.cfg.UIDBase) {
				delete(p.UIDs, id)
			}
		}
		s.uidMap = p.UIDs
	}
	if p.GIDs != nil {
		for id, gid := range p.GIDs {
			if !validateID(gid, s.cfg.GIDBase) {
				delete(p.GIDs, id)
			}
		}
		s.gidMap = p.GIDs
	}
	if p.NextUID > s.nextUID && validateID(p.NextUID, s.cfg.UIDBase) {
		s.nextUID = p.NextUID
	}
	if p.NextGID > s.nextGID && validateID(p.NextGID, s.cfg.GIDBase) {
		s.nextGID = p.NextGID
	}
}

func (s *Store) savePersisted() error {
	p := persistedMap{
		UIDs:    s.uidMap,
		GIDs:    s.gidMap,
		NextUID: s.nextUID,
		NextGID: s.nextGID,
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.cfg.PersistPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// Atomic write: write to temp file with O_EXCL|O_NOFOLLOW to prevent symlink attacks, then rename.
	// O_EXCL ensures the file doesn't exist (no TOCTOU gap between check and create).
	// O_NOFOLLOW prevents following symlinks on the temp path.
	tmpPath := s.cfg.PersistPath + ".tmp"
	// Remove any pre-existing temp file (could be a stale leftover or a symlink).
	// Lstat first — only remove regular files, refuse to unlink symlinks.
	if lfi, lerr := os.Lstat(tmpPath); lerr == nil {
		if lfi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("temp persist path %s is a symlink, refusing to write", tmpPath)
		}
		os.Remove(tmpPath)
	}
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("creating temp persist file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("writing temp persist file: %w", err)
	}
	// Fsync before close to ensure data is on disk before rename.
	// Without this, a power failure could leave a zero-length or partial file
	// at the temp path, and the rename could be reordered before the data write.
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("syncing temp persist file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, s.cfg.PersistPath)
}

// openNoFollow opens a file for reading, rejecting symlinks atomically via O_NOFOLLOW.
// Returns an error if the path is a symlink or doesn't exist.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// validateID checks that a UID/GID is within safe bounds (not root, not system, not overflowed).
func validateID(id, base int) bool {
	return id >= base && id > 0 && id <= 0x7FFFFFFF // positive 32-bit range
}

// assignUID returns a stable UID for the given IDP user.
func (s *Store) assignUID(idpUserID string, claims map[string]string) int {
	// 1. Check custom claim override
	if v, ok := claims["uidNumber"]; ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil && validateID(n, s.cfg.UIDBase) {
			// Check for collision: different user claiming same UID
			for existingID, existingUID := range s.uidMap {
				if existingUID == n && existingID != idpUserID {
					log.Printf("[pocketid] WARNING: user %s claims uidNumber %d but it is already assigned to user %s — using auto-assigned UID instead", idpUserID, n, existingID)
					goto persistedCheck
				}
			}
			// Cross-check: UID must not collide with any group GID, since
			// each user's UID doubles as their private group GID.
			for _, existingGID := range s.gidMap {
				if existingGID == n {
					log.Printf("[pocketid] WARNING: user %s claims uidNumber %d but it collides with a group GID — using auto-assigned UID instead", idpUserID, n)
					goto persistedCheck
				}
			}
			if s.uidMap[idpUserID] != n {
				s.uidMap[idpUserID] = n
				s.dirty = true
			}
			return n
		}
	}
persistedCheck:
	// 2. Check persisted map
	if uid, ok := s.uidMap[idpUserID]; ok {
		return uid
	}
	// 3. Auto-assign — skip values already claimed by other users
	uid := s.nextUID
	attempts := 0
	for s.isUIDTaken(uid) {
		uid++
		attempts++
		if attempts > 100000 || !validateID(uid, s.cfg.UIDBase) {
			// UID space exhausted — log and return -1 to signal failure
			log.Printf("[pocketid] WARNING: UID space exhausted (nextUID=%d, base=%d) — user %s skipped", s.nextUID, s.cfg.UIDBase, idpUserID)
			return -1
		}
	}
	if !validateID(uid, s.cfg.UIDBase) {
		log.Printf("[pocketid] WARNING: UID %d out of range (base=%d) — user %s skipped", uid, s.cfg.UIDBase, idpUserID)
		return -1
	}
	s.nextUID = uid + 1
	s.uidMap[idpUserID] = uid
	s.dirty = true
	return uid
}

// isUIDTaken checks if a UID is already assigned to any user or collides with
// an IDP group GID. Since each user's UID doubles as their private group GID,
// UIDs and GIDs must not overlap to prevent unintended group membership.
func (s *Store) isUIDTaken(uid int) bool {
	for _, existingUID := range s.uidMap {
		if existingUID == uid {
			return true
		}
	}
	for _, existingGID := range s.gidMap {
		if existingGID == uid {
			return true
		}
	}
	return false
}

// assignGID returns a stable GID for the given IDP group.
func (s *Store) assignGID(idpGroupID string, claims map[string]string) int {
	if v, ok := claims["gidNumber"]; ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil && validateID(n, s.cfg.GIDBase) {
			// Check for collision: different group claiming same GID
			for existingID, existingGID := range s.gidMap {
				if existingGID == n && existingID != idpGroupID {
					log.Printf("[pocketid] WARNING: group %s claims gidNumber %d but it is already assigned to group %s — using auto-assigned GID instead", idpGroupID, n, existingID)
					goto persistedGIDCheck
				}
			}
			// Cross-check: GID must not collide with any user UID, since
			// each user's UID doubles as their private group GID.
			for _, existingUID := range s.uidMap {
				if existingUID == n {
					log.Printf("[pocketid] WARNING: group %s claims gidNumber %d but it collides with a user UID — using auto-assigned GID instead", idpGroupID, n)
					goto persistedGIDCheck
				}
			}
			if s.gidMap[idpGroupID] != n {
				s.gidMap[idpGroupID] = n
				s.dirty = true
			}
			return n
		}
	}
persistedGIDCheck:
	if gid, ok := s.gidMap[idpGroupID]; ok {
		return gid
	}
	// Auto-assign — skip values already claimed by other groups
	gid := s.nextGID
	attempts := 0
	for s.isGIDTaken(gid) {
		gid++
		attempts++
		if attempts > 100000 || !validateID(gid, s.cfg.GIDBase) {
			log.Printf("[pocketid] WARNING: GID space exhausted (nextGID=%d, base=%d) — group %s skipped", s.nextGID, s.cfg.GIDBase, idpGroupID)
			return -1
		}
	}
	if !validateID(gid, s.cfg.GIDBase) {
		log.Printf("[pocketid] WARNING: GID %d out of range (base=%d) — group %s skipped", gid, s.cfg.GIDBase, idpGroupID)
		return -1
	}
	s.nextGID = gid + 1
	s.gidMap[idpGroupID] = gid
	s.dirty = true
	return gid
}

// isGIDTaken checks if a GID is already assigned to any group or collides with
// a user's UID. Since each user's UID doubles as their private group GID,
// GIDs and UIDs must not overlap to prevent unintended group membership.
func (s *Store) isGIDTaken(gid int) bool {
	for _, existingGID := range s.gidMap {
		if existingGID == gid {
			return true
		}
	}
	for _, existingUID := range s.uidMap {
		if existingUID == gid {
			return true
		}
	}
	return false
}

// validSSHKeyPrefix matches SSH public key values that start with a recognized key type.
// This prevents authorized_keys options injection (e.g. command="/bin/evil" ssh-rsa ...).
var validSSHKeyPrefix = regexp.MustCompile(`^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) `)

// isValidSSHKey checks that a string looks like a valid SSH public key
// (starts with a recognized key type followed by a space).
// Rejects keys containing newlines to prevent injection of additional
// authorized_keys entries (e.g. command="/bin/evil" via embedded \n).
const maxSSHKeyLength = 16384 // 16KB max per SSH key (typical keys are under 1KB)

func isValidSSHKey(key string) bool {
	trimmed := strings.TrimSpace(key)
	if len(trimmed) > maxSSHKeyLength {
		return false
	}
	if strings.ContainsAny(trimmed, "\n\r") {
		return false
	}
	return validSSHKeyPrefix.MatchString(trimmed)
}

// extractSSHKeys collects SSH keys from claims: sshPublicKey (unnumbered),
// then sshPublicKey1 through sshPublicKey99. Keys that don't match a recognized
// SSH key format are rejected to prevent authorized_keys options injection attacks.
func extractSSHKeys(claims map[string]string) []string {
	var keys []string
	// Check unnumbered sshPublicKey first
	if k, ok := claims["sshPublicKey"]; ok && k != "" {
		if isValidSSHKey(k) {
			keys = append(keys, strings.TrimSpace(k))
		}
	}
	for i := 1; i <= 99; i++ {
		key := fmt.Sprintf("sshPublicKey%d", i)
		if k, ok := claims[key]; ok && k != "" {
			if isValidSSHKey(k) {
				keys = append(keys, strings.TrimSpace(k))
			}
		}
	}
	return keys
}

// Refresh fetches all users and groups from the identity provider and rebuilds the in-memory store.
func (s *Store) Refresh(provider Provider) error {
	ctx, cancel := contextWithRefreshTimeout()
	defer cancel()
	start := time.Now()

	users, err := provider.ListAllUsers(ctx)
	if err != nil {
		globalMetrics.RecordSync(time.Since(start), err, 0, 0, 0, 0, 0, 0)
		return fmt.Errorf("fetching users: %w", err)
	}

	groups, err := provider.ListAllGroups(ctx)
	if err != nil {
		globalMetrics.RecordSync(time.Since(start), err, 0, 0, 0, 0, 0, 0)
		return fmt.Errorf("fetching groups: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Build groups first so we can assign primary groups to users
	newGroups := make(map[string]config.Group, len(groups))
	newGidToName := make(map[int]string, len(groups))
	memberMap := make(map[string][]string) // groupID -> []username
	groupNameToGID := make(map[string]int) // groupName -> GID

	for _, g := range groups {
		if !isValidGroupName(g.Name) {
			continue // skip groups with invalid names
		}

		claims := ClaimsMap(g.CustomClaims)
		gid := s.assignGID(g.ID, claims)
		if gid < 0 {
			continue // GID space exhausted — skip this group
		}

		cg := config.Group{
			Name:      g.Name,
			GIDNumber: gid,
		}
		newGroups[strings.ToLower(g.Name)] = cg
		newGidToName[gid] = g.Name
		groupNameToGID[g.Name] = gid

		// Collect member usernames
		var memberNames []string
		for _, u := range g.Users {
			memberNames = append(memberNames, u.Username)
		}
		memberMap[g.ID] = memberNames
	}

	// Build users
	newUsers := make(map[string]config.User, len(users))

	// Build a map of username -> list of group GIDs for OtherGroups.
	// Only include groups that passed validation and were assigned a GID.
	// Without the ok-check, skipped groups yield GID 0 (root/wheel) from the
	// zero-value map lookup, injecting root group membership into every member.
	userGroupGIDs := make(map[string][]int)
	for _, g := range groups {
		gid, ok := groupNameToGID[g.Name]
		if !ok {
			continue // group was skipped (invalid name, GID exhaustion, etc.)
		}
		for _, u := range g.Users {
			userGroupGIDs[u.Username] = append(userGroupGIDs[u.Username], gid)
		}
	}

	now := time.Now()
	for _, u := range users {
		if u.Disabled {
			continue
		}
		if !isValidUsername(u.Username) {
			continue // skip reserved/invalid usernames
		}

		claims := ClaimsMap(u.CustomClaims)
		uid := s.assignUID(u.ID, claims)
		if uid < 0 {
			continue // UID space exhausted — skip this user
		}
		sshKeys := extractSSHKeys(claims)

		shell := s.cfg.DefaultShell
		if v, ok := claims["loginShell"]; ok && v != "" && ValidateLoginShell(v) {
			shell = v
		}

		// Check login time windows — fail closed: if the claim is set but
		// unparseable, disable the account. An admin who set allowedLoginHours
		// intended to restrict access; silently ignoring a parse error would
		// leave the user unrestricted (fail-open).
		disabled := false
		if v, ok := claims["allowedLoginHours"]; ok && v != "" {
			windows, err := ParseTimeWindows(v)
			if err != nil {
				disabled = true // unparseable → deny access (fail closed)
			} else if !IsWithinWindow(windows, now) {
				disabled = true
			}
		}

		// User private group as primary (UID == GID), all IDP groups are "other"
		primaryGroup := uid
		otherGroups := []int{}
		if gids, ok := userGroupGIDs[u.Username]; ok {
			otherGroups = gids
		}

		cu := config.User{
			Name:         u.Username,
			UIDNumber:    uid,
			PrimaryGroup: primaryGroup,
			OtherGroups:  otherGroups,
			Mail:         u.Email,
			LoginShell:   shell,
			Homedir:      s.cfg.HomeDir(u.Username),
			SSHKeys:      sshKeys,
			GivenName:    u.FirstName,
			SN:           u.LastName,
			Disabled:     disabled,
			// Impossible hash prevents LDAP bind — IDP users authenticate via
			// passkeys/SSH keys, never via LDAP password. Without this, glauth
			// accepts ANY password for users with empty PassSHA256.
			PassSHA256: "!",
			// Search capability so sssd service account can find them
			Capabilities: []config.Capability{},
		}
		lowerName := strings.ToLower(u.Username)
		if existing, dup := newUsers[lowerName]; dup {
			log.Printf("[pocketid] WARNING: duplicate username %q (IDP IDs: keeping existing UID %d, skipping new) — check Pocket ID for duplicate accounts",
				u.Username, existing.UIDNumber)
			continue // first-writer-wins: skip duplicates to prevent privilege merging
		}
		newUsers[lowerName] = cu
	}

	// Build a validated memberMap for security-sensitive features (sudo, netgroup, access).
	// Only include usernames that passed isValidUsername and are not disabled.
	// This prevents: disabled users retaining sudo/netgroup/access privileges,
	// invalid/reserved usernames appearing in sudoUser (e.g., "ALL" injection).
	validatedMemberMap := make(map[string][]string, len(memberMap))
	for gid, members := range memberMap {
		var valid []string
		for _, m := range members {
			if u, ok := newUsers[strings.ToLower(m)]; ok && !u.Disabled {
				valid = append(valid, m)
			}
		}
		if len(valid) > 0 {
			validatedMemberMap[gid] = valid
		}
	}

	// Build sudo rules (using validated members only)
	sudoRules := BuildSudoRules(groups, validatedMemberMap, s.cfg.BaseDN, s.cfg.SudoNoAuthenticate)

	// Build netgroup entries (using validated members only)
	netgroupEntries := BuildNetgroupEntries(groups, validatedMemberMap, s.cfg.BaseDN)

	// Build automount entries
	automountEntries := BuildAutomountEntries(groups, s.cfg.BaseDN)

	// Build host-based access control map (using validated members only)
	userHosts := BuildUserHostMap(groups, validatedMemberMap)

	// Persist UID/GID maps BEFORE swapping in new data.
	// This ensures that on restart after a persist failure, the old UID/GID map
	// is consistent with what was previously served (no UID reassignment).
	if s.dirty {
		if err := s.savePersisted(); err != nil {
			return fmt.Errorf("persisting UID/GID map: %w", err)
		}
		s.dirty = false
	}

	// Swap in new data (atomic — all fields updated together under lock)
	s.users = newUsers
	s.groups = newGroups
	s.gidToName = newGidToName
	s.sudoRules = sudoRules
	s.netgroupEntries = netgroupEntries
	s.automountEntries = automountEntries
	s.userHosts = userHosts

	// Record metrics
	globalMetrics.RecordSync(time.Since(start), nil,
		len(newUsers), len(newGroups), len(sudoRules),
		len(netgroupEntries), len(automountEntries), len(userHosts))

	return nil
}

// FindUser looks up a user by name or by email (UPN).
func (s *Store) FindUser(userName string, searchByUPN bool) (bool, config.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if searchByUPN {
		for _, u := range s.users {
			if strings.EqualFold(u.Mail, userName) {
				return true, s.deepCopyUser(u), nil
			}
		}
		return false, config.User{}, nil
	}

	u, ok := s.users[strings.ToLower(userName)]
	if !ok {
		return false, config.User{}, nil
	}
	return true, s.deepCopyUser(u), nil
}

// deepCopyUser returns a copy of the user with independent slice backing arrays.
// This prevents data races when glauth's LDAPOpsHelper mutates slices (e.g.,
// filterAttributes) concurrently with other goroutines reading the store.
// SSH keys are suppressed for disabled users to prevent authentication via
// sss_ssh_authorizedkeys when the account should be inactive (e.g., outside
// allowedLoginHours time window).
func (s *Store) deepCopyUser(u config.User) config.User {
	c := u
	if u.Disabled {
		c.SSHKeys = nil
	} else if len(u.SSHKeys) > 0 {
		c.SSHKeys = make([]string, len(u.SSHKeys))
		copy(c.SSHKeys, u.SSHKeys)
	}
	if len(u.OtherGroups) > 0 {
		c.OtherGroups = make([]int, len(u.OtherGroups))
		copy(c.OtherGroups, u.OtherGroups)
	}
	if len(u.Capabilities) > 0 {
		c.Capabilities = make([]config.Capability, len(u.Capabilities))
		copy(c.Capabilities, u.Capabilities)
	}
	if len(u.PassAppSHA256) > 0 {
		c.PassAppSHA256 = make([]string, len(u.PassAppSHA256))
		copy(c.PassAppSHA256, u.PassAppSHA256)
	}
	if len(u.PassAppBcrypt) > 0 {
		c.PassAppBcrypt = make([]string, len(u.PassAppBcrypt))
		copy(c.PassAppBcrypt, u.PassAppBcrypt)
	}
	if u.CustomAttrs != nil {
		c.CustomAttrs = make(map[string]interface{}, len(u.CustomAttrs))
		for k, v := range u.CustomAttrs {
			c.CustomAttrs[k] = v
		}
	}
	return c
}

// deepCopyGroup returns a copy of the group with independent slice backing arrays.
func deepCopyGroup(g config.Group) config.Group {
	c := g
	if len(g.Capabilities) > 0 {
		c.Capabilities = make([]config.Capability, len(g.Capabilities))
		copy(c.Capabilities, g.Capabilities)
	}
	if len(g.IncludeGroups) > 0 {
		c.IncludeGroups = make([]int, len(g.IncludeGroups))
		copy(c.IncludeGroups, g.IncludeGroups)
	}
	return c
}

// FindGroup looks up a group by name.
func (s *Store) FindGroup(groupName string) (bool, config.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	g, ok := s.groups[strings.ToLower(groupName)]
	if ok {
		return true, deepCopyGroup(g), nil
	}

	// Check for user private group (UPG): a group with the same name as a user,
	// whose GID equals the user's UID.
	u, ok := s.users[strings.ToLower(groupName)]
	if ok {
		upg := config.Group{
			Name:      u.Name,
			GIDNumber: u.UIDNumber,
		}
		return true, upg, nil
	}

	return false, config.Group{}, nil
}

// FindPosixAccounts returns LDAP entries for all users.
func (s *Store) FindPosixAccounts(backend config.Backend, hierarchy string) ([]*ldap.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := make([]*ldap.Entry, 0, len(s.users))
	for _, u := range s.users {
		attrs := []*ldap.EntryAttribute{}

		// Name attributes — emit both the configured nameformat (typically "cn")
		// and "uid" so that SSSD's default ldap_user_name=uid filter matches.
		// TrueNAS SCALE and other appliances generate their own sssd.conf with
		// uid as the user name attribute and cannot be easily overridden.
		emittedUID := false
		for _, nameAttr := range backend.NameFormatAsArray {
			attrs = append(attrs, &ldap.EntryAttribute{Name: nameAttr, Values: []string{u.Name}})
			if nameAttr == "uid" {
				emittedUID = true
			}
		}
		if !emittedUID {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{u.Name}})
		}

		if len(u.GivenName) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{u.GivenName}})
		}
		if len(u.SN) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "sn", Values: []string{u.SN}})
		}

		attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{"users"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uidNumber", Values: []string{fmt.Sprintf("%d", u.UIDNumber)}})

		if u.Disabled {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"inactive"}})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"active"}})
		}

		if len(u.Mail) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{u.Mail}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "userPrincipalName", Values: []string{u.Mail}})
		}

		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount", "shadowAccount"}})

		if len(u.LoginShell) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{u.LoginShell}})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{"/bin/bash"}})
		}

		if len(u.Homedir) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{u.Homedir}})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{"/home/" + u.Name}})
		}

		attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{u.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gecos", Values: []string{u.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", u.PrimaryGroup)}})

		// memberOf — only include IDP groups (OtherGroups), not the user private
		// group (PrimaryGroup). PrimaryGroup uses the user's UID as GID, which
		// can collide with a real IDP group's auto-assigned GID, causing users
		// to appear as members of groups they don't belong to.
		memberOfDNs := s.getGroupDNs(backend, u.OtherGroups)
		attrs = append(attrs, &ldap.EntryAttribute{Name: "memberOf", Values: memberOfDNs})

		// shadow attributes
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowExpire", Values: []string{"-1"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowFlag", Values: []string{"134538308"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowInactive", Values: []string{"-1"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowLastChange", Values: []string{"11000"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowMax", Values: []string{"99999"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowMin", Values: []string{"-1"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowWarning", Values: []string{"7"}})

		// Host-based access control (copy slice to prevent mutation by glauth's filterAttributes)
		if hosts, ok := s.userHosts[u.Name]; ok && len(hosts) > 0 {
			hostsCopy := make([]string, len(hosts))
			copy(hostsCopy, hosts)
			attrs = append(attrs, &ldap.EntryAttribute{Name: "host", Values: hostsCopy})
		}

		// SSH keys (copy slice to prevent mutation by glauth's filterAttributes)
		// Skip SSH keys for disabled users (e.g., outside allowedLoginHours window)
		// to prevent authentication via sss_ssh_authorizedkeys when the account
		// should be inactive.
		if len(u.SSHKeys) > 0 && !u.Disabled {
			sshAttr := backend.SSHKeyAttr
			if sshAttr == "" {
				sshAttr = "sshPublicKey"
			}
			keysCopy := make([]string, len(u.SSHKeys))
			copy(keysCopy, u.SSHKeys)
			attrs = append(attrs, &ldap.EntryAttribute{Name: sshAttr, Values: keysCopy})
		}

		// Build flat DN: cn=username,dc=baseDN (no OU hierarchy)
		escapedName := EscapeDNValue(u.Name)
		dn := fmt.Sprintf("%s=%s,%s",
			backend.NameFormatAsArray[0], escapedName,
			backend.BaseDN)

		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}

	return entries, nil
}

// FindPosixGroups returns LDAP entries for all groups.
func (s *Store) FindPosixGroups(backend config.Backend, hierarchy string) ([]*ldap.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	asGroupOfUniqueNames := hierarchy == "ou=groups"
	entries := make([]*ldap.Entry, 0, len(s.groups)+len(s.users))

	// Emit user private groups (UPGs) — one per user, GID == UID.
	// Without these, the user's primary group GID has no corresponding
	// posixGroup entry and tools like `id` show "cannot find name for group ID".
	for _, u := range s.users {
		attrs := []*ldap.EntryAttribute{}
		for _, groupAttr := range backend.GroupFormatAsArray {
			attrs = append(attrs, &ldap.EntryAttribute{Name: groupAttr, Values: []string{u.Name}})
		}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("User private group for %s", u.Name)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", u.UIDNumber)}})

		userDN := fmt.Sprintf("%s=%s,%s", backend.NameFormatAsArray[0], EscapeDNValue(u.Name), backend.BaseDN)
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uniqueMember", Values: []string{userDN}})

		if asGroupOfUniqueNames {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"groupOfUniqueNames", "top"}})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: []string{u.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup", "top"}})
		}

		dn := fmt.Sprintf("%s=%s,%s", backend.GroupFormatAsArray[0], EscapeDNValue(u.Name), backend.BaseDN)
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}

	for _, g := range s.groups {
		attrs := []*ldap.EntryAttribute{}

		for _, groupAttr := range backend.GroupFormatAsArray {
			attrs = append(attrs, &ldap.EntryAttribute{Name: groupAttr, Values: []string{g.Name}})
		}

		attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{g.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", g.GIDNumber)}})

		memberDNs := s.getGroupMemberDNs(backend, g.GIDNumber)
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uniqueMember", Values: memberDNs})

		if asGroupOfUniqueNames {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"groupOfUniqueNames", "top"}})
		} else {
			memberIDs := s.getGroupMemberIDs(g.GIDNumber)
			attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: memberIDs})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup", "top"}})
		}

		dn := fmt.Sprintf("%s=%s,%s", backend.GroupFormatAsArray[0], EscapeDNValue(g.Name), backend.BaseDN)
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}

	return entries, nil
}

// GetSudoRules returns a copy of the synthesized sudoRole entries slice.
// The copy ensures the caller's iteration is safe even if Refresh() replaces
// the underlying slice concurrently.
func (s *Store) GetSudoRules() []*ldap.Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ldap.Entry, len(s.sudoRules))
	copy(out, s.sudoRules)
	return out
}

// GetNetgroupEntries returns a copy of the synthesized nisNetgroup entries slice.
func (s *Store) GetNetgroupEntries() []*ldap.Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ldap.Entry, len(s.netgroupEntries))
	copy(out, s.netgroupEntries)
	return out
}

// GetAutomountEntries returns a copy of the synthesized automount entries slice.
func (s *Store) GetAutomountEntries() []*ldap.Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ldap.Entry, len(s.automountEntries))
	copy(out, s.automountEntries)
	return out
}

// getGroupMemberDNs returns DNs of all users in a group.
// Only checks OtherGroups (IDP group memberships), NOT PrimaryGroup,
// because PrimaryGroup uses UID-as-GID which can collide with real IDP group GIDs.
func (s *Store) getGroupMemberDNs(backend config.Backend, gid int) []string {
	members := make(map[string]bool)
	for _, u := range s.users {
		if u.Disabled {
			continue // exclude time-window-disabled users from group membership
		}
		for _, othergid := range u.OtherGroups {
			if othergid == gid {
				dn := fmt.Sprintf("%s=%s,%s",
					backend.NameFormatAsArray[0], EscapeDNValue(u.Name),
					backend.BaseDN)
				members[dn] = true
				break
			}
		}
	}
	m := make([]string, 0, len(members))
	for k := range members {
		m = append(m, k)
	}
	sort.Strings(m)
	return m
}

// getGroupMemberIDs returns usernames of all users in a group.
// Only checks OtherGroups (IDP group memberships), NOT PrimaryGroup,
// because PrimaryGroup uses UID-as-GID which can collide with real IDP group GIDs.
func (s *Store) getGroupMemberIDs(gid int) []string {
	members := make(map[string]bool)
	for _, u := range s.users {
		if u.Disabled {
			continue // exclude time-window-disabled users from group membership
		}
		for _, othergid := range u.OtherGroups {
			if othergid == gid {
				members[u.Name] = true
				break
			}
		}
	}
	m := make([]string, 0, len(members))
	for k := range members {
		m = append(m, k)
	}
	sort.Strings(m)
	return m
}

// getGroupDNs returns DNs for all groups matching the given GIDs.
func (s *Store) getGroupDNs(backend config.Backend, gids []int) []string {
	groups := make(map[string]bool)
	for _, gid := range gids {
		if name, ok := s.gidToName[gid]; ok {
			dn := fmt.Sprintf("%s=%s,%s", backend.GroupFormatAsArray[0], EscapeDNValue(name), backend.BaseDN)
			groups[dn] = true
		}
	}
	g := make([]string, 0, len(groups))
	for k := range groups {
		g = append(g, k)
	}
	sort.Strings(g)
	return g
}

// GetUsers returns a shallow copy of all users (for testing).
func (s *Store) GetUsers() map[string]config.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]config.User, len(s.users))
	for k, v := range s.users {
		out[k] = v
	}
	return out
}

// GetGroups returns a shallow copy of all groups (for testing).
func (s *Store) GetGroups() map[string]config.Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]config.Group, len(s.groups))
	for k, v := range s.groups {
		out[k] = v
	}
	return out
}
