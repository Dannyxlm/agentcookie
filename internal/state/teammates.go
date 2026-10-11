package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TeammatesStateVersion is the on-disk format version of
// teammates-state.json.
const TeammatesStateVersion = 1

// TeammatesPath is the daemon-owned teammate binding state. The owner's
// list lives in ~/.config/agentcookie/teammates.yaml; this file is written
// only by the daemon so it never rewrites the owner's file.
func TeammatesPath(home string) string {
	return filepath.Join(home, ".agentcookie", "teammates-state.json")
}

// TeammatesState is the whole teammates-state.json document.
type TeammatesState struct {
	Version int `json:"version"`
	// Teammates holds one record per name that has ever been listed. A
	// record outlives removal from teammates.yaml (RemovedAt is set) so a
	// removed teammate's key is never treated as a non-teammate peer.
	Teammates map[string]*TeammateRecord `json:"teammates,omitempty"`
	// MigratedLegacy lists legacy push peers (source.yaml sink/sinks)
	// whose name was listed as a teammate. Push to them stays suppressed
	// for good, even after the name is removed from teammates.yaml.
	MigratedLegacy []MigratedLegacyPeer `json:"migrated_legacy,omitempty"`
	// ConfigError is the last teammates.yaml load error; empty while the
	// file loads. Teammate pulls and pairings are suspended while it is set.
	ConfigError   string    `json:"config_error,omitempty"`
	ConfigErrorAt time.Time `json:"config_error_at,omitempty"`

	// Tincan is the teammate lifecycle's last view of the relay.
	Tincan TincanStatus `json:"tincan,omitzero"`
	// LaptopDNSName is this laptop's MagicDNS name, last discovered from
	// Tailscale. Pairing notices pin it as the laptop teammates pull from.
	LaptopDNSName string `json:"laptop_dns_name,omitempty"`
	// ReleasePin is the release a pairing notice installs, with the SHA256
	// of its Linux asset, computed once per release.
	ReleasePin *ReleasePin `json:"release_pin,omitempty"`
}

// TincanStatus is what the lifecycle last saw of the Tincan relay.
type TincanStatus struct {
	// Path is the resolved absolute tincan binary.
	Path string `json:"path,omitempty"`
	// LastRosterAt is the last successful roster read.
	LastRosterAt time.Time `json:"last_roster_at,omitzero"`
	// NodeFieldsVisible: the last roster carried admin node fields. False
	// means an older relay or a laptop missing from the relay's --admin
	// list, and every teammate stays waiting for its machine.
	NodeFieldsVisible bool      `json:"node_fields_visible,omitempty"`
	LastError         string    `json:"last_error,omitempty"`
	LastErrorAt       time.Time `json:"last_error_at,omitzero"`
}

// ReleasePin is the agentcookie release a teammate installs.
type ReleasePin struct {
	Tag    string `json:"tag"`
	SHA256 string `json:"sha256"`
}

// Teammate lifecycle phases (TeammateRecord.Phase).
const (
	PhaseWaitingForNode   = "waiting_for_node"
	PhaseAwaitingApproval = "awaiting_approval"
	PhasePairing          = "pairing"
	PhaseHeld             = "held"
	PhasePaired           = "paired"
	PhaseRemoved          = "removed"
)

// Notify purposes and statuses (TeammateRecord.NotifyPurpose, NotifyStatus).
const (
	NotifyPurposePairing = "pairing"
	NotifyPurposeStale   = "stale"

	NotifySent        = "sent"
	NotifyHeld        = "held"
	NotifyRateLimited = "rate-limited"
	NotifyError       = "error"
)

// TeammateRecord is one teammate's binding and history.
type TeammateRecord struct {
	ListedAt  time.Time `json:"listed_at,omitempty"`
	RemovedAt time.Time `json:"removed_at,omitempty"`
	// BoundNodeID is the Tailscale node StableID the owner approved. Every
	// /pair and /pull from this teammate must come from this node.
	BoundNodeID   string    `json:"bound_node_id,omitempty"`
	BoundNodeName string    `json:"bound_node_name,omitempty"`
	ApprovedAt    time.Time `json:"approved_at,omitempty"`
	// PairCodeMintedAt is when the latest pairing code was minted;
	// PairedAt when a /pair from the bound node last completed.
	PairCodeMintedAt time.Time `json:"pair_code_minted_at,omitempty"`
	PairedAt         time.Time `json:"paired_at,omitempty"`
	LastPulledAt     time.Time `json:"last_pulled_at,omitempty"`
	LastPullError    string    `json:"last_pull_error,omitempty"`
	LastPullErrorAt  time.Time `json:"last_pull_error_at,omitempty"`

	// Lifecycle fields, written by the teammate lifecycle.

	// Phase is one of the Phase* constants; empty before the first roster.
	Phase string `json:"phase,omitempty"`
	// Kind is the agent's Tincan kind from the roster.
	Kind string `json:"kind,omitempty"`
	// PendingNode* is the machine waiting for the owner's approval.
	PendingNodeID   string `json:"pending_node_id,omitempty"`
	PendingNodeName string `json:"pending_node_name,omitempty"`
	PendingNodeUser string `json:"pending_node_user,omitempty"`
	// ReplacesNode* is the previously bound machine a pending one replaces.
	ReplacesNodeID   string `json:"replaces_node_id,omitempty"`
	ReplacesNodeName string `json:"replaces_node_name,omitempty"`
	// RelaySeenAt is the agent's latest relay call the roster showed.
	RelaySeenAt time.Time `json:"relay_seen_at,omitzero"`
	// The open (or last) notify to this teammate. At most one is open.
	NotifyID      string    `json:"notify_id,omitempty"`
	NotifyPurpose string    `json:"notify_purpose,omitempty"`
	NotifyStatus  string    `json:"notify_status,omitempty"`
	NotifySentAt  time.Time `json:"notify_sent_at,omitzero"`
	NotifyError   string    `json:"notify_error,omitempty"`
	// CodeExpiresAt is when the code in the last pairing notice expires.
	CodeExpiresAt time.Time `json:"code_expires_at,omitzero"`
	// LastPairAttemptAt is the last /pair request that carried this
	// teammate's pending code, whether it paired or was refused.
	LastPairAttemptAt time.Time `json:"last_pair_attempt_at,omitzero"`
	// PairCodeMissedAt is the expiry of a pairing code whose notice the
	// teammate picked up (it polled the relay after the notice) but never
	// answered with a /pair. It survives the re-mint that replaces that
	// notice, so doctor can still name a missing tailnet ACL rule.
	PairCodeMissedAt time.Time `json:"pair_code_missed_at,omitzero"`
	// LastRepairAt is the last automatic re-pair after a lost key.
	LastRepairAt time.Time `json:"last_repair_at,omitzero"`
	// StaleNotifiedAt is the last staleness notice.
	StaleNotifiedAt time.Time `json:"stale_notified_at,omitzero"`
}

// MigratedLegacyPeer is a legacy push peer moved onto teammate mode.
type MigratedLegacyPeer struct {
	Name       string    `json:"name"`
	MigratedAt time.Time `json:"migrated_at"`
}

// Teammate returns name's record, creating it on first use.
func (s *TeammatesState) Teammate(name string) *TeammateRecord {
	if s.Teammates == nil {
		s.Teammates = make(map[string]*TeammateRecord)
	}
	r, ok := s.Teammates[name]
	if !ok {
		r = &TeammateRecord{}
		s.Teammates[name] = r
	}
	return r
}

// AddMigratedLegacy records name as migrated. It reports whether name was
// newly added, so the caller can log its one-time hint.
func (s *TeammatesState) AddMigratedLegacy(name string, at time.Time) bool {
	for _, m := range s.MigratedLegacy {
		if m.Name == name {
			return false
		}
	}
	s.MigratedLegacy = append(s.MigratedLegacy, MigratedLegacyPeer{Name: name, MigratedAt: at.UTC()})
	return true
}

// IsMigrated reports whether name is a migrated legacy push peer.
func (s *TeammatesState) IsMigrated(name string) bool {
	for _, m := range s.MigratedLegacy {
		if m.Name == name {
			return true
		}
	}
	return false
}

func (s *TeammatesState) clone() TeammatesState {
	out := *s
	if s.Teammates != nil {
		out.Teammates = make(map[string]*TeammateRecord, len(s.Teammates))
		for k, v := range s.Teammates {
			cp := *v
			out.Teammates[k] = &cp
		}
	}
	out.MigratedLegacy = append([]MigratedLegacyPeer(nil), s.MigratedLegacy...)
	if s.ReleasePin != nil {
		pin := *s.ReleasePin
		out.ReleasePin = &pin
	}
	return out
}

// TeammateStore serializes reads and writes of teammates-state.json for
// one daemon. Every Update is written atomically (temp file plus rename,
// mode 0600).
type TeammateStore struct {
	mu     sync.Mutex
	st     TeammatesState
	writer *Writer
}

// OpenTeammateStore loads path. A missing file starts empty; an unreadable
// or corrupt file is an error so binding state is never silently dropped.
func OpenTeammateStore(path string) (*TeammateStore, error) {
	s := &TeammateStore{writer: NewWriter(path), st: TeammatesState{Version: TeammatesStateVersion}}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &s.st); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if s.st.Version == 0 {
		s.st.Version = TeammatesStateVersion
	}
	return s, nil
}

// Snapshot returns a deep copy of the current state.
func (s *TeammateStore) Snapshot() TeammatesState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.clone()
}

// Record returns a copy of name's record.
func (s *TeammateStore) Record(name string) (TeammateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.st.Teammates[name]
	if !ok {
		return TeammateRecord{}, false
	}
	return *r, true
}

// IsMigrated reports whether name is a migrated legacy push peer.
func (s *TeammateStore) IsMigrated(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.IsMigrated(name)
}

// Update applies fn to the state and saves it. If fn returns an error or
// the save fails, the in-memory state is left as it was before the call.
func (s *TeammateStore) Update(fn func(*TeammatesState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.st.clone()
	if err := fn(&next); err != nil {
		return err
	}
	next.Version = TeammatesStateVersion
	if err := s.writer.Save(&next); err != nil {
		return fmt.Errorf("save teammates state: %w", err)
	}
	s.st = next
	return nil
}
