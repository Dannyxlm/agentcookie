package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/mvanhorn/agentcookie/internal/config"
	"github.com/mvanhorn/agentcookie/internal/keystore"
	"github.com/mvanhorn/agentcookie/internal/notify"
	"github.com/mvanhorn/agentcookie/internal/state"
	"github.com/mvanhorn/agentcookie/internal/tincan"
	"github.com/mvanhorn/agentcookie/internal/tsclient"
)

// Lifecycle timing and seams. Tests override them.
var (
	// teammateRosterInterval is how often the roster is read.
	teammateRosterInterval = 10 * time.Minute
	// teammateApprovalPoll is how often CLI approvals are picked up.
	teammateApprovalPoll = 3 * time.Second
	// laptopDNSNameFunc discovers this laptop's MagicDNS name.
	laptopDNSNameFunc = discoverLaptopDNSName
	// approvalDialogFunc shows the owner's approval dialog.
	approvalDialogFunc = notify.AskApproval
	// ownerNoticeFunc posts a plain notification to the owner.
	ownerNoticeFunc = notify.Show
)

// teammateApprovalsDir holds approvals queued by `agentcookie teammates
// approve` for the daemon: <name>.json in, <name>.result.json out. The
// daemon owns teammates-state.json, so the CLI never writes it.
func teammateApprovalsDir(home string) string {
	return filepath.Join(home, ".agentcookie", "teammate-approvals")
}

// approvalIntent is one queued CLI approval.
type approvalIntent struct {
	NodeID      string    `json:"node_id"`
	RequestedAt time.Time `json:"requested_at"`
}

// approvalResult is the daemon's answer to an approvalIntent.
type approvalResult struct {
	NodeID  string    `json:"node_id"`
	OK      bool      `json:"ok"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

// tmInput is an owner answer delivered into the lifecycle goroutine.
type tmInput struct {
	name string
	ev   tmEvent
}

// teammateLifecycle drives every listed teammate through stepTeammate. All
// decisions run on the one goroutine in Run; dialogs run beside it and
// answer through inputs.
type teammateLifecycle struct {
	hub              *teammateHub
	home             string
	log              io.Writer
	now              func() time.Time
	cookiesChangedAt func() time.Time

	mem     map[string]*tmMem
	dialogs map[string]context.CancelFunc
	inputs  chan tmInput
	reload  chan struct{}

	lastRosterErr   string
	lastInboxErr    string
	warnedNoNodes   bool
	warnedNoPin     bool
	warnedAMD64Only bool
}

func newTeammateLifecycle(hub *teammateHub, home string) *teammateLifecycle {
	return &teammateLifecycle{
		hub:              hub,
		home:             home,
		log:              hub.log,
		now:              hub.now,
		cookiesChangedAt: pullPayloadCache.ChangedAt,
		mem:              make(map[string]*tmMem),
		dialogs:          make(map[string]context.CancelFunc),
		inputs:           make(chan tmInput, 8),
		reload:           make(chan struct{}, 1),
	}
}

// startTeammateLifecycle runs the lifecycle for the life of ctx. It does
// nothing while teammates.yaml is absent or empty, and picks up a file
// created later through the hub's reload hook.
func startTeammateLifecycle(ctx context.Context, hub *teammateHub, home string) {
	if hub == nil || hub.store == nil {
		return
	}
	l := newTeammateLifecycle(hub, home)
	go l.Run(ctx)
}

// Run reads the roster on start, every teammateRosterInterval and after
// every teammates.yaml reload, and reacts to /pair and /pull events, owner
// dialog answers and CLI approvals until ctx ends.
func (l *teammateLifecycle) Run(ctx context.Context) {
	l.hub.OnReload(func() {
		select {
		case l.reload <- struct{}{}:
		default:
		}
	})
	l.processApprovals(ctx)
	l.syncAll(ctx)
	roster := time.NewTicker(teammateRosterInterval)
	defer roster.Stop()
	approvals := time.NewTicker(teammateApprovalPoll)
	defer approvals.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-roster.C:
			l.syncAll(ctx)
		case <-l.reload:
			l.syncAll(ctx)
		case <-approvals.C:
			l.processApprovals(ctx)
		case ev := <-l.hub.Events():
			l.handleHubEvent(ctx, ev)
		case in := <-l.inputs:
			l.handleInput(ctx, in)
		}
	}
}

func (l *teammateLifecycle) logf(format string, args ...any) {
	fmt.Fprintf(l.log, "agentcookie source: "+format+"\n", args...)
}

func (l *teammateLifecycle) memFor(name string) *tmMem {
	m, ok := l.mem[name]
	if !ok {
		m = &tmMem{}
		l.mem[name] = m
	}
	return m
}

// apply runs one event through stepTeammate for name, saves the fields it
// changed, and runs its actions. A failed save runs no actions and
// suspends teammate access (suspendForSave).
func (l *teammateLifecycle) apply(ctx context.Context, name string, ev tmEvent) error {
	if err := l.hub.saveFailed(); err != nil {
		return err // no transition runs on top of state that was not saved
	}
	before, _ := l.hub.store.Record(name)
	m := l.memFor(name)
	m.CodeLive = l.hub.pairingPending(name)
	next, acts, stepErr := stepTeammate(tmState{Rec: before, Mem: *m}, ev, l.now().UTC())
	if err := l.hub.store.Update(func(st *state.TeammatesState) error {
		mergeRecord(st.Teammate(name), before, next.Rec)
		return nil
	}); err != nil {
		// Fail closed: the transition is not on disk, so none of its
		// actions run and teammate access stops until a restart.
		l.hub.suspendForSave(err)
		return fmt.Errorf("teammate %s: %w", name, err)
	}
	*m = next.Mem
	if before.Phase != next.Rec.Phase && next.Rec.Phase != "" {
		l.logf("teammate %s: %s", name, phaseLabel(next.Rec.Phase))
	}
	for _, a := range acts {
		l.execute(ctx, name, a)
	}
	return stepErr
}

// mergeRecord writes into dst only the fields the step changed, so a
// concurrent /pull or /pair update to other fields is never overwritten.
func mergeRecord(dst *state.TeammateRecord, before, after state.TeammateRecord) {
	dv := reflect.ValueOf(dst).Elem()
	bv, av := reflect.ValueOf(before), reflect.ValueOf(after)
	for i := 0; i < av.NumField(); i++ {
		if !reflect.DeepEqual(bv.Field(i).Interface(), av.Field(i).Interface()) {
			dv.Field(i).Set(av.Field(i))
		}
	}
}

func (l *teammateLifecycle) execute(ctx context.Context, name string, a tmAction) {
	switch a.Kind {
	case actDialog:
		l.showDialog(ctx, name, a)
	case actPairingNotify:
		l.sendPairing(ctx, name, a.NodeID)
	case actStaleNotify:
		l.sendStale(ctx, name)
	case actCancelNotify:
		c, err := l.client()
		if err == nil {
			err = c.Cancel(ctx, a.RequestID)
		}
		// A notice the teammate already answered, or that closed, needs no
		// withdrawal; the step already cleared it from the record.
		if err != nil && !errors.Is(err, tincan.ErrNotCancellable) {
			l.logf("teammate %s: could not withdraw notice %s: %v", name, a.RequestID, err)
		}
	case actCancelPairing:
		l.hub.CancelPairing(name)
	case actDeleteKey:
		if err := keystore.Delete(l.hub.configDir, name); err != nil {
			l.logf("teammate %s: delete key: %v", name, err)
			return
		}
		if a.NodeID != "" {
			l.logf("teammate %s: a different machine carries this name now; deleted the key of the old machine %s (node %s)", name, a.NodeName, a.NodeID)
			return
		}
		l.logf("teammate %s removed: its key is deleted and its next pull is refused. Cookies it already received stay valid on that machine until they expire or you sign out of those sites.", name)
	case actCheckHold:
		c, err := l.client()
		if err != nil {
			return
		}
		status, err := c.RequestStatus(ctx, a.RequestID)
		if err != nil {
			l.logf("teammate %s: check held notice %s: %v", name, a.RequestID, err)
			return
		}
		_ = l.apply(ctx, name, tmEvent{Kind: evHoldStatus, Status: status})
	}
}

// client builds the tincan client from the current teammates.yaml.
func (l *teammateLifecycle) client() (*tincan.Client, error) {
	return teammateTincanClient(l.hub.config(), l.home)
}

// teammateTincanClient resolves the tincan binary and TINCAN_CONFIG for
// the laptop's `agentcookie` agent.
func teammateTincanClient(cfg *config.TeammatesConfig, home string) (*tincan.Client, error) {
	var configured, conf string
	if cfg != nil {
		configured, conf = cfg.TincanPath, cfg.TincanConfig
	}
	if conf == "" {
		conf = tincan.DefaultConfigPath(home)
	}
	path, err := tincan.Resolve(configured, home)
	if err != nil {
		return nil, err
	}
	return &tincan.Client{Path: path, Config: conf}, nil
}

// syncAll applies removals, reads the roster, drains the inbox, and steps
// every listed teammate with what the roster shows.
func (l *teammateLifecycle) syncAll(ctx context.Context) {
	if l.hub.Suspended() != nil {
		return // fail closed: the list is unknown
	}
	snap := l.hub.store.Snapshot()
	var removed []string
	for name, rec := range snap.Teammates {
		if !rec.RemovedAt.IsZero() && rec.Phase != state.PhaseRemoved {
			removed = append(removed, name)
		}
	}
	sort.Strings(removed)
	for _, name := range removed {
		_ = l.apply(ctx, name, tmEvent{Kind: evRemoved})
		if cancel, ok := l.dialogs[name]; ok {
			cancel()
			delete(l.dialogs, name)
		}
		delete(l.mem, name)
	}
	l.deleteStaleKeys()
	if !l.hub.Active() {
		return
	}
	l.refreshLaptopName(ctx)
	roster, err := l.readRoster(ctx)
	if err != nil {
		return
	}
	l.drainInbox(ctx)
	changed := l.cookiesChangedAt()
	for _, name := range l.hub.config().Names() {
		a, ok := roster.Find(name)
		_ = l.apply(ctx, name, tmEvent{Kind: evRoster, OnRoster: ok, Agent: a, CookiesChangedAt: changed})
	}
}

// deleteStaleKeys deletes keys/<name>.json for every recorded teammate
// that is no longer listed. Removal already deleted its key, but a /pair
// that completed mid-removal can write one afterwards. Only names in the
// teammate state are considered, so a non-teammate peer's key is never
// touched. The caller has checked that teammates.yaml loaded.
func (l *teammateLifecycle) deleteStaleKeys() {
	snap := l.hub.store.Snapshot()
	names := make([]string, 0, len(snap.Teammates))
	for name, rec := range snap.Teammates {
		if !rec.RemovedAt.IsZero() && !l.hub.IsListed(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		path, err := keystore.Path(l.hub.configDir, name)
		if err != nil {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := keystore.Delete(l.hub.configDir, name); err != nil {
			l.logf("teammate %s: delete stale key: %v", name, err)
			continue
		}
		l.logf("teammate %s: deleted a key written after its removal (a pairing that finished mid-removal)", name)
	}
}

// readRoster reads the roster and records the relay's status. Failures
// are logged once per distinct error, not every poll.
func (l *teammateLifecycle) readRoster(ctx context.Context) (*tincan.Roster, error) {
	c, err := l.client()
	var roster *tincan.Roster
	if err == nil {
		roster, err = c.Roster(ctx)
	}
	now := l.now().UTC()
	_ = l.hub.store.Update(func(st *state.TeammatesState) error {
		if c != nil {
			st.Tincan.Path = c.Path
		}
		if err != nil {
			st.Tincan.LastError, st.Tincan.LastErrorAt = err.Error(), now
			return nil
		}
		st.Tincan.LastRosterAt = now
		st.Tincan.LastError, st.Tincan.LastErrorAt = "", time.Time{}
		st.Tincan.NodeFieldsVisible = roster.NodeFieldsVisible()
		return nil
	})
	if err != nil {
		if err.Error() != l.lastRosterErr {
			l.logf("teammates: cannot read the Tincan roster (%v); retrying every %s", err, teammateRosterInterval)
			l.lastRosterErr = err.Error()
		}
		return nil, err
	}
	if l.lastRosterErr != "" {
		l.logf("teammates: Tincan roster readable again")
		l.lastRosterErr = ""
	}
	if !roster.NodeFieldsVisible() && !l.warnedNoNodes {
		l.logf("teammates: the Tincan roster shows no Tailscale nodes (an older relay, or this laptop is not on the relay's --admin list); teammates wait for their machine. See `agentcookie teammates setup`.")
		l.warnedNoNodes = true
	} else if roster.NodeFieldsVisible() {
		l.warnedNoNodes = false
	}
	return roster, nil
}

func (l *teammateLifecycle) drainInbox(ctx context.Context) {
	c, err := l.client()
	if err != nil {
		return
	}
	if _, err := c.DrainInbox(ctx); err != nil {
		if err.Error() != l.lastInboxErr {
			l.logf("teammates: drain the agentcookie Tincan inbox: %v", err)
			l.lastInboxErr = err.Error()
		}
		return
	}
	l.lastInboxErr = ""
}

func (l *teammateLifecycle) handleHubEvent(ctx context.Context, ev TeammateEvent) {
	switch ev.Kind {
	case TeammatePaired:
		_ = l.apply(ctx, ev.Name, tmEvent{Kind: evPaired, NodeID: ev.NodeID})
	case TeammateKeyLost:
		_ = l.apply(ctx, ev.Name, tmEvent{Kind: evKeyLost, NodeID: ev.NodeID})
	}
}

func (l *teammateLifecycle) handleInput(ctx context.Context, in tmInput) {
	switch in.ev.Kind {
	case evApprove:
		if err := l.approve(ctx, in.name, in.ev.NodeID); err != nil {
			l.logf("teammate %s: approval of node %s not applied: %v", in.name, in.ev.NodeID, err)
		}
	case evNotNow:
		l.logf("teammate %s: Not now; asking again when agentcookie restarts or the machine changes. From a terminal: %s",
			in.name, notify.ApproveCommand(in.name, in.ev.NodeID))
		_ = l.apply(ctx, in.name, in.ev)
	}
}

// approve binds nodeID for name if it is still the machine awaiting
// approval. The roster is read first so a machine that changed since the
// dialog is caught.
func (l *teammateLifecycle) approve(ctx context.Context, name, nodeID string) error {
	if err := l.hub.Suspended(); err != nil {
		return fmt.Errorf("teammates are suspended: %w", err)
	}
	if !l.hub.IsListed(name) {
		return fmt.Errorf("%s is not listed in teammates.yaml", name)
	}
	if roster, err := l.readRoster(ctx); err == nil {
		a, ok := roster.Find(name)
		_ = l.apply(ctx, name, tmEvent{Kind: evRoster, OnRoster: ok, Agent: a, CookiesChangedAt: l.cookiesChangedAt()})
	}
	if err := l.apply(ctx, name, tmEvent{Kind: evApprove, NodeID: nodeID}); err != nil {
		return err
	}
	rec, _ := l.hub.store.Record(name)
	l.logf("teammate %s: approved machine %s (node %s)", name, rec.BoundNodeName, rec.BoundNodeID)
	return nil
}

func (l *teammateLifecycle) showDialog(ctx context.Context, name string, a tmAction) {
	req := notify.ApprovalRequest{Agent: name, NodeID: a.NodeID, NodeName: a.NodeName, NodeUser: a.NodeUser, Replaces: a.Replaces}
	replaces := ""
	if a.Replaces != "" {
		replaces = ", replacing " + a.Replaces
	}
	l.logf("teammate %s is on machine %s (login %s, node %s)%s and waits for your approval. From a terminal: %s",
		name, a.NodeName, a.NodeUser, a.NodeID, replaces, notify.ApproveCommand(name, a.NodeID))
	if cancel, ok := l.dialogs[name]; ok {
		cancel()
	}
	dctx, cancel := context.WithCancel(ctx)
	l.dialogs[name] = cancel
	ask, notice := approvalDialogFunc, ownerNoticeFunc
	go func() {
		defer cancel()
		approved, err := ask(dctx, req)
		if dctx.Err() != nil {
			return // replaced by a newer dialog, or shutting down
		}
		if err != nil {
			_ = notice(ctx, "agentcookie: approve teammate "+name, "Run: "+notify.ApproveCommand(name, a.NodeID))
			fmt.Fprintf(l.log, "agentcookie source: teammate %s: no approval dialog (%v); approve from a terminal: %s\n", name, err, notify.ApproveCommand(name, a.NodeID))
			return
		}
		kind := evNotNow
		if approved {
			kind = evApprove
		}
		select {
		case l.inputs <- tmInput{name: name, ev: tmEvent{Kind: kind, NodeID: a.NodeID}}:
		case <-ctx.Done():
		}
	}()
}

// sendPairing mints a code for the bound node and sends the pairing notice.
func (l *teammateLifecycle) sendPairing(ctx context.Context, name, nodeID string) {
	res, expires := l.pairingSend(ctx, name, nodeID)
	if res.Outcome != tincan.OutcomeSent && res.Outcome != tincan.OutcomeHeld {
		l.hub.CancelPairing(name)
		// A missing release pin was logged once by releasePin; the
		// reason is on the record either way.
		if !errors.Is(res.Err, errNoReleasePin) {
			l.logf("teammate %s: pairing notice not sent (%s): %v; retrying later", name, res.Outcome, res.Err)
		}
	} else if res.Outcome == tincan.OutcomeHeld {
		l.logf("teammate %s: pairing notice %s is held by the Tincan approval gate; add agentcookie to that teammate's unless list in approval.json", name, res.RequestID)
	} else {
		l.logf("teammate %s: pairing notice %s sent; code valid until %s", name, res.RequestID, expires.Format(time.Kitchen))
	}
	_ = l.apply(ctx, name, tmEvent{Kind: evNotifyResult, Purpose: state.NotifyPurposePairing, Result: res, CodeExpires: expires.UTC()})
}

func (l *teammateLifecycle) pairingSend(ctx context.Context, name, nodeID string) (tincan.SendResult, time.Time) {
	fail := func(err error) (tincan.SendResult, time.Time) {
		return tincan.SendResult{Outcome: tincan.OutcomeError, Err: err}, time.Time{}
	}
	pin, err := l.releasePin()
	if err != nil {
		return fail(err)
	}
	laptop, err := l.laptopName(ctx)
	if err != nil {
		return fail(err)
	}
	c, err := l.client()
	if err != nil {
		return fail(err)
	}
	code, expires, err := l.hub.MintPairing(name, nodeID)
	if err != nil {
		return fail(err)
	}
	text := pairingNoticeText(pairingNotice{
		Name: name, Laptop: laptop, Code: string(code), Expires: expires,
		Tag: pin.Tag, SHA256: pin.SHA256, SHA256ARM64: pin.SHA256ARM64, Cadence: l.cadenceFor(name),
	})
	return c.Notify(ctx, name, text), expires
}

func (l *teammateLifecycle) sendStale(ctx context.Context, name string) {
	rec, _ := l.hub.store.Record(name)
	c, err := l.client()
	res := tincan.SendResult{Outcome: tincan.OutcomeError, Err: err}
	if err == nil {
		res = c.Notify(ctx, name, staleNoticeText(name, rec.LastPulledAt))
	}
	if res.Outcome == tincan.OutcomeSent || res.Outcome == tincan.OutcomeHeld {
		l.logf("teammate %s: no pull since %s while cookies changed; reminder %s %s", name, rec.LastPulledAt.Format(time.RFC3339), res.RequestID, res.Outcome)
	} else {
		l.logf("teammate %s: staleness reminder not sent (%s): %v", name, res.Outcome, res.Err)
	}
	_ = l.apply(ctx, name, tmEvent{Kind: evNotifyResult, Purpose: state.NotifyPurposeStale, Result: res})
}

// cadenceFor is the listed cadence, else the default for the agent's kind.
func (l *teammateLifecycle) cadenceFor(name string) config.Cadence {
	if cfg := l.hub.config(); cfg != nil {
		for _, tm := range cfg.Teammates {
			if tm.Name == name && tm.Cadence != "" {
				return tm.Cadence
			}
		}
	}
	rec, _ := l.hub.store.Record(name)
	return defaultCadence(rec.Kind)
}

// releasePin returns the release this build pins in the install line:
// its own tag and the Linux digests embedded at release build time. A
// build without them sends no pairing notice; the reason is logged once
// and recorded on the teammate for status, doctor and teammates list.
func (l *teammateLifecycle) releasePin() (releasePin, error) {
	pin, err := buildReleasePin()
	if err != nil {
		if !l.warnedNoPin {
			l.warnedNoPin = true
			l.logf("teammates: %v; pairing notices are not sent until this laptop runs an agentcookie release build", err)
		}
		return releasePin{}, err
	}
	if pin.SHA256ARM64 == "" && !l.warnedAMD64Only {
		l.warnedAMD64Only = true
		l.logf("teammates: release %s embeds no linux_arm64 digest; the install line pins amd64 only and an arm64 teammate cannot install it", pin.Tag)
	}
	return pin, nil
}

// refreshLaptopName rediscovers the laptop's MagicDNS name and keeps it.
func (l *teammateLifecycle) refreshLaptopName(ctx context.Context) {
	name, err := laptopDNSNameFunc(ctx)
	if err != nil || name == "" {
		return
	}
	if l.hub.store.Snapshot().LaptopDNSName == name {
		return
	}
	if err := l.hub.store.Update(func(st *state.TeammatesState) error {
		st.LaptopDNSName = name
		return nil
	}); err != nil {
		l.logf("teammates: %v", err)
	}
}

// laptopName is the laptop's MagicDNS name as last discovered. syncAll
// refreshes it every cycle, so Tailscale is asked here only when no name
// has been discovered yet.
func (l *teammateLifecycle) laptopName(ctx context.Context) (string, error) {
	if name := l.hub.store.Snapshot().LaptopDNSName; name != "" {
		return name, nil
	}
	l.refreshLaptopName(ctx)
	if name := l.hub.store.Snapshot().LaptopDNSName; name != "" {
		return name, nil
	}
	return "", errors.New("this laptop's MagicDNS name is unknown (is Tailscale up?)")
}

// discoverLaptopDNSName asks Tailscale for this machine's MagicDNS name.
func discoverLaptopDNSName(ctx context.Context) (string, error) {
	cli, err := tsclient.FindCLI()
	if err != nil {
		return "", err
	}
	st, err := tsclient.Get(ctx, cli)
	if err != nil {
		return "", err
	}
	if st.Self == nil || st.Self.DNSName == "" {
		return "", errors.New("tailscale status has no MagicDNS name for this machine")
	}
	return strings.TrimSuffix(st.Self.DNSName, "."), nil
}

// processApprovals applies approvals queued by `agentcookie teammates
// approve` and answers each with a result file.
func (l *teammateLifecycle) processApprovals(ctx context.Context) {
	dir := teammateApprovalsDir(l.home)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || strings.HasSuffix(name, ".result") || strings.HasPrefix(name, ".") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		_ = os.Remove(path)
		if err != nil {
			continue
		}
		var in approvalIntent
		res := approvalResult{At: l.now().UTC()}
		if err := json.Unmarshal(data, &in); err != nil || in.NodeID == "" {
			res.Message = "unreadable approval request"
		} else {
			res.NodeID = in.NodeID
			if err := l.approve(ctx, name, in.NodeID); err != nil {
				res.Message = err.Error()
				if rec, _ := l.hub.store.Record(name); errors.Is(err, errApprovalStale) && rec.PendingNodeID != "" {
					res.Message += fmt.Sprintf(" (now waiting: %s, node %s)", rec.PendingNodeName, rec.PendingNodeID)
				}
			} else {
				res.OK = true
				res.Message = "approved; pairing notice sent"
			}
		}
		if err := writeJSONFile(filepath.Join(dir, name+".result.json"), res); err != nil {
			l.logf("teammates: %v", err)
		}
	}
}

// writeJSONFile writes v to path atomically with mode 0600.
func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), 0o600)
}

// config returns the last teammates.yaml that loaded (nil before any).
func (h *teammateHub) config() *config.TeammatesConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cfg
}

// pairingPending reports whether name has an unexpired pending code.
func (h *teammateHub) pairingPending(name string) bool {
	now := h.now()
	h.pairings.mu.Lock()
	defer h.pairings.mu.Unlock()
	e, ok := h.pairings.byName[name]
	return ok && now.Before(e.Expires)
}

// phaseLabel is the owner-facing wording of a lifecycle phase.
func phaseLabel(phase string) string {
	switch phase {
	case state.PhaseWaitingForNode:
		return "waiting for its machine"
	case state.PhaseAwaitingApproval:
		return "waiting for approval"
	case state.PhasePairing:
		return "pairing"
	case state.PhaseHeld:
		return "held by the Tincan approval gate"
	case state.PhasePaired:
		return "paired"
	case state.PhaseRemoved:
		return "removed"
	case "":
		return "not seen yet"
	}
	return phase
}
