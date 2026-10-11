package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mvanhorn/agentcookie/internal/config"
	"github.com/mvanhorn/agentcookie/internal/state"
	"github.com/mvanhorn/agentcookie/internal/tsclient"
)

// teammateStaleAfter is how long a paired teammate may go without a pull
// before doctor and status warn.
const teammateStaleAfter = 6 * time.Hour

// teammateView is what doctor and status read about teammates.
type teammateView struct {
	present bool // teammates.yaml exists
	cfgErr  error
	listed  int
	rows    []TeammateStatus
	snap    state.TeammatesState
	// stateErr is set when teammates-state.json cannot be read.
	stateErr error
	tincan   string // configured or resolved tincan path
}

func loadTeammateView(configDir, home string) teammateView {
	var v teammateView
	if _, err := os.Stat(config.TeammatesPath(configDir)); err != nil {
		return v
	}
	v.present = true
	cfg, cfgErr := config.LoadTeammates(configDir)
	v.cfgErr = cfgErr
	if cfg != nil {
		v.listed = len(cfg.Teammates)
		v.tincan = cfg.TincanPath
	}
	store, err := state.OpenTeammateStore(state.TeammatesPath(home))
	if err != nil {
		v.stateErr = err
		return v
	}
	v.snap = store.Snapshot()
	if v.snap.Tincan.Path != "" {
		v.tincan = v.snap.Tincan.Path
	}
	v.rows, v.stateErr = TeammateStatuses(configDir, home)
	return v
}

// laptopTarget is this laptop as an ACL destination.
func (v teammateView) laptopTarget() string {
	if n := strings.TrimSuffix(v.snap.LaptopDNSName, "."); n != "" {
		return n
	}
	return "<this laptop>"
}

// liveNodeTags looks up a node's ACL tags in `tailscale status --json`.
func liveNodeTags(nodeID string) ([]string, error) {
	cli, err := tsclient.FindCLI()
	if err != nil {
		return nil, err
	}
	st, err := tsclient.Get(context.Background(), cli)
	if err != nil {
		return nil, err
	}
	if p := st.PeerByStableID(nodeID); p != nil {
		return p.Tags, nil
	}
	return nil, nil
}

// checkTeammates is doctor's teammates section. It returns nothing when
// teammates.yaml does not exist.
func checkTeammates(d doctorDeps) []Check {
	home := d.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	v := loadTeammateView(d.ConfigDir, home)
	if !v.present {
		return nil
	}
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	tags := d.NodeTags
	if tags == nil {
		tags = liveNodeTags
	}

	var src *state.SourceState
	var srcErr error
	if d.LoadSourceState != nil {
		src, srcErr = d.LoadSourceState()
	}
	checks := []Check{checkTeammateListener(src, srcErr), checkTeammateReleasePin()}

	if v.cfgErr != nil {
		checks = append(checks, Check{
			Name: "Teammates config", Severity: SeverityFail,
			Detail:      "teammates.yaml does not load: " + v.cfgErr.Error() + "; every teammate pull and pairing is suspended",
			Remediation: "fix " + config.TeammatesPath(d.ConfigDir) + "; the daemon reloads it on save",
		})
	} else {
		checks = append(checks, Check{Name: "Teammates config", Severity: SeverityOK,
			Detail: fmt.Sprintf("%d listed in %s", v.listed, config.TeammatesPath(d.ConfigDir))})
	}
	if v.stateErr != nil {
		checks = append(checks, Check{Name: "Teammates state", Severity: SeverityFail,
			Detail:      "cannot read teammates state: " + v.stateErr.Error(),
			Remediation: "inspect " + state.TeammatesPath(home)})
		return checks
	}
	checks = append(checks, checkTincanForTeammates(v, now))
	for _, r := range v.rows {
		diag := diagnoseTeammate(r, v.laptopTarget(), tags, now)
		checks = append(checks, Check{Name: "Teammate " + r.Name, Severity: diag.Severity, Detail: diag.Detail, Remediation: diag.Remediation})
	}
	return checks
}

func checkTeammateListener(src *state.SourceState, err error) Check {
	c := Check{Name: "Teammate pull listener"}
	switch {
	case err != nil:
		c.Severity, c.Detail = SeverityFail, "cannot read source state: "+err.Error()
		c.Remediation = "teammates pull from the agentcookie daemon (source --watch); check its log"
	case src == nil || src.PullListener == "":
		c.Severity, c.Detail = SeverityFail, "not running: no pull listener reported by source --watch"
		c.Remediation = "start the agentcookie daemon (source --watch); teammates pull from its port 9998"
	case src.PullListener == "up":
		c.Severity, c.Detail = SeverityOK, "up on "+orDash(src.PullListenerAddr)
	default:
		c.Severity, c.Detail = SeverityFail, src.PullListener+": waiting for a tailnet address, so no teammate can pull or pair"
		c.Remediation = "bring Tailscale up on this laptop; the listener binds as soon as it has a 100.x address"
	}
	return c
}

// checkTeammateReleasePin reports the release this binary pins in pairing
// notices: its own tag and the Linux digests embedded at release build
// time. Without them the daemon sends no pairing notice.
func checkTeammateReleasePin() Check {
	c := Check{Name: "Teammate release pin"}
	pin, err := buildReleasePin()
	switch {
	case err != nil:
		c.Severity = SeverityFail
		c.Detail = err.Error() + "; the daemon sends no pairing notice, so every approved teammate keeps waiting"
		c.Remediation = "run an agentcookie release build on this laptop (its Linux tarball digests are embedded at build time)"
	case pin.SHA256ARM64 == "":
		c.Severity = SeverityWarn
		c.Detail = pin.Tag + " pins linux amd64 only; an arm64 teammate cannot install it"
	default:
		c.Severity = SeverityOK
		c.Detail = pin.Tag + " pins linux amd64 and arm64"
	}
	return c
}

func checkTincanForTeammates(v teammateView, now time.Time) Check {
	c := Check{Name: "Tincan"}
	const fix = "run `agentcookie teammates setup`"
	lastErr := ""
	if v.snap.Tincan.LastError != "" {
		lastErr = "; last error: " + v.snap.Tincan.LastError
	}
	switch {
	case v.tincan == "":
		c.Severity, c.Detail, c.Remediation = SeverityWarn, "tincan path not recorded, so the daemon cannot read the roster or send pairing notices"+lastErr, fix
	case !fileExists(v.tincan):
		c.Severity, c.Detail, c.Remediation = SeverityWarn, "tincan not found at "+v.tincan+lastErr, fix
	case !v.snap.Tincan.NodeFieldsVisible:
		what := "no roster read yet"
		if !v.snap.Tincan.LastRosterAt.IsZero() {
			what = "the roster shows no Tailscale nodes (the relay is older than admin node fields, or this laptop is not on the relay's --admin list)"
		}
		c.Severity, c.Detail = SeverityWarn, what+"; every teammate waits for its machine"+lastErr
		c.Remediation = fix + ", and add this laptop to the relay's --admin list"
	default:
		c.Severity = SeverityOK
		c.Detail = fmt.Sprintf("%s; roster read %s ago, node fields visible%s", v.tincan, humanAgo(now.Sub(v.snap.Tincan.LastRosterAt)), lastErr)
	}
	return c
}

// teammateDiag is one teammate's doctor line.
type teammateDiag struct {
	Severity    Severity
	Detail      string
	Remediation string
}

// diagnoseTeammate turns a teammate row into its doctor line. tags is
// asked for the bound node's ACL tags only when the tailnet ACL is blamed.
func diagnoseTeammate(r TeammateStatus, laptop string, tags func(string) ([]string, error), now time.Time) teammateDiag {
	detail := r.StateLabel
	if r.NodeName != "" {
		detail += " on " + strings.TrimSuffix(r.NodeName, ".")
	}
	if r.State == state.PhasePaired || !r.LastPulledAt.IsZero() {
		if r.LastPulledAt.IsZero() {
			detail += ", never pulled"
		} else {
			detail += ", last pull " + humanAgo(now.Sub(r.LastPulledAt)) + " ago"
		}
	}
	if r.LastPullError != "" {
		detail += "; last pull error: " + r.LastPullError
	}
	if r.NotifyError != "" {
		detail += "; last notice failed: " + r.NotifyError
	}
	d := teammateDiag{Severity: SeverityInfo, Detail: detail}
	held := r.State == state.PhaseHeld || r.NotifyStatus == state.NotifyHeld

	switch {
	case r.State == "suspended":
		d.Severity, d.Remediation = SeverityWarn, "fix teammates.yaml (see Teammates config)"
	case r.State == state.PhaseRemoved:
		d.Detail += "; cookies it already received stay valid on that machine"
	case held:
		d.Severity = SeverityWarn
		d.Detail += "; its notice is held by the Tincan approval gate"
		d.Remediation = `add "agentcookie" to this teammate's "unless" list in the relay's approval.json`
	case r.State == state.PhaseAwaitingApproval:
		d.Severity = SeverityWarn
		if r.PendingNodeID != "" {
			d.Detail += fmt.Sprintf(": %s (%s, node %s)", r.PendingNodeName, r.PendingNodeUser, r.PendingNodeID)
			if r.Replaces != "" {
				d.Detail += ", replacing " + r.Replaces
			}
			d.Remediation = fmt.Sprintf("approve in the dialog, or run: agentcookie teammates approve %s --node %s", r.Name, r.PendingNodeID)
		}
	case r.State == state.PhasePairing:
		rec := state.TeammateRecord{
			NotifyPurpose: r.NotifyPurpose, NotifyStatus: r.NotifyStatus, NotifySentAt: r.NotifySentAt,
			CodeExpiresAt: r.CodeExpiresAt, RelaySeenAt: r.RelaySeenAt, LastPairAttemptAt: r.LastPairAttemptAt,
		}
		missed := !r.PairCodeMissedAt.IsZero() && !r.LastPairAttemptAt.After(r.PairCodeMissedAt)
		expiredUntried := r.NotifyPurpose == state.NotifyPurposePairing && r.NotifyStatus == state.NotifySent &&
			!r.CodeExpiresAt.IsZero() && !now.Before(r.CodeExpiresAt) && !r.LastPairAttemptAt.After(r.NotifySentAt)
		switch {
		case pairNoticeUnanswered(rec, now) || missed:
			src := aclSource(r, tags)
			d.Severity = SeverityWarn
			d.Detail += "; it picked up its pairing notice but no /pair reached this laptop before the code expired, so the tailnet ACL most likely blocks it"
			d.Remediation = fmt.Sprintf("add the tailnet ACL rule %s -> %s:9998, for example {\"action\": \"accept\", \"src\": [\"%s\"], \"dst\": [\"%s:9998\"]}", src, laptop, src, laptop)
		case expiredUntried:
			d.Severity = SeverityWarn
			d.Detail += "; its pairing code expired and the teammate has not picked up its pairing notice"
			d.Remediation = "it gets a fresh code the next time it checks Tincan; if it never does, check that the agent is running and wakes on Tincan notices"
		case !r.CodeExpiresAt.IsZero() && now.Before(r.CodeExpiresAt):
			d.Detail += ", code valid until " + r.CodeExpiresAt.Local().Format(time.Kitchen)
		}
		if !r.LastPairAttemptAt.IsZero() {
			d.Detail += ", last /pair attempt " + humanAgo(now.Sub(r.LastPairAttemptAt)) + " ago"
		}
	case r.State == state.PhasePaired:
		last := r.LastPulledAt
		if last.IsZero() {
			last = r.PairedAt
		}
		if !last.IsZero() && now.Sub(last) > teammateStaleAfter {
			d.Severity = SeverityWarn
			d.Detail += "; no pull for over 6h"
			d.Remediation = fmt.Sprintf("check that %s runs `agentcookie sink --pull-once` at the start of each turn (its standing line) and can reach this laptop on port 9998", r.Name)
		} else {
			d.Severity = SeverityOK
		}
	}
	return d
}

// aclSource is the ACL source naming a teammate's machine: its first
// Tailscale tag when the node has one, else its node name.
func aclSource(r TeammateStatus, tags func(string) ([]string, error)) string {
	if tags != nil && r.NodeID != "" {
		if t, err := tags(r.NodeID); err == nil && len(t) > 0 {
			return t[0]
		}
	}
	if n := strings.TrimSuffix(r.NodeName, "."); n != "" {
		return n
	}
	return r.Name
}
