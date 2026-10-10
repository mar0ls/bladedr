package scan

import (
	"context"
	"slices"
	"sort"
	"strings"

	"bladedr/internal/probe"
	"bladedr/internal/store"
)

// fleetOnlyCategory are digest categories that exist to be compared across hosts. They are
// kept out of the frozen baseline and the drift engine: a rotated password or a new key file
// is not drift worth an alert by itself, and the baseline would freeze them at the first
// scan, hiding every later change from the comparison they are collected for.
var fleetOnlyCategory = map[string]bool{
	probe.DigestPasswordHashes: true,
	probe.DigestPrivateKeys:    true,
}

// takeInventory removes the fleet-only categories from digest and returns the host's current
// credential inventory: those categories plus its authorized keys, which stay in the digest
// for drift as well.
func takeInventory(digest map[string][]string) map[string][]string {
	inv := map[string][]string{}
	if keys := digest[probe.DigestAuthorizedKeys]; len(keys) > 0 {
		inv[probe.DigestAuthorizedKeys] = append([]string(nil), keys...)
	}
	for cat := range fleetOnlyCategory {
		if items, ok := digest[cat]; ok {
			inv[cat] = items
			delete(digest, cat)
		}
	}
	return inv
}

// maxAlsoOn bounds the host names listed in evidence.
const maxAlsoOn = 8

// holder is who has an identifier on one host: the accounts that carry it.
type holder struct {
	host     string // host id
	accounts []string
	state    string // private keys: "plain" or "locked"
}

// index maps identifier -> hosts holding it, from items of the form "account:id[:state]".
func index(invs []*store.Inventory, category string) map[string][]holder {
	out := map[string][]holder{}
	for _, inv := range invs {
		byID := map[string]*holder{}
		for _, it := range inv.Items[category] {
			parts := strings.Split(it, ":")
			if len(parts) < 2 {
				continue
			}
			id, state := parts[1], ""
			if len(parts) > 2 {
				state = parts[2]
			}
			h := byID[id]
			if h == nil {
				h = &holder{host: inv.HostID, state: state}
				byID[id] = h
			}
			h.accounts = append(h.accounts, parts[0])
		}
		for id, h := range byID {
			out[id] = append(out[id], *h)
		}
	}
	return out
}

// others returns the hosts other than self that hold an identifier, as sorted names.
func others(holders []holder, self string, names map[string]string) []string {
	var out []string
	for _, h := range holders {
		if h.host != self {
			n := names[h.host]
			if n == "" {
				n = h.host
			}
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func clip(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	return in
}

// applyCredentialReuse records this host's current credential inventory and raises the
// findings that only exist across hosts. It reads authorized keys, password-hash
// fingerprints and private keys of every host as of their last scan, never the secrets.
//
// An SSH key is a path between machines. One authorized on many hosts is the single
// credential that opens all of them; a private key stored on a host whose public half is
// authorized elsewhere is the step that makes the path usable, because compromising this
// host now yields access to those. The same password hash on two hosts means one password
// protects both, so cracking either opens the other.
func (r *Runner) applyCredentialReuse(ctx context.Context, host *store.Host, sc *store.Scan, inv map[string][]string) int {
	// Saved even when empty: a host that has removed its last key must stop counting as one
	// that has it, or every other host keeps being told the key is shared.
	if err := r.Store.SaveInventory(ctx, &store.Inventory{HostID: host.ID, Items: inv}); err != nil {
		return 0
	}
	invs, err := r.Store.ListInventories(ctx)
	if err != nil {
		return 0
	}
	hosts, err := r.Store.ListHosts(ctx)
	if err != nil {
		return 0
	}
	names := map[string]string{}
	for _, h := range hosts {
		n := h.Hostname
		if n == "" {
			n = h.PrimaryIP
		}
		names[h.ID] = n
	}

	keys := index(invs, probe.DigestAuthorizedKeys)
	hashes := index(invs, probe.DigestPasswordHashes)
	priv := index(invs, probe.DigestPrivateKeys)

	score := 0
	emit := func(rule, title, severity string, pts int, mitre []string, dedup string, ev map[string]any) {
		obs := &store.Observation{
			HostID: host.ID, ScanID: sc.ID, Source: store.SourceFleet, RuleID: rule, Category: "credential",
			Mitre: mitre, Title: title, Severity: severity, Score: pts, Evidence: ev,
			DedupKey: "reuse|" + dedup, Status: store.ObsOpen,
		}
		if _, err := r.Store.UpsertObservation(ctx, obs); err == nil {
			score += pts / 5
		}
	}
	mine := func(category string) map[string]holder {
		out := map[string]holder{}
		for id, hs := range index([]*store.Inventory{{HostID: host.ID, Items: inv}}, category) {
			out[id] = hs[0]
		}
		return out
	}
	short := func(id string) string {
		if len(id) > 12 {
			return id[:12]
		}
		return id
	}

	for id, h := range mine(probe.DigestAuthorizedKeys) {
		also := others(keys[id], host.ID, names)
		if len(also) == 0 {
			continue
		}
		emit("fleet-shared-ssh-key", "SSH key "+short(id)+" is authorized on "+itoa(len(also)+1)+" hosts", "low", 20,
			[]string{"T1098.004", "T1021.004"}, "ssh-key|"+id,
			map[string]any{
				"key": short(id), "hosts_with": len(also) + 1, "accounts": h.accounts, "also_on": clip(also, maxAlsoOn),
				"root": slices.Contains(h.accounts, "root"),
			})
	}

	for id, h := range mine(probe.DigestPasswordHashes) {
		also := others(hashes[id], host.ID, names)
		if len(also) == 0 && len(h.accounts) < 2 {
			continue
		}
		emit("fleet-shared-password-hash", "Password hash "+short(id)+" is shared across "+itoa(len(also)+1)+" host(s) / "+itoa(len(h.accounts))+" account(s) here",
			"medium", 45, []string{"T1078", "T1110.002"}, "pwhash|"+id,
			map[string]any{
				"fingerprint": short(id), "hosts_with": len(also) + 1, "accounts": h.accounts, "also_on": clip(also, maxAlsoOn),
				"root": slices.Contains(h.accounts, "root"),
			})
	}

	for id, h := range mine(probe.DigestPrivateKeys) {
		authorizedOn := others(keys[id], host.ID, names)
		if len(authorizedOn) > 0 {
			sev, pts := "medium", 55
			if h.state == "locked" {
				sev, pts = "low", 25 // passphrase-protected: still a path, but not a free one
			}
			emit("ssh-private-key-grants-access", "Private key "+short(id)+" stored here is authorized on "+itoa(len(authorizedOn))+" other host(s)",
				sev, pts, []string{"T1552.004", "T1021.004"}, "privkey-access|"+id,
				map[string]any{"key": short(id), "owner": h.accounts, "protection": h.state, "authorized_on": clip(authorizedOn, maxAlsoOn), "hosts_with": len(authorizedOn)})
		}
		if copies := others(priv[id], host.ID, names); len(copies) > 0 {
			emit("fleet-private-key-copied", "Private key "+short(id)+" is stored on "+itoa(len(copies)+1)+" hosts", "medium", 45,
				[]string{"T1552.004"}, "privkey-copy|"+id,
				map[string]any{"key": short(id), "owner": h.accounts, "protection": h.state, "also_on": clip(copies, maxAlsoOn), "hosts_with": len(copies) + 1})
		}
	}
	if score > 40 {
		score = 40
	}
	return score
}
