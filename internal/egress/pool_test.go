package egress

import (
	"context"
	"testing"
	"time"

	"ferry/internal/store"
)

type healthyTunnel struct{ tunnel }

func (healthyTunnel) Alive() bool { return true }

func TestStrictRegionRotationAndSticky(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(d *store.State) error {
		d.Regions["KR"] = store.Region{Code: "KR", Enabled: true}
		d.Accounts["client"] = store.SavedAccount{
			Account: store.Account{Name: "client", Enabled: true, Regions: []string{"JP", "KR"}, Mode: "rotate", Limit: 2},
			Hash:    store.Digest("test"),
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a := New(context.Background(), s, false)
	now := time.Now()
	for _, x := range []*liveExit{
		{ID: "jp-1", Region: "JP", Role: "主用", LastOK: now, t: healthyTunnel{}},
		{ID: "jp-2", Region: "JP", Role: "候选", LastOK: now, t: healthyTunnel{}},
		{ID: "kr-1", Region: "KR", Role: "主用", LastOK: now, t: healthyTunnel{}},
	} {
		a.exits[x.ID] = x
	}
	who, ok := a.Authenticate("client", "test")
	if !ok {
		t.Fatal("valid proxy account rejected")
	}
	first, err := a.chooseLocked(who, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.chooseLocked(who, "example.com:443")
	if err != nil || first.ID == second.ID {
		t.Fatal("auto mode repeated available exit")
	}
	if _, ok := a.Authenticate("client.US", "test"); ok {
		t.Fatal("accepted unauthorized region")
	}
	who, ok = a.Authenticate("client.JP", "test")
	if !ok {
		t.Fatal("allowed selector rejected")
	}
	x, err := a.chooseLocked(who, "example.com:443")
	if err != nil || x.ID != "jp-1" {
		t.Fatal("explicit region must use its primary")
	}
	a.cooldowns["jp-1|example.com"] = targetCooldown{"jp-1", "example.com", now.Add(time.Minute)}
	x, err = a.chooseLocked(who, "example.com:443")
	if err != nil || x.ID != "jp-2" {
		t.Fatal("target cooldown must stay within the region")
	}
	x, err = a.chooseLocked(who, "different.example:443")
	if err != nil || x.ID != "jp-1" {
		t.Fatal("target cooldown affected another domain")
	}
	a.bindings["sticky"] = binding{"sticky", "client", "JP", "jp-2", now.Add(time.Minute)}
	who, ok = a.Authenticate("client.JP.sticky", "test")
	if !ok {
		t.Fatal("valid binding selector rejected")
	}
	x, err = a.chooseLocked(who, "example.com:443")
	if err != nil || x.ID != "jp-2" {
		t.Fatal("existing binding lost its assigned exit")
	}
	delete(a.exits, "jp-2")
	if _, err := a.chooseLocked(who, "example.com:443"); err == nil {
		t.Fatal("dead binding fell back")
	}
	delete(a.exits, "jp-1")
	who.Binding = ""
	if _, err := a.chooseLocked(who, "example.com:443"); err == nil {
		t.Fatal("empty region fell back to Korea")
	}
}
