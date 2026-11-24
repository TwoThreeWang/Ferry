package egress

import (
	"context"
	"testing"
	"time"

	"ferry/internal/store"
)

func testPool(t *testing.T) *Pool {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(d *store.State) error {
		d.Regions["KR"] = store.Region{Code: "KR", Enabled: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return New(context.Background(), s, false)
}

func saveAccount(t *testing.T, a *Pool, q Change) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	q.Mode, q.Limit, q.Enabled = "rotate", 5, true
	if q.ID == "" {
		if _, ok := a.s.View().Accounts[q.Name]; ok {
			q.ID = q.Name
		}
	}
	if _, err := a.accountActionLocked("accounts/save", q); err != nil {
		t.Fatal(err)
	}
}

func TestAccountExpiryCanBeChangedAndCleared(t *testing.T) {
	a := testPool(t)
	saveAccount(t, a, Change{Name: "client", Regions: []string{"JP"}, Days: 10})
	first := a.s.View().Accounts["client"].Expires
	if first.IsZero() {
		t.Fatal("new account ignored Days")
	}
	saveAccount(t, a, Change{Name: "client", Regions: []string{"JP"}})
	if got := a.s.View().Accounts["client"].Expires; !got.Equal(first) {
		t.Fatalf("edit without Days changed expiry to %v", got)
	}
	saveAccount(t, a, Change{Name: "client", Regions: []string{"JP"}, Days: 30})
	if got := a.s.View().Accounts["client"].Expires; !got.After(first) {
		t.Fatal("Days did not extend an existing account")
	}
	saveAccount(t, a, Change{Name: "client", Regions: []string{"JP"}, ClearExpiry: true})
	if got := a.s.View().Accounts["client"].Expires; !got.IsZero() {
		t.Fatalf("ClearExpiry kept %v", got)
	}
	a.mu.Lock()
	_, err := a.accountActionLocked("accounts/save", Change{Name: "client", ID: "client", Mode: "rotate", Limit: 5, Regions: []string{"JP"}, Days: 3, ClearExpiry: true})
	a.mu.Unlock()
	if err == nil {
		t.Fatal("accepted ClearExpiry together with Days")
	}
}

func TestRemovingRegionEndsItsConnectionsAndSessions(t *testing.T) {
	a := testPool(t)
	saveAccount(t, a, Change{Name: "client", Regions: []string{"JP", "KR"}})
	cancelled := map[string]bool{}
	a.mu.Lock()
	for _, f := range []flow{{ID: "jp", Account: "client", Region: "JP"}, {ID: "kr", Account: "client", Region: "KR"}, {ID: "other", Account: "other", Region: "KR"}} {
		id := f.ID
		f.cancel = func() { cancelled[id] = true }
		a.flows[id] = f
	}
	a.bindings["s-jp"] = binding{ID: "s-jp", Account: "client", Region: "JP", Expires: time.Now().Add(time.Hour)}
	a.bindings["s-kr"] = binding{ID: "s-kr", Account: "client", Region: "KR", Expires: time.Now().Add(time.Hour)}
	a.mu.Unlock()

	saveAccount(t, a, Change{Name: "client", Regions: []string{"JP"}})
	if !cancelled["kr"] || cancelled["jp"] || cancelled["other"] {
		t.Fatalf("cancelled %v, want only kr", cancelled)
	}
	if _, ok := a.bindings["s-kr"]; ok {
		t.Fatal("session in removed region kept")
	}
	if _, ok := a.bindings["s-jp"]; !ok {
		t.Fatal("session in allowed region removed")
	}
}

func TestBindingReportsLostExit(t *testing.T) {
	a := testPool(t)
	now := time.Now()
	a.exits["live"] = &liveExit{ID: "live", Region: "JP", LastOK: now, t: healthyTunnel{}}
	a.exits["drain"] = &liveExit{ID: "drain", Region: "JP", LastOK: now, DrainUntil: now.Add(time.Minute), t: healthyTunnel{}}
	a.exits["stale"] = &liveExit{ID: "stale", Region: "JP", LastOK: now.Add(-time.Hour), t: healthyTunnel{}}
	for id, exit := range map[string]string{"a": "live", "b": "drain", "c": "stale", "d": "gone"} {
		a.bindings[id] = binding{ID: id, Account: "client", Region: "JP", Exit: exit, Expires: now.Add(time.Hour)}
	}
	got := map[string]string{}
	for _, b := range a.Snapshot().Bindings {
		got[b.ID] = b.ExitState
	}
	want := map[string]string{"a": "ok", "b": "lost", "c": "unavailable", "d": "lost"}
	for id, state := range want {
		if got[id] != state {
			t.Errorf("binding %s: %q, want %q", id, got[id], state)
		}
	}
}

func TestEventsArePersistedOutsideThePoolLock(t *testing.T) {
	a := testPool(t)
	a.mu.Lock()
	a.recordLocked("exit", "JP", "first")
	a.recordLocked("exit", "JP", "second")
	if n := len(a.s.View().Events); n != 0 {
		a.mu.Unlock()
		t.Fatalf("event written while holding the pool lock (%d events)", n)
	}
	a.mu.Unlock()
	a.FlushEvents()
	events := a.s.View().Events
	if len(events) != 2 || events[0].Message != "first" || events[1].Message != "second" {
		t.Fatalf("persisted events %+v", events)
	}
	a.FlushEvents()
	if len(a.s.View().Events) != 2 {
		t.Fatal("flush repeated events")
	}
}
