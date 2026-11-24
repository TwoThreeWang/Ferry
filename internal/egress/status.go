package egress

import (
	"slices"
	"sort"
	"time"

	"ferry/internal/store"
)

type RegionView struct {
	Code       string
	Enabled    bool
	Target     int
	Healthy    int
	Nodes      int
	Primary    string
	Connecting bool
}
type ExitView struct {
	DialStats                         DialSummary
	ID, Region, Role, IP, Node, State string
	Accept                            bool
	Connections                       int
	LatencyMS                         int64
	Since, LastOK, DrainUntil         time.Time
}
type NodeView struct {
	ID, Region, Protocol string
	Cooldown             time.Time
	Connected            bool
}

// BindingView reports whether a fixed session's exit can still take
// connections: "ok", "unavailable" (failing probes, may recover) or "lost"
// (closed, replaced or draining; the session fails until it expires).
type BindingView struct {
	binding
	ExitState string
}

type Snapshot struct {
	DialStats                DialSummary
	Started, Time, CatalogAt time.Time
	Tunnels                  bool
	CatalogError             string
	Config                   store.Config
	Regions                  []RegionView
	Exits                    []ExitView
	Nodes                    []NodeView
	Accounts                 []store.Account
	Flows                    []flow
	Bindings                 []BindingView
	Cooldowns                []targetCooldown
	Operations               []operation
	Events                   []store.Event
}

func (a *Pool) Snapshot() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := a.s.View()
	now := time.Now()
	result := Snapshot{Started: a.started, Time: now, CatalogAt: a.catalogAt, Tunnels: a.tunnels, CatalogError: a.catalogError,
		DialStats: summarizeDials(a.dials, "", now.Add(-5*time.Minute)), Config: state.Config}
	for code, r := range state.Regions {
		view := RegionView{Code: code, Enabled: r.Enabled, Target: 3, Connecting: a.busy[code] > 0}
		for _, n := range a.nodes {
			if n.Country() == code {
				view.Nodes++
			}
		}
		for _, x := range a.exits {
			if x.Region != code {
				continue
			}
			ready := r.Enabled && x.ready(now, state.Config.ProbeSeconds)
			label := "健康"
			switch {
			case !x.DrainUntil.IsZero():
				label = "排空中"
			case !x.t.Alive():
				label = "已断开"
			case x.Failures > 0 || !x.ready(now, state.Config.ProbeSeconds):
				label = "探测异常"
			}
			if ready {
				view.Healthy++
				if x.Role == "主用" {
					view.Primary = x.IP
				}
			}
			result.Exits = append(result.Exits, ExitView{summarizeDials(a.dials, x.ID, now.Add(-5*time.Minute)), x.ID, x.Region, x.Role, x.IP, x.Node, label, ready, a.exitLoadLocked(x.ID), x.LatencyMS, x.Since, x.LastOK, x.DrainUntil})
		}
		result.Regions = append(result.Regions, view)
	}
	for _, n := range a.nodes {
		key := n.ID()
		connected := false
		for _, x := range a.exits {
			if x.Node == key {
				connected = true
				break
			}
		}
		result.Nodes = append(result.Nodes, NodeView{key, n.Country(), n.Protocol(), a.cooling[key], connected})
	}
	for _, s := range state.Accounts {
		result.Accounts = append(result.Accounts, s.Account)
	}
	for _, f := range a.flows {
		result.Flows = append(result.Flows, f)
	}
	for _, b := range a.bindings {
		exitState := "ok"
		switch x := a.exits[b.Exit]; {
		case x == nil || !x.DrainUntil.IsZero():
			exitState = "lost"
		case !state.Regions[x.Region].Enabled || !x.ready(now, state.Config.ProbeSeconds):
			exitState = "unavailable"
		}
		result.Bindings = append(result.Bindings, BindingView{b, exitState})
	}
	for _, c := range a.cooldowns {
		result.Cooldowns = append(result.Cooldowns, c)
	}
	result.Operations = slices.Clone(a.operations)
	result.Events = slices.Clone(state.Events)
	slices.Reverse(result.Operations)
	slices.Reverse(result.Events)
	sort.Slice(result.Regions, func(i, j int) bool { return result.Regions[i].Code < result.Regions[j].Code })
	sort.Slice(result.Accounts, func(i, j int) bool { return result.Accounts[i].Name < result.Accounts[j].Name })
	sort.Slice(result.Flows, func(i, j int) bool { return result.Flows[i].Since.After(result.Flows[j].Since) })
	return result
}
func (a *Pool) ReadyCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := a.s.View()
	now := time.Now()
	count := 0
	for _, x := range a.exits {
		if state.Regions[x.Region].Enabled && x.ready(now, state.Config.ProbeSeconds) {
			count++
		}
	}
	return count
}
