package egress

import (
	"errors"
	"regexp"
	"slices"
	"time"

	"ferry/internal/store"
	"ferry/internal/vpngate"
)

var (
	ErrInvalid     = errors.New("invalid request")
	ErrMissing     = errors.New("not found")
	ErrConflict    = errors.New("already exists or state has changed")
	ErrUnavailable = vpngate.ErrUnavailable
	hostPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)
	countryPattern = regexp.MustCompile("^[A-Z]{2}$")
)

func Invalid(message string) error { return errors.Join(ErrInvalid, errors.New(message)) }

type Queued struct{ ID string }
type Change struct {
	ID, Region, Name, Mode, Target, Account string
	Regions                                 []string
	Enabled                                 bool
	// ClearExpiry makes an existing account permanent. Days > 0 sets a new
	// expiry counted from now; otherwise an existing expiry is kept.
	ClearExpiry          bool
	Limit, Days, Minutes int
	Config               store.Config
}

func (a *Pool) Change(path string, q Change) (any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch path {
	case "regions/save":
		if !countryPattern.MatchString(q.Region) {
			return nil, Invalid("国家代码应为两个大写字母")
		}
		err := a.s.Update(func(d *store.State) error {
			if _, ok := d.Regions[q.Region]; !ok && len(d.Regions) >= 24 {
				return ErrConflict
			}
			d.Regions[q.Region] = store.Region{Code: q.Region, Enabled: q.Enabled}
			d.AddEvent("audit", "", "地区配置 "+q.Region)
			return nil
		})
		if err == nil && !q.Enabled {
			for _, x := range a.exits {
				if x.Region == q.Region && x.DrainUntil.IsZero() {
					a.drainLocked(x)
				}
			}
		}
		return "ok", err
	case "nodes/refresh":
		if !a.tunnels {
			return nil, Invalid("当前未开启隧道")
		}
		if a.catalogBusy {
			return nil, ErrConflict
		}
		a.catalogDue = time.Time{}
		return "ok", nil
	case "nodes/connect":
		id, err := a.launchLocked(q.Region, "", q.ID)
		if err != nil {
			return nil, Invalid(err.Error())
		}
		return Queued{id}, nil
	case "exits/probe", "exits/promote", "exits/drain", "exits/replace", "exits/close":
		return a.exitActionLocked(path, q.ID)
	case "accounts/save", "accounts/delete", "accounts/rotate":
		return a.accountActionLocked(path, q)
	case "sessions", "sessions/delete", "feedback", "cooldowns/delete", "connections/close":
		return a.connectionActionLocked(path, q)
	case "config":
		c := q.Config
		if c.MaxTunnels < 3 || c.MaxTunnels > slotsMax || c.ProbeSeconds < 10 || c.ProbeSeconds > 600 || c.DrainSeconds < 0 || c.DrainSeconds > 600 || c.RetentionDays < 1 || c.RetentionDays > 90 {
			return nil, ErrInvalid
		}
		if c.MaxTunnels < len(a.occupied) {
			return nil, Invalid("上限低于当前已使用的隧道数，请先排空")
		}
		err := a.s.Update(func(d *store.State) error { d.Config = c; d.AddEvent("audit", "", "修改系统设置"); return nil })
		if err == nil && !c.LogTargets {
			for id, f := range a.flows {
				f.Target = ""
				a.flows[id] = f
			}
		}
		return "ok", err
	}
	return nil, ErrMissing
}
func (a *Pool) exitActionLocked(path, id string) (any, error) {
	x := a.exits[id]
	if x == nil {
		return nil, ErrMissing
	}
	switch path {
	case "exits/probe":
		if x.probing || !x.DrainUntil.IsZero() {
			return nil, ErrConflict
		}
		id := a.taskLocked("出口探测", x.Region)
		a.probeLocked(x, id)
		return Queued{id}, nil
	case "exits/replace":
		if !x.DrainUntil.IsZero() {
			return nil, ErrConflict
		}
		id, err := a.launchLocked(x.Region, x.ID, "")
		if err != nil {
			return nil, Invalid(err.Error())
		}
		return Queued{id}, nil
	case "exits/promote":
		if !x.ready(time.Now(), a.s.View().Config.ProbeSeconds) {
			return nil, ErrConflict
		}
		for _, y := range a.exits {
			if y.Region == x.Region && y.Role == "主用" {
				y.Role = ""
			}
		}
		x.Role = "主用"
		a.assignRolesLocked(x.Region, time.Now())
	case "exits/drain":
		a.drainLocked(x)
	case "exits/close":
		a.removeLocked(x)
	}
	a.recordLocked("audit", x.Region, path+" "+x.IP)
	return "ok", nil
}
func (a *Pool) accountActionLocked(path string, q Change) (any, error) {
	if !store.ValidName(q.Name) {
		return nil, Invalid("账号限 2–40 位字母、数字、横线或下划线")
	}
	next, exists := a.s.View().Accounts[q.Name]
	if path != "accounts/save" && !exists {
		return nil, ErrMissing
	}
	secret := ""
	switch path {
	case "accounts/rotate":
		secret = store.NewToken()
		next.Hash = store.Digest(secret)
	case "accounts/save":
		if q.Limit < 1 || q.Limit > 512 || q.Days < 0 || q.Days > 365 || q.ClearExpiry && q.Days > 0 || !slices.Contains([]string{"rotate", "region", "sticky"}, q.Mode) ||
			len(q.Regions) == 0 || q.Mode == "region" && len(q.Regions) != 1 {
			return nil, Invalid("请检查地区、模式、连接数和有效期")
		}
		for _, r := range q.Regions {
			if _, ok := a.s.View().Regions[r]; !ok {
				return nil, Invalid("所选地区尚未配置")
			}
		}
		if !exists && len(a.s.View().Accounts) >= 100 {
			return nil, ErrConflict
		}
		if exists && q.ID != q.Name {
			return nil, ErrConflict
		}
		if !exists {
			secret = store.NewToken()
			next.Hash = store.Digest(secret)
		}
		expiry := next.Expires
		if !exists || q.ClearExpiry {
			expiry = time.Time{}
		}
		if q.Days > 0 {
			expiry = time.Now().AddDate(0, 0, q.Days)
		}
		next.Account = store.Account{Name: q.Name, Mode: q.Mode, Regions: q.Regions, Limit: q.Limit, Enabled: q.Enabled, Expires: expiry}
	}
	err := a.s.Update(func(d *store.State) error {
		if path == "accounts/delete" {
			delete(d.Accounts, q.Name)
		} else {
			d.Accounts[q.Name] = next
		}
		d.AddEvent("audit", "", path+" "+q.Name)
		return nil
	})
	if err != nil {
		return nil, err
	}
	gone := path == "accounts/delete"
	revoked := gone || !next.Enabled || path == "accounts/rotate"
	for _, f := range a.flows {
		// Removing a region from an account also ends connections that use it.
		if f.Account == q.Name && (revoked || !slices.Contains(next.Regions, f.Region)) {
			f.cancel()
		}
	}
	if gone {
		delete(a.lastExit, q.Name)
	}
	for k, b := range a.bindings {
		if b.Account == q.Name && (gone || !slices.Contains(next.Regions, b.Region)) {
			delete(a.bindings, k)
		}
	}
	if secret != "" {
		return map[string]string{"Secret": secret}, nil
	}
	return "ok", nil
}
func (a *Pool) connectionActionLocked(path string, q Change) (any, error) {
	switch path {
	case "connections/close":
		f, ok := a.flows[q.ID]
		if !ok {
			return nil, ErrMissing
		}
		f.cancel()
		a.recordLocked("audit", f.Region, "中断连接 "+f.ID)
	case "sessions":
		account, ok := a.s.View().Accounts[q.Account]
		if !ok || !account.Enabled || q.Minutes < 1 || q.Minutes > 1440 || len(a.bindings) >= 1024 {
			return nil, ErrInvalid
		}
		if q.Region == "" && account.Mode == "region" {
			q.Region = account.Regions[0]
		}
		var selected *liveExit
		for _, x := range a.exits {
			if !a.s.View().Regions[x.Region].Enabled || !slices.Contains(account.Regions, x.Region) || q.Region != "" && x.Region != q.Region || !x.ready(time.Now(), a.s.View().Config.ProbeSeconds) {
				continue
			}
			if selected == nil || x.Role == "主用" && selected.Role != "主用" {
				selected = x
			}
		}
		if selected == nil {
			return nil, ErrUnavailable
		}
		id := store.Digest(store.NewToken())[:16]
		b := binding{id, q.Account, selected.Region, selected.ID, time.Now().Add(time.Duration(q.Minutes) * time.Minute)}
		a.bindings[id] = b
		return b, nil
	case "sessions/delete":
		if _, ok := a.bindings[q.ID]; !ok {
			return nil, ErrMissing
		}
		delete(a.bindings, q.ID)
	case "feedback":
		b, ok := a.bindings[q.ID]
		if !ok || time.Now().After(b.Expires) || a.exits[b.Exit] == nil {
			return nil, ErrMissing
		}
		host := targetHost(q.Target)
		if !hostPattern.MatchString(host) || q.Minutes < 1 || q.Minutes > 60 || len(a.cooldowns) >= 2048 {
			return nil, ErrInvalid
		}
		a.cooldowns[b.Exit+"|"+host] = targetCooldown{b.Exit, host, time.Now().Add(time.Duration(q.Minutes) * time.Minute)}
		a.recordLocked("cooldown", b.Region, "客户端报告目标限流，已记录冷却")
	case "cooldowns/delete":
		delete(a.cooldowns, q.ID+"|"+targetHost(q.Target))
	}
	return "ok", nil
}
