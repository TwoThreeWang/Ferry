package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"ferry/internal/store"
	"ferry/internal/vpngate"
)

const slotsMax = 24

type tunnel interface {
	Alive() bool
	Cancel()
	Check(context.Context) netip.Addr
	Close()
	CloseIdleConnections()
	Context() context.Context
	Dial(context.Context, string, string) (net.Conn, error)
	NodeIP() netip.Addr
	RoundTrip(*http.Request) (*http.Response, error)
}

type Identity struct {
	Account string
	Region  string
	Binding string
	hash    string
}

type liveExit struct {
	ID         string
	Region     string
	Role       string
	IP         string
	Node       string
	Since      time.Time
	LastOK     time.Time
	LatencyMS  int64
	Failures   int
	DrainUntil time.Time
	t          tunnel
	index      int
	probing    bool
}

type operation struct {
	ID     string
	Kind   string
	Region string
	State  string
	Detail string
	Time   time.Time
}

type flow struct {
	ID      string
	Account string
	Region  string
	Exit    string
	IP      string
	Target  string
	Since   time.Time
	cancel  context.CancelFunc
}

type binding struct {
	ID      string
	Account string
	Region  string
	Exit    string
	Expires time.Time
}

type targetCooldown struct {
	Exit    string
	Target  string
	Expires time.Time
}

type dialSample struct {
	Time         time.Time
	Exit         string
	Milliseconds int64
	OK           bool
}
type DialSummary struct {
	Total      int
	Successful int
	P50, P95   int64
}

func summarizeDials(samples []dialSample, exit string, cutoff time.Time) DialSummary {
	var summary DialSummary
	var duration []int64
	for _, sample := range samples {
		if sample.Time.Before(cutoff) || exit != "" && sample.Exit != exit {
			continue
		}
		summary.Total++
		if sample.OK {
			summary.Successful++
			duration = append(duration, sample.Milliseconds)
		}
	}
	if n := len(duration); n > 0 {
		slices.Sort(duration)
		summary.P50 = duration[(50*n+99)/100-1]
		summary.P95 = duration[(95*n+99)/100-1]
	}
	return summary
}

type Pool struct {
	dials        []dialSample
	mu           sync.Mutex
	s            *store.Store
	ctx          context.Context
	started      time.Time
	tunnels      bool
	exits        map[string]*liveExit
	occupied     map[int]bool
	busy         map[string]int // tunnel attempts in flight per region
	fillAfter    map[string]time.Time
	nodes        []vpngate.Node
	catalogDue   time.Time
	catalogAt    time.Time
	catalogBusy  bool
	catalogError string
	cooling      map[string]time.Time
	geoCache     map[netip.Addr]geoRecord
	operations   []operation
	flows        map[string]flow
	bindings     map[string]binding
	cooldowns    map[string]targetCooldown
	lastExit     map[string]string
	connecting   map[netip.Addr]bool
	// Events wait here until persistEvents writes them outside a.mu.
	pendingEvents []store.Event
	eventsDue     chan struct{}
	flushMu       sync.Mutex
}

// maxConnectsPerRegion bounds parallel tunnel attempts while a region fills up.
const maxConnectsPerRegion = 2

func New(ctx context.Context, s *store.Store, tunnels bool) *Pool {
	return &Pool{ctx: ctx, s: s, tunnels: tunnels, started: time.Now(), exits: map[string]*liveExit{}, occupied: map[int]bool{}, busy: map[string]int{}, fillAfter: map[string]time.Time{}, cooling: map[string]time.Time{}, geoCache: map[netip.Addr]geoRecord{}, flows: map[string]flow{}, bindings: map[string]binding{}, cooldowns: map[string]targetCooldown{}, lastExit: map[string]string{}, connecting: map[netip.Addr]bool{}, eventsDue: make(chan struct{}, 1)}
}

// recordLocked queues an event. Writing state.json syncs to disk, so it happens
// in persistEvents instead of while proxy connections wait for a.mu.
func (a *Pool) recordLocked(kind, region, message string) {
	if len(a.pendingEvents) >= 1000 {
		a.pendingEvents = a.pendingEvents[1:]
	}
	a.pendingEvents = append(a.pendingEvents, store.Event{Time: time.Now(), Region: region, Kind: kind, Message: message})
	select {
	case a.eventsDue <- struct{}{}:
	default:
	}
}

func (a *Pool) persistEvents() {
	for {
		select {
		case <-a.ctx.Done():
			a.FlushEvents()
			return
		case <-a.eventsDue:
			a.FlushEvents()
		}
	}
}

// FlushEvents writes queued events to the store.
func (a *Pool) FlushEvents() {
	a.flushMu.Lock()
	defer a.flushMu.Unlock()
	a.mu.Lock()
	events := a.pendingEvents
	a.pendingEvents = nil
	a.mu.Unlock()
	if len(events) == 0 {
		return
	}
	if err := a.s.Update(func(d *store.State) error {
		d.AddEvents(events...)
		return nil
	}); err != nil {
		log.Printf("persist %d events: %v", len(events), err)
	}
}
func (a *Pool) taskLocked(kind, region string) string {
	id := store.Digest(store.NewToken())[:12]
	a.operations = append(a.operations, operation{id, kind, region, "running", "", time.Now()})
	if len(a.operations) > 100 {
		a.operations = a.operations[len(a.operations)-100:]
	}
	return id
}
func (a *Pool) finishLocked(id, detail string, err error) {
	for i := range a.operations {
		op := &a.operations[i]
		if op.ID != id {
			continue
		}
		op.State = "done"
		op.Detail = detail
		if err != nil {
			op.State = "failed"
			op.Detail = err.Error()
		}
		a.recordLocked("task", op.Region, op.Kind+": "+op.Detail)
		return
	}
}
func (x *liveExit) ready(now time.Time, probeSeconds int) bool {
	return x.DrainUntil.IsZero() && x.Failures < 2 && x.t.Alive() && now.Sub(x.LastOK) < time.Duration(2*probeSeconds+12)*time.Second
}

func (a *Pool) Run() {
	go a.persistEvents()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	cat := vpngate.NewCatalogue(nil)
	for {
		select {
		case <-a.ctx.Done():
			return
		case now := <-tick.C:
			a.tick(now, cat)
		}
	}
}
func (a *Pool) tick(now time.Time, cat *vpngate.Catalogue) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, t := range a.cooling {
		if !now.Before(t) {
			delete(a.cooling, k)
		}
	}
	for k, t := range a.cooldowns {
		if !now.Before(t.Expires) {
			delete(a.cooldowns, k)
		}
	}
	for k, b := range a.bindings {
		if !now.Before(b.Expires) {
			delete(a.bindings, k)
		}
	}
	if !a.tunnels {
		return
	}
	state := a.s.View()
	if !a.catalogBusy && !now.Before(a.catalogDue) {
		a.catalogBusy = true
		id := a.taskLocked("刷新节点", "")
		go a.fetchCatalog(cat, id)
	}
	for id, x := range a.exits {
		if !x.t.Alive() || (!x.DrainUntil.IsZero() && (!now.Before(x.DrainUntil) || a.exitLoadLocked(id) == 0)) {
			a.removeLocked(x)
			continue
		}
		if x.DrainUntil.IsZero() && !x.probing && now.Sub(x.LastOK) >= time.Duration(state.Config.ProbeSeconds)*time.Second {
			a.probeLocked(x, "")
		}
	}
	regions := make([]string, 0, len(state.Regions))
	for code, r := range state.Regions {
		if r.Enabled {
			regions = append(regions, code)
		}
	}
	sort.Slice(regions, func(i, j int) bool {
		x, y := a.regionLoadLocked(regions[i]), a.regionLoadLocked(regions[j])
		if x != y {
			return x < y
		}
		return regions[i] < regions[j]
	})
	for _, code := range regions {
		a.assignRolesLocked(code, now)
		if a.regionLoadLocked(code)+a.busy[code] < 3 && a.busy[code] < maxConnectsPerRegion && !now.Before(a.fillAfter[code]) {
			if _, err := a.launchLocked(code, "", ""); err != nil {
				a.fillAfter[code] = now.Add(8 * time.Second)
			}
		}
	}
}
func (a *Pool) fetchCatalog(cat *vpngate.Catalogue, id string) {
	nodes, err := cat.Refresh(a.ctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.catalogBusy = false
	a.catalogDue = time.Now().Add(5 * time.Minute)
	if err != nil {
		a.catalogError = err.Error()
		a.catalogDue = time.Now().Add(time.Minute)
	} else {
		a.nodes = nodes
		a.catalogAt = time.Now()
		a.catalogError = ""
	}
	a.finishLocked(id, fmt.Sprintf("收到 %d 条节点记录", len(nodes)), err)
}
func (a *Pool) exitLoadLocked(id string) int {
	n := 0
	for _, f := range a.flows {
		if f.Exit == id {
			n++
		}
	}
	return n
}
func (a *Pool) regionLoadLocked(code string) int {
	n := 0
	for _, x := range a.exits {
		if x.Region == code && x.DrainUntil.IsZero() {
			n++
		}
	}
	return n
}
func (a *Pool) removeLocked(x *liveExit) {
	delete(a.exits, x.ID)
	x.t.Cancel()
	a.cooling[x.Node] = time.Now().Add(3 * time.Minute)
	go func() {
		x.t.Close()
		a.mu.Lock()
		delete(a.occupied, x.index)
		a.mu.Unlock()
	}()
}
func (a *Pool) assignRolesLocked(region string, now time.Time) {
	var active []*liveExit
	for _, x := range a.exits {
		if x.Region != region || !x.DrainUntil.IsZero() {
			continue
		}
		if !x.ready(now, a.s.View().Config.ProbeSeconds) {
			x.Role = ""
			continue
		}
		active = append(active, x)
	}
	slices.SortFunc(active, func(x, y *liveExit) int {
		if x.Role == "主用" {
			if y.Role != "主用" {
				return -1
			}
		}
		if y.Role == "主用" {
			return 1
		}
		if x.LatencyMS < y.LatencyMS {
			return -1
		}
		if x.LatencyMS > y.LatencyMS {
			return 1
		}
		return strings.Compare(x.ID, y.ID)
	})
	for i, x := range active {
		if i < 3 {
			x.Role = []string{"主用", "候选", "备用"}[i]
		} else {
			x.Role = ""
		}
	}
}
func (a *Pool) drainLocked(x *liveExit) {
	x.Role = ""
	x.DrainUntil = time.Now().Add(time.Duration(a.s.View().Config.DrainSeconds) * time.Second)
	x.t.CloseIdleConnections()
	a.assignRolesLocked(x.Region, time.Now())
}
func (a *Pool) launchLocked(region, replace, nodeID string) (string, error) {
	if !a.tunnels {
		return "", errors.New("隧道功能已关闭")
	}
	if !a.s.View().Regions[region].Enabled {
		return "", errors.New("地区未启用")
	}
	if a.busy[region] >= maxConnectsPerRegion {
		return "", errors.New("该地区正在建线，请稍后再试")
	}
	if len(a.occupied) >= a.s.View().Config.MaxTunnels {
		return "", errors.New("已达到隧道上限，需要一个空闲位置")
	}
	if replace == "" && a.regionLoadLocked(region)+a.busy[region] >= 3 {
		return "", errors.New("地区已达到三个出口")
	}
	var candidate *vpngate.Node
	for _, n := range a.nodes {
		if n.Country() != region || (nodeID != "" && nodeID != n.ID()) || time.Now().Before(a.cooling[n.ID()]) || a.connecting[n.IP()] {
			continue
		}
		inUse := false
		for _, x := range a.exits {
			if x.t.NodeIP() == n.IP() {
				inUse = true
				break
			}
		}
		if !inUse {
			candidate = &n
			break
		}
	}
	if candidate == nil {
		return "", errors.New("没有可用的待连接节点，或节点仍在冷却")
	}
	index := 0
	for a.occupied[index] {
		index++
	}
	a.occupied[index] = true
	a.busy[region]++
	a.connecting[candidate.IP()] = true
	id := a.taskLocked("建立出口", region)
	if replace != "" {
		for i := range a.operations {
			if a.operations[i].ID == id {
				a.operations[i].Kind = "验证并替换出口"
			}
		}
	}
	go a.connectNode(id, region, replace, index, *candidate)
	return id, nil
}

type geoRecord struct {
	country string
	expires time.Time
}

func (a *Pool) countryFor(ctx context.Context, ip netip.Addr) (string, error) {
	a.mu.Lock()
	record := a.geoCache[ip]
	a.mu.Unlock()
	if time.Now().Before(record.expires) {
		return record.country, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.country.is/"+ip.String(), nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Transport: geoTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return "", errors.New("地区核验服务不可用")
	}
	defer res.Body.Close()
	var out struct {
		IP      string
		Country string
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&out) != nil ||
		out.IP != ip.String() || !countryPattern.MatchString(out.Country) {
		return "", errors.New("无法核验公网出口地区")
	}
	a.mu.Lock()
	if len(a.geoCache) > 512 {
		clear(a.geoCache)
	}
	a.geoCache[ip] = geoRecord{out.Country, time.Now().Add(30 * time.Minute)}
	a.mu.Unlock()
	return out.Country, nil
}

var geoTransport = &http.Transport{TLSHandshakeTimeout: 4 * time.Second, IdleConnTimeout: 30 * time.Second}

func (a *Pool) connectNode(id, region, replace string, index int, n vpngate.Node) {
	started := time.Now()
	t, err := vpngate.Start(a.ctx, index, n)
	if err == nil {
		var country string
		country, err = a.countryFor(a.ctx, t.ExitIP())
		if err == nil && country != region {
			err = fmt.Errorf("出口核验地区 %s 与请求地区 %s 不同", country, region)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.busy[region]--
	delete(a.connecting, n.IP())
	if err == nil && !a.s.View().Regions[region].Enabled {
		err = errors.New("地区已停用")
	}
	if err == nil && (replace == "" || a.exits[replace] == nil || !a.exits[replace].DrainUntil.IsZero()) && a.regionLoadLocked(region) >= 3 {
		err = errors.New("地区已满")
	}
	if err == nil {
		for _, x := range a.exits {
			if x.IP == t.ExitIP().String() {
				err = errors.New("出口公网 IP 已在池内")
				break
			}
		}
	}
	if err != nil {
		a.cooling[n.ID()] = time.Now().Add(3 * time.Minute)
		a.fillAfter[region] = time.Now().Add(2 * time.Second)
		if t != nil {
			go func() { t.Close(); a.mu.Lock(); delete(a.occupied, index); a.mu.Unlock() }()
		} else {
			delete(a.occupied, index)
		}
		a.finishLocked(id, "", err)
		return
	}
	x := &liveExit{ID: id, Region: region, IP: t.ExitIP().String(), Node: n.ID(), Since: time.Now(), LastOK: time.Now(), LatencyMS: time.Since(started).Milliseconds(), t: t, index: index}
	if old := a.exits[replace]; old != nil && old.DrainUntil.IsZero() {
		x.Role = old.Role
		a.drainLocked(old)
	}
	a.exits[id] = x
	a.assignRolesLocked(region, time.Now())
	a.finishLocked(id, "已核验地区与公网出口 "+x.IP, nil)
}
func (a *Pool) probeLocked(x *liveExit, id string) {
	x.probing = true
	go func() {
		start := time.Now()
		ip := x.t.Check(a.ctx)
		dur := time.Since(start)
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.exits[x.ID] != x || !x.DrainUntil.IsZero() {
			if id != "" {
				a.finishLocked(id, "", ErrConflict)
			}
			return
		}
		x.probing = false
		var err error
		if ip.String() != x.IP {
			x.Failures++
			if ip.IsValid() {
				x.Failures = 2
			}
			err = errors.New("公网出口探测失败或出口 IP 已变化")
			if x.Failures >= 2 {
				a.removeLocked(x)
				a.recordLocked("exit", x.Region, x.IP+" 已退出分配池")
			}
		} else {
			x.Failures = 0
			x.LastOK = time.Now()
			x.LatencyMS = dur.Milliseconds()
		}
		a.assignRolesLocked(x.Region, time.Now())
		if id != "" {
			a.finishLocked(id, "公网出口验证成功", err)
		}
	}()
}

func (a *Pool) Authenticate(username, password string) (Identity, bool) {
	parts := strings.Split(username, ".")
	if len(parts) > 3 || !store.ValidName(parts[0]) {
		return Identity{}, false
	}
	who := Identity{Account: parts[0], hash: store.Digest(password)}
	if len(parts) > 1 {
		who.Region = strings.ToUpper(parts[1])
		if who.Region == "AUTO" {
			who.Region = ""
		}
		if parts[1] == "" || who.Region != "" && !countryPattern.MatchString(who.Region) {
			return Identity{}, false
		}
	}
	if len(parts) > 2 {
		if !store.ValidName(parts[2]) {
			return Identity{}, false
		}
		who.Binding = parts[2]
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.validIdentityLocked(who)
	return who, ok
}
func (a *Pool) validIdentityLocked(who Identity) (store.SavedAccount, bool) {
	account, ok := a.s.View().Accounts[who.Account]
	return account, ok && account.Enabled && (account.Expires.IsZero() || time.Now().Before(account.Expires)) &&
		store.Equal(account.Hash, who.hash) && (who.Region == "" || slices.Contains(account.Regions, who.Region))
}
func (a *Pool) chooseLocked(who Identity, target string) (*liveExit, error) {
	acc, ok := a.validIdentityLocked(who)
	if !ok {
		return nil, ErrUnavailable
	}
	now := time.Now()
	region := who.Region
	if acc.Mode == "region" && region == "" {
		region = acc.Regions[0]
	}
	if acc.Mode == "sticky" && who.Binding == "" {
		return nil, errors.New("需要固定会话 ID")
	}
	bound := ""
	if who.Binding != "" {
		b, found := a.bindings[who.Binding]
		if !found || b.Account != who.Account || !now.Before(b.Expires) || (region != "" && b.Region != region) {
			return nil, ErrUnavailable
		}
		region = b.Region
		bound = b.Exit
	}
	state := a.s.View()
	var choices []*liveExit
	host := targetHost(target)
	for _, x := range a.exits {
		if !state.Regions[x.Region].Enabled || !slices.Contains(acc.Regions, x.Region) || region != "" && x.Region != region || bound != "" && x.ID != bound ||
			!x.ready(now, state.Config.ProbeSeconds) || now.Before(a.cooldowns[x.ID+"|"+host].Expires) {
			continue
		}
		choices = append(choices, x)
	}
	if len(choices) == 0 {
		return nil, ErrUnavailable
	}
	// Explicit regions prefer the stable primary; auto mode balances new connections.
	sort.Slice(choices, func(i, j int) bool {
		x, y := choices[i], choices[j]
		if region != "" && (x.Role == "主用") != (y.Role == "主用") {
			return x.Role == "主用"
		}
		if region == "" {
			last := a.lastExit[who.Account]
			if (x.ID == last) != (y.ID == last) {
				return y.ID == last
			}
		}
		lx, ly := a.exitLoadLocked(x.ID), a.exitLoadLocked(y.ID)
		if lx != ly {
			return lx < ly
		}
		return x.ID < y.ID
	})
	a.lastExit[who.Account] = choices[0].ID
	return choices[0], nil
}
func targetHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
func (a *Pool) reserve(ctx context.Context, who Identity, target string) (*liveExit, context.Context, func(), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	acc, ok := a.validIdentityLocked(who)
	if !ok {
		return nil, nil, nil, ErrUnavailable
	}
	count := 0
	for _, f := range a.flows {
		if f.Account == acc.Name {
			count++
		}
	}
	if count >= acc.Limit {
		return nil, nil, nil, errors.New("connection limit reached")
	}
	x, err := a.chooseLocked(who, target)
	if err != nil {
		return nil, nil, nil, err
	}
	id := store.Digest(store.NewToken())[:16]
	request, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(x.t.Context(), cancel)
	if !a.s.View().Config.LogTargets {
		target = ""
	}
	a.flows[id] = flow{id, acc.Name, x.Region, x.ID, x.IP, target, time.Now(), cancel}
	return x, request, func() {
		stop()
		cancel()
		a.mu.Lock()
		delete(a.flows, id)
		a.mu.Unlock()
	}, nil
}

func (a *Pool) Dial(ctx context.Context, who Identity, network, addr string) (net.Conn, error) {
	x, ctx, release, err := a.reserve(ctx, who, addr)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	conn, err := x.t.Dial(ctx, network, addr)
	a.mu.Lock()
	if len(a.dials) >= 4096 {
		copy(a.dials, a.dials[1024:])
		a.dials = a.dials[:len(a.dials)-1024]
	}
	a.dials = append(a.dials, dialSample{time.Now(), x.ID, time.Since(started).Milliseconds(), err == nil})
	a.mu.Unlock()
	if err != nil {
		release()
		return nil, err
	}
	c := &trackedConn{Conn: conn, release: release}
	c.stop = context.AfterFunc(ctx, func() { conn.Close() })
	return c, nil
}

type trackedConn struct {
	net.Conn
	release func()
	stop    func() bool
	once    sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.stop(); c.release() })
	return err
}
func (c *trackedConn) CloseWrite() error {
	if c, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return c.Close()
}

func (a *Pool) RoundTrip(who Identity, r *http.Request) (*http.Response, error) {
	x, ctx, release, err := a.reserve(r.Context(), who, r.URL.Host)
	if err != nil {
		return nil, err
	}
	resp, err := x.t.RoundTrip(r.WithContext(ctx))
	if err != nil {
		release()
		return nil, err
	}
	resp.Body = &trackedBody{ReadCloser: resp.Body, release: release}
	return resp, nil
}

type trackedBody struct {
	io.ReadCloser
	release func()
}

func (b *trackedBody) Close() error { defer b.release(); return b.ReadCloser.Close() }
