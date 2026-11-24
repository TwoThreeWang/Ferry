package admin

import (
	"context"
	"log"
	"slices"
	"sync"
	"time"

	"ferry/internal/egress"
	"ferry/internal/store"
)

type Server struct {
	pool         *egress.Pool
	s            *store.Store
	mu           sync.Mutex
	sessions     map[string]webSession
	failures     map[string][]time.Time // failed password checks per client address
	allFailures  []time.Time
	lastOTP      int64
	proxyAddress string
}

type webSession struct {
	Token   string
	CSRF    string
	Created time.Time
	Used    time.Time
	Agent   string
}

// New creates the console. proxyAddress is the host:port that clients should
// use for the proxy; the console shows it in examples.
func New(pool *egress.Pool, s *store.Store, proxyAddress string) *Server {
	return &Server{pool: pool, s: s, sessions: make(map[string]webSession), failures: make(map[string][]time.Time), proxyAddress: proxyAddress}
}

func (a *Server) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			a.mu.Lock()
			for id, session := range a.sessions {
				if sessionExpired(session, now) {
					delete(a.sessions, id)
				}
			}
			a.mu.Unlock()
		}
	}
}

type deviceView struct {
	ID, Agent     string
	Created, Used time.Time
	Current       bool
}

type statusView struct {
	egress.Snapshot
	Admin        string
	TOTP         bool
	ProxyAddress string
	Keys         []store.APIKey
	Devices      []deviceView
}

func (a *Server) status(snapshot egress.Snapshot, id string) statusView {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := a.s.View()
	result := statusView{Snapshot: snapshot, Admin: state.Admin, TOTP: state.TOTP != "", ProxyAddress: a.proxyAddress}
	for _, k := range state.Keys {
		result.Keys = append(result.Keys, k.APIKey)
	}
	if id == "" {
		return result
	}
	now := time.Now()
	for key, session := range a.sessions {
		if !sessionExpired(session, now) {
			result.Devices = append(result.Devices, deviceView{store.Digest(key)[:16], session.Agent, session.Created, session.Used, key == id})
		}
	}
	return result
}

func (a *Server) audit(message string) {
	if err := a.s.Update(func(state *store.State) error {
		state.AddEvent("audit", "", message)
		return nil
	}); err != nil {
		log.Printf("persist event: %v", err)
	}
}

func (a *Server) keyAction(path, keyID, name, scope string) (any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if path == "keys/delete" {
		return "ok", a.s.Update(func(d *store.State) error {
			if _, ok := d.Keys[keyID]; !ok {
				return egress.ErrMissing
			}
			delete(d.Keys, keyID)
			d.AddEvent("audit", "", "撤销 API 凭据")
			return nil
		})
	}
	if !store.ValidName(name) || !slices.Contains([]string{"read", "write", "feedback"}, scope) || len(a.s.View().Keys) >= 50 {
		return nil, egress.ErrInvalid
	}
	secret := store.NewToken()
	id := store.Digest(secret)[:12]
	err := a.s.Update(func(d *store.State) error {
		d.Keys[id] = store.SavedKey{APIKey: store.APIKey{ID: id, Name: name, Scope: scope, Created: time.Now()}, Hash: store.Digest(secret)}
		d.AddEvent("audit", "", "创建 API 凭据 "+name)
		return nil
	})
	return map[string]string{"Secret": secret}, err
}
