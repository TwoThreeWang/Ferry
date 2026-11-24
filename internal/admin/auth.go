package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"ferry/internal/egress"
	"ferry/internal/store"
)

func sessionExpired(s webSession, now time.Time) bool {
	return now.Sub(s.Created) > 12*time.Hour || now.Sub(s.Used) > 30*time.Minute
}

// Failed password checks are limited per client address, so one noisy source
// cannot lock the administrator out. A higher global cap still bounds
// distributed guessing. Successful attempts are not counted.
const (
	failuresPerSource = 8
	failuresGlobal    = 60
)

func attemptSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *Server) allowAttemptLocked(r *http.Request) bool {
	now := time.Now()
	old := func(t time.Time) bool { return now.Sub(t) > time.Minute }
	a.allFailures = slices.DeleteFunc(a.allFailures, old)
	for source, times := range a.failures {
		if times = slices.DeleteFunc(times, old); len(times) == 0 {
			delete(a.failures, source)
		} else {
			a.failures[source] = times
		}
	}
	return len(a.failures[attemptSource(r)]) < failuresPerSource && len(a.allFailures) < failuresGlobal
}

func (a *Server) failedAttemptLocked(r *http.Request) {
	now := time.Now()
	source := attemptSource(r)
	a.failures[source] = append(a.failures[source], now)
	a.allFailures = append(a.allFailures, now)
}
func (a *Server) browserSessionLocked(r *http.Request) (string, webSession, bool) {
	c, err := r.Cookie("ferry_session")
	if err != nil {
		return "", webSession{}, false
	}
	key := store.Digest(c.Value)
	s, ok := a.sessions[key]
	if !ok || sessionExpired(s, time.Now()) {
		delete(a.sessions, key)
		return "", webSession{}, false
	}
	if r.URL.Path != "/api/v1/status" && r.URL.Path != "/api/v1/stream" {
		s.Used = time.Now()
		a.sessions[key] = s
	}
	return key, s, true
}
func (a *Server) startSessionLocked(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("ferry_session"); err == nil {
		delete(a.sessions, store.Digest(c.Value))
	}
	if len(a.sessions) >= 50 {
		for id, s := range a.sessions {
			if sessionExpired(s, time.Now()) {
				delete(a.sessions, id)
			}
		}
		if len(a.sessions) >= 50 {
			for id := range a.sessions {
				delete(a.sessions, id)
				break
			}
		}
	}
	token := store.NewToken()
	now := time.Now()
	agent := r.UserAgent()
	if len(agent) > 200 {
		agent = agent[:200]
	}
	session := webSession{CSRF: store.NewToken(), Created: now, Used: now, Agent: agent}
	a.sessions[store.Digest(token)] = session
	http.SetCookie(w, &http.Cookie{Name: "ferry_session", Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]any{"Authenticated": true, "CSRF": session.CSRF})
}

func (a *Server) gate(r *http.Request) (sessionID string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if id, s, ok := a.browserSessionLocked(r); ok {
		if r.Method != "GET" && !store.Equal(s.CSRF, r.Header.Get("X-Ferry-CSRF")) {
			return "", errForbidden
		}
		return id, nil
	}
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		for _, k := range a.s.View().Keys {
			if store.Equal(k.Hash, store.Digest(token)) {
				if k.Scope == "feedback" && r.Method == "GET" {
					return "", errForbidden
				}
				if r.Method != "GET" && k.Scope != "write" && !(k.Scope == "feedback" && (r.URL.Path == "/api/v1/feedback" || r.URL.Path == "/api/v1/sessions")) {
					return "", errForbidden
				}
				return "", nil
			}
		}
	}
	return "", errUnauthorized
}

func (a *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, s, ok := a.browserSessionLocked(r)
	writeJSON(w, 200, map[string]any{"Initialized": a.s.View().Admin != "", "SetupAvailable": a.s.View().BootstrapHash != "", "Authenticated": ok, "CSRF": s.CSRF})
}

type authInput struct {
	Username   string
	Password   string
	Code       string
	SetupToken string
}

func (a *Server) login(w http.ResponseWriter, r *http.Request) {
	var q authInput
	if !decodeBody(w, r, &q) {
		return
	}
	if len(q.Password) > 256 || len(q.Username) > 40 || len(q.Code) > 128 {
		fail(w, egress.ErrInvalid)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.allowAttemptLocked(r) {
		fail(w, errRate)
		return
	}
	d := a.s.View()
	if d.Admin == "" || !d.Password.Matches(q.Password) || d.Admin != q.Username {
		a.failedAttemptLocked(r)
		fail(w, errUnauthorized)
		return
	}
	if d.TOTP != "" {
		if q.Code == "" {
			writeJSON(w, 200, map[string]bool{"NeedCode": true})
			return
		}
		if !a.verifySecondLocked(q.Code) {
			a.failedAttemptLocked(r)
			fail(w, errUnauthorized)
			return
		}
	}
	a.startSessionLocked(w, r)
}
func (a *Server) setup(w http.ResponseWriter, r *http.Request) {
	var q authInput
	if !decodeBody(w, r, &q) {
		return
	}
	if !store.ValidName(q.Username) || len(q.Password) < 12 || len(q.Password) > 256 {
		fail(w, egress.ErrInvalid)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.allowAttemptLocked(r) {
		fail(w, errRate)
		return
	}
	if a.s.View().Admin != "" || a.s.View().BootstrapHash == "" || !store.Equal(store.Digest(q.SetupToken), a.s.View().BootstrapHash) {
		a.failedAttemptLocked(r)
		fail(w, errForbidden)
		return
	}
	err := a.s.Update(func(d *store.State) error {
		d.Admin = q.Username
		d.Password = store.HashPassword(q.Password)
		d.BootstrapHash = ""
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	a.startSessionLocked(w, r)
}
func validateOTP(secret, code string, now time.Time) int64 {
	if len(code) != 6 {
		return -1
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(raw) != 20 {
		return -1
	}
	step := now.Unix() / 30
	for _, i := range []int64{0, -1, 1} {
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], uint64(step+i))
		h := hmac.New(sha1.New, raw)
		h.Write(counter[:])
		sum := h.Sum(nil)
		offset := sum[len(sum)-1] & 15
		n := binary.BigEndian.Uint32(sum[offset:]) & 0x7fffffff
		if store.Equal(code, fmt.Sprintf("%06d", n%1000000)) {
			return step + i
		}
	}
	return -1
}
func (a *Server) verifySecondLocked(code string) bool {
	state := a.s.View()
	if step := validateOTP(state.TOTP, code, time.Now()); step > a.lastOTP && step >= 0 {
		a.lastOTP = step
		return true
	}
	for i, hash := range state.Recovery {
		if store.Equal(hash, store.Digest(code)) {
			return a.s.Update(func(d *store.State) error { d.Recovery = slices.Delete(d.Recovery, i, i+1); return nil }) == nil
		}
	}
	return false
}
func (a *Server) securityAction(w http.ResponseWriter, r *http.Request, id, action string) {
	if id == "" {
		fail(w, errForbidden)
		return
	}
	var q struct{ Password, Next, Code, Secret, Device string }
	if !decodeBody(w, r, &q) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.sessions[id]; !ok {
		fail(w, errUnauthorized)
		return
	}
	if action == "logout" {
		delete(a.sessions, id)
		http.SetCookie(w, &http.Cookie{Name: "ferry_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
		writeJSON(w, 200, "ok")
		return
	}
	if action == "revoke" {
		for k := range a.sessions {
			if k != id && (q.Device == "" || store.Digest(k)[:16] == q.Device) {
				delete(a.sessions, k)
			}
		}
		a.audit("撤销管理会话")
		writeJSON(w, 200, "ok")
		return
	}
	if len(q.Password) > 256 || len(q.Next) > 256 || len(q.Code) > 128 || len(q.Secret) > 128 {
		fail(w, egress.ErrInvalid)
		return
	}
	if !a.allowAttemptLocked(r) {
		fail(w, errRate)
		return
	}
	if !a.s.View().Password.Matches(q.Password) {
		a.failedAttemptLocked(r)
		fail(w, errUnauthorized)
		return
	}
	if a.s.View().TOTP != "" && !a.verifySecondLocked(q.Code) {
		a.failedAttemptLocked(r)
		fail(w, errUnauthorized)
		return
	}
	var result any = "ok"
	switch action {
	case "password":
		if len(q.Next) < 12 {
			fail(w, egress.ErrInvalid)
			return
		}
		if err := a.s.Update(func(d *store.State) error { d.Password = store.HashPassword(q.Next); return nil }); err != nil {
			fail(w, err)
			return
		}
	case "totp-secret":
		if a.s.View().TOTP != "" {
			fail(w, egress.ErrConflict)
			return
		}
		raw := make([]byte, 20)
		rand.Read(raw)
		secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		s := a.sessions[id]
		s.Token = secret
		a.sessions[id] = s
		writeJSON(w, 200, map[string]string{"Secret": secret})
		return
	case "totp-enable":
		s := a.sessions[id]
		step := validateOTP(s.Token, q.Code, time.Now())
		if a.s.View().TOTP != "" || s.Token == "" || step < 0 {
			fail(w, errUnauthorized)
			return
		}
		recovery := make([]string, 8)
		if err := a.s.Update(func(d *store.State) error {
			d.TOTP = s.Token
			d.Recovery = nil
			for i := range recovery {
				recovery[i] = store.NewToken()[:20]
				d.Recovery = append(d.Recovery, store.Digest(recovery[i]))
			}
			return nil
		}); err != nil {
			fail(w, err)
			return
		}
		a.lastOTP = step
		s.Token = ""
		a.sessions[id] = s
		result = map[string]any{"Recovery": recovery}
	case "totp-disable":
		if err := a.s.Update(func(d *store.State) error { d.TOTP = ""; d.Recovery = nil; return nil }); err != nil {
			fail(w, err)
			return
		}
		a.lastOTP = 0
	default:
		fail(w, egress.ErrMissing)
		return
	}
	for k := range a.sessions {
		if k != id {
			delete(a.sessions, k)
		}
	}
	a.audit("更新管理员安全设置")
	writeJSON(w, 200, result)
}

var (
	errUnauthorized = errors.New("身份验证失败或管理会话已过期")
	errForbidden    = errors.New("此凭据没有该操作权限")
	errRate         = errors.New("尝试过于频繁，请稍后重试")
)
