package admin

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ferry/internal/egress"
	"ferry/internal/store"
)

func testConsole(t *testing.T) (*Server, string) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	token, err := InitToken(s)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return New(egress.New(ctx, s, false), s, "192.0.2.10:7928"), token
}

func post(h http.Handler, path, body, from string, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.RemoteAddr = from
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Ferry-Request", "1")
	if csrf != "" {
		r.Header.Set("X-Ferry-CSRF", csrf)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func setupBody(token string) string {
	b, _ := json.Marshal(authInput{Username: "admin", Password: "correct-horse-battery", SetupToken: token})
	return string(b)
}

// One noisy client must not lock out the administrator connecting from elsewhere.
func TestFailedAttemptsAreLimitedPerSource(t *testing.T) {
	a, token := testConsole(t)
	h := a.Handler()
	for i := range failuresPerSource {
		if w := post(h, "/api/v1/setup", setupBody("wrong"), "198.51.100.7:4000", nil, ""); w.Code != http.StatusForbidden {
			t.Fatalf("attempt %d: status %d", i, w.Code)
		}
	}
	if w := post(h, "/api/v1/setup", setupBody(token), "198.51.100.7:4001", nil, ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("noisy source not limited: %d", w.Code)
	}
	if w := post(h, "/api/v1/setup", setupBody(token), "203.0.113.9:5000", nil, ""); w.Code != http.StatusOK {
		t.Fatalf("other source locked out: %d %s", w.Code, w.Body)
	}
}

func TestGlobalFailureCap(t *testing.T) {
	a, _ := testConsole(t)
	r := httptest.NewRequest("POST", "/", nil)
	a.mu.Lock()
	defer a.mu.Unlock()
	for range failuresGlobal {
		r.RemoteAddr = "198.51.100." + time.Now().Format("150405.000000") + ":1"
		a.failedAttemptLocked(r)
	}
	r.RemoteAddr = "203.0.113.1:1"
	if a.allowAttemptLocked(r) {
		t.Fatal("global cap ignored")
	}
}

func TestSessionWritesNeedCSRFAndStreamPushesStatus(t *testing.T) {
	a, token := testConsole(t)
	h := a.Handler()
	w := post(h, "/api/v1/setup", setupBody(token), "127.0.0.1:1", nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", w.Code, w.Body)
	}
	var session struct{ CSRF string }
	_ = json.NewDecoder(w.Body).Decode(&session)
	cookies := w.Result().Cookies()
	change := `{"Region":"KR","Enabled":true}`
	if w := post(h, "/api/v1/regions/save", change, "127.0.0.1:1", cookies, ""); w.Code != http.StatusForbidden {
		t.Fatalf("write without CSRF: %d", w.Code)
	}
	if w := post(h, "/api/v1/regions/save", change, "127.0.0.1:1", cookies, session.CSRF); w.Code != http.StatusOK {
		t.Fatalf("write with CSRF: %d %s", w.Code, w.Body)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/stream", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	lines := bufio.NewScanner(res.Body)
	lines.Buffer(make([]byte, 1<<20), 1<<20)
	for lines.Scan() {
		data, ok := strings.CutPrefix(lines.Text(), "data: ")
		if !ok {
			continue
		}
		var status struct {
			ProxyAddress string
			Regions      []struct{ Code string }
		}
		if err := json.Unmarshal([]byte(data), &status); err != nil {
			t.Fatal(err)
		}
		if status.ProxyAddress != "192.0.2.10:7928" || len(status.Regions) != 2 {
			t.Fatalf("stream status %+v", status)
		}
		return
	}
	t.Fatalf("stream ended without status: %v", lines.Err())
}
