package admin

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"ferry/internal/egress"
)

//go:embed web/*
var assets embed.FS

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	status := 500
	message := err.Error()
	switch {
	case errors.Is(err, errUnauthorized):
		status = 401
	case errors.Is(err, errForbidden):
		status = 403
	case errors.Is(err, egress.ErrMissing):
		status = 404
	case errors.Is(err, egress.ErrConflict):
		status = 409
	case errors.Is(err, errRate):
		status = 429
		w.Header().Set("Retry-After", "60")
	case errors.Is(err, egress.ErrUnavailable):
		status = 503
		message = "没有可用且符合条件的出口"
	case errors.Is(err, egress.ErrInvalid):
		status = 400
	default:
		log.Printf("operation failed: %v", err)
		message = "服务暂时无法完成该操作，请查看日志"
	}
	writeJSON(w, status, map[string]string{"Error": message})
}
func decodeBody(w http.ResponseWriter, r *http.Request, out any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, egress.ErrInvalid)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		fail(w, egress.Invalid("请求内容不符合接口格式"))
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		fail(w, egress.ErrInvalid)
		return false
	}
	return true
}
func (a *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	web, _ := fs.Sub(assets, "web")
	mux.Handle("GET /", http.FileServerFS(web))
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]bool{"Live": true}) })
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, _ *http.Request) {
		count := a.pool.ReadyCount()
		status := 200
		if count == 0 {
			status = 503
		}
		writeJSON(w, status, map[string]any{"Ready": count > 0, "Usable": count})
	})
	mux.HandleFunc("GET /api/v1/auth", a.authStatus)
	mux.HandleFunc("POST /api/v1/login", a.login)
	mux.HandleFunc("POST /api/v1/setup", a.setup)
	mux.HandleFunc("GET /api/v1/", a.protected)
	mux.HandleFunc("POST /api/v1/", a.protected)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != "GET" && r.Header.Get("X-Ferry-Request") != "1" {
			fail(w, errForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func (a *Server) protected(w http.ResponseWriter, r *http.Request) {
	id, err := a.gate(r)
	if err != nil {
		fail(w, err)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	switch r.Method {
	case "GET":
		if path == "stream" {
			a.stream(w, r, id)
			return
		}
		a.readAPI(w, r, id, path)
	case "POST":
		if strings.HasPrefix(path, "security/") {
			a.securityAction(w, r, id, strings.TrimPrefix(path, "security/"))
			return
		}
		var q struct {
			egress.Change
			Scope string
		}
		if !decodeBody(w, r, &q) {
			return
		}
		var result any
		if path == "keys/create" || path == "keys/delete" {
			result, err = a.keyAction(path, q.ID, q.Name, q.Scope)
		} else {
			result, err = a.pool.Change(path, q.Change)
		}
		if err != nil {
			fail(w, err)
			return
		}
		status := 200
		if _, ok := result.(egress.Queued); ok {
			status = 202
		}
		writeJSON(w, status, result)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, 405, map[string]string{"Error": "方法不支持"})
	}
}

func (a *Server) readAPI(w http.ResponseWriter, r *http.Request, id, path string) {
	s := a.pool.Snapshot()
	switch path {
	case "status":
		writeJSON(w, 200, a.status(s, id))
	case "overview":
		writeJSON(w, 200, map[string]any{"Started": s.Started, "Time": s.Time, "Regions": s.Regions, "Connections": len(s.Flows), "CatalogAt": s.CatalogAt, "CatalogError": s.CatalogError})
	case "regions":
		writeJSON(w, 200, s.Regions)
	case "exits":
		writeJSON(w, 200, slices.DeleteFunc(s.Exits, func(x egress.ExitView) bool {
			return r.URL.Query().Get("region") != "" && x.Region != r.URL.Query().Get("region")
		}))
	case "nodes":
		writeJSON(w, 200, slices.DeleteFunc(s.Nodes, func(n egress.NodeView) bool {
			return n.Connected || r.URL.Query().Get("region") != "" && n.Region != r.URL.Query().Get("region")
		}))
	case "operations":
		writeJSON(w, 200, s.Operations)
	case "events":
		writeJSON(w, 200, s.Events)
	case "cooldowns":
		writeJSON(w, 200, s.Cooldowns)
	case "config":
		writeJSON(w, 200, s.Config)
	case "sessions":
		writeJSON(w, 200, s.Bindings)
	default:
		if code, ok := strings.CutPrefix(path, "regions/"); ok {
			for _, r := range s.Regions {
				if r.Code == code {
					writeJSON(w, 200, map[string]any{"Region": r, "Exits": slices.DeleteFunc(s.Exits, func(x egress.ExitView) bool { return x.Region != code }), "Nodes": slices.DeleteFunc(s.Nodes, func(n egress.NodeView) bool { return n.Region != code || n.Connected })})
					return
				}
			}
		}
		if key, ok := strings.CutPrefix(path, "exits/"); ok {
			for _, x := range s.Exits {
				if x.ID == key {
					writeJSON(w, 200, x)
					return
				}
			}
		}
		if key, ok := strings.CutPrefix(path, "operations/"); ok {
			for _, op := range s.Operations {
				if op.ID == key {
					writeJSON(w, 200, op)
					return
				}
			}
		}
		fail(w, egress.ErrMissing)
	}
}
func (a *Server) stream(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		fail(w, errForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	// Check for changes every 2 seconds and push the full status only when it
	// changed (ignoring the clock), or every 30 seconds as a heartbeat.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	controller := http.NewResponseController(w)
	var lastKey []byte
	var lastSent time.Time
	for {
		a.mu.Lock()
		session, ok := a.sessions[id]
		a.mu.Unlock()
		if !ok || sessionExpired(session, time.Now()) {
			return
		}
		view := a.status(a.pool.Snapshot(), id)
		body, err := json.Marshal(view)
		if err != nil {
			log.Printf("status stream: %v", err)
			return
		}
		view.Time = time.Time{}
		key, _ := json.Marshal(view)
		if !bytes.Equal(key, lastKey) || time.Since(lastSent) >= 30*time.Second {
			_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := fmt.Fprintf(w, "event: status\ndata: %s\n\n", body); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
			lastKey, lastSent = key, time.Now()
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}
