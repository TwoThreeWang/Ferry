package store

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"
)

var namePattern = regexp.MustCompile("^[A-Za-z0-9_-]{2,40}$")

func ValidName(name string) bool { return namePattern.MatchString(name) }

func NewToken() string { return rand.Text() + rand.Text() }

type PasswordHash struct {
	Salt string
	Sum  string
}

func Digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func Equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func HashPassword(password string) PasswordHash {
	salt := rand.Text()
	key, err := pbkdf2.Key(sha256.New, password, []byte(salt), 600000, 32)
	if err != nil {
		panic(err)
	}
	return PasswordHash{salt, hex.EncodeToString(key)}
}
func (h PasswordHash) Matches(password string) bool {
	key, err := pbkdf2.Key(sha256.New, password, []byte(h.Salt), 600000, 32)
	return err == nil && h.Salt != "" && Equal(h.Sum, hex.EncodeToString(key))
}

type Region struct {
	Code    string
	Enabled bool
}
type Account struct {
	Name    string
	Mode    string
	Regions []string
	Limit   int
	Enabled bool
	Expires time.Time
}
type SavedAccount struct {
	Account
	Hash string
}

type APIKey struct {
	ID      string
	Name    string
	Scope   string
	Created time.Time
}
type SavedKey struct {
	APIKey
	Hash string
}
type Config struct {
	MaxTunnels    int
	ProbeSeconds  int
	DrainSeconds  int
	RetentionDays int
	LogTargets    bool
}
type Event struct {
	Time    time.Time
	Region  string
	Kind    string
	Message string
}
type State struct {
	Admin         string
	Password      PasswordHash
	TOTP          string
	Recovery      []string
	BootstrapHash string
	Regions       map[string]Region
	Accounts      map[string]SavedAccount
	Keys          map[string]SavedKey
	Config        Config
	Events        []Event
}

type Store struct {
	mu   sync.RWMutex
	path string
	data State
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "state.json")}
	raw, err := os.ReadFile(s.path)
	if err == nil {
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, err
		}
		return s, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.data = State{
		Regions:  map[string]Region{"JP": {"JP", true}},
		Accounts: map[string]SavedAccount{}, Keys: map[string]SavedKey{},
		Config: Config{MaxTunnels: 9, ProbeSeconds: 30, DrainSeconds: 90, RetentionDays: 7},
	}
	return s, nil
}

// View returns a snapshot. Maps and slices in it are read-only and remain valid
// when a subsequent update publishes a different state.
func (s *Store) View() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}

// Update publishes a new snapshot only after the state file is replaced.
func (s *Store) Update(f func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := json.Marshal(s.data)
	if err != nil {
		return err
	}
	var next State
	if err = json.Unmarshal(old, &next); err != nil {
		return err
	}
	if err = f(&next); err != nil {
		return err
	}
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if _, err = temp.Write(b); err != nil {
		return err
	}
	if err = temp.Sync(); err != nil {
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Rename(temp.Name(), s.path); err != nil {
		return err
	}
	s.data = next
	return nil
}
func (s *State) AddEvent(kind, region, message string) {
	s.AddEvents(Event{time.Now(), region, kind, message})
}

// AddEvents appends events that may have been recorded earlier, applying the
// retention window and the 300-event cap.
func (s *State) AddEvents(added ...Event) {
	min := time.Now().AddDate(0, 0, -s.Config.RetentionDays)
	events := slices.DeleteFunc(s.Events, func(x Event) bool { return x.Time.Before(min) })
	events = append(events, added...)
	if len(events) > 300 {
		events = events[len(events)-300:]
	}
	s.Events = events
}
