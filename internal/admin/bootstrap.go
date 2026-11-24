package admin

import (
	"errors"
	"os"
	"strings"

	"ferry/internal/store"
)

func Reset(s *store.Store) error {
	return s.Update(func(d *store.State) error {
		d.Admin = ""
		d.Password = store.PasswordHash{}
		d.TOTP = ""
		d.Recovery = nil
		d.BootstrapHash = ""
		return nil
	})
}

func InitToken(s *store.Store) (string, error) {
	token := store.NewToken()
	err := s.Update(func(d *store.State) error {
		if d.Admin != "" {
			return errors.New("administrator already initialized")
		}
		d.BootstrapHash = store.Digest(token)
		return nil
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func EnsureBootstrap(s *store.Store, tokenFile string) error {
	state := s.View()
	if state.Admin != "" || state.BootstrapHash != "" {
		return nil
	}
	if tokenFile == "" {
		return errors.New("run ferry init-token before first start")
	}
	b, err := os.ReadFile(tokenFile)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(b))
	if len(token) < 32 || len(token) > 256 {
		return errors.New("setup token must be 32–256 characters")
	}
	return s.Update(func(d *store.State) error {
		d.BootstrapHash = store.Digest(token)
		return nil
	})
}
