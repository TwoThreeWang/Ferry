//go:build !linux

package vpngate

import (
	"errors"
	"syscall"
)

func bindToTunnel(_ string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, _ syscall.RawConn) error {
		return errors.New("VPN tunneling requires Linux")
	}
}
