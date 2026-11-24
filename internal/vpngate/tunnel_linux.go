package vpngate

import (
	"syscall"
)

func bindToTunnel(dev string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, conn syscall.RawConn) error {
		var bindErr error
		if err := conn.Control(func(fd uintptr) {
			bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
		}); err != nil {
			return err
		}
		return bindErr
	}
}
