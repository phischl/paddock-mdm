package supervisor

import (
	"net"
	"os"
)

// SdNotify sends a state ("READY=1", "WATCHDOG=1") to systemd's NOTIFY_SOCKET; without one it does nothing.
func SdNotify(state string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	if addr[0] == '@' {
		addr = "\x00" + addr[1:] // abstract socket
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte(state))
}
