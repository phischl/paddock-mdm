//go:build !linux

package notifier

import "net"

// unackedBytes reports every byte as acknowledged: the send-queue check needs Linux's SIOCOUTQ, and the server only
// runs on Linux; other builds keep the close handshake as the only delivery check.
func unackedBytes(net.Conn) (int, error) {
	return 0, nil
}
