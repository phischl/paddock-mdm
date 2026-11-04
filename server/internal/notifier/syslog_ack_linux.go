package notifier

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// unackedBytes returns the bytes written to conn that the peer has not acknowledged yet (SIOCOUTQ, which Linux defines
// as TIOCOUTQ), or the pending socket error, for example ECONNRESET after a reset. The stdlib syscall package is used
// because golang.org/x/sys is not a direct dependency.
func unackedBytes(conn net.Conn) (int, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, fmt.Errorf("unacked bytes: %T has no file descriptor", conn)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("unacked bytes: %w", err)
	}
	var n int32
	var opErr error
	if err := rc.Control(func(fd uintptr) {
		soErr, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_ERROR)
		switch {
		case err != nil:
			opErr = err
			return
		case soErr != 0:
			opErr = syscall.Errno(soErr)
			return
		}
		// The pointer conversion stays inside the call expression, the only form the unsafe rules allow for syscalls.
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCOUTQ,
			uintptr(unsafe.Pointer(&n))) //nolint:gosec // the ioctl writes one int32 into n
		if errno != 0 {
			opErr = errno
		}
	}); err != nil {
		return 0, fmt.Errorf("unacked bytes: %w", err)
	}
	if opErr != nil {
		return 0, fmt.Errorf("unacked bytes: %w", opErr)
	}
	return int(n), nil
}
