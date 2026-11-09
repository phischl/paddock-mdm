package selfservice

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

// TestSocket: the socket exists only while the server runs, is world-connectable (0666) and identifies the caller by
// the kernel's peer credentials.
func TestSocket(t *testing.T) {
	f := newFixture(t)
	f.sys.Passwd = map[string]int{"tester": os.Getuid()}
	f.svc.SetBundle(softwareBundle(spec()), nil)
	path := filepath.Join(t.TempDir(), "run", "selfservice.sock")
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("socket before the start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.svc.Serve(ctx, path) }()
	eventually(t, func() bool { _, err := os.Lstat(path); return err == nil })
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&fs.ModeSocket == 0 || fi.Mode().Perm() != 0o666 {
		t.Fatalf("socket %v %v", fi.Mode(), err)
	}
	if di, err := os.Stat(filepath.Dir(path)); err != nil || di.Mode().Perm() != 0o755 {
		t.Errorf("directory %v %v", di.Mode(), err)
	}
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	res, err := hc.Get("http://selfservice/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	var st Status
	err = json.NewDecoder(res.Body).Decode(&st)
	_ = res.Body.Close()
	if err != nil || res.StatusCode != http.StatusOK || st.User.Name != "tester" || st.User.Directory {
		t.Fatalf("status %d %+v %v", res.StatusCode, st, err)
	}
	hc.CloseIdleConnections()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("socket after the stop: %v", err)
	}
}

// TestPeerListenerLimit: at most MaxConns connections are accepted at a time; closing one frees its slot.
func TestPeerListenerLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	pl := newPeerListener(ln, 2, 2, peerOf)
	accepted := make(chan net.Conn, 3)
	go func() {
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	for range 3 {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
	}
	first, second := <-accepted, <-accepted
	if pc := first.(*peerConn); pc.peer.err != nil || pc.peer.uid != os.Getuid() {
		t.Errorf("peer %+v", pc.peer)
	}
	select {
	case <-accepted:
		t.Fatal("a third connection was accepted")
	default:
	}
	_ = first.Close()
	_ = first.Close()
	third := <-accepted
	_ = second.Close()
	_ = third.Close()
}

// TestPeerListenerPerUID (decision 12): one UID holds at most MaxConnsPerUID connections; a further one of that UID
// is closed unanswered, while another UID is still served.
func TestPeerListenerPerUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var mu sync.Mutex
	uids := []int{1000, 1000, 1000, 1000, 1000, 1001}
	fakePeer := func(net.Conn) peer {
		mu.Lock()
		defer mu.Unlock()
		uid := uids[0]
		uids = uids[1:]
		return peer{uid: uid}
	}
	pl := newPeerListener(ln, MaxConns, MaxConnsPerUID, fakePeer)
	accepted := make(chan net.Conn, len(uids))
	go func() {
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	var clients []net.Conn
	for range len(uids) {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		defer func() { _ = c.Close() }()
	}
	var got []int
	for range MaxConnsPerUID + 1 {
		select {
		case c := <-accepted:
			got = append(got, c.(*peerConn).peer.uid)
		case <-time.After(5 * time.Second):
			t.Fatalf("accepted only %v", got)
		}
	}
	if want := []int{1000, 1000, 1000, 1000, 1001}; !slices.Equal(got, want) {
		t.Errorf("accepted UIDs %v, want %v", got, want)
	}
	_ = clients[MaxConnsPerUID].SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := clients[MaxConnsPerUID].Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the fifth connection of UID 1000 was not closed: %v", err)
	}
}
