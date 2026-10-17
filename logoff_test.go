package smb2

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

// deadTransport models a socket that is up enough to be read from but whose
// writes fail: the LOGOFF round trip cannot complete. It records Close calls so
// a test can assert teardown released it.
type deadTransport struct {
	m         sync.Mutex
	closes    int
	closed    chan struct{}
	closeOnce sync.Once
}

func newDeadTransport() *deadTransport {
	return &deadTransport{closed: make(chan struct{})}
}

func (t *deadTransport) Write(p []byte) (int, error) {
	return 0, errors.New("dead transport")
}

// ReadSize blocks until the transport is closed, the way a real socket with a
// silent peer does, so the receiver goroutine stays alive until teardown.
func (t *deadTransport) ReadSize() (int, error) {
	<-t.closed
	return 0, net.ErrClosed
}

func (t *deadTransport) Read(p []byte) (int, error) {
	<-t.closed
	return 0, net.ErrClosed
}

func (t *deadTransport) Close() error {
	t.m.Lock()
	t.closes++
	t.m.Unlock()

	t.closeOnce.Do(func() { close(t.closed) })

	return nil
}

func (t *deadTransport) closeCount() int {
	t.m.Lock()
	defer t.m.Unlock()

	return t.closes
}

// newTestConn wires a conn to an arbitrary transport with negotiated
// parameters matching a typical SMB 3.0.2 connection, and starts its
// sender/receiver goroutines.
func newTestConn(t transport) *conn {
	c := &conn{
		t:                   t,
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(128),
		rdone:               make(chan struct{}, 1),
		wdone:               make(chan struct{}, 1),
		write:               make(chan []byte, 1),
		werr:                make(chan error, 1),
		dialect:             smb2.SMB302,
		maxReadSize:         bufSize,
		maxWriteSize:        bufSize,
		maxTransactSize:     bufSize,
		capabilities:        smb2.SMB2_GLOBAL_CAP_LARGE_MTU,
	}

	go c.runSender()
	go c.runReceiver()

	return c
}

// TestLogoffClosesTransportOnFailure pins the contract that logoff releases the
// connection even when the LOGOFF round trip errors. There is no other way to
// release the socket and the sender/receiver goroutines, so returning early
// would leak them for the life of the process — precisely on the path a caller
// discarding a broken session takes.
func TestLogoffClosesTransportOnFailure(t *testing.T) {
	require := require.New(t)

	dt := newDeadTransport()
	c := newTestConn(dt)
	s := &session{conn: c}

	err := s.logoff(context.Background())
	require.Error(err, "the round trip cannot succeed over a dead transport")
	require.Equal(1, dt.closeCount(), "transport must be closed despite the failed round trip")

	// The receiver observed the close and shut the connection down, which in
	// turn releases the sender.
	require.Eventually(func() bool {
		select {
		case <-c.wdone:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond, "receiver goroutine did not shut down")
}

// A second logoff on an already-torn-down connection must not block: the
// receiver is gone, so nothing will drain a second rdone signal.
func TestLogoffTwiceDoesNotBlock(t *testing.T) {
	require := require.New(t)

	dt := newDeadTransport()
	c := newTestConn(dt)
	s := &session{conn: c}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 3 {
			_ = s.logoff(context.Background())
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("repeated logoff blocked")
	}

	require.Equal(3, dt.closeCount())
}

// A request issued after a logoff has torn the connection down must return,
// not hang.
//
// logoff signals rdone before closing the transport, so the receiver treats
// the read failure as an expected shutdown and clears the error:
//
//	case <-conn.rdone:
//	    err = nil
//	...
//	conn.err = err
//
// That leaves conn.err nil, so the guard in makeRequestResponse does not fire
// for the next request. Meanwhile the receiver has closed wdone and released
// the sender, so conn.write has no reader. The send still succeeds once
// because the channel is buffered, and what follows is a wait on conn.werr
// that nothing will ever answer — with a context that is never cancelled,
// which is what Logoff passes.
//
// TestLogoffTwiceDoesNotBlock covers the same defect but races the teardown,
// so it usually passes and occasionally hits its five second timeout.
func TestSendAfterTeardownDoesNotBlock(t *testing.T) {
	require := require.New(t)

	dt := newDeadTransport()
	c := newTestConn(dt)
	s := &session{conn: c}

	// A real logoff, so the receiver exits by the expected path and records a
	// nil connection error.
	_ = s.logoff(context.Background())
	<-c.wdone

	// Give the sender the moment it needs to observe wdone and return, so the
	// request below genuinely has no reader rather than racing for one.
	time.Sleep(50 * time.Millisecond)

	// The shutdown was the expected one, so the requests in flight were told
	// nothing was wrong. The connection is still closed, and must say so.
	require.Error(c.err, "a closed connection must report itself closed")

	done := make(chan error, 1)
	go func() {
		done <- s.logoff(context.Background())
	}()

	select {
	case err := <-done:
		require.Error(err, "a request on a torn-down connection must report one")
	case <-time.After(2 * time.Second):
		t.Fatal("request on a torn-down connection blocked")
	}
}
