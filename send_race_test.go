package smb2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"
	"time"
)

// gatedTransport blocks every Write until release is closed, then reads the
// whole packet, as a socket write that was slow to drain would.
type gatedTransport struct {
	entered chan struct{}
	release chan struct{}
}

func (g *gatedTransport) Write(p []byte) (int, error) {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	<-g.release
	var sum byte
	for _, b := range p {
		sum += b
	}
	_ = sum
	return len(p), nil
}
func (g *gatedTransport) ReadSize() (int, error) { return 0, errors.New("unused") }
func (g *gatedTransport) Read([]byte) (int, error) {
	return 0, errors.New("unused")
}
func (g *gatedTransport) Close() error { return nil }

// A send whose context ends while runSender is still writing its packet must
// not let the next send re-encode into the shared encode/encrypt buffers
// (session.go encrypt) until that write is over. Run under -race: before the
// fix the second send wrote the buffer while the writer goroutine read it.
func TestSendAbandonedMidWriteDoesNotShareBufferWithNextSend(t *testing.T) {
	c := newRollbackConn()
	gt := &gatedTransport{entered: make(chan struct{}, 1), release: make(chan struct{})}
	c.t = gt
	c.wdone = make(chan struct{}, 1)
	c.requireEncryption = true

	blk, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	c.session.Store(&session{conn: c, sessionId: 1, encrypter: gcm})

	go c.runSender()
	t.Cleanup(func() { c.wdone <- struct{}{} })

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	first := make(chan error, 1)
	go func() {
		_, err := c.sendWith(ctx1, newReadReq(1), nil, 0)
		first <- err
	}()
	<-gt.entered // runSender holds the first packet, mid-write
	cancel1()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("first send: want context.Canceled, got %v", err)
	}

	// The second send must wait for the abandoned write rather than encode over
	// the packet being written. The release is deliberately not ordered after
	// the second send, so only a settled write gives the race detector a
	// happens-before edge between the writer's read and the next encode.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	second := make(chan error, 1)
	go func() {
		_, err := c.sendWith(ctx2, newReadReq(1), nil, 0)
		second <- err
	}()
	close(gt.release)
	if err := <-second; err != nil {
		t.Fatalf("second send: %v", err)
	}
}
