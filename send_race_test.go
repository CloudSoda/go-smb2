package smb2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2/internal/smb2"
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

	blk, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	c.session.Store(&session{conn: c, sessionId: 1, encrypter: gcm, sessionFlags: smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA})

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

// While an abandoned write is unsettled, a send whose own context ends gives
// up without allocating a message ID or keeping its loan, and the abandoned
// write stays counted until its result is consumed.
func TestSendWaitingOnAbandonedWriteRefundsOnContextEnd(t *testing.T) {
	for name, send := range map[string]func(c *conn, ctx context.Context) error{
		"sendWith": func(c *conn, ctx context.Context) error {
			_, err := c.sendWith(ctx, newReadReq(1), nil, 1)
			return err
		},
		"sendCompound": func(c *conn, ctx context.Context) error {
			_, err := c.sendCompound(ctx, []compoundEntry{{req: newReadReq(1)}})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := newRollbackConn()
			borrowed, _, err := c.account.borrow(context.Background(), 1)
			if err != nil || borrowed != 1 {
				t.Fatalf("borrow: %d, %v", borrowed, err)
			}
			c.abandonedWrites = 1

			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if err := send(c, ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("want DeadlineExceeded, got %v", err)
			}
			if got := len(c.account.balance); got != startBalance {
				t.Fatalf("loan not refunded: balance %d, want %d", got, startBalance)
			}
			if c.sequenceWindow != 1 {
				t.Fatalf("window moved to %d with nothing sent", c.sequenceWindow)
			}
			if c.abandonedWrites != 1 {
				t.Fatalf("abandonedWrites = %d, want 1 until the result is consumed", c.abandonedWrites)
			}

			c.werr <- nil
			if err := c.settleAbandonedWrites(context.Background()); err != nil || c.abandonedWrites != 0 {
				t.Fatalf("settle: err %v, abandonedWrites %d", err, c.abandonedWrites)
			}
		})
	}
}
