package smb2

// Credit-accounting tests driven against a fake server that keeps its own books.
//
// The invariant under test is that the client's spendable balance never exceeds
// what the server has granted. A client holding credits the server never issued
// will address message IDs past the server's command sequence window, which a
// real server answers with STATUS_INVALID_PARAMETER or a disconnect
// (MS-SMB2 3.3.5.2.3).
//
// Settlement has exactly one owner per request: a response settles the loan when
// tryHandle banks the server's grant, and otherwise the loan is refunded. The two
// tests here pin one half of that rule each.

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudsoda/go-smb2/internal/erref"
	"github.com/cloudsoda/go-smb2/internal/smb2"
)

// Reads at this offset are answered with STATUS_OBJECT_NAME_NOT_FOUND.
const errorOffset = 0xEE00

// Nonzero so session.recv's IBM-iSeries session-id adoption path (an
// unsynchronized write to s.sessionId when it is 0) stays out of the way.
const booksSessionId = 0xb00c5

type bookedResponse struct {
	msgId  uint64
	cc     uint16
	status uint32
}

// creditBooksServer is a fake server that keeps honest credit books: grants
// are counted when a response is written (that is when the client can first
// use them), consumption when a request arrives, and any request whose
// [MessageId, MessageId+CreditCharge) range exceeds total granted credits is
// recorded as a sequence-window violation — the check a real server enforces
// with STATUS_INVALID_PARAMETER / disconnect.
type creditBooksServer struct {
	t transport

	mu        sync.Mutex
	granted   uint64 // total credits ever granted, incl. the initial credit
	consumed  uint64 // total CreditCharge received
	firstDone bool

	violations atomic.Int64
	respDelay  atomic.Int64 // per-response delay in ns; lets in-flight pile up
	queue      chan bookedResponse
}

func newCreditBooksServer(t transport) *creditBooksServer {
	return &creditBooksServer{t: t, granted: 1, queue: make(chan bookedResponse, 1024)}
}

// outstanding is the number of credits the server believes the client holds.
func (s *creditBooksServer) outstanding() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.granted - s.consumed
}

func (s *creditBooksServer) run() {
	go s.respond()

	buf := make([]byte, bufSize)
	for {
		n, err := s.t.ReadSize()
		if err != nil {
			close(s.queue)
			return
		}
		if _, err := s.t.Read(buf[:n]); err != nil {
			close(s.queue)
			return
		}

		p := smb2.PacketCodec(buf[:n])
		msgId := p.MessageId()
		cc := p.CreditCharge()
		if cc == 0 {
			cc = 1
		}

		s.mu.Lock()
		if msgId+uint64(cc) > s.granted {
			s.violations.Add(1)
		}
		s.consumed += uint64(cc)
		s.mu.Unlock()

		status := uint32(erref.STATUS_SUCCESS)
		if binary.LittleEndian.Uint64(buf[72:80]) == errorOffset { // ReadRequest.Offset
			status = uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND)
		}

		s.queue <- bookedResponse{msgId: msgId, cc: cc, status: status}
	}
}

func (s *creditBooksServer) respond() {
	resp := &smb2.ReadResponse{
		PacketHeader: smb2.PacketHeader{
			Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
			SessionId: booksSessionId,
		},
		Data: make([]byte, 8),
	}
	respBuf := make([]byte, resp.Size())
	resp.Encode(respBuf)
	respBuf[64+2] = 80 // DataOffset from packet start
	rp := smb2.PacketCodec(respBuf)
	rp.SetCommand(smb2.SMB2_READ)

	for br := range s.queue {
		if d := s.respDelay.Load(); d > 0 {
			time.Sleep(time.Duration(d))
		}

		// Replacement-only grant policy (a conservative/loaded server),
		// plus a one-time window build-up like a session-setup grant.
		g := br.cc
		s.mu.Lock()
		if !s.firstDone {
			s.firstDone = true
			g += 31
		}
		s.granted += uint64(g)
		s.mu.Unlock()

		rp.SetMessageId(br.msgId)
		rp.SetCreditResponse(g)
		rp.SetStatus(br.status)

		if _, err := s.t.Write(respBuf); err != nil {
			return
		}
	}
}

func TestCreditDoubleSettlement(t *testing.T) {
	t.Run("control", func(t *testing.T) { runCreditBooks(t, false) })
	t.Run("error-responses", func(t *testing.T) { runCreditBooks(t, true) })
}

func runCreditBooks(t *testing.T, injectErrors bool) {
	require := require.New(t)
	assert := assert.New(t)

	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	c.session.Store(&session{
		conn:         c,
		sessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST,
		sessionId:    booksSessionId,
	})

	srv := newCreditBooksServer(direct(serverConn))
	go srv.run()

	f := newBenchFile(c)
	buf := make([]byte, 8)

	// Phase A: successful reads — books must stay balanced.
	for range 20 {
		_, err := f.readAt(buf, 0)
		require.NoError(err)
	}

	// Phase B: operations that fail with an error-status response.
	const K = 24
	if injectErrors {
		for range K {
			_, err := f.readAt(buf, errorOffset)
			require.Error(err, "expected error from read at errorOffset")
		}
	}

	// Phase B2: CLOSE consumes a window slot like any other file operation, so
	// it must borrow too. (The fake server answers everything with a READ-shaped
	// response, so close reports a decode error; what is under test here is the
	// books, not the reply.)
	for range 5 {
		f.close()
	}

	// Books check. Everything above is sequential and settled.
	clientCredits := int64(len(c.account.balance))
	serverCredits := int64(srv.outstanding())
	fabricated := clientCredits - serverCredits
	t.Logf("client balance=%d server outstanding=%d fabricated=%+d",
		clientCredits, serverCredits, fabricated)

	// With single-owner settlement, error-status responses no longer fabricate
	// credits: the balance must track the server's outstanding grant exactly,
	// whether or not operations failed.
	assert.Zero(fabricated, "books diverged (injectErrors=%v): client=%d server=%d",
		injectErrors, clientCredits, serverCredits)

	// Phase C: concurrent burst of multi-credit reads while responses are
	// delayed. With honest books in-flight credits can never exceed the
	// server's window; fabricated credits let the client overrun it.
	srv.respDelay.Store(int64(2 * time.Millisecond))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			big := make([]byte, 512*1024)
			for range 3 {
				f.readAt(big, 0)
			}
		})
	}
	wg.Wait()

	v := srv.violations.Load()
	t.Logf("sequence-window violations during burst: %d", v)
	assert.Zero(v, "client overran the server's sequence window %d times (injectErrors=%v)", v, injectErrors)
}

// TestTryHandleRefundsLoanOnFailedVerification covers the other half of the
// single-owner rule: a response that fails verification (bad signature, decode
// error) pops the request but is not a settlement, so tryHandle must refund
// the loan itself.
//
// Leaving that refund to conn.recv would leak the loan whenever the caller's
// context is already done, because recv can then return by the context path,
// where the request has already been popped and nothing refunds. The leak is
// permanent, so a connection that keeps hitting it eventually starves and every
// operation blocks in account.borrow.
//
// Each round below uses a cancelled context, so which path recv returns by is
// unpredictable; 50 rounds make hitting the leaky one a near-certainty.
func TestTryHandleRefundsLoanOnFailedVerification(t *testing.T) {
	require := require.New(t)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(128),
	}

	// Open the account up to 9 credits. Each round borrows and must return 2.
	c.account.settle(8, 8)
	const want = 9
	require.Equal(want, len(c.account.balance))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	verifyErr := &InvalidResponseError{"packet failed signature verification"}

	for round := range 50 {
		borrowed, _, err := c.account.borrow(context.Background(), 2)
		require.NoError(err)
		require.EqualValues(2, borrowed)

		msgId := uint64(round)
		rr := &requestResponse{msgId: msgId, ctx: ctx, recv: make(chan []byte, 1)}
		rr.loan.Store(uint32(borrowed))
		c.outstandingRequests.set(msgId, rr)

		// A response arrives for this request but fails verification.
		pkt := make([]byte, 64)
		smb2.PacketCodec(pkt).SetMessageId(msgId)
		require.NoError(c.tryHandle(pkt, verifyErr, nil))

		require.Equal(want, len(c.account.balance),
			"round %d: loan must be refunded when the response is not a settlement", round)

		// The caller then observes the failure, by whichever path recv returns.
		// The loan is already claimed, so neither path refunds twice.
		_, err = c.recv(rr)
		require.Error(err)
		require.Equal(want, len(c.account.balance),
			"round %d: loan must not be refunded twice", round)
	}
}
