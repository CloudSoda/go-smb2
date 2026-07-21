package smb2

// White-box tests for the credit refund/settlement paths in conn.go.
//
// Two invariants are under test:
//
//  1. The window/credit invariant (SEQUENCE-ROLLBACK.md): after any send that
//     fails before the packet reaches the writer, conn.sequenceWindow (the next
//     message ID the client will allocate) plus len(conn.account.balance) (the
//     spendable credit count) must equal the server's window ceiling. A send that
//     allocates a message ID but never transmits it must roll the window back, or
//     the client's ID counter drifts ahead of what its balance can address.
//
//  2. Single-owner settlement (commit 62dc3c9): each requestResponse carries its
//     loan in an atomic; claimLoan swap-takes it exactly once, so whichever of the
//     receiver or a failure path evicts the request settles the loan, and the
//     loser's refund becomes a no-op charge of zero.
//
// TestSendWith... and TestSendCompound... are regression tests for invariant 1:
// before the rollback fix, their sequenceWindow assertions failed (the window
// stayed advanced at 3 and 7) while the refund assertions passed.
// TestPendingResponseSettlesLoanOnce and TestRecvRefundsLoan pin invariant 2.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cloudsoda/go-smb2/internal/erref"
	"github.com/cloudsoda/go-smb2/internal/smb2"
)

// startBalance is the spendable credit count after opening a fresh test account
// up from its initial single credit.
const startBalance = 9

// newRollbackConn builds a conn with no sender/receiver goroutines, matching the
// negotiated parameters of a typical SMB 3.0.2 large-MTU connection. No session
// is stored, so the encode paths skip signing and encryption. sequenceWindow
// starts at 1 (the first message ID a real client allocates), and the account is
// opened up to startBalance spendable credits.
func newRollbackConn() *conn {
	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(128),
		write:               make(chan []byte, 1),
		werr:                make(chan error, 1),
		dialect:             smb2.SMB302,
		capabilities:        smb2.SMB2_GLOBAL_CAP_LARGE_MTU,
		maxReadSize:         bufSize,
		maxWriteSize:        bufSize,
		maxTransactSize:     bufSize,
	}
	c.sequenceWindow = 1
	c.account.charge(8, 8) // 1 initial + 8 == startBalance spendable credits
	return c
}

// newReadReq mirrors what client.go's readAtChunk builds, with CreditCharge set
// explicitly to the amount loaned for this request. A zero-value FileId encodes
// fine because nothing decodes it in these tests.
func newReadReq(creditCharge uint16) *smb2.ReadRequest {
	req := &smb2.ReadRequest{
		Length:       64 * 1024 * uint32(creditCharge),
		Offset:       0,
		FileId:       &smb2.FileId{},
		MinimumCount: 0,
	}
	req.CreditCharge = creditCharge
	return req
}

// TestSendWithRollsBackWindowOnAbandonedSend pins invariant 1 for sendWith.
//
// The "abandoned-send" subtest drives sendWith's outer `case <-ctx.Done()` arm:
// makeRequestResponse has already allocated a message ID and advanced the
// window, but the packet never reaches the writer because the write channel is
// full and the context is cancelled while the handoff is blocked. The loan must
// be refunded and the window must roll back. The "conn-err" and
// "ctx-already-done" subtests cover the two pre-registration refund arms, which
// never advance the window.
func TestSendWithRollsBackWindowOnAbandonedSend(t *testing.T) {
	t.Run("abandoned-send", func(t *testing.T) {
		require := require.New(t)

		c := newRollbackConn()

		// Loan 2 credits: balance drops to startBalance-2.
		loaned, _, err := c.account.loan(context.Background(), 2)
		require.NoError(err)
		require.EqualValues(2, loaned)
		require.Equal(startBalance-2, len(c.account.balance))

		req := newReadReq(loaned)

		// Fill the single-slot write channel so the handoff in sendWith can never
		// proceed and the outer ctx.Done() arm is the only exit.
		c.write <- []byte{}

		// Cancel only after sendWith is blocked on the write handoff. A too-early
		// cancel (before the early check at the top of sendWith) would instead
		// take the pre-registration refund arm, which never advances the window;
		// the window assertion would then be vacuous but not incorrect.
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		rr, err := c.sendWith(ctx, req, nil, loaned)

		// 1. The abandoned send fails with the context error and yields no rr.
		require.ErrorIs(err, context.Canceled)
		require.Nil(rr)

		// 2. The loan is refunded: balance is back to startBalance.
		require.Equal(startBalance, len(c.account.balance),
			"loan must be refunded on the abandoned-send arm")

		// 3. The window rolls back to 1: the allocated message ID is given back
		//    because it was never transmitted. Before the rollback fix this
		//    failed with sequenceWindow stuck at 3.
		require.EqualValues(1, c.sequenceWindow,
			"window must roll back when the packet is never transmitted")
	})

	t.Run("conn-err", func(t *testing.T) {
		require := require.New(t)

		c := newRollbackConn()

		// A prior fatal error on the connection makes sendWith refund and return
		// before it ever allocates a message ID.
		errBoom := errors.New("connection already failed")
		c.err = errBoom

		loaned, _, err := c.account.loan(context.Background(), 2)
		require.NoError(err)
		require.EqualValues(2, loaned)

		req := newReadReq(loaned)

		rr, err := c.sendWith(context.Background(), req, nil, loaned)

		require.ErrorIs(err, errBoom)
		require.Nil(rr)
		// Refunded, and the window was never advanced.
		require.Equal(startBalance, len(c.account.balance))
		require.EqualValues(1, c.sequenceWindow)
	})

	t.Run("ctx-already-done", func(t *testing.T) {
		require := require.New(t)

		c := newRollbackConn()

		loaned, _, err := c.account.loan(context.Background(), 2)
		require.NoError(err)
		require.EqualValues(2, loaned)

		req := newReadReq(loaned)

		// An already-cancelled context is caught by the early select at the top
		// of sendWith, refunding before any message ID is allocated.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		rr, err := c.sendWith(ctx, req, nil, loaned)

		require.ErrorIs(err, context.Canceled)
		require.Nil(rr)
		require.Equal(startBalance, len(c.account.balance))
		require.EqualValues(1, c.sequenceWindow)
	})
}

// TestSendCompoundRollsBackWindowOnAbandonedSend pins invariant 1 for
// sendCompound with a multi-entry batch. The "abandoned-send" subtest drives the
// outer `case <-ctx.Done()` arm: all three requests have been registered and the
// window advanced by the batch's total credit charge, but the frame never
// reaches the writer. refundCompound must restore the batch's credits, and the
// window must roll back by the batch total. The "ctx-already-done" subtest
// covers the pre-flight refund arm, which never advances the window.
func TestSendCompoundRollsBackWindowOnAbandonedSend(t *testing.T) {
	// CreditCharges 1, 2, 3 sum to a batch total of 6.
	const batchTotal = 6

	t.Run("abandoned-send", func(t *testing.T) {
		require := require.New(t)

		c := newRollbackConn()

		// Loan the batch total up front: balance drops to startBalance-batchTotal.
		loaned, _, err := c.account.loan(context.Background(), batchTotal)
		require.NoError(err)
		require.EqualValues(batchTotal, loaned)
		require.Equal(startBalance-batchTotal, len(c.account.balance))

		entries := []compoundEntry{
			{req: newReadReq(1)},
			{req: newReadReq(2)},
			{req: newReadReq(3)},
		}

		// Fill the write channel so the frame handoff can never proceed.
		c.write <- []byte{}

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		rrs, err := c.sendCompound(ctx, entries)

		require.ErrorIs(err, context.Canceled)
		require.Nil(rrs)

		// refundCompound restores the batch's credits.
		require.Equal(startBalance, len(c.account.balance),
			"batch credits must be refunded on the abandoned-send arm")

		// The window rolls back by the batch total to 1. Before the rollback fix
		// this failed with sequenceWindow stuck at 7.
		require.EqualValues(1, c.sequenceWindow,
			"window must roll back by the batch total when the frame is never transmitted")

		// The batch's requests were evicted by refundCompound. Message IDs are
		// allocated from sequenceWindow==1 in charge order: 1, 1+1==2, 2+2==4.
		for _, msgId := range []uint64{1, 2, 4} {
			_, ok := c.outstandingRequests.pop(msgId)
			require.False(ok, "request %d must no longer be outstanding", msgId)
		}
	})

	t.Run("ctx-already-done", func(t *testing.T) {
		require := require.New(t)

		c := newRollbackConn()

		loaned, _, err := c.account.loan(context.Background(), batchTotal)
		require.NoError(err)
		require.EqualValues(batchTotal, loaned)

		entries := []compoundEntry{
			{req: newReadReq(1)},
			{req: newReadReq(2)},
			{req: newReadReq(3)},
		}

		// An already-cancelled context is caught by sendCompound's pre-flight
		// select before any message ID is allocated.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		rrs, err := c.sendCompound(ctx, entries)

		require.ErrorIs(err, context.Canceled)
		require.Nil(rrs)
		require.Equal(startBalance, len(c.account.balance))
		require.EqualValues(1, c.sequenceWindow)
	})
}

// TestPendingResponseSettlesLoanOnce is a regression guard for tryHandle's
// STATUS_PENDING arm, which was previously untested. An interim
// STATUS_PENDING response settles the loan (it banks the server's grant and
// claims the loan) and re-registers the request, so a caller that later abandons
// the request must NOT receive a second refund. Pins invariant 2.
func TestPendingResponseSettlesLoanOnce(t *testing.T) {
	require := require.New(t)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(128),
	}
	c.account.charge(8, 8)
	require.Equal(startBalance, len(c.account.balance))

	// The caller's context is already done, so when it later calls recv both of
	// recv's select arms would be ready.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	loaned, _, err := c.account.loan(context.Background(), 2)
	require.NoError(err)
	require.EqualValues(2, loaned)
	require.Equal(startBalance-2, len(c.account.balance))

	const msgId = 5
	rr := &requestResponse{
		msgId:         msgId,
		ctx:           ctx,
		recv:          make(chan []byte, 1),
		creditRequest: 2,
	}
	rr.loan.Store(uint32(loaned))
	c.outstandingRequests.set(msgId, rr)

	// An interim STATUS_PENDING response granting 2 credits. A plain 64-byte
	// buffer gives asyncId 0, which is fine for the AsyncId() read on this arm.
	pkt := make([]byte, 64)
	p := smb2.PacketCodec(pkt)
	p.SetMessageId(msgId)
	p.SetStatus(uint32(erref.STATUS_PENDING))
	p.SetCreditResponse(2)

	require.NoError(c.tryHandle(pkt, nil, nil))

	// The grant of 2 is banked against creditRequest 2, so balance returns to
	// startBalance, and the request is re-registered for the final response.
	require.Equal(startBalance, len(c.account.balance),
		"the pending grant must bank the loan back exactly once")

	c.outstandingRequests.m.Lock()
	_, present := c.outstandingRequests.requests[msgId]
	c.outstandingRequests.m.Unlock()
	require.True(present, "STATUS_PENDING must re-register the request")

	// The caller now abandons the request: recv's ctx arm pops the re-registered
	// request and calls claimLoan, which yields 0 because tryHandle already
	// settled the loan. No second refund fires, so the balance stays at
	// startBalance rather than climbing to 11.
	_, err = c.recv(rr)
	require.Error(err)
	require.Equal(startBalance, len(c.account.balance),
		"a settled loan must not be refunded a second time")
}

// TestRecvRefundsLoan covers recv's two real refund paths with a nonzero,
// unclaimed loan. Existing tests only reach these arms after the loan is already
// claimed, so the refund itself is never exercised there. Both subtests pin
// invariant 2.
func TestRecvRefundsLoan(t *testing.T) {
	t.Run("ctx-eviction", func(t *testing.T) {
		require := require.New(t)

		c := &conn{
			outstandingRequests: newOutstandingRequests(),
			account:             openAccount(128),
		}
		c.account.charge(8, 8)
		require.Equal(startBalance, len(c.account.balance))

		loaned, _, err := c.account.loan(context.Background(), 2)
		require.NoError(err)
		require.EqualValues(2, loaned)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		const msgId = 7
		rr := &requestResponse{
			msgId: msgId,
			ctx:   ctx,
			recv:  make(chan []byte, 1),
		}
		rr.loan.Store(uint32(loaned))
		c.outstandingRequests.set(msgId, rr)

		// recv's recv channel is empty, so the cancelled-context arm wins: it pops
		// the request and refunds the still-unclaimed loan.
		_, err = c.recv(rr)
		require.ErrorIs(err, context.Canceled)
		require.Equal(startBalance, len(c.account.balance),
			"the ctx arm must refund an unclaimed loan")

		_, ok := c.outstandingRequests.pop(msgId)
		require.False(ok, "recv must have evicted the request")
	})

	t.Run("shutdown", func(t *testing.T) {
		require := require.New(t)

		c := &conn{
			outstandingRequests: newOutstandingRequests(),
			account:             openAccount(128),
		}
		c.account.charge(8, 8)
		require.Equal(startBalance, len(c.account.balance))

		loaned, _, err := c.account.loan(context.Background(), 2)
		require.NoError(err)
		require.EqualValues(2, loaned)

		// A live (non-cancelled) context, so the pkt arm — not the ctx arm — is the
		// one that fires.
		const msgId = 8
		rr := &requestResponse{
			msgId: msgId,
			ctx:   context.Background(),
			recv:  make(chan []byte, 1),
		}
		rr.loan.Store(uint32(loaned))
		c.outstandingRequests.set(msgId, rr)

		// Transport shutdown sets rr.err and closes rr.recv WITHOUT evicting the
		// request, so no one has settled the loan yet.
		errShutdown := errors.New("transport shut down")
		c.outstandingRequests.shutdown(errShutdown)

		// recv takes the pkt arm on the closed channel, sees rr.err, and refunds.
		_, err = c.recv(rr)
		require.ErrorIs(err, errShutdown)
		require.Equal(startBalance, len(c.account.balance),
			"the shutdown path must refund an unclaimed loan")

		// The loan was settled exactly once: a second claim yields nothing, so no
		// double refund is possible.
		require.Zero(rr.claimLoan(), "the loan must already be claimed")
	})
}
