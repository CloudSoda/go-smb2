package smb2

// White-box tests hardening the single-owner credit settlement rule introduced
// by the double-settlement fix: each requestResponse carries its loan in an
// atomic; claimLoan swap-takes it exactly once, so whichever of the receiver or
// a failure path evicts the request settles the loan, and the loser's refund
// becomes a no-op charge of zero. The paths covered here — tryHandle's
// STATUS_PENDING arm and recv's two refund arms with a nonzero, unclaimed
// loan — were previously untested.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cloudsoda/go-smb2/internal/erref"
	"github.com/cloudsoda/go-smb2/internal/smb2"
)

// startBalance is the spendable credit count after opening a fresh test account
// up from its initial single credit.
const startBalance = 9

// TestPendingResponseSettlesLoanOnce is a regression guard for tryHandle's
// STATUS_PENDING arm, which was previously untested. An interim
// STATUS_PENDING response settles the loan (it banks the server's grant and
// claims the loan) and re-registers the request, so a caller that later abandons
// the request must NOT receive a second refund.
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
// claimed, so the refund itself is never exercised there.
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
