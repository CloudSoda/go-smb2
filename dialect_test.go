package smb2

import (
	"context"
	"net"
	"sort"
	"testing"

	"github.com/cloudsoda/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
// makeRequest dialect filtering (no network required)
// ----------------------------------------------------------------------------

func TestMakeRequestDialectFiltering(t *testing.T) {
	// allDialects is the full ordered list the library advertises by default
	// (highest first, matching clientDialects in feature.go).
	allDialects := []uint16{smb2.SMB311, smb2.SMB302, smb2.SMB300, smb2.SMB210, smb2.SMB202}

	dialectsOf := func(t *testing.T, n *Negotiator) []uint16 {
		t.Helper()
		req, err := n.makeRequest()
		require.NoError(t, err)
		return req.Dialects
	}

	t.Run("NoConstraint_AdvertisesAll", func(t *testing.T) {
		n := &Negotiator{}
		got := dialectsOf(t, n)
		require.Equal(t, allDialects, got)
	})

	t.Run("MinDialect_SMB300_DropsOlderOnes", func(t *testing.T) {
		n := &Negotiator{MinDialect: DialectSMB300}
		got := dialectsOf(t, n)
		for _, d := range got {
			require.GreaterOrEqual(t, d, uint16(DialectSMB300), "dialect %#x is below MinDialect", d)
		}
		require.NotContains(t, got, uint16(DialectSMB202))
		require.NotContains(t, got, uint16(DialectSMB210))
	})

	t.Run("MaxDialect_SMB302_DropsNewerOnes", func(t *testing.T) {
		n := &Negotiator{MaxDialect: DialectSMB302}
		got := dialectsOf(t, n)
		for _, d := range got {
			require.LessOrEqual(t, d, uint16(DialectSMB302), "dialect %#x is above MaxDialect", d)
		}
		require.NotContains(t, got, uint16(DialectSMB311))
	})

	t.Run("MinAndMax_SMB300ToSMB302_ExactRange", func(t *testing.T) {
		n := &Negotiator{MinDialect: DialectSMB300, MaxDialect: DialectSMB302}
		got := dialectsOf(t, n)
		want := []uint16{smb2.SMB302, smb2.SMB300}
		// sort both to make comparison order-independent
		sort.Slice(got, func(i, j int) bool { return got[i] > got[j] })
		require.Equal(t, want, got)
	})

	t.Run("MinAndMax_SameDialect_SingleEntry", func(t *testing.T) {
		n := &Negotiator{MinDialect: DialectSMB311, MaxDialect: DialectSMB311}
		got := dialectsOf(t, n)
		require.Equal(t, []uint16{smb2.SMB311}, got)
	})

	t.Run("MinDialectHigherThanAnySupported_ReturnsError", func(t *testing.T) {
		n := &Negotiator{MinDialect: 0x0400} // hypothetical future dialect
		_, err := n.makeRequest()
		require.Error(t, err)
		require.IsType(t, &InternalError{}, err)
	})

	t.Run("MaxDialectLowerThanAnySupported_ReturnsError", func(t *testing.T) {
		n := &Negotiator{MaxDialect: 0x0100} // below SMB 2.0.2
		_, err := n.makeRequest()
		require.Error(t, err)
		require.IsType(t, &InternalError{}, err)
	})

	t.Run("MinAboveMax_EmptyRange_ReturnsError", func(t *testing.T) {
		n := &Negotiator{MinDialect: DialectSMB311, MaxDialect: DialectSMB300}
		_, err := n.makeRequest()
		require.Error(t, err)
		require.IsType(t, &InternalError{}, err)
	})

	t.Run("MinEqualsMax_PinsToSingleDialect", func(t *testing.T) {
		// Using MinDialect == MaxDialect is the public way to pin to one dialect.
		n := &Negotiator{MinDialect: DialectSMB302, MaxDialect: DialectSMB302}
		got := dialectsOf(t, n)
		require.Equal(t, []uint16{smb2.SMB302}, got)
	})
}

// ----------------------------------------------------------------------------
// negotiate() dialect enforcement (uses a minimal fake NEGOTIATE server)
// ----------------------------------------------------------------------------

// fakeNegotiateServer reads one NEGOTIATE request from t and writes back a
// NegotiateResponse with the given dialectRevision, then returns.  It is
// intentionally minimal: security buffers and negotiate contexts are empty so
// that the client side only needs to parse the dialect field.
func fakeNegotiateServer(t transport, dialectRevision uint16) {
	// Drain the incoming request.
	n, err := t.ReadSize()
	if err != nil {
		return
	}
	buf := make([]byte, n)
	if _, err := t.Read(buf); err != nil {
		return
	}
	p := smb2.PacketCodec(buf)

	resp := &smb2.NegotiateResponse{
		PacketHeader: smb2.PacketHeader{
			Flags:                 smb2.SMB2_FLAGS_SERVER_TO_REDIR,
			MessageId:             p.MessageId(),
			CreditRequestResponse: 1,
		},
		SecurityMode:    smb2.SMB2_NEGOTIATE_SIGNING_ENABLED,
		DialectRevision: dialectRevision,
		MaxTransactSize: 65536,
		MaxReadSize:     65536,
		MaxWriteSize:    65536,
		SystemTime:      &smb2.Filetime{},
		ServerStartTime: &smb2.Filetime{},
	}

	out := make([]byte, resp.Size())
	resp.Encode(out)
	_, _ = t.Write(out)
}

func runNegotiate(clientConn net.Conn, n *Negotiator) error {
	t := direct(clientConn)
	a := openAccount(clientMaxCreditBalance)
	ctx := context.Background()
	conn, err := n.negotiate(ctx, t, a)
	if conn != nil {
		conn.rdone <- struct{}{}
		clientConn.Close()
	}
	return err
}

// runNegotiateConn is like runNegotiate but returns the resulting conn on
// success so callers can inspect its fields.  The caller is responsible for
// cleanup (e.g. via t.Cleanup): c.rdone <- struct{}{}; clientConn.Close().
// On error the conn is nil and the underlying pipe goroutines will terminate
// naturally when serverConn is closed by the caller's defer.
func runNegotiateConn(clientConn net.Conn, n *Negotiator) (*conn, error) {
	c, err := n.negotiate(context.Background(), direct(clientConn), openAccount(clientMaxCreditBalance))
	return c, err
}

// TestNegotiateDialectConnState verifies that the fields on *conn that back
// the public Session accessors are written correctly during negotiate().
func TestNegotiateDialectConnState(t *testing.T) {
	negotiate := func(t *testing.T, n *Negotiator, serverDialect uint16) *conn {
		t.Helper()
		clientConn, serverConn := net.Pipe()
		go fakeNegotiateServer(direct(serverConn), serverDialect)
		defer serverConn.Close()
		c, err := runNegotiateConn(clientConn, n)
		require.NoError(t, err)
		require.NotNil(t, c)
		t.Cleanup(func() {
			c.rdone <- struct{}{}
			clientConn.Close()
		})
		return c
	}

	t.Run("DialectStoredOnConn", func(t *testing.T) {
		c := negotiate(t, &Negotiator{}, smb2.SMB302)
		require.Equal(t, uint16(smb2.SMB302), c.dialect)
	})

	t.Run("RequireSigning_StoredOnConn", func(t *testing.T) {
		c := negotiate(t, &Negotiator{RequireMessageSigning: true}, smb2.SMB302)
		require.True(t, c.requireSigning)
	})

	t.Run("NoRequireSigning_ConnFlagFalse", func(t *testing.T) {
		// fakeNegotiateServer sets SecurityMode = SIGNING_ENABLED (not REQUIRED),
		// so requireSigning should stay false when the Negotiator doesn't set it.
		c := negotiate(t, &Negotiator{}, smb2.SMB302)
		require.False(t, c.requireSigning)
	})
}

func TestNegotiateDialectEnforcement(t *testing.T) {
	negotiate := func(t *testing.T, n *Negotiator, serverDialect uint16) error {
		t.Helper()
		clientConn, serverConn := net.Pipe()
		go fakeNegotiateServer(direct(serverConn), serverDialect)
		defer serverConn.Close()
		return runNegotiate(clientConn, n)
	}

	t.Run("ServerMeetsMinDialect_Succeeds", func(t *testing.T) {
		err := negotiate(t, &Negotiator{MinDialect: DialectSMB300}, smb2.SMB302)
		require.NoError(t, err)
	})

	t.Run("ServerEqualsMinDialect_Succeeds", func(t *testing.T) {
		err := negotiate(t, &Negotiator{MinDialect: DialectSMB300}, smb2.SMB300)
		require.NoError(t, err)
	})

	t.Run("ServerBelowMinDialect_Fails", func(t *testing.T) {
		err := negotiate(t, &Negotiator{MinDialect: DialectSMB300}, smb2.SMB210)
		require.Error(t, err)
		require.IsType(t, &InvalidResponseError{}, err)
		require.ErrorContains(t, err, "minimum")
	})

	t.Run("ServerMeetsMaxDialect_Succeeds", func(t *testing.T) {
		err := negotiate(t, &Negotiator{MaxDialect: DialectSMB311}, smb2.SMB302)
		require.NoError(t, err)
	})

	t.Run("ServerEqualsMaxDialect_Succeeds", func(t *testing.T) {
		err := negotiate(t, &Negotiator{MaxDialect: DialectSMB302}, smb2.SMB302)
		require.NoError(t, err)
	})

	t.Run("ServerAboveMaxDialect_Fails", func(t *testing.T) {
		// Use a hypothetical dialect between SMB302 and SMB311 so the
		// NegotiateResponseDecoder.IsInvalid() check (which has special logic
		// only for SMB311) does not trigger first, letting our MaxDialect
		// check produce the expected error.
		const hypotheticalSMB304 uint16 = 0x0304
		err := negotiate(t, &Negotiator{MaxDialect: DialectSMB302}, hypotheticalSMB304)
		require.Error(t, err)
		require.IsType(t, &InvalidResponseError{}, err)
		require.ErrorContains(t, err, "maximum")
	})

	t.Run("ServerWithinMinMaxRange_Succeeds", func(t *testing.T) {
		err := negotiate(t, &Negotiator{MinDialect: DialectSMB300, MaxDialect: DialectSMB311}, smb2.SMB302)
		require.NoError(t, err)
	})

	t.Run("ServerOutsideRange_BelowMin_Fails", func(t *testing.T) {
		err := negotiate(t, &Negotiator{MinDialect: DialectSMB300, MaxDialect: DialectSMB311}, smb2.SMB210)
		require.Error(t, err)
		require.IsType(t, &InvalidResponseError{}, err)
	})

	t.Run("NoConstraint_AnyDialect_Succeeds", func(t *testing.T) {
		err := negotiate(t, &Negotiator{}, smb2.SMB302)
		require.NoError(t, err)
	})
}
