package smb2

import (
	"net"
	"testing"

	"github.com/cloudsoda/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
// negotiate() — conn field verification after successful negotiate
// ----------------------------------------------------------------------------

// TestNegotiateEncryptionConnState verifies that the conn fields backing
// Session.IsEncrypted() and Session.Dialect() are stored correctly.
func TestNegotiateEncryptionConnState(t *testing.T) {
	const encCap = smb2.SMB2_GLOBAL_CAP_ENCRYPTION

	negotiate := func(t *testing.T, n *Negotiator, serverDialect uint16, serverCaps uint32) *conn {
		t.Helper()
		clientConn, serverConn := net.Pipe()
		go fakeNegotiateServerWithCaps(direct(serverConn), serverDialect, serverCaps)
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

	t.Run("RequireEncryption_StoredOnConn", func(t *testing.T) {
		c := negotiate(t, &Negotiator{RequireMessageEncryption: true}, smb2.SMB302, encCap)
		require.True(t, c.requireEncryption)
	})

	t.Run("NoRequireEncryption_ConnFlagFalse", func(t *testing.T) {
		c := negotiate(t, &Negotiator{}, smb2.SMB302, 0)
		require.False(t, c.requireEncryption)
	})

	t.Run("DialectStoredOnConn_WithEncryption", func(t *testing.T) {
		c := negotiate(t, &Negotiator{RequireMessageEncryption: true}, smb2.SMB302, encCap)
		require.Equal(t, uint16(smb2.SMB302), c.dialect)
	})
}

// ----------------------------------------------------------------------------
// makeRequest() — RequireMessageEncryption dialect filtering (no network)
// ----------------------------------------------------------------------------

func TestMakeRequestEncryptionDialectFiltering(t *testing.T) {
	dialectsOf := func(t *testing.T, n *Negotiator) []uint16 {
		t.Helper()
		req, err := n.makeRequest()
		require.NoError(t, err)
		return req.Dialects
	}

	t.Run("RequireEncryption_NoConstraints_AdvertisesOnlySMB3x", func(t *testing.T) {
		n := &Negotiator{RequireMessageEncryption: true}
		got := dialectsOf(t, n)
		for _, d := range got {
			require.GreaterOrEqual(t, d, uint16(smb2.SMB300),
				"dialect %#x is below SMB 3.0 but encryption was required", d)
		}
		require.NotContains(t, got, uint16(smb2.SMB202))
		require.NotContains(t, got, uint16(smb2.SMB210))
		require.Contains(t, got, uint16(smb2.SMB311))
		require.Contains(t, got, uint16(smb2.SMB302))
		require.Contains(t, got, uint16(smb2.SMB300))
	})

	t.Run("RequireEncryption_MaxSMB300_AdvertisesSMB300Only", func(t *testing.T) {
		n := &Negotiator{RequireMessageEncryption: true, MaxDialect: DialectSMB300}
		got := dialectsOf(t, n)
		require.Equal(t, []uint16{smb2.SMB300}, got)
	})

	t.Run("RequireEncryption_MaxSMB302_AdvertisesSMB300AndSMB302", func(t *testing.T) {
		n := &Negotiator{RequireMessageEncryption: true, MaxDialect: DialectSMB302}
		got := dialectsOf(t, n)
		require.ElementsMatch(t, []uint16{smb2.SMB302, smb2.SMB300}, got)
		require.NotContains(t, got, uint16(smb2.SMB311))
		require.NotContains(t, got, uint16(smb2.SMB210))
	})

	t.Run("RequireEncryption_MinSMB311_AdvertisesSMB311Only", func(t *testing.T) {
		// Caller's MinDialect >= SMB300: respected as-is.
		n := &Negotiator{RequireMessageEncryption: true, MinDialect: DialectSMB311}
		got := dialectsOf(t, n)
		require.Equal(t, []uint16{smb2.SMB311}, got)
	})

	t.Run("RequireEncryption_MinSMB210_RaisedToSMB300", func(t *testing.T) {
		// MinDialect below SMB 3.0 is silently raised to SMB300.
		n := &Negotiator{RequireMessageEncryption: true, MinDialect: DialectSMB210}
		got := dialectsOf(t, n)
		for _, d := range got {
			require.GreaterOrEqual(t, d, uint16(smb2.SMB300),
				"dialect %#x should have been excluded by auto-raise to SMB 3.0", d)
		}
	})

	t.Run("RequireEncryption_MaxBelowSMB300_ReturnsError", func(t *testing.T) {
		n := &Negotiator{RequireMessageEncryption: true, MaxDialect: DialectSMB210}
		_, err := n.makeRequest()
		require.Error(t, err)
		require.IsType(t, &InternalError{}, err)
		require.ErrorContains(t, err, "SMB 3.0")
	})

	t.Run("RequireEncryption_MaxSMB202_ReturnsError", func(t *testing.T) {
		n := &Negotiator{RequireMessageEncryption: true, MaxDialect: DialectSMB202}
		_, err := n.makeRequest()
		require.Error(t, err)
		require.IsType(t, &InternalError{}, err)
	})

	t.Run("NoEncryption_MaxSMB210_AdvertisesSMB2xDialects", func(t *testing.T) {
		// Baseline: without RequireMessageEncryption the old behaviour is unchanged.
		n := &Negotiator{MaxDialect: DialectSMB210}
		got := dialectsOf(t, n)
		require.NotContains(t, got, uint16(smb2.SMB311))
		require.Contains(t, got, uint16(smb2.SMB210))
		require.Contains(t, got, uint16(smb2.SMB202))
	})
}

// ----------------------------------------------------------------------------
// negotiate() — RequireMessageEncryption capability enforcement (fake server)
// ----------------------------------------------------------------------------

// fakeNegotiateServerWithCaps is like fakeNegotiateServer but also sets the
// Capabilities field in the NEGOTIATE response, allowing tests to control
// whether SMB2_GLOBAL_CAP_ENCRYPTION is advertised.
func fakeNegotiateServerWithCaps(t transport, dialectRevision uint16, caps uint32) {
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
		Capabilities:    caps,
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

func TestNegotiateEncryptionEnforcement(t *testing.T) {
	const encCap = smb2.SMB2_GLOBAL_CAP_ENCRYPTION

	negotiate := func(t *testing.T, n *Negotiator, serverDialect uint16, serverCaps uint32) error {
		t.Helper()
		clientConn, serverConn := net.Pipe()
		go fakeNegotiateServerWithCaps(direct(serverConn), serverDialect, serverCaps)
		defer serverConn.Close()
		return runNegotiate(clientConn, n)
	}

	t.Run("RequireEncryption_ServerAdvertisesCap_Succeeds", func(t *testing.T) {
		err := negotiate(t,
			&Negotiator{RequireMessageEncryption: true},
			smb2.SMB302, encCap)
		require.NoError(t, err)
	})

	t.Run("RequireEncryption_ServerNoCap_Fails", func(t *testing.T) {
		err := negotiate(t,
			&Negotiator{RequireMessageEncryption: true},
			smb2.SMB302, 0)
		require.Error(t, err)
		require.IsType(t, &InvalidResponseError{}, err)
		require.ErrorContains(t, err, "encryption")
	})

	t.Run("RequireEncryption_WithMinSMB300_ServerSMB300WithCap_Succeeds", func(t *testing.T) {
		err := negotiate(t,
			&Negotiator{RequireMessageEncryption: true, MinDialect: DialectSMB300},
			smb2.SMB300, encCap)
		require.NoError(t, err)
	})

	t.Run("RequireEncryption_WithMaxSMB302_ServerSMB300WithCap_Succeeds", func(t *testing.T) {
		err := negotiate(t,
			&Negotiator{RequireMessageEncryption: true, MaxDialect: DialectSMB302},
			smb2.SMB300, encCap)
		require.NoError(t, err)
	})

	t.Run("NoRequireEncryption_ServerNoCap_Succeeds", func(t *testing.T) {
		// Baseline: without RequireMessageEncryption the cap is not checked.
		err := negotiate(t,
			&Negotiator{},
			smb2.SMB302, 0)
		require.NoError(t, err)
	})

	t.Run("RequireEncryption_ServerSMB210_Fails", func(t *testing.T) {
		// SMB 2.x server: the auto-raised min should prevent this dialect from
		// being advertised, but even if the server somehow selected it, the
		// capability check would catch the lack of encryption support.
		// Here we test with MaxDialect=SMB302 so SMB210 would be below min.
		err := negotiate(t,
			&Negotiator{RequireMessageEncryption: true},
			smb2.SMB210, 0)
		require.Error(t, err)
		require.ErrorContains(t, err, "encryption")
	})
}
