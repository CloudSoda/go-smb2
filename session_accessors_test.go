package smb2

import (
	"context"
	"testing"

	"github.com/cloudsoda/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

// makeTestSession builds a minimal Session with the given fields set directly
// on the underlying conn/session structs (white-box, same package).
func makeTestSession(dialect uint16, requireSigning bool, sessionFlags uint16, cipherId uint16) *Session {
	c := &conn{
		dialect:        dialect,
		requireSigning: requireSigning,
		cipherId:       cipherId,
	}
	s := &session{
		conn:         c,
		sessionFlags: sessionFlags,
	}
	return &Session{s: s, ctx: context.Background()}
}

// makeTestShare builds a minimal Share with the given session and share flags.
func makeTestShare(sessionFlags uint16, shareFlags uint32) *Share {
	c := &conn{}
	s := &session{conn: c, sessionFlags: sessionFlags}
	tc := &treeConn{session: s, shareFlags: shareFlags}
	return &Share{treeConn: tc, ctx: context.Background()}
}

// ----------------------------------------------------------------------------
// Session.Dialect()
// ----------------------------------------------------------------------------

func TestSession_Dialect(t *testing.T) {
	tests := []struct {
		name    string
		dialect uint16
	}{
		{"SMB202", DialectSMB202},
		{"SMB210", DialectSMB210},
		{"SMB300", DialectSMB300},
		{"SMB302", DialectSMB302},
		{"SMB311", DialectSMB311},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sess := makeTestSession(tc.dialect, false, 0, 0)
			require.Equal(t, tc.dialect, sess.Dialect())
		})
	}
}

// ----------------------------------------------------------------------------
// Session.IsSigned()
// ----------------------------------------------------------------------------

func TestSession_IsSigned(t *testing.T) {
	t.Run("RequireSigning_True", func(t *testing.T) {
		sess := makeTestSession(DialectSMB311, true, 0, 0)
		require.True(t, sess.IsSigned())
	})

	t.Run("RequireSigning_False", func(t *testing.T) {
		sess := makeTestSession(DialectSMB311, false, 0, 0)
		require.False(t, sess.IsSigned())
	})
}

// ----------------------------------------------------------------------------
// Session.IsEncrypted()
// ----------------------------------------------------------------------------

func TestSession_IsEncrypted(t *testing.T) {
	t.Run("SessionFlagSet_True", func(t *testing.T) {
		sess := makeTestSession(DialectSMB311, false, smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA, 0)
		require.True(t, sess.IsEncrypted())
	})

	t.Run("SessionFlagNotSet_False", func(t *testing.T) {
		sess := makeTestSession(DialectSMB311, false, 0, 0)
		require.False(t, sess.IsEncrypted())
	})

	t.Run("OtherFlagsSet_NotEncrypted", func(t *testing.T) {
		// IS_GUEST and IS_NULL must not be confused with ENCRYPT_DATA.
		flags := uint16(smb2.SMB2_SESSION_FLAG_IS_GUEST | smb2.SMB2_SESSION_FLAG_IS_NULL)
		sess := makeTestSession(DialectSMB210, false, flags, 0)
		require.False(t, sess.IsEncrypted())
	})
}

// ----------------------------------------------------------------------------
// Session.CipherID()
// ----------------------------------------------------------------------------

func TestSession_CipherID(t *testing.T) {
	t.Run("NoCipher_Zero", func(t *testing.T) {
		sess := makeTestSession(DialectSMB302, false, 0, 0)
		require.Equal(t, uint16(0), sess.CipherID())
	})

	t.Run("AES128CCM", func(t *testing.T) {
		sess := makeTestSession(DialectSMB311, false, smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA, smb2.AES128CCM)
		require.Equal(t, CipherAES128CCM, sess.CipherID())
	})

	t.Run("AES128GCM", func(t *testing.T) {
		sess := makeTestSession(DialectSMB311, false, smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA, smb2.AES128GCM)
		require.Equal(t, CipherAES128GCM, sess.CipherID())
	})
}

// ----------------------------------------------------------------------------
// Share.IsEncrypted()
// ----------------------------------------------------------------------------

func TestShare_IsEncrypted(t *testing.T) {
	const encSession = smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA
	const encShare = smb2.SMB2_SHAREFLAG_ENCRYPT_DATA

	t.Run("SessionFlagSet_ShareFlagNotSet_True", func(t *testing.T) {
		sh := makeTestShare(encSession, 0)
		require.True(t, sh.IsEncrypted())
	})

	t.Run("SessionFlagNotSet_ShareFlagSet_True", func(t *testing.T) {
		sh := makeTestShare(0, encShare)
		require.True(t, sh.IsEncrypted())
	})

	t.Run("BothFlagsSet_True", func(t *testing.T) {
		sh := makeTestShare(encSession, encShare)
		require.True(t, sh.IsEncrypted())
	})

	t.Run("NeitherFlagSet_False", func(t *testing.T) {
		sh := makeTestShare(0, 0)
		require.False(t, sh.IsEncrypted())
	})
}
