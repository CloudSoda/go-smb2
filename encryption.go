package smb2

import (
	"errors"
	"fmt"

	"github.com/cloudsoda/go-smb2/internal/smb2"
)

// ErrEncryptionRequired is returned (wrapped) by Dial and DialConn when
// Negotiator.RequireEncryption is set and the connection cannot be encrypted.
var ErrEncryptionRequired = errors.New("smb2: encryption required but not available")

// errUnencryptedResponse is what a request gets when the server answers in
// clear on an encrypted-only connection: an active attacker stripping the
// encryption, or a broken server. The response is refused, not delivered.
var errUnencryptedResponse = &InvalidResponseError{"unencrypted response on an encrypted-only connection"}

// Encrypted reports whether the session's traffic is encrypted: the server
// set SMB2_SESSION_FLAG_ENCRYPT_DATA, or the dialer required encryption.
func (c *Session) Encrypted() bool {
	return c.s.encrypted()
}

// Encrypted reports whether the traffic of this share is encrypted: the
// session is encrypted, or the server marked the share SMB2_SHAREFLAG_ENCRYPT_DATA.
func (fs *Share) Encrypted() bool {
	return fs.treeConn.session.encrypted() || fs.treeConn.shareFlags&smb2.SMB2_SHAREFLAG_ENCRYPT_DATA != 0
}

// checkEncryptionKeys refuses a session that cannot be encrypted when the
// dialer required it: no keys were derived (a guest or anonymous session has
// no session key) or the final flags say guest or anonymous.
func (s *session) checkEncryptionKeys() error {
	if !s.requireEncryption {
		return nil
	}
	if s.encrypter == nil || s.decrypter == nil ||
		s.sessionFlags&(smb2.SMB2_SESSION_FLAG_IS_GUEST|smb2.SMB2_SESSION_FLAG_IS_NULL) != 0 {
		return fmt.Errorf("%w: a guest or anonymous session has no encryption key", ErrEncryptionRequired)
	}
	return nil
}

// admit ends session setup: a session that fails the encryption requirement is
// refused, otherwise the receiver is allowed to use it.
func (s *session) admit() (*session, error) {
	if err := s.checkEncryptionKeys(); err != nil {
		return nil, err
	}

	// now, allow access from receiver
	s.useSession.Store(true)

	return s, nil
}

func (s *session) encrypted() bool {
	return s.encrypter != nil && (s.requireEncryption || s.sessionFlags&smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA != 0)
}
