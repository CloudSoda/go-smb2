package smb2

import (
	"github.com/cloudsoda/go-smb2/internal/smb2"
)

// Dialect version constants for use with Negotiator.MinDialect and
// Negotiator.MaxDialect.
//
// Numeric values match the DialectRevision field in the SMB2 NEGOTIATE
// request/response (MS-SMB2 §2.2.3 / §2.2.4). Higher values represent newer
// protocol versions with stronger security guarantees:
//
//   - SMB 2.0.2 / 2.1: no transport encryption; signing uses HMAC-SHA256.
//   - SMB 3.0 / 3.0.2: AES-128-CCM encryption available; signing uses AES-CMAC.
//   - SMB 3.1.1: mandatory pre-auth integrity (SHA-512); AES-128-GCM or
//     AES-128-CCM encryption; signing uses AES-CMAC or AES-GMAC.
//
// For new deployments, setting MinDialect to DialectSMB300 or DialectSMB311 is
// strongly recommended so that a MitM or misconfigured server cannot downgrade
// the connection to a dialect without encryption support.
const (
	DialectSMB202 uint16 = smb2.SMB202 // SMB 2.0.2 — no encryption, HMAC-SHA256 signing
	DialectSMB210 uint16 = smb2.SMB210 // SMB 2.1   — no encryption, HMAC-SHA256 signing
	DialectSMB300 uint16 = smb2.SMB300 // SMB 3.0   — AES-128-CCM encryption, AES-CMAC signing
	DialectSMB302 uint16 = smb2.SMB302 // SMB 3.0.2 — AES-128-CCM encryption, AES-CMAC signing
	DialectSMB311 uint16 = smb2.SMB311 // SMB 3.1.1 — AES-GCM/CCM encryption, pre-auth integrity
)

// Cipher algorithm constants for use with Session.CipherID.
// These values match the CipherId field in the SMB2_ENCRYPTION_CAPABILITIES
// negotiate context (MS-SMB2 §2.2.3.1.2).
//
// Both ciphers are AES-128; the difference is the mode of operation.
// AES-128-GCM (DialectSMB311 only) is generally preferred over AES-128-CCM
// because GCM is more widely hardware-accelerated.
const (
	CipherAES128CCM uint16 = smb2.AES128CCM // AES-128-CCM (SMB 3.0, 3.0.2, 3.1.1)
	CipherAES128GCM uint16 = smb2.AES128GCM // AES-128-GCM (SMB 3.1.1 only)
)

// client

const (
	clientCapabilities = smb2.SMB2_GLOBAL_CAP_LARGE_MTU | smb2.SMB2_GLOBAL_CAP_ENCRYPTION
)

var (
	clientHashAlgorithms = []uint16{smb2.SHA512}
	clientCiphers        = []uint16{smb2.AES128GCM, smb2.AES128CCM}
	clientDialects       = []uint16{smb2.SMB311, smb2.SMB302, smb2.SMB300, smb2.SMB210, smb2.SMB202}
)

const (
	clientMaxCreditBalance = 128
)

const (
	clientMaxSymlinkDepth = 8
)

// Mapping strategies that can be used when a reserved character is encountered
// in a file name.
type MapChars int

const (
	// Don't map reserved characters
	MapCharsNone MapChars = 0
	// Map reserved characters using the Services for Mac scheme. This is
	// equivalent to using the 'mapposix' when mounting a volume in Linux.
	MapCharsSFM MapChars = 1
	// Map reserved characters using the Services for Unix scheme. This is
	// equivalent to using 'mapchars' when mounting a volume in Linux.
	MapCharsSFU MapChars = 2
)
