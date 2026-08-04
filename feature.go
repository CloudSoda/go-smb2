package smb2

import (
	"github.com/cloudsoda/go-smb2/internal/smb2"
)

// client

const (
	clientCapabilities = smb2.SMB2_GLOBAL_CAP_LARGE_MTU | smb2.SMB2_GLOBAL_CAP_ENCRYPTION
)

var (
	clientHashAlgorithms = []uint16{smb2.SHA512}
	clientCiphers        = []uint16{smb2.AES256GCM, smb2.AES256CCM, smb2.AES128GCM, smb2.AES128CCM}
	clientDialects       = []uint16{smb2.SMB311, smb2.SMB302, smb2.SMB300, smb2.SMB210, smb2.SMB202}
)

// Cipher algorithm IDs for SMB 3.x encryption, as returned by Session.CipherID().
const (
	CipherAES128CCM uint16 = smb2.AES128CCM // AES-128-CCM (SMB 3.0, 3.0.2, 3.1.1)
	CipherAES128GCM uint16 = smb2.AES128GCM // AES-128-GCM (SMB 3.1.1 only)
	CipherAES256CCM uint16 = smb2.AES256CCM // AES-256-CCM (SMB 3.1.1 only)
	CipherAES256GCM uint16 = smb2.AES256GCM // AES-256-GCM (SMB 3.1.1 only)
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
