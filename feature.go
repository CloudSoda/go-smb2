package smb2

import (
	"github.com/cloudsoda/go-smb2/internal/smb2"
)

// SMB dialects, in the order the protocol ranks them. Use them with
// Negotiator.MinDialect and Negotiator.MaxDialect to bound what the client
// will speak, or with Negotiator.SpecifiedDialect to pin exactly one.
const (
	SMB202 uint16 = 0x202
	SMB210 uint16 = 0x210
	SMB300 uint16 = 0x300
	SMB302 uint16 = 0x302
	SMB311 uint16 = 0x311
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
