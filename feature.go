package smb2

import (
	. "github.com/cloudsoda/go-smb2/internal/smb2"
)

// client

const (
	clientCapabilities = SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_ENCRYPTION
)

var (
	clientHashAlgorithms = []uint16{SHA512}
	clientCiphers        = []uint16{AES128GCM, AES128CCM}
	clientDialects       = []uint16{SMB311, SMB302, SMB300, SMB210, SMB202}
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
