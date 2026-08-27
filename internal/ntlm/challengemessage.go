package ntlm

import (
	"bytes"
	"errors"

	"github.com/cloudsoda/go-smb2/internal/utf16le"
)

type ChallengeMessage struct {
	raw        []byte
	flags      uint32
	info       *targetInfoEncoder
	targetName []byte
}

// Unmarshal parses the ChallengeMessage in cmsg and returns the result.
func UnmarshalChallengeMessage(cmsg, nmsg []byte, targetSPN string) (*ChallengeMessage, error) {
	//        ChallengeMessage
	//   0-8: Signature
	//  8-12: MessageType
	// 12-20: TargetNameFields
	// 20-24: NegotiateFlags
	// 24-32: ServerChallenge
	// 32-40: _
	// 40-48: TargetInfoFields
	// 48-56: Version
	//   56-: Payload
	if len(cmsg) < 48 {
		return nil, errors.New("message length is too short")
	}

	if !bytes.Equal(cmsg[:8], signature) {
		return nil, errors.New("invalid signature")
	}

	if le.Uint32(cmsg[8:12]) != NtLmChallenge {
		return nil, errors.New("invalid message type")
	}

	flags := le.Uint32(nmsg[12:16]) & le.Uint32(cmsg[20:24])

	// NTLMSSP_REQUEST_TARGET and NTLMSSP_NEGOTIATE_TARGET_INFO are requested
	// by the client and granted, or not, by the server. Requiring them refuses
	// servers that authenticate perfectly well without them, which is what
	// several NAS and embedded SMB implementations do. Windows and smbclient
	// both carry on, so their absence is handled rather than rejected.
	//
	// The cost is real and worth stating: with no target info there is no
	// MsvAvTimestamp and no server-supplied channel binding, so the NTLMv2
	// response cannot be bound to the server that asked for it, which is what
	// makes relaying harder. That is the server's choice to make, and refusing
	// to talk to it does not make the exchange safer, only absent.

	var targetName []byte
	if flags&NTLMSSP_REQUEST_TARGET != 0 {
		targetNameLen := le.Uint16(cmsg[12:14])    // cmsg.TargetNameLen
		targetNameMaxLen := le.Uint16(cmsg[14:16]) // cmsg.TargetNameMaxLen
		if targetNameMaxLen < targetNameLen {
			return nil, errors.New("invalid target name format")
		}
		targetNameBufferOffset := le.Uint32(cmsg[16:20]) // cmsg.TargetNameBufferOffset
		targetNameEnd := uint64(targetNameBufferOffset) + uint64(targetNameLen)
		if targetNameEnd > uint64(len(cmsg)) {
			return nil, errors.New("invalid target name format")
		}
		targetName = cmsg[targetNameBufferOffset:targetNameEnd] // cmsg.TargetName
	}

	// An empty AV pair list is a bare MsvAvEOL, which is what the encoder
	// expects every list to end with. A server that does not advertise
	// target info has no list to give, so it gets an empty one rather than
	// whatever the unadvertised fields happen to contain.
	targetInfo := []byte{0x00, 0x00, 0x00, 0x00}
	if flags&NTLMSSP_NEGOTIATE_TARGET_INFO != 0 {
		targetInfoLen := le.Uint16(cmsg[40:42])    // cmsg.TargetInfoLen
		targetInfoMaxLen := le.Uint16(cmsg[42:44]) // cmsg.TargetInfoMaxLen
		if targetInfoMaxLen < targetInfoLen {
			return nil, errors.New("invalid target info format")
		}
		targetInfoBufferOffset := le.Uint32(cmsg[44:48]) // cmsg.TargetInfoBufferOffset
		targetInfoEnd := uint64(targetInfoBufferOffset) + uint64(targetInfoLen)
		if targetInfoEnd > uint64(len(cmsg)) {
			return nil, errors.New("invalid target info format")
		}
		targetInfo = cmsg[targetInfoBufferOffset:targetInfoEnd] // cmsg.TargetInfo
	}

	info := newTargetInfoEncoder(targetInfo, utf16le.Encode(targetSPN, utf16le.MapCharsNone))
	if info == nil {
		return nil, errors.New("invalid target info format")
	}

	return &ChallengeMessage{
		raw:        cmsg,
		flags:      flags,
		info:       info,
		targetName: targetName,
	}, nil
}
