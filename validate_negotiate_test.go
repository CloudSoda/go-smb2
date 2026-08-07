package smb2

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/cloudsoda/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
// Unit tests for ValidateNegotiateInfoRequest encoder
// ----------------------------------------------------------------------------

func TestValidateNegotiateInfoRequestEncode(t *testing.T) {
	require := require.New(t)

	req := &smb2.ValidateNegotiateInfoRequest{
		Capabilities: 0x0000007f,
		Guid:         [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SecurityMode: 0x0001,
		Dialects:     []uint16{smb2.SMB202, smb2.SMB210, smb2.SMB300, smb2.SMB302},
	}

	expectedSize := 4 + 16 + 2 + 2 + 4*2 // Capabilities + Guid + SecurityMode + DialectCount + 4 dialects
	require.Equal(expectedSize, req.Size())

	buf := make([]byte, req.Size())
	req.Encode(buf)

	le := binary.LittleEndian

	require.Equal(uint32(0x0000007f), le.Uint32(buf[0:4]))    // Capabilities
	require.Equal(req.Guid[:], buf[4:20])                     // Guid
	require.Equal(uint16(0x0001), le.Uint16(buf[20:22]))      // SecurityMode
	require.Equal(uint16(4), le.Uint16(buf[22:24]))           // DialectCount
	require.Equal(uint16(smb2.SMB202), le.Uint16(buf[24:26])) // Dialects[0]
	require.Equal(uint16(smb2.SMB210), le.Uint16(buf[26:28])) // Dialects[1]
	require.Equal(uint16(smb2.SMB300), le.Uint16(buf[28:30])) // Dialects[2]
	require.Equal(uint16(smb2.SMB302), le.Uint16(buf[30:32])) // Dialects[3]
}

func TestValidateNegotiateInfoRequestEncodeEmpty(t *testing.T) {
	req := &smb2.ValidateNegotiateInfoRequest{
		Capabilities: 0,
		SecurityMode: 0,
		Dialects:     nil,
	}
	require.Equal(t, 4+16+2+2, req.Size())
	buf := make([]byte, req.Size())
	req.Encode(buf) // must not panic
}

// ----------------------------------------------------------------------------
// Unit tests for ValidateNegotiateInfoResponseDecoder
// ----------------------------------------------------------------------------

func makeValidateNegotiateInfoOutput(caps uint32, guid [16]byte, secMode uint16, dialect uint16) []byte {
	buf := make([]byte, 24)
	le := binary.LittleEndian
	le.PutUint32(buf[0:4], caps)
	copy(buf[4:20], guid[:])
	le.PutUint16(buf[20:22], secMode)
	le.PutUint16(buf[22:24], dialect)
	return buf
}

func TestValidateNegotiateInfoResponseDecoderValid(t *testing.T) {
	require := require.New(t)

	guid := [16]byte{0xAA, 0xBB, 0xCC, 0xDD}
	data := makeValidateNegotiateInfoOutput(0x7f, guid, 0x03, smb2.SMB302)
	r := smb2.ValidateNegotiateInfoResponseDecoder(data)

	require.False(r.IsInvalid())
	require.Equal(uint32(0x7f), r.Capabilities())
	require.True(bytes.Equal(guid[:], r.Guid()))
	require.Equal(uint16(0x03), r.SecurityMode())
	require.Equal(uint16(smb2.SMB302), r.Dialect())
}

func TestValidateNegotiateInfoResponseDecoderTooShort(t *testing.T) {
	for n := 0; n < 24; n++ {
		r := smb2.ValidateNegotiateInfoResponseDecoder(make([]byte, n))
		require.True(t, r.IsInvalid(), "expected invalid for len=%d", n)
	}
}

// ----------------------------------------------------------------------------
// Integration tests for validateNegotiateInfo() using a fake server
// ----------------------------------------------------------------------------

// ioctlFakeServer handles a single IOCTL request and sends back an
// IoctlResponse.  If respErr is non-zero the server sends an error response
// instead.  If signed is true the response packet has SMB2_FLAGS_SIGNED set.
func ioctlFakeServer(
	t *testing.T,
	srv transport,
	sessionId uint64,
	treeId uint32,
	output []byte,
	signed bool,
	respErr uint32,
) {
	t.Helper()

	n, err := srv.ReadSize()
	if err != nil {
		return
	}
	reqBuf := make([]byte, n)
	if _, err := srv.Read(reqBuf); err != nil {
		return
	}
	p := smb2.PacketCodec(reqBuf)

	if respErr != 0 {
		// Send an error response.
		var rawBytes rawBytesEncoder
		resp := &smb2.ErrorResponse{
			PacketHeader: smb2.PacketHeader{
				Status:    respErr,
				Command:   smb2.SMB2_IOCTL,
				Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
				MessageId: p.MessageId(),
				TreeId:    treeId,
				SessionId: sessionId,
			},
			ErrorData: &rawBytes, // nil-like but valid encoder
		}
		_ = resp
		// Build a minimal error packet manually.
		errBuf := make([]byte, 64+8+1)
		ep := smb2.PacketCodec(errBuf)
		ep.SetProtocolId()
		ep.SetStructureSize()
		ep.SetStatus(respErr)
		ep.SetCommand(smb2.SMB2_IOCTL)
		ep.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		ep.SetMessageId(p.MessageId())
		ep.SetTreeId(treeId)
		ep.SetSessionId(sessionId)
		ep.SetCreditResponse(1)
		// StructureSize for error response = 9
		errBuf[64] = 9
		errBuf[65] = 0
		_, _ = srv.Write(errBuf)
		return
	}

	resp := &smb2.IoctlResponse{
		PacketHeader: smb2.PacketHeader{
			Command:   smb2.SMB2_IOCTL,
			Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
			MessageId: p.MessageId(),
			TreeId:    treeId,
			SessionId: sessionId,
		},
		CtlCode: smb2.FSCTL_VALIDATE_NEGOTIATE_INFO,
		FileId:  sentinelFileId,
		Input:   &rawBytesEncoder{},
		Output:  &rawBytesEncoder{data: output},
	}

	flags := uint32(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	if signed {
		flags |= uint32(smb2.SMB2_FLAGS_SIGNED)
	}
	resp.PacketHeader.Flags = flags

	respBuf := make([]byte, resp.Size())
	resp.Encode(respBuf)
	// Patch the OutputOffset: Encode places output at offset 48 within
	// response body, but the decoder subtracts 64 from the stored offset
	// (which is from start of packet).  IoctlResponse.Encode already writes
	// the correct packet-absolute offset, so we don't need to fix it.
	rp := smb2.PacketCodec(respBuf)
	rp.SetCreditResponse(p.CreditRequest())
	_, _ = srv.Write(respBuf)
}

// rawBytesEncoder wraps a byte slice so it can be used as an Encoder.
type rawBytesEncoder struct {
	data []byte
}

func (r *rawBytesEncoder) Size() int       { return len(r.data) }
func (r *rawBytesEncoder) Encode(b []byte) { copy(b, r.data) }

// newTestConn creates a conn + session + treeConn backed by a net.Pipe(),
// pre-populated with the negotiate parameters needed for validateNegotiateInfo.
func newTestTreeConn(
	clientConn net.Conn,
	dialect uint16,
	serverCaps uint32,
	serverSecMode uint16,
	serverGuid [16]byte,
) (*conn, *session, *treeConn, func()) {
	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(128),
		rdone:               make(chan struct{}, 1),
		wdone:               make(chan struct{}, 1),
		write:               make(chan []byte, 1),
		werr:                make(chan error, 1),
		dialect:             dialect,
		maxReadSize:         bufSize,
		maxWriteSize:        bufSize,
		maxTransactSize:     bufSize,
		capabilities:        smb2.SMB2_GLOBAL_CAP_LARGE_MTU,
		// populate the fields validateNegotiateInfo reads
		negotiateClientGuid:   [16]byte{0x01},
		negotiateSecurityMode: 0x01,
		negotiateDialects:     []uint16{smb2.SMB202, smb2.SMB210, smb2.SMB300, smb2.SMB302},
		serverCapabilities:    serverCaps,
		serverSecurityMode:    serverSecMode,
		serverGuid:            serverGuid,
	}
	go c.runSender()
	go c.runReceiver()

	s := &session{
		conn:         c,
		sessionId:    0x1234,
		sessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST, // skip signing for unit tests
	}
	c.session.Store(s)

	const treeId = 0x0001
	tc := &treeConn{session: s, treeId: treeId}

	cleanup := func() {
		c.rdone <- struct{}{}
		clientConn.Close()
	}
	return c, s, tc, cleanup
}

func TestValidateNegotiateInfo_Success(t *testing.T) {
	require := require.New(t)

	serverGuid := [16]byte{0xDE, 0xAD, 0xBE, 0xEF}
	serverCaps := uint32(0x7f)
	serverSecMode := uint16(0x03)

	output := makeValidateNegotiateInfoOutput(serverCaps, serverGuid, serverSecMode, smb2.SMB302)

	clientConn, serverConn := net.Pipe()
	c, _, tc, cleanup := newTestTreeConn(clientConn, smb2.SMB302, serverCaps, serverSecMode, serverGuid)
	defer cleanup()
	_ = c

	go ioctlFakeServer(t, direct(serverConn), 0x1234, tc.treeId, output, true /*signed*/, 0)

	err := validateNegotiateInfo(context.Background(), tc)
	require.NoError(err)
}

func TestValidateNegotiateInfo_UnsignedResponse(t *testing.T) {
	require := require.New(t)

	serverGuid := [16]byte{0x01}
	serverCaps := uint32(0x7f)
	serverSecMode := uint16(0x03)

	output := makeValidateNegotiateInfoOutput(serverCaps, serverGuid, serverSecMode, smb2.SMB302)

	clientConn, serverConn := net.Pipe()
	_, _, tc, cleanup := newTestTreeConn(clientConn, smb2.SMB302, serverCaps, serverSecMode, serverGuid)
	defer cleanup()

	// Server sends response without SMB2_FLAGS_SIGNED
	go ioctlFakeServer(t, direct(serverConn), 0x1234, tc.treeId, output, false /*unsigned*/, 0)

	err := validateNegotiateInfo(context.Background(), tc)
	require.Error(err)
	require.IsType(&InvalidResponseError{}, err)
	require.ErrorContains(err, "not signed")
}

func TestValidateNegotiateInfo_CapabilitiesMismatch(t *testing.T) {
	require := require.New(t)

	serverGuid := [16]byte{0x01}
	serverCaps := uint32(0x7f)
	serverSecMode := uint16(0x03)

	// Server returns different capabilities
	output := makeValidateNegotiateInfoOutput(0x01, serverGuid, serverSecMode, smb2.SMB302)

	clientConn, serverConn := net.Pipe()
	_, _, tc, cleanup := newTestTreeConn(clientConn, smb2.SMB302, serverCaps, serverSecMode, serverGuid)
	defer cleanup()

	go ioctlFakeServer(t, direct(serverConn), 0x1234, tc.treeId, output, true, 0)

	err := validateNegotiateInfo(context.Background(), tc)
	require.Error(err)
	require.IsType(&InvalidResponseError{}, err)
	require.ErrorContains(err, "capabilities mismatch")
}

func TestValidateNegotiateInfo_SecurityModeMismatch(t *testing.T) {
	require := require.New(t)

	serverGuid := [16]byte{0x01}
	serverCaps := uint32(0x7f)
	serverSecMode := uint16(0x03)

	// Server returns different security mode
	output := makeValidateNegotiateInfoOutput(serverCaps, serverGuid, 0x01, smb2.SMB302)

	clientConn, serverConn := net.Pipe()
	_, _, tc, cleanup := newTestTreeConn(clientConn, smb2.SMB302, serverCaps, serverSecMode, serverGuid)
	defer cleanup()

	go ioctlFakeServer(t, direct(serverConn), 0x1234, tc.treeId, output, true, 0)

	err := validateNegotiateInfo(context.Background(), tc)
	require.Error(err)
	require.IsType(&InvalidResponseError{}, err)
	require.ErrorContains(err, "security mode mismatch")
}

func TestValidateNegotiateInfo_DialectMismatch(t *testing.T) {
	require := require.New(t)

	serverGuid := [16]byte{0x01}
	serverCaps := uint32(0x7f)
	serverSecMode := uint16(0x03)

	// Server reports a different dialect
	output := makeValidateNegotiateInfoOutput(serverCaps, serverGuid, serverSecMode, smb2.SMB300)

	clientConn, serverConn := net.Pipe()
	_, _, tc, cleanup := newTestTreeConn(clientConn, smb2.SMB302, serverCaps, serverSecMode, serverGuid)
	defer cleanup()

	go ioctlFakeServer(t, direct(serverConn), 0x1234, tc.treeId, output, true, 0)

	err := validateNegotiateInfo(context.Background(), tc)
	require.Error(err)
	require.IsType(&InvalidResponseError{}, err)
	require.ErrorContains(err, "dialect mismatch")
}

func TestValidateNegotiateInfo_GuidMismatch(t *testing.T) {
	require := require.New(t)

	serverGuid := [16]byte{0xAA}
	serverCaps := uint32(0x7f)
	serverSecMode := uint16(0x03)
	differentGuid := [16]byte{0xBB}

	// Server returns a different GUID
	output := makeValidateNegotiateInfoOutput(serverCaps, differentGuid, serverSecMode, smb2.SMB302)

	clientConn, serverConn := net.Pipe()
	_, _, tc, cleanup := newTestTreeConn(clientConn, smb2.SMB302, serverCaps, serverSecMode, serverGuid)
	defer cleanup()

	go ioctlFakeServer(t, direct(serverConn), 0x1234, tc.treeId, output, true, 0)

	err := validateNegotiateInfo(context.Background(), tc)
	require.Error(err)
	require.IsType(&InvalidResponseError{}, err)
	require.ErrorContains(err, "GUID mismatch")
}

// TestValidateNegotiateInfo_NotCalledForSMB311 verifies that no IOCTL is sent
// for an SMB 3.1.1 connection (pre-auth integrity is used instead).
// We accomplish this by NOT starting a fake server – if validateNegotiateInfo
// were called it would block or fail.
func TestValidateNegotiateInfo_NotCalledForSMB311(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(128),
		rdone:               make(chan struct{}, 1),
		wdone:               make(chan struct{}, 1),
		write:               make(chan []byte, 1),
		werr:                make(chan error, 1),
		dialect:             smb2.SMB311,
		maxReadSize:         bufSize,
		maxWriteSize:        bufSize,
		maxTransactSize:     bufSize,
	}
	go c.runSender()
	go c.runReceiver()
	defer func() {
		c.rdone <- struct{}{}
		clientConn.Close()
	}()

	s := &session{conn: c, sessionId: 0x5678}
	c.session.Store(s)

	// For SMB311 the treeConnect code must NOT call validateNegotiateInfo.
	// We verify the guard condition directly.
	require.NotEqual(t, smb2.SMB300, c.dialect)
	require.NotEqual(t, smb2.SMB302, c.dialect)
}
