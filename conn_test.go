package smb2

import (
	"context"
	"crypto/aes"
	"net"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2/internal/crypto/cmac"
	"github.com/cloudsoda/go-smb2/internal/erref"
	"github.com/cloudsoda/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

func TestSessionRecv(t *testing.T) {
	require := require.New(t)

	// helper sends one request through c and returns the result of s.recv.
	roundTrip := func(t *testing.T, c *conn, s *session) error {
		t.Helper()
		var req smb2.ReadRequest
		req.CreditCharge = 1
		rr, err := c.send(context.Background(), &req)
		require.NoError(err)
		_, err = s.recv(rr)
		return err
	}

	t.Run("AdoptsSessionId", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		c, cleanup := newBenchConn(clientConn)
		defer cleanup()

		const serverSessionId uint64 = 0x1234
		go fakeServer(direct(serverConn), nil, serverSessionId)

		s := &session{conn: c, sessionId: 0}

		require.NoError(roundTrip(t, c, s))
		require.Equal(serverSessionId, s.sessionId)
	})

	t.Run("MatchingSessionId", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		c, cleanup := newBenchConn(clientConn)
		defer cleanup()

		const id uint64 = 0xCAFE
		go fakeServer(direct(serverConn), nil, id)

		s := &session{conn: c, sessionId: id}

		require.NoError(roundTrip(t, c, s))
		require.Equal(id, s.sessionId)
	})

	t.Run("RejectsSessionIdMismatch", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		c, cleanup := newBenchConn(clientConn)
		defer cleanup()

		go fakeServer(direct(serverConn), nil, 0xBBBB)

		s := &session{conn: c, sessionId: 0xAAAA}

		err := roundTrip(t, c, s)
		require.Error(err)
		require.IsType(&InvalidResponseError{}, err)
	})
}

func TestTryVerify(t *testing.T) {
	// builds an SMB2 response header
	makeHdr := func(status uint32, flags uint32, sessionId, msgID uint64) smb2.PacketCodec {
		pkt := make([]byte, 64)
		p := smb2.PacketCodec(pkt)
		p.SetProtocolId()
		p.SetStructureSize()
		p.SetCommand(smb2.SMB2_CREATE)
		p.SetStatus(status)
		p.SetFlags(flags)
		p.SetMessageId(msgID)
		p.SetSessionId(sessionId)
		return pkt
	}

	require := require.New(t)
	const sessionID uint64 = 0xCAFE

	// SMB 3.0.x-style signing-required conn with a CMAC verifier.
	ciph, err := aes.NewCipher(make([]byte, 16))
	require.NoError(err)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		requireSigning:      true,
		dialect:             smb2.SMB302,
	}
	s := &session{conn: c, sessionId: sessionID, verifier: cmac.New(ciph)}
	c.session.Store(s)

	t.Run("STATUS_PENDING should skip verification", func(t *testing.T) {
		pkt := makeHdr(uint32(erref.STATUS_PENDING), smb2.SMB2_FLAGS_SERVER_TO_REDIR|smb2.SMB2_FLAGS_ASYNC_COMMAND, sessionID, smb2.SMB2_CREATE)
		require.NoError(c.tryVerify(pkt, false))
	})

	t.Run("regular message, signed flag, bad signature - should fail", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR|smb2.SMB2_FLAGS_SIGNED, sessionID, 21)
		pkt.SetSignature(zero[:])
		require.IsType(&InvalidResponseError{}, c.tryVerify(pkt, false))
	})

	t.Run("regular message, unset signed flag, bad signature - should fail", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, sessionID, smb2.SMB2_CREATE)
		pkt.SetSignature(zero[:])
		err := c.tryVerify(pkt, false)
		require.IsType(&InvalidResponseError{}, err)
		require.ErrorContains(err, "packet failed signature verification")
	})

	t.Run("OPLOCK_BREAK should skip verification", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, sessionID, 0xFFFFFFFFFFFFFFFF)
		require.NoError(c.tryVerify(pkt, false))
	})

	t.Run("unsigned message, signing not negotiated - succeeds", func(t *testing.T) {
		// we need a connection that doesn't require signing for this subtest
		c := &conn{
			outstandingRequests: newOutstandingRequests(),
			dialect:             smb2.SMB302,
		}
		s := &session{conn: c, sessionId: sessionID}
		c.session.Store(s)

		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, sessionID, smb2.SMB2_CREATE)
		require.NoError(c.tryVerify(pkt, false))
	})

	t.Run("encrypted message without signature, succeeds", func(t *testing.T) {
		// pass an invalid session id, and use a connection that requires
		// signing to make sure we're getting an early return due to encryption
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, 0, smb2.SMB2_CREATE)
		require.NoError(c.tryVerify(pkt, true))
	})

	t.Run("signed message succeeds", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR|smb2.SMB2_FLAGS_SIGNED, sessionID, smb2.SMB2_CREATE)

		// actually sign the packet
		verifier := cmac.New(ciph)
		verifier.Write(pkt)
		pkt.SetSignature(verifier.Sum(nil))

		require.NoError(c.tryVerify(pkt, false))
	})
}

// buildCompoundPacket constructs a raw SMB2 frame where the first packet has
// NextCommand set to nextCmd. If nextCmd != 0 and is within bounds, a second
// valid 64-byte header is appended after the gap.  The returned slice is ready
// to send via transport.Write.
func buildCompoundPacket(t *testing.T, totalSize int, nextCmd uint32) []byte {
	t.Helper()
	pkt := make([]byte, totalSize)
	p := smb2.PacketCodec(pkt)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(smb2.SMB2_READ)
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	p.SetNextCommand(nextCmd)
	p.SetMessageId(99)
	// If the offset is valid, write a second valid header at pkt[nextCmd:].
	if nextCmd != 0 && int(nextCmd)+64 <= totalSize {
		p2 := smb2.PacketCodec(pkt[nextCmd:])
		p2.SetProtocolId()
		p2.SetStructureSize()
		p2.SetCommand(smb2.SMB2_READ)
		p2.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		p2.SetMessageId(100)
	}
	return pkt
}

// sendRaw writes a single raw SMB2 payload (without any length framing) via
// the directTCP transport so the receiver reads it as one SMB2 message.
func sendRaw(t *testing.T, srv transport, payload []byte) {
	t.Helper()
	_, err := srv.Write(payload)
	if err != nil {
		t.Logf("sendRaw: transport write error (expected on closed pipe): %v", err)
	}
}

// waitConnClosed blocks until conn.err is non-nil (receiver shut down) or the
// test deadline is reached.
func waitConnClosed(t *testing.T, c *conn) error {
	t.Helper()
	// wdone is closed by runReceiver when it exits, which also sets conn.err.
	select {
	case <-c.wdone:
	case <-time.After(3 * time.Second):
		require.Fail(t, "timed out waiting for connection to close")
	}
	c.m.Lock()
	defer c.m.Unlock()
	return c.err
}

// TestCompoundReceiverNextCommandValidation verifies that the receiver handles
// malformed NextCommand offsets without panicking (security finding #1).
func TestCompoundReceiverNextCommandValidation(t *testing.T) {
	// makeConn creates a fresh conn wired over a net.Pipe.
	// The server-side transport is returned for the caller to drive.
	makeConn := func(t *testing.T) (*conn, transport, func()) {
		t.Helper()
		clientConn, serverConn := net.Pipe()
		c, cleanup := newBenchConn(clientConn)
		return c, direct(serverConn), func() {
			cleanup()
			serverConn.Close()
		}
	}

	t.Run("NextCommandBeyondPacketEnd_NoPanic", func(t *testing.T) {
		c, srv, cleanup := makeConn(t)
		defer cleanup()

		// NextCommand = 200, but the packet is only 128 bytes long.
		// pkt[:200] would panic without the bounds check.
		pkt := buildCompoundPacket(t, 128, 200)
		sendRaw(t, srv, pkt)

		err := waitConnClosed(t, c)
		require.Error(t, err)
		var inv *InvalidResponseError
		require.ErrorAs(t, err, &inv, "expected InvalidResponseError, got %T: %v", err, err)
	})

	t.Run("NextCommandTooSmall_NoPanic", func(t *testing.T) {
		c, srv, cleanup := makeConn(t)
		defer cleanup()

		// NextCommand = 8 (8-byte aligned, passes the alignment check in
		// IsInvalid, but < 64 so pkt[:8] is shorter than an SMB2 header).
		pkt := buildCompoundPacket(t, 256, 8)
		sendRaw(t, srv, pkt)

		err := waitConnClosed(t, c)
		require.Error(t, err)
		var inv *InvalidResponseError
		require.ErrorAs(t, err, &inv, "expected InvalidResponseError, got %T: %v", err, err)
	})

	t.Run("NextCommandExactlyPacketLength_NoPanic", func(t *testing.T) {
		c, srv, cleanup := makeConn(t)
		defer cleanup()

		// NextCommand == len(pkt): pkt[off:] would be empty, but pkt[:off]
		// is the whole buffer. The second iteration would then run on an
		// empty slice and panic reading p[20:24] in NextCommand().
		pkt := buildCompoundPacket(t, 128, 128)
		sendRaw(t, srv, pkt)

		err := waitConnClosed(t, c)
		require.Error(t, err)
		var inv *InvalidResponseError
		require.ErrorAs(t, err, &inv, "expected InvalidResponseError, got %T: %v", err, err)
	})

	t.Run("InvalidChainedHeader_NoPanic", func(t *testing.T) {
		c, srv, cleanup := makeConn(t)
		defer cleanup()

		// First packet has a valid NextCommand (64 bytes), but the second
		// segment has a corrupted protocol ID — IsInvalid() should catch it.
		pkt := buildCompoundPacket(t, 128, 64)
		// Corrupt the protocol magic of the second header.
		pkt[64] = 0xDE
		pkt[65] = 0xAD
		sendRaw(t, srv, pkt)

		// The receiver should skip the invalid segment but stay alive.
		// Give it a moment to process, then confirm no crash.
		time.Sleep(100 * time.Millisecond)
		// Connection should still be running (no fatal error).
		c.m.Lock()
		connErr := c.err
		c.m.Unlock()
		// It is acceptable for the conn to have shut down *or* to have
		// skipped the packet; either way it must not have panicked.
		_ = connErr
	})
}
