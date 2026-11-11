package smb2

// Credit books across connection setup: NEGOTIATE, SESSION_SETUP, TREE_CONNECT
// and ECHO each consume a message id and must be debited like any other request.

import (
	"context"
	"encoding/asn1"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudsoda/go-smb2/internal/erref"
	"github.com/cloudsoda/go-smb2/internal/smb2"
	"github.com/cloudsoda/go-smb2/internal/spnego"
)

var fakeMechOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// fakeInitiator completes any authentication exchange.
type fakeInitiator struct{}

func (fakeInitiator) OID() asn1.ObjectIdentifier                 { return fakeMechOid }
func (fakeInitiator) InitSecContext() ([]byte, error)            { return []byte{1}, nil }
func (fakeInitiator) AcceptSecContext(sc []byte) ([]byte, error) { return []byte{1}, nil }
func (fakeInitiator) Sum(bs []byte) []byte                       { return []byte{1} }
func (fakeInitiator) SessionKey() []byte                         { return nil }

// handshakeServer is a fake server that keeps its own credit books. It grants
// one credit for NEGOTIATE and otherwise what the client asked for, up to
// maxGrant.
type handshakeServer struct {
	t        transport
	maxGrant uint16

	mu         sync.Mutex
	granted    uint64 // total credits ever granted, incl. the initial credit
	consumed   uint64 // total CreditCharge received
	violations int
}

func newHandshakeServer(t transport, maxGrant uint16) *handshakeServer {
	return &handshakeServer{t: t, maxGrant: maxGrant, granted: 1}
}

func (s *handshakeServer) outstanding() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.granted - s.consumed
}

func (s *handshakeServer) run() {
	buf := make([]byte, bufSize)
	setupLegs := 0

	for {
		n, err := s.t.ReadSize()
		if err != nil {
			return
		}
		if _, err := s.t.Read(buf[:n]); err != nil {
			return
		}

		p := smb2.PacketCodec(buf[:n])
		cc := max(p.CreditCharge(), 1)

		hdr := smb2.PacketHeader{
			Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
			MessageId: p.MessageId(),
			SessionId: booksSessionId,
		}

		s.mu.Lock()
		if p.MessageId()+uint64(cc) > s.granted {
			s.violations++
		}
		s.consumed += uint64(cc)

		grant := min(p.CreditRequest(), s.maxGrant)
		if p.Command() == smb2.SMB2_NEGOTIATE {
			grant = 1
		}
		grant = max(grant, 1)
		s.granted += uint64(grant)
		s.mu.Unlock()

		hdr.CreditRequestResponse = grant

		var resp smb2.Packet
		switch p.Command() {
		case smb2.SMB2_NEGOTIATE:
			resp = &smb2.NegotiateResponse{
				PacketHeader:    hdr,
				DialectRevision: smb2.SMB302,
				MaxTransactSize: bufSize,
				MaxReadSize:     bufSize,
				MaxWriteSize:    bufSize,
				SystemTime:      new(smb2.Filetime),
				ServerStartTime: new(smb2.Filetime),
			}
		case smb2.SMB2_SESSION_SETUP:
			token, err := spnego.EncodeNegTokenResp(1, fakeMechOid, []byte{1}, nil)
			if err != nil {
				panic(err)
			}
			setupLegs++
			if setupLegs == 1 {
				hdr.Status = uint32(erref.STATUS_MORE_PROCESSING_REQUIRED)
			}
			resp = &smb2.SessionSetupResponse{
				PacketHeader:   hdr,
				SessionFlags:   smb2.SMB2_SESSION_FLAG_IS_GUEST,
				SecurityBuffer: token,
			}
		case smb2.SMB2_TREE_CONNECT:
			hdr.TreeId = 1
			resp = &smb2.TreeConnectResponse{PacketHeader: hdr}
		case smb2.SMB2_ECHO:
			resp = &smb2.EchoResponse{PacketHeader: hdr}
		default:
			resp = &smb2.ErrorResponse{PacketHeader: hdr}
		}

		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)
		if _, err := s.t.Write(pkt); err != nil {
			return
		}
	}
}

func TestHandshakeCreditBooks(t *testing.T) {
	for _, tc := range []struct {
		name             string
		maxCreditBalance uint16 // Dialer.MaxCreditBalance
		maxGrant         uint16 // most credits the server grants in one response
		wantWindow       int
	}{
		{"default pool", 0, 8192, clientMaxCreditBalance},
		{"large pool", 2050, 8192, 2050},
		{"server grants less", 0, 32, clientMaxCreditBalance},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)

			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				clientConn.Close()
				serverConn.Close()
			})

			srv := newHandshakeServer(direct(serverConn), tc.maxGrant)
			go srv.run()

			d := &Dialer{Initiator: fakeInitiator{}, MaxCreditBalance: tc.maxCreditBalance}
			sess, err := d.DialConn(context.Background(), clientConn, "host")
			require.NoError(err)

			account := sess.s.conn.account
			assertBooks := func(step string) {
				t.Helper()
				assert.Zero(srv.violations, "%s: client overran the server's sequence window", step)
				assert.EqualValues(srv.outstanding(), len(account.balance),
					"%s: client balance differs from what the server granted", step)
			}

			assertBooks("session setup")
			if tc.maxGrant >= uint16(tc.wantWindow) {
				assert.EqualValues(tc.wantWindow, srv.outstanding())
			}

			_, err = sess.Mount("share")
			require.NoError(err)
			assertBooks("tree connect")

			require.NoError(sess.Echo())
			assertBooks("echo")
		})
	}
}
