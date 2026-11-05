package smb2

// Tests for requests that size their own output buffer when borrowCredits
// returns a short grant.
//
// account.borrow blocks only for the first credit and takes the rest if they
// happen to be available, so a request can be granted fewer credits than its
// buffer needs. A server fails any request whose CreditCharge is below
// (max(SendPayloadSize, ExpectedResponsePayloadSize)-1)/65536+1 with
// STATUS_INVALID_PARAMETER (MS-SMB2 3.1.5.2, 3.3.5.2.5), so a request must
// shrink its output buffer to what was granted rather than send under-charged.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudsoda/go-smb2/internal/erref"
	"github.com/cloudsoda/go-smb2/internal/smb2"
	"github.com/cloudsoda/go-smb2/internal/utf16le"
)

const multiCreditPayloadSize = 64 * 1024

type rawOutput []byte

func (r rawOutput) Size() int         { return len(r) }
func (r rawOutput) Encode(pkt []byte) { copy(pkt, r) }

type chargedRequest struct {
	msgId   uint64
	cmd     uint16
	cc      uint16
	payload int // max(request payload, maximum response size)
	fileId  [16]byte
	offset  uint64 // READ only
}

// sentRequest records what the client put on the wire for a multi-credit
// command, for assertions after the fact.
type sentRequest struct {
	cmd     uint16
	cc      uint16
	payload int
}

// chargeCheckingServer is a fake server that, like a real one, checks each
// request's CreditCharge against the larger of its payload and its maximum
// response size, and answers an under-charged request with
// STATUS_INVALID_PARAMETER. It keeps credit books the same way
// creditBooksServer does and grants back exactly what each request was charged,
// so the client's balance stays where the test put it.
//
// Every handle is a directory of the same dirEntries entries. QUERY_DIRECTORY
// returns as many entries as fit in OutputBufferLength and resumes from there on
// the next call, then STATUS_NO_MORE_FILES.
type chargeCheckingServer struct {
	t          transport
	dirEntries []string

	mu         sync.Mutex
	granted    uint64
	consumed   uint64
	sent       []sentRequest
	underpaid  []sentRequest
	windowMiss int
	cursors    map[[16]byte]int // next entry to return, per handle

	respDelay atomic.Int64
	queue     chan chargedRequest
}

func newChargeCheckingServer(t transport, initialGrant uint64, dirEntries []string) *chargeCheckingServer {
	return &chargeCheckingServer{
		t:          t,
		dirEntries: dirEntries,
		granted:    initialGrant,
		cursors:    make(map[[16]byte]int),
		queue:      make(chan chargedRequest, 1024),
	}
}

func (s *chargeCheckingServer) outstanding() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.granted - s.consumed
}

func (s *chargeCheckingServer) requests(cmd uint16) []sentRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []sentRequest
	for _, r := range s.sent {
		if r.cmd == cmd {
			out = append(out, r)
		}
	}
	return out
}

func (s *chargeCheckingServer) run() {
	go s.respond()

	buf := make([]byte, bufSize+1024)
	for {
		n, err := s.t.ReadSize()
		if err != nil {
			close(s.queue)
			return
		}
		if _, err := s.t.Read(buf[:n]); err != nil {
			close(s.queue)
			return
		}

		p := smb2.PacketCodec(buf[:n])
		body := buf[64:n]
		req := chargedRequest{msgId: p.MessageId(), cmd: p.Command(), cc: max(p.CreditCharge(), 1)}

		le := binary.LittleEndian
		switch req.cmd {
		case smb2.SMB2_QUERY_DIRECTORY:
			copy(req.fileId[:], body[8:24])
			req.payload = int(le.Uint32(body[28:32])) // OutputBufferLength
		case smb2.SMB2_QUERY_INFO:
			copy(req.fileId[:], body[24:40])
			req.payload = max(int(le.Uint32(body[12:16])), int(le.Uint32(body[4:8]))) // InputBufferLength, OutputBufferLength
		case smb2.SMB2_READ:
			req.payload = int(le.Uint32(body[4:8])) // Length
			req.offset = le.Uint64(body[8:16])
		}

		s.mu.Lock()
		if req.msgId+uint64(req.cc) > s.granted {
			s.windowMiss++
		}
		s.consumed += uint64(req.cc)
		if req.payload > 0 {
			sr := sentRequest{cmd: req.cmd, cc: req.cc, payload: req.payload}
			s.sent = append(s.sent, sr)
			if needed := uint16((req.payload-1)/multiCreditPayloadSize + 1); req.cc < needed {
				s.underpaid = append(s.underpaid, sr)
			}
		}
		s.mu.Unlock()

		s.queue <- req
	}
}

func (s *chargeCheckingServer) respond() {
	for req := range s.queue {
		if d := s.respDelay.Load(); d > 0 {
			time.Sleep(time.Duration(d))
		}

		s.mu.Lock()
		s.granted += uint64(req.cc)
		s.mu.Unlock()

		hdr := smb2.PacketHeader{
			Flags:                 smb2.SMB2_FLAGS_SERVER_TO_REDIR,
			SessionId:             booksSessionId,
			MessageId:             req.msgId,
			CreditRequestResponse: req.cc,
			Command:               req.cmd,
		}

		var resp smb2.Packet
		if needed := uint16((req.payload-1)/multiCreditPayloadSize + 1); req.payload > 0 && req.cc < needed {
			hdr.Status = uint32(erref.STATUS_INVALID_PARAMETER)
			resp = &smb2.ErrorResponse{PacketHeader: hdr}
		} else {
			resp = s.handle(hdr, req)
		}

		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)
		if _, ok := resp.(*smb2.ReadResponse); ok {
			pkt[64+2] = 80 // DataOffset from packet start
		}
		if _, err := s.t.Write(pkt); err != nil {
			return
		}
	}
}

func (s *chargeCheckingServer) handle(hdr smb2.PacketHeader, req chargedRequest) smb2.Packet {
	switch req.cmd {
	case smb2.SMB2_QUERY_DIRECTORY:
		out := s.nextEntries(req.fileId, req.payload)
		if out == nil {
			hdr.Status = uint32(erref.STATUS_NO_MORE_FILES)
			return &smb2.ErrorResponse{PacketHeader: hdr}
		}
		return &smb2.QueryDirectoryResponse{PacketHeader: hdr, Output: out}
	case smb2.SMB2_QUERY_INFO:
		// FileAllInformation: zeroed fixed part plus an empty FileNameInformation.
		return &smb2.QueryInfoResponse{PacketHeader: hdr, Output: make(rawOutput, 100)}
	case smb2.SMB2_READ:
		return &smb2.ReadResponse{PacketHeader: hdr, Data: make([]byte, req.payload)}
	default:
		return &smb2.ErrorResponse{PacketHeader: hdr}
	}
}

// nextEntries encodes as many FileIdBothDirectoryInformation entries as fit in
// limit bytes, starting where the previous call on the handle stopped. It
// returns nil once the directory is exhausted.
func (s *chargeCheckingServer) nextEntries(fileId [16]byte, limit int) rawOutput {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cursors[fileId]
	var out []byte
	prev := -1
	for next < len(s.dirEntries) {
		name := utf16le.Encode(s.dirEntries[next], utf16le.MapCharsNone)
		size := 104 + len(name)
		start := (len(out) + 7) &^ 7
		if start+size > limit {
			break
		}
		if prev >= 0 {
			binary.LittleEndian.PutUint32(out[prev:prev+4], uint32(start-prev))
		}
		out = append(out, make([]byte, start+size-len(out))...)
		binary.LittleEndian.PutUint32(out[start+60:start+64], uint32(len(name)))
		binary.LittleEndian.PutUint64(out[start+96:start+104], uint64(next+1))
		copy(out[start+104:], name)
		prev = start
		next++
	}
	s.cursors[fileId] = next
	if prev < 0 {
		return nil
	}
	return out
}

func dirEntryNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("file-%05d", i)
	}
	return names
}

// newChargeCheckingConn returns a client conn whose account holds exactly
// balance credits, and a server whose books agree.
func newChargeCheckingConn(t *testing.T, balance uint16, dirEntries []string) (*conn, *chargeCheckingServer) {
	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	t.Cleanup(cleanup)

	c.session.Store(&session{
		conn:         c,
		sessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST,
		sessionId:    booksSessionId,
	})
	c.account.settle(balance-1, balance-1)

	srv := newChargeCheckingServer(direct(serverConn), uint64(balance), dirEntries)
	go srv.run()
	return c, srv
}

func openFakeHandle(c *conn, id byte) *File {
	f := newBenchFile(c)
	f.fd = &smb2.FileId{Volatile: [8]byte{id}}
	f.name = fmt.Sprintf("dir%d", id)
	return f
}

func assertChargesCover(t *testing.T, reqs []sentRequest) {
	t.Helper()
	for _, r := range reqs {
		assert.LessOrEqual(t, r.payload, int(r.cc)*multiCreditPayloadSize,
			"command %d sent with CreditCharge %d for a %d byte payload", r.cmd, r.cc, r.payload)
	}
}

// TestShortGrantShrinksOutputBuffer drains the balance to two credits, then
// lists a directory larger than two credits' worth of output and stats a handle.
// Both size their output to maxTransactSize (sixteen credits here), so both get
// a short grant and must shrink the buffer to it.
func TestShortGrantShrinksOutputBuffer(t *testing.T) {
	const balance = 2
	entries := dirEntryNames(5000) // 128 bytes each: ~640 KiB, 5 calls at 128 KiB
	c, srv := newChargeCheckingConn(t, balance, entries)

	f := openFakeHandle(c, 1)

	fis, err := f.Readdir(-1)
	require.NoError(t, err)
	require.Len(t, fis, len(entries))
	for i, fi := range fis {
		require.Equal(t, entries[i], fi.Name())
	}

	dirReqs := srv.requests(smb2.SMB2_QUERY_DIRECTORY)
	assertChargesCover(t, dirReqs)
	// Five full buffers, then STATUS_NO_MORE_FILES.
	require.Len(t, dirReqs, 6)
	for _, r := range dirReqs {
		assert.EqualValues(t, balance, r.cc)
		assert.Equal(t, balance*multiCreditPayloadSize, r.payload)
	}

	_, err = f.stat()
	require.NoError(t, err)

	infoReqs := srv.requests(smb2.SMB2_QUERY_INFO)
	require.Len(t, infoReqs, 1)
	assertChargesCover(t, infoReqs)
	assert.EqualValues(t, balance, infoReqs[0].cc)

	srv.mu.Lock()
	assert.Empty(t, srv.underpaid)
	assert.Zero(t, srv.windowMiss)
	srv.mu.Unlock()
	assert.EqualValues(t, srv.outstanding(), len(c.account.balance), "client and server books diverged")
}

// TestShortGrantQueryInfoInputTooLarge covers a QUERY_INFO whose input buffer
// alone needs more credits than were granted. The input can't shrink, so the
// request must not be sent, and the partial grant must go back to the account.
func TestShortGrantQueryInfoInputTooLarge(t *testing.T) {
	const balance = 2
	c, srv := newChargeCheckingConn(t, balance, nil)

	f := openFakeHandle(c, 1)
	_, err := f.queryInfo(&smb2.QueryInfoRequest{
		InfoType:           smb2.SMB2_0_INFO_FILE,
		FileInfoClass:      smb2.FileAllInformation,
		OutputBufferLength: 1024,
		Input:              rawOutput(make([]byte, 4*multiCreditPayloadSize)),
	})
	var internal *InternalError
	require.True(t, errors.As(err, &internal), "want *InternalError, got %v", err)

	assert.Empty(t, srv.requests(smb2.SMB2_QUERY_INFO), "under-charged request reached the server")
	assert.Equal(t, balance, len(c.account.balance), "partial grant was not returned to the account")
}

// TestShortGrantConcurrentListings runs many listings, stats and large reads at
// once against a small balance, so short grants of every size happen. Every
// listing must be complete and no request may be under-charged.
func TestShortGrantConcurrentListings(t *testing.T) {
	const (
		balance  = 24
		listers  = 16
		readers  = 4
		rounds   = 5
		readSize = 512 * 1024
	)
	entries := dirEntryNames(3000)
	c, srv := newChargeCheckingConn(t, balance, entries)
	srv.respDelay.Store(int64(200 * time.Microsecond))

	var wg sync.WaitGroup
	errs := make(chan error, listers+readers)

	for l := range listers {
		wg.Go(func() {
			for r := range rounds {
				f := openFakeHandle(c, byte(l*rounds+r+1))
				if _, err := f.stat(); err != nil {
					errs <- fmt.Errorf("lister %d round %d: stat: %w", l, r, err)
					return
				}
				fis, err := f.Readdir(-1)
				if err != nil {
					errs <- fmt.Errorf("lister %d round %d: readdir: %w", l, r, err)
					return
				}
				if len(fis) != len(entries) {
					errs <- fmt.Errorf("lister %d round %d: listed %d entries, want %d", l, r, len(fis), len(entries))
					return
				}
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	var rwg sync.WaitGroup
	for range readers {
		rwg.Go(func() {
			f := newBenchFile(c)
			buf := make([]byte, readSize)
			for ctx.Err() == nil {
				if _, err := f.readAt(buf, 0); err != nil {
					errs <- fmt.Errorf("read: %w", err)
					return
				}
			}
		})
	}

	wg.Wait()
	cancel()
	rwg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	dirReqs := srv.requests(smb2.SMB2_QUERY_DIRECTORY)
	assertChargesCover(t, dirReqs)
	assertChargesCover(t, srv.requests(smb2.SMB2_QUERY_INFO))

	shrunk := 0
	for _, r := range dirReqs {
		if r.payload < bufSize {
			shrunk++
		}
	}
	t.Logf("%d QUERY_DIRECTORY requests, %d with a shrunk buffer", len(dirReqs), shrunk)
	assert.NotZero(t, shrunk, "no short grants happened; the test is not exercising credit pressure")

	srv.mu.Lock()
	assert.Empty(t, srv.underpaid)
	assert.Zero(t, srv.windowMiss)
	srv.mu.Unlock()
	assert.EqualValues(t, srv.outstanding(), len(c.account.balance), "client and server books diverged")
}
