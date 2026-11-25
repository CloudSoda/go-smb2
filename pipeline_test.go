package smb2

// Tests and benchmarks of ReadAt/WriteAt over several chunks against an
// in-process server that answers after a fixed latency, so requests sent
// back to back are in flight at the same time (BackupZit patch, see
// NOTICE.BackupZit).

import (
	"bytes"
	"crypto/aes"
	"errors"
	"hash"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2/internal/crypto/cmac"
	"github.com/cloudsoda/go-smb2/internal/erref"
	"github.com/cloudsoda/go-smb2/internal/smb2"
)

// latencyServer serves READ and WRITE on one file held in memory. Each
// response leaves latency after its request arrived; requests are read while
// earlier responses wait, as a real server on a network does.
type latencyServer struct {
	t         transport
	latency   time.Duration
	sessionId uint64
	signer    hash.Hash // signs responses if set

	// fail, if set, returns an NTSTATUS to answer the request with instead.
	fail func(cmd uint16, off uint64) erref.NtStatus

	mu   sync.Mutex
	data []byte

	inflight    atomic.Int32
	maxInflight atomic.Int32
	requests    atomic.Int32
}

type delayed struct {
	due time.Time
	pkt []byte
}

func (s *latencyServer) run() {
	out := make(chan delayed, 1024)
	go func() {
		for d := range out {
			if w := time.Until(d.due); w > 0 {
				time.Sleep(w)
			}
			s.inflight.Add(-1)
			if _, err := s.t.Write(d.pkt); err != nil {
				for range out {
				}
				return
			}
		}
	}()
	defer close(out)

	req := make([]byte, 2*bufSize)
	for {
		n, err := s.t.ReadSize()
		if err != nil {
			return
		}
		if n > len(req) {
			return
		}
		if _, err := s.t.Read(req[:n]); err != nil {
			return
		}
		arrived := time.Now()
		s.requests.Add(1)
		if v := s.inflight.Add(1); v > s.maxInflight.Load() {
			s.maxInflight.Store(v)
		}
		out <- delayed{arrived.Add(s.latency), s.respond(req[:n])}
	}
}

func (s *latencyServer) respond(pkt []byte) []byte {
	p := smb2.PacketCodec(pkt)
	hdr := smb2.PacketHeader{
		Command:               p.Command(),
		CreditRequestResponse: p.CreditRequest(),
		Flags:                 smb2.SMB2_FLAGS_SERVER_TO_REDIR,
		MessageId:             p.MessageId(),
		SessionId:             s.sessionId,
	}

	var res smb2.Packet
	switch p.Command() {
	case smb2.SMB2_READ:
		r := smb2.ReadRequestDecoder(p.Data())
		if st := s.status(smb2.SMB2_READ, r.Offset()); st != 0 {
			res = s.errorResponse(hdr, st)
			break
		}
		s.mu.Lock()
		off := r.Offset()
		if off >= uint64(len(s.data)) {
			s.mu.Unlock()
			res = s.errorResponse(hdr, erref.STATUS_END_OF_FILE)
			break
		}
		end := min(off+uint64(r.Length()), uint64(len(s.data)))
		data := append([]byte(nil), s.data[off:end]...)
		s.mu.Unlock()
		res = &smb2.ReadResponse{PacketHeader: hdr, Data: data}
	case smb2.SMB2_WRITE:
		w := smb2.WriteRequestDecoder(p.Data())
		if st := s.status(smb2.SMB2_WRITE, w.Offset()); st != 0 {
			res = s.errorResponse(hdr, st)
			break
		}
		data := pkt[w.DataOffset() : uint32(w.DataOffset())+w.Length()]
		s.mu.Lock()
		if end := int(w.Offset()) + len(data); end > len(s.data) {
			s.data = append(s.data, make([]byte, end-len(s.data))...)
		}
		copy(s.data[w.Offset():], data)
		s.mu.Unlock()
		res = &smb2.WriteResponse{PacketHeader: hdr, Count: w.Length()}
	default:
		res = s.errorResponse(hdr, erref.STATUS_NOT_SUPPORTED)
	}

	buf := make([]byte, res.Size())
	res.Encode(buf)
	if _, ok := res.(*smb2.ReadResponse); ok {
		// Encode writes the offset within the body; the decoder expects
		// it from the packet start (see fakeServer).
		buf[64+2] = 80
	}
	if s.signer != nil {
		rp := smb2.PacketCodec(buf)
		rp.SetFlags(rp.Flags() | smb2.SMB2_FLAGS_SIGNED)
		s.signer.Reset()
		s.signer.Write(buf)
		rp.SetSignature(s.signer.Sum(nil))
	}
	return buf
}

func (s *latencyServer) status(cmd uint16, off uint64) erref.NtStatus {
	if s.fail == nil {
		return 0
	}
	return s.fail(cmd, off)
}

func (s *latencyServer) errorResponse(hdr smb2.PacketHeader, st erref.NtStatus) smb2.Packet {
	hdr.Status = uint32(st)
	return &smb2.ErrorResponse{PacketHeader: hdr}
}

func (s *latencyServer) snapshot() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.data...)
}

// newLatencyFile connects a File to a latencyServer holding data. With a
// signing key, the session signs and verifies with AES-CMAC (SMB 3.0).
func newLatencyFile(tb testing.TB, latency time.Duration, data []byte, signKey []byte) (*File, *latencyServer) {
	tb.Helper()
	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	tb.Cleanup(cleanup)
	// The credits a session setup asks for (initRequest): the account
	// holds clientMaxCreditBalance then, as on a real connection.
	c.account.settle(c.account.initRequest(), 0)

	srv := &latencyServer{t: direct(serverConn), latency: latency, data: data}
	s := &session{conn: c, sessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST}
	if signKey != nil {
		newCMAC := func() hash.Hash {
			ciph, err := aes.NewCipher(signKey)
			if err != nil {
				tb.Fatal(err)
			}
			return cmac.New(ciph)
		}
		s.sessionFlags = 0
		s.sessionId = 0x1234
		s.signer = newCMAC()
		s.verifier = newCMAC()
		c.requireSigning = true
		srv.sessionId = s.sessionId
		srv.signer = newCMAC()
	}
	c.session.Store(s)
	go srv.run()
	return newBenchFile(c), srv
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>11)
	}
	return b
}

func TestReadAtSeveralChunks(t *testing.T) {
	const mib = 1 << 20
	data := pattern(9*mib + 100)
	f, srv := newLatencyFile(t, 2*time.Millisecond, data, nil)

	for _, tc := range []struct {
		name string
		off  int64
		n    int
	}{
		{"one chunk", 0, mib},
		{"chunk and tail", 5, mib + 28},
		{"four chunks", 3, 4 * mib},
		{"eight chunks and a bit", 17, 8*mib + 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := srv.requests.Load()
			buf := make([]byte, tc.n)
			n, err := f.ReadAt(buf, tc.off)
			if err != nil || n != tc.n {
				t.Fatalf("ReadAt = %d, %v; want %d, nil", n, err, tc.n)
			}
			if !bytes.Equal(buf, data[tc.off:tc.off+int64(tc.n)]) {
				t.Fatal("wrong data")
			}
			if want := int32((tc.n + mib - 1) / mib); srv.requests.Load()-before != want {
				t.Errorf("%d READ requests, want %d", srv.requests.Load()-before, want)
			}
		})
	}
	if v := srv.maxInflight.Load(); v < 2 {
		t.Errorf("at most %d READ requests in flight, want several", v)
	}
}

func TestReadAtShortAtEnd(t *testing.T) {
	const mib = 1 << 20
	data := pattern(2*mib + 500)
	f, _ := newLatencyFile(t, time.Millisecond, data, nil)

	// Reads that reach past the end: the requests past it answer
	// STATUS_END_OF_FILE, the one across it is short. Like upstream,
	// ReadAt returns the bytes up to the end without an error then.
	for _, off := range []int64{0, 100, mib, 2 * mib, 2*mib + 499} {
		buf := make([]byte, 4*mib)
		n, err := f.ReadAt(buf, off)
		if want := len(data) - int(off); n != want || err != nil {
			t.Fatalf("ReadAt at %d = %d, %v; want %d, nil", off, n, err, want)
		}
		if !bytes.Equal(buf[:n], data[off:]) {
			t.Fatalf("ReadAt at %d: wrong data", off)
		}
	}
	// At and after the end.
	for _, off := range []int64{int64(len(data)), int64(len(data)) + 5*mib} {
		n, err := f.ReadAt(make([]byte, 3*mib), off)
		if n != 0 || err != io.EOF {
			t.Fatalf("ReadAt at %d = %d, %v; want 0, EOF", off, n, err)
		}
	}
}

func TestReadAtErrorWhilePipelined(t *testing.T) {
	const mib = 1 << 20
	data := pattern(8 * mib)
	f, srv := newLatencyFile(t, time.Millisecond, data, nil)
	srv.fail = func(cmd uint16, off uint64) erref.NtStatus {
		if cmd == smb2.SMB2_READ && off == 2*mib {
			return erref.STATUS_ACCESS_DENIED
		}
		return 0
	}

	buf := make([]byte, 6*mib)
	n, err := f.ReadAt(buf, 0)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("ReadAt = %d, %v; want ErrPermission", n, err)
	}

	// The connection stays usable: every response of the failed call has
	// been taken, and later reads get their own data.
	srv.fail = nil
	for range 3 {
		n, err := f.ReadAt(buf, mib)
		if err != nil || n != len(buf) || !bytes.Equal(buf, data[mib:7*mib]) {
			t.Fatalf("ReadAt after error = %d, %v", n, err)
		}
	}
	if v := srv.inflight.Load(); v != 0 {
		t.Errorf("%d requests still in flight", v)
	}
}

func TestReadAtSigned(t *testing.T) {
	const mib = 1 << 20
	data := pattern(3*mib + 7)
	f, _ := newLatencyFile(t, 0, data, []byte("0123456789abcdef"))
	buf := make([]byte, len(data))
	n, err := f.ReadAt(buf, 0)
	if err != nil || n != len(data) || !bytes.Equal(buf, data) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
}

func TestWriteAtSeveralChunks(t *testing.T) {
	const mib = 1 << 20
	f, srv := newLatencyFile(t, 2*time.Millisecond, nil, nil)

	want := []byte(nil)
	off := 0
	for _, n := range []int{100, mib, mib + 28, 4 * mib, 8*mib + 1000} {
		p := pattern(n + off)[off:]
		before := srv.requests.Load()
		m, err := f.WriteAt(p, int64(off))
		if err != nil || m != n {
			t.Fatalf("WriteAt %d at %d = %d, %v", n, off, m, err)
		}
		if got, want := srv.requests.Load()-before, int32((n+mib-1)/mib); got != want {
			t.Errorf("WriteAt %d: %d WRITE requests, want %d", n, got, want)
		}
		want = append(want[:off], p...)
		off += n / 2
	}
	if got := srv.snapshot(); !bytes.Equal(got, want) {
		t.Fatalf("server holds %d bytes, not the %d written", len(got), len(want))
	}
}

func TestWriteAtErrorWhilePipelined(t *testing.T) {
	const mib = 1 << 20
	f, srv := newLatencyFile(t, time.Millisecond, nil, nil)
	srv.fail = func(cmd uint16, off uint64) erref.NtStatus {
		if cmd == smb2.SMB2_WRITE && off == 3*mib {
			return erref.STATUS_DISK_FULL
		}
		return 0
	}

	n, err := f.WriteAt(pattern(6*mib), 0)
	var re *ResponseError
	if !errors.As(err, &re) || erref.NtStatus(re.Code) != erref.STATUS_DISK_FULL {
		t.Fatalf("WriteAt = %d, %v; want STATUS_DISK_FULL", n, err)
	}
	if n > 3*mib {
		t.Fatalf("WriteAt reports %d bytes written, past the failed chunk at %d", n, 3*mib)
	}

	srv.fail = nil
	p := pattern(5 * mib)
	if n, err := f.WriteAt(p, 0); err != nil || n != len(p) {
		t.Fatalf("WriteAt after error = %d, %v", n, err)
	}
	if got := srv.snapshot(); !bytes.Equal(got[:len(p)], p) {
		t.Fatal("wrong data after error")
	}
	if v := srv.inflight.Load(); v != 0 {
		t.Errorf("%d requests still in flight", v)
	}
}

func TestWriteAtSigned(t *testing.T) {
	f, srv := newLatencyFile(t, 0, nil, []byte("0123456789abcdef"))
	p := pattern(3<<20 + 7)
	if n, err := f.WriteAt(p, 0); err != nil || n != len(p) {
		t.Fatalf("WriteAt = %d, %v", n, err)
	}
	if !bytes.Equal(srv.snapshot(), p) {
		t.Fatal("wrong data")
	}
}

// benchLatency is a LAN round trip: about what a 1 GBit/s network to a NAS
// adds to each request besides the transfer itself.
const benchLatency = 500 * time.Microsecond

func BenchmarkReadAtLatency(b *testing.B) {
	for _, sz := range []struct {
		name string
		n    int
	}{
		{"1MB", 1 << 20},
		{"1MB+28", 1<<20 + 28},
		{"4MB", 4 << 20},
	} {
		b.Run(sz.name, func(b *testing.B) {
			f, _ := newLatencyFile(b, benchLatency, pattern(sz.n), nil)
			buf := make([]byte, sz.n)
			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			for b.Loop() {
				if n, err := f.readAt(buf, 0); err != nil || n != sz.n {
					b.Fatalf("readAt = %d, %v", n, err)
				}
			}
		})
	}
}

func BenchmarkWriteAtLatency(b *testing.B) {
	for _, sz := range []struct {
		name string
		n    int
	}{
		{"1MB", 1 << 20},
		{"1MB+28", 1<<20 + 28},
		{"4MB", 4 << 20},
	} {
		b.Run(sz.name, func(b *testing.B) {
			f, _ := newLatencyFile(b, benchLatency, nil, nil)
			p := pattern(sz.n)
			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			for b.Loop() {
				if n, err := f.writeAt(p, 0); err != nil || n != sz.n {
					b.Fatalf("writeAt = %d, %v", n, err)
				}
			}
		})
	}
}

// BenchmarkReadAtSigned reads over a signed session without latency: the
// client verifies (and the in-process server computes) one AES-CMAC per
// 1 MiB response.
func BenchmarkReadAtSigned(b *testing.B) {
	const n = 4 << 20
	f, _ := newLatencyFile(b, 0, pattern(n), []byte("0123456789abcdef"))
	buf := make([]byte, n)
	b.SetBytes(n)
	b.ReportAllocs()
	for b.Loop() {
		if m, err := f.readAt(buf, 0); err != nil || m != n {
			b.Fatalf("readAt = %d, %v", m, err)
		}
	}
}
