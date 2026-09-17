package msrpc

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func buildBindAck(callId, assocGroup uint32, secAddr string, results []uint16) []byte {
	b := make([]byte, 26)
	b[0] = RPC_VERSION
	b[1] = RPC_VERSION_MINOR
	b[2] = RPC_TYPE_BIND_ACK
	b[3] = RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST
	b[4] = 0x10
	le.PutUint32(b[12:16], callId)
	le.PutUint16(b[16:18], MaxXmitFrag)
	le.PutUint16(b[18:20], MaxXmitFrag)
	le.PutUint32(b[20:24], assocGroup)

	spec := append([]byte(secAddr), 0)
	le.PutUint16(b[24:26], uint16(len(spec)))
	b = append(b, spec...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}

	b = append(b, byte(len(results)), 0, 0, 0)
	for _, r := range results {
		res := make([]byte, 24) // result, reason, transfer syntax
		le.PutUint16(res[0:2], r)
		copy(res[4:20], NDR_UUID[:])
		le.PutUint32(res[20:24], NDR_VERSION)
		b = append(b, res...)
	}

	le.PutUint16(b[8:10], uint16(len(b)))

	return b
}

func TestBindAckIsAccepted(t *testing.T) {
	tests := []struct {
		name    string
		secAddr string
		results []uint16
		want    bool
	}{
		{"accepted", `\PIPE\srvsvc`, []uint16{RPC_RESULT_ACCEPTANCE}, true},
		{"user rejection", `\PIPE\srvsvc`, []uint16{RPC_RESULT_USER_REJECTION}, false},
		{"provider rejection", `\PIPE\srvsvc`, []uint16{RPC_RESULT_PROVIDER_REJECTION}, false},
		{"no results", `\PIPE\srvsvc`, nil, false},
		{"one of two accepted", `\PIPE\srvsvc`, []uint16{RPC_RESULT_PROVIDER_REJECTION, RPC_RESULT_ACCEPTANCE}, true},
		{"empty sec addr", "", []uint16{RPC_RESULT_ACCEPTANCE}, true},
		{"long sec addr", `\PIPE\a-rather-longer-endpoint-name`, []uint16{RPC_RESULT_ACCEPTANCE}, true},
		{"unaligned sec addr", `\PIPE\ab`, []uint16{RPC_RESULT_ACCEPTANCE}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewBindAckDecoder(buildBindAck(5, 0, tt.secAddr, tt.results))
			require.False(t, d.IsInvalid())
			require.Equal(t, uint32(5), d.CallId())
			require.Equal(t, tt.want, d.IsAccepted())
		})
	}
}

func TestBindAckTruncated(t *testing.T) {
	const secAddr = `\PIPE\srvsvc`
	full := buildBindAck(5, 0, secAddr, []uint16{RPC_RESULT_ACCEPTANCE})
	resultListOff := roundup(26+len(secAddr)+1, 4)

	t.Run("accepted only once the first result is present", func(t *testing.T) {
		need := resultListOff + 4 + 2 // n_results and reserved, then result

		for n := range len(full) + 1 {
			d := NewBindAckDecoder(full[:n])
			var accepted bool
			require.NotPanics(t, func() { accepted = d.IsAccepted() }, "prefix of %d bytes", n)
			require.Equal(t, n >= need, accepted, "prefix of %d bytes", n)
		}
	})

	t.Run("sec addr length exceeds buffer", func(t *testing.T) {
		b := append([]byte(nil), full...)
		le.PutUint16(b[24:26], 0xffff)
		require.False(t, NewBindAckDecoder(b).IsAccepted())
	})

	t.Run("n_results exceeds results present", func(t *testing.T) {
		b := append([]byte(nil), full...)
		b[resultListOff] = 0xff
		le.PutUint16(b[resultListOff+4:resultListOff+6], RPC_RESULT_PROVIDER_REJECTION)

		var accepted bool
		require.NotPanics(t, func() { accepted = NewBindAckDecoder(b).IsAccepted() })
		require.False(t, accepted)
	})
}

func TestBindEncode(t *testing.T) {
	uuid := [16]byte{
		0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
		0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
	}

	r := &Bind{CallId: 7, InterfaceUUID: uuid, InterfaceVersion: 3, InterfaceVersionMinor: 0}
	b := make([]byte, r.Size())
	r.Encode(b)

	require.Len(t, b, 72)
	require.Equal(t, uint8(RPC_TYPE_BIND), b[2])
	require.Equal(t, uint16(72), le.Uint16(b[8:10]), "frag length")
	require.Equal(t, uint32(7), le.Uint32(b[12:16]))
	require.Equal(t, uint32(1), le.Uint32(b[24:28]), "one context item")
	require.Equal(t, uuid[:], b[32:48], "interface uuid, in wire order")
	require.Equal(t, uint16(3), le.Uint16(b[48:50]))
	require.Equal(t, NDR_UUID[:], b[52:68], "transfer syntax")
	require.Equal(t, uint32(NDR_VERSION), le.Uint32(b[68:72]))
}

type stubEncoder []byte

func (s stubEncoder) Size() int       { return len(s) }
func (s stubEncoder) Encode(b []byte) { copy(b, s) }

func TestRequestFraming(t *testing.T) {
	stub := stubEncoder("0123456789")

	r := &Request{CallId: 11, ContextId: 0, Opnum: 15, Stub: stub}
	b := make([]byte, r.Size())
	r.Encode(b)

	require.Len(t, b, StubOffset+len(stub))
	require.Equal(t, uint8(RPC_TYPE_REQUEST), b[2])
	require.Equal(t, uint16(len(b)), le.Uint16(b[8:10]), "frag length covers the whole PDU")
	require.Equal(t, uint32(11), le.Uint32(b[12:16]))
	require.Equal(t, uint32(len(stub)), le.Uint32(b[16:20]), "alloc hint is the stub length")
	require.Equal(t, uint16(15), le.Uint16(b[22:24]))
	require.Equal(t, []byte(stub), b[StubOffset:], "the stub starts at StubOffset")
}

func TestResponseDecoder(t *testing.T) {
	stub := []byte{1, 2, 3, 4}

	response := func() []byte {
		b := make([]byte, StubOffset)
		b[0] = RPC_VERSION
		b[2] = RPC_TYPE_RESPONSE
		b = append(b, stub...)
		le.PutUint16(b[8:10], uint16(len(b)))
		return b
	}

	t.Run("valid response", func(t *testing.T) {
		d := NewResponseDecoder(response())
		require.False(t, d.IsInvalid())
		require.Equal(t, stub, d.Stub())
	})

	t.Run("shorter than header", func(t *testing.T) {
		d := NewResponseDecoder(response()[:StubOffset-1])
		require.True(t, d.IsInvalid())
		require.Nil(t, d.Stub())
	})

	t.Run("bind ack packet type", func(t *testing.T) {
		b := response()
		b[2] = RPC_TYPE_BIND_ACK
		require.True(t, NewResponseDecoder(b).IsInvalid())
	})

	t.Run("bytes past frag_length", func(t *testing.T) {
		b := append(response(), 0xaa, 0xbb)
		d := NewResponseDecoder(b)
		require.False(t, d.IsInvalid())
		require.Equal(t, stub, d.Stub())
	})

	t.Run("frag_length past buffer", func(t *testing.T) {
		b := response()
		le.PutUint16(b[8:10], uint16(len(b)+1))
		require.True(t, NewResponseDecoder(b).IsInvalid())
	})

	t.Run("frag_length shorter than header", func(t *testing.T) {
		b := response()
		le.PutUint16(b[8:10], StubOffset-1)
		require.True(t, NewResponseDecoder(b).IsInvalid())
	})

	t.Run("authentication verifier", func(t *testing.T) {
		b := make([]byte, StubOffset)
		b[0] = RPC_VERSION
		b[2] = RPC_TYPE_RESPONSE
		b = append(b, 1, 2, 3)                 // stub
		b = append(b, 0)                       // auth_pad
		b = append(b, 10, 2, 1, 0, 0, 0, 0, 0) // sec trailer, auth_pad_length 1
		b = append(b, 9, 9, 9, 9, 9, 9)        // auth_value
		le.PutUint16(b[8:10], uint16(len(b)))
		le.PutUint16(b[10:12], 6)

		d := NewResponseDecoder(b)
		require.False(t, d.IsInvalid())
		require.Equal(t, []byte{1, 2, 3}, d.Stub())
	})

	t.Run("auth_length past frag_length", func(t *testing.T) {
		b := response()
		le.PutUint16(b[10:12], 100)
		require.True(t, NewResponseDecoder(b).IsInvalid())
	})
}

func TestFaultDecoder(t *testing.T) {
	fault := func() []byte {
		b := make([]byte, 32)
		b[0] = RPC_VERSION
		b[2] = RPC_TYPE_FAULT
		le.PutUint16(b[8:10], uint16(len(b)))
		le.PutUint32(b[12:16], 7)
		le.PutUint32(b[24:28], 0x1c010002) // nca_op_rng_error
		return b
	}

	t.Run("valid fault", func(t *testing.T) {
		d := NewFaultDecoder(fault())
		require.False(t, d.IsInvalid())
		require.Equal(t, uint32(7), d.CallId())
		require.Equal(t, uint32(0x1c010002), d.Status())
	})

	t.Run("shorter than status", func(t *testing.T) {
		require.True(t, NewFaultDecoder(fault()[:faultStatusEnd-1]).IsInvalid())
	})

	t.Run("response packet type", func(t *testing.T) {
		b := fault()
		b[2] = RPC_TYPE_RESPONSE
		require.True(t, NewFaultDecoder(b).IsInvalid())
	})
}

// capturedSambaBindAck is the bind_ack a Samba server returned for a bind to
// srvsvc v3.0 with NDR v2. Its layout:
//
//	00:16  common header, PTYPE 12, call id 0xbda5abf0
//	16:24  max xmit 4280, max recv 4280, assoc group 0xa928
//	24:26  sec_addr length, 13
//	26:39  sec_addr, "\pipe\srvsvc\x00"
//	39:40  padding to a 4-byte boundary
//	40:44  n_results 1, then three reserved octets
//	44:48  result 0 (acceptance), reason 0
//	48:68  accepted transfer syntax, NDR v2
const capturedSambaBindAck = "" +
	"05000c031000000044000000f0aba5bdb810b81028a900000d005c706970655c" +
	"73727673766300000100000000000000045d888aeb1cc9119fe808002b104860" +
	"02000000"

// capturedOneFSBindAck is the bind_ack a Dell PowerScale (OneFS) server
// returned for the same bind. It has the same layout, but the server answered
// the proposed fragment size of 4280 with its own limit of 4096.
const capturedOneFSBindAck = "" +
	"05000c0310000000440000008f00bc2c00100010aaba00000d005c706970655c" +
	"73727673766300000100000000000000045d888aeb1cc9119fe808002b104860" +
	"02000000"

// capturedWindowsBindAck is the bind_ack a Windows 11 server returned for a
// bind that proposed a fragment size of 128. The server answered with 2048, and
// its sec_addr is "\PIPE\srvsvc\x00".
const capturedWindowsBindAck = "" +
	"05000c0310000000440000001a3d8e3c00080008d03f00000d005c504950455c" +
	"73727673766300000100000000000000045d888aeb1cc9119fe808002b104860" +
	"02000000"

func TestBindAckFromServers(t *testing.T) {
	tests := []struct {
		name       string
		bindAck    string
		callId     uint32
		maxFrag    uint16
		assocGroup uint32
	}{
		{name: "samba", bindAck: capturedSambaBindAck, callId: 0xbda5abf0, maxFrag: 4280, assocGroup: 0xa928},
		{name: "onefs", bindAck: capturedOneFSBindAck, callId: 0x2cbc008f, maxFrag: 4096, assocGroup: 0xbaaa},
		{name: "windows", bindAck: capturedWindowsBindAck, callId: 0x3c8e3d1a, maxFrag: 2048, assocGroup: 0x3fd0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := hex.DecodeString(tt.bindAck)
			require.NoError(t, err)

			d := NewBindAckDecoder(b)
			require.False(t, d.IsInvalid())

			require.Equal(t, uint8(RPC_VERSION), d.Version())
			require.Equal(t, uint8(RPC_TYPE_BIND_ACK), d.PacketType())
			require.Equal(t, uint16(len(b)), d.FragLength())
			require.Equal(t, tt.callId, d.CallId())
			require.Equal(t, tt.maxFrag, d.MaxXmitFrag())
			require.Equal(t, tt.maxFrag, d.MaxRecvFrag())
			require.Equal(t, tt.assocGroup, d.AssocGroupId())
			require.Equal(t, 40, d.resultListOffset())
			require.True(t, d.IsAccepted())
		})
	}
}

func TestBuildBindAckMatchesSamba(t *testing.T) {
	built := buildBindAck(0xbda5abf0, 0xa928, `\pipe\srvsvc`, []uint16{RPC_RESULT_ACCEPTANCE})

	require.Equal(t, capturedSambaBindAck, hex.EncodeToString(built))
}

// A pipeReader returns msgs the way a message-mode named pipe does: a read
// returns at most the unread part of the current message. Once msgs is empty,
// a read returns 0 and err.
type pipeReader struct {
	msgs [][]byte
	err  error
}

func (p *pipeReader) read(b []byte) (int, error) {
	if len(p.msgs) == 0 {
		return 0, p.err
	}
	n := copy(b, p.msgs[0])
	p.msgs[0] = p.msgs[0][n:]
	if len(p.msgs[0]) == 0 {
		p.msgs = p.msgs[1:]
	}
	return n, nil
}

func buildResponse(callId uint32, flags uint8, stub string) []byte {
	b := make([]byte, StubOffset)
	b[0] = RPC_VERSION
	b[2] = RPC_TYPE_RESPONSE
	b[3] = flags
	b[4] = 0x10
	le.PutUint32(b[12:16], callId)
	b = append(b, stub...)
	le.PutUint16(b[8:10], uint16(len(b)))
	return b
}

func TestReadResponse(t *testing.T) {
	const callId = 7

	whole := buildResponse(callId, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, "whole stub")
	part1 := buildResponse(callId, RPC_PACKET_FLAG_FIRST, "part one, ")
	part2 := buildResponse(callId, 0, "part two, ")
	part3 := buildResponse(callId, RPC_PACKET_FLAG_LAST, "part three")

	tests := []struct {
		name  string
		first []byte
		msgs  [][]byte
		want  string
	}{
		{
			name:  "single fragment",
			first: whole,
			want:  "whole stub",
		},
		{
			name: "single fragment not yet read",
			msgs: [][]byte{whole},
			want: "whole stub",
		},
		{
			name:  "three fragments",
			first: part1,
			msgs:  [][]byte{part2, part3},
			want:  "part one, part two, part three",
		},
		{
			name:  "truncated single fragment",
			first: bytes.Clone(whole[:20]),
			msgs:  [][]byte{whole[20:]},
			want:  "whole stub",
		},
		{
			name:  "truncated first of three fragments",
			first: bytes.Clone(part1[:30]),
			msgs:  [][]byte{part1[30:], part2, part3},
			want:  "part one, part two, part three",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &pipeReader{msgs: tt.msgs}

			stub, err := ReadResponse(tt.first, callId, p.read)
			require.NoError(t, err)
			require.Equal(t, tt.want, string(stub))
			require.Empty(t, p.msgs, "unread messages")
		})
	}
}

func TestReadResponseErrors(t *testing.T) {
	const callId = 7

	whole := buildResponse(callId, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, "whole stub")
	part1 := buildResponse(callId, RPC_PACKET_FLAG_FIRST, "part one, ")

	fault := make([]byte, 32)
	fault[0] = RPC_VERSION
	fault[2] = RPC_TYPE_FAULT
	fault[3] = RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST
	le.PutUint16(fault[8:10], uint16(len(fault)))
	le.PutUint32(fault[12:16], callId)
	le.PutUint32(fault[24:28], 5)

	tests := []struct {
		name        string
		first       []byte
		readErr     error
		wantErr     string
		wantInvalid bool
	}{
		{
			name:        "call id mismatch",
			first:       buildResponse(callId+1, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, "stub"),
			wantErr:     "broken rpc response format",
			wantInvalid: true,
		},
		{
			name:    "fault",
			first:   fault,
			wantErr: "rpc fault with status 0x00000005",
		},
		{
			name:        "no last fragment",
			first:       part1,
			wantErr:     "truncated rpc fragment",
			wantInvalid: true,
		},
		{
			name:        "truncated fragment not completed",
			first:       bytes.Clone(whole[:20]),
			wantErr:     "truncated rpc fragment",
			wantInvalid: true,
		},
		{
			name:        "shorter than common header",
			first:       bytes.Clone(whole[:CommonHeaderSize-1]),
			wantErr:     "truncated rpc fragment",
			wantInvalid: true,
		},
		{
			name:    "read error",
			first:   part1,
			readErr: io.ErrUnexpectedEOF,
			wantErr: io.ErrUnexpectedEOF.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &pipeReader{err: tt.readErr}

			stub, err := ReadResponse(tt.first, callId, p.read)
			require.ErrorContains(t, err, tt.wantErr)
			require.Nil(t, stub)

			var invalid *InvalidResponseError
			require.Equal(t, tt.wantInvalid, errors.As(err, &invalid))
		})
	}
}

func TestReadResponseSizeLimit(t *testing.T) {
	const callId = 7

	// The reader returns fragments without RPC_PACKET_FLAG_LAST until it has
	// returned slightly more than maxResponseStub bytes, then fails, so that a
	// missing size check fails the test instead of exhausting memory.
	frag := buildResponse(callId, 0, strings.Repeat("x", 60000))
	var rest []byte
	returned := 0
	read := func(b []byte) (int, error) {
		if len(rest) == 0 {
			if returned > maxResponseStub+2*len(frag) {
				return 0, io.ErrUnexpectedEOF
			}
			rest = frag
		}
		n := copy(b, rest)
		rest = rest[n:]
		returned += n
		return n, nil
	}

	stub, err := ReadResponse(nil, callId, read)
	require.ErrorContains(t, err, "rpc response exceeds 16 MiB")
	require.Nil(t, stub)

	var invalid *InvalidResponseError
	require.ErrorAs(t, err, &invalid)
}

// splitFragments splits b, a sequence of complete PDUs, at their frag_length
// boundaries.
func splitFragments(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var frags [][]byte
	for len(b) > 0 {
		require.GreaterOrEqual(t, len(b), CommonHeaderSize)
		n := int(HeaderDecoder(b).FragLength())
		require.GreaterOrEqual(t, len(b), n)
		frags = append(frags, b[:n])
		b = b[n:]
	}
	return frags
}

func TestReadResponseFromOneFS(t *testing.T) {
	// Each file holds a NetrShareEnum response from a Dell PowerScale (OneFS)
	// server to a bind that proposed a maximum fragment size of 4280, 1024 or
	// 512 bytes, so the server sent the same stub in 1, 2 or 4 fragments. Each
	// share name and comment in the stub was replaced by placeholder text of
	// the same length.
	files := []string{
		"onefs_netshareenum_1_fragments.bin",
		"onefs_netshareenum_2_fragments.bin",
		"onefs_netshareenum_4_fragments.bin",
	}

	var stubs [][]byte
	for i, file := range files {
		t.Run(file, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("testdata", file))
			require.NoError(t, err)

			frags := splitFragments(t, b)
			require.Len(t, frags, 1<<i)

			p := &pipeReader{msgs: frags[1:]}
			stub, err := ReadResponse(frags[0], HeaderDecoder(frags[0]).CallId(), p.read)
			require.NoError(t, err)
			require.Equal(t, 1932, len(stub))
			require.Equal(t, 0, len(p.msgs), "unread messages")

			stubs = append(stubs, stub)
		})
	}

	require.Equal(t, len(files), len(stubs))
	for i := 1; i < len(stubs); i++ {
		require.True(t, bytes.Equal(stubs[0], stubs[i]), "stub from %s differs from %s", files[i], files[0])
	}
}

// capturedWindowsFault is the fault PDU a Windows 11 server returned for a
// srvsvc request with opnum 250, which the interface does not define.
const capturedWindowsFault = "" +
	"050003231000000020000000af8b173420000000000000000200011c00000000"

func TestFaultFromWindows(t *testing.T) {
	const ncaOpRngError = 0x1c010002
	const pfcDidNotExecute = 0x20

	b, err := hex.DecodeString(capturedWindowsFault)
	require.NoError(t, err)

	d := NewFaultDecoder(b)
	require.False(t, d.IsInvalid())
	require.Equal(t, uint32(0x34178baf), d.CallId())
	require.Equal(t, uint32(ncaOpRngError), d.Status())
	require.Equal(t, uint8(RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST|pfcDidNotExecute), d.PacketFlags())

	stub, err := ReadResponse(b, d.CallId(), (&pipeReader{}).read)
	require.ErrorContains(t, err, "rpc fault with status 0x1c010002")
	require.Nil(t, stub)

	var invalid *InvalidResponseError
	require.False(t, errors.As(err, &invalid))
}
