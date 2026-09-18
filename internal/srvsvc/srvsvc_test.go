package srvsvc

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unicode/utf16"

	"github.com/cloudsoda/go-smb2/internal/msrpc"
	"github.com/stretchr/testify/require"
)

type testShare struct {
	name       string
	typ        uint32
	comment    string
	nilName    bool
	nilComment bool
}

// appendString appends s to b as an NDR conformant and varying string, padded
// to a 4-byte boundary.
func appendString(b []byte, s string) []byte {
	u := append(utf16.Encode([]rune(s)), 0)

	b = le.AppendUint32(b, uint32(len(u))) // max count
	b = le.AppendUint32(b, 0)              // offset
	b = le.AppendUint32(b, uint32(len(u))) // actual count

	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	for len(b)%4 != 0 {
		b = append(b, 0)
	}

	return b
}

func buildStub(level ShareInfoLevel, shares []testShare, returnValue uint32) []byte {
	b := le.AppendUint32(nil, uint32(level))
	b = le.AppendUint32(b, uint32(level))       // union switch
	b = le.AppendUint32(b, 0x20000)             // container referent id
	b = le.AppendUint32(b, uint32(len(shares))) // entries read
	b = le.AppendUint32(b, 0x20004)             // array referent id
	b = le.AppendUint32(b, uint32(len(shares))) // array max count

	ref := uint32(0x20008)
	nextRef := func(isNil bool) uint32 {
		if isNil {
			return 0
		}
		ref += 4
		return ref - 4
	}

	for _, s := range shares {
		b = le.AppendUint32(b, nextRef(s.nilName))
		if level == ShareInfoLevel1 {
			b = le.AppendUint32(b, s.typ)
			b = le.AppendUint32(b, nextRef(s.nilComment))
		}
	}

	for _, s := range shares {
		if !s.nilName {
			b = appendString(b, s.name)
		}
		if level == ShareInfoLevel1 && !s.nilComment {
			b = appendString(b, s.comment)
		}
	}

	b = le.AppendUint32(b, uint32(len(shares))) // totalentries
	b = le.AppendUint32(b, 0)                   // resume handle referent id
	b = le.AppendUint32(b, returnValue)

	return b
}

// setEntryCount sets both the entry count and the array maximum count of a stub
// built by buildStub.
func setEntryCount(b []byte, count uint32) {
	le.PutUint32(b[12:16], count)
	le.PutUint32(b[20:24], count)
}

func requireInvalid(t *testing.T, stub []byte, msgAndArgs ...any) {
	t.Helper()
	shares, rv, ok := NetShareEnumAllResponseDecoder(stub).Decode()
	require.False(t, ok, msgAndArgs...)
	require.Nil(t, shares, msgAndArgs...)
	require.Zero(t, rv, msgAndArgs...)
}

func TestNetShareEnumAllResponseLevel1(t *testing.T) {
	shares := []testShare{
		{name: "public", typ: STYPE_DISKTREE, comment: "everyone"},
		{name: "IPC$", typ: STYPE_IPC | STYPE_SPECIAL, comment: "Remote IPC"},
		{name: "laser", typ: STYPE_PRINTQ | STYPE_TEMPORARY, comment: ""},
		{name: "ünïcødé", typ: STYPE_DISKTREE, comment: "ünïcødé remark"},
	}

	d := NetShareEnumAllResponseDecoder(buildStub(ShareInfoLevel1, shares, 0))

	level, ok := d.Level()
	require.True(t, ok)
	require.Equal(t, ShareInfoLevel1, level)

	got, rv, ok := d.Decode()
	require.True(t, ok)
	require.Zero(t, rv)
	require.Len(t, got, len(shares))
	for i, s := range shares {
		require.Equal(t, s.name, got[i].Name, "share %d name", i)
		require.Equal(t, s.typ, got[i].Type, "share %d type", i)
		require.Equal(t, s.comment, got[i].Comment, "share %d comment", i)
	}
}

func TestNetShareEnumAllResponseLevel0(t *testing.T) {
	shares := []testShare{{name: "public"}, {name: "other"}}

	got, rv, ok := NetShareEnumAllResponseDecoder(buildStub(ShareInfoLevel0, shares, 0)).Decode()
	require.True(t, ok)
	require.Zero(t, rv)
	require.Equal(t, []ShareInfo1{{Name: "public"}, {Name: "other"}}, got)
}

func TestNetShareEnumAllResponseNilStrings(t *testing.T) {
	shares := []testShare{
		{name: "first", typ: STYPE_DISKTREE, nilComment: true},
		{name: "second", typ: STYPE_PRINTQ, comment: "second remark"},
		{typ: STYPE_DEVICE, comment: "no name", nilName: true},
	}

	got, rv, ok := NetShareEnumAllResponseDecoder(buildStub(ShareInfoLevel1, shares, 0)).Decode()
	require.True(t, ok)
	require.Zero(t, rv)
	require.Equal(t, []ShareInfo1{
		{Name: "first", Type: STYPE_DISKTREE},
		{Name: "second", Type: STYPE_PRINTQ, Comment: "second remark"},
		{Type: STYPE_DEVICE, Comment: "no name"},
	}, got)
}

func appendUint32s(b []byte, vs ...uint32) []byte {
	for _, v := range vs {
		b = le.AppendUint32(b, v)
	}
	return b
}

func TestNetShareEnumAllResponseReturnValue(t *testing.T) {
	const errorAccessDenied = 5

	tests := []struct {
		name string
		stub []byte
	}{
		{
			// level, union switch, container referent id, totalentries,
			// resume handle referent id, return value
			name: "null container",
			stub: appendUint32s(nil, 1, 1, 0, 0, 0, errorAccessDenied),
		},
		{
			// level, union switch, container referent id, entries read, array
			// referent id, totalentries, resume handle referent id, return value
			name: "null array",
			stub: appendUint32s(nil, 1, 1, 0x20000, 0, 0, 0, 0, errorAccessDenied),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, rv, ok := NetShareEnumAllResponseDecoder(tt.stub).Decode()
			require.True(t, ok)
			require.Empty(t, got)
			require.Equal(t, uint32(errorAccessDenied), rv)
		})
	}
}

func TestNetShareEnumAllResponseResumeHandle(t *testing.T) {
	b := buildStub(ShareInfoLevel1, []testShare{{name: "public", comment: "x"}}, 0)
	b = b[:len(b)-8]             // resume handle referent id, return value
	b = le.AppendUint32(b, 1)    // resume handle referent id
	b = le.AppendUint32(b, 42)   // resume handle
	b = le.AppendUint32(b, 0xea) // ERROR_MORE_DATA

	_, rv, ok := NetShareEnumAllResponseDecoder(b).Decode()
	require.True(t, ok)
	require.Equal(t, uint32(0xea), rv)
}

func TestNetShareEnumAllResponseTruncated(t *testing.T) {
	full := buildStub(ShareInfoLevel1, []testShare{
		{name: "public", typ: STYPE_DISKTREE, comment: "everyone"},
		{name: "private", typ: STYPE_DISKTREE, comment: "nobody"},
	}, 0)

	for n := range len(full) {
		d := NetShareEnumAllResponseDecoder(full[:n])
		require.NotPanics(t, func() { d.Level() }, "prefix of %d bytes", n)
		requireInvalid(t, full[:n], "prefix of %d bytes", n)
	}

	_, _, ok := NetShareEnumAllResponseDecoder(full).Decode()
	require.True(t, ok)
}

func TestNetShareEnumAllResponseUnsupportedLevel(t *testing.T) {
	levels := []ShareInfoLevel{2, 501, 502, 503, 9999}
	for _, level := range levels {
		b := buildStub(ShareInfoLevel1, []testShare{{name: "public", comment: "x"}}, 0)
		le.PutUint32(b[0:4], uint32(level))
		le.PutUint32(b[4:8], uint32(level))

		requireInvalid(t, b, "level %d", level)
	}
}

func TestNetShareEnumAllResponseUnionSwitchMismatch(t *testing.T) {
	b := buildStub(ShareInfoLevel1, []testShare{{name: "public", comment: "x"}}, 0)
	le.PutUint32(b[4:8], uint32(ShareInfoLevel0))

	requireInvalid(t, b)
}

func TestNetShareEnumAllResponseBogusCount(t *testing.T) {
	for _, count := range []uint32{0xffffffff, 0x7fffffff, 1 << 20} {
		b := buildStub(ShareInfoLevel1, []testShare{{name: "public", comment: "x"}}, 0)
		setEntryCount(b, count)

		requireInvalid(t, b, "count %d", count)
	}

	t.Run("entry count differs from array max count", func(t *testing.T) {
		b := buildStub(ShareInfoLevel1, []testShare{{name: "public", comment: "x"}}, 0)
		le.PutUint32(b[20:24], 2)

		requireInvalid(t, b)
	})
}

func TestNetShareEnumAllResponseBogusCountAllocation(t *testing.T) {
	// In case of a regression in the entry count check, this will only
	// allocate about 40 MiB, which should be fine for any computer built
	// in the last 20 years.
	const count = 1 << 20

	b := buildStub(ShareInfoLevel1, []testShare{{name: "public", comment: "x"}}, 0)
	setEntryCount(b, count)
	d := NetShareEnumAllResponseDecoder(b)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	d.Decode()
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	require.Less(t, allocated, uint64(1024*1024),
		"decoding a response with a count of %d allocated %d bytes", count, allocated)
}

func TestNetShareEnumAllResponseFuzzBytes(t *testing.T) {
	full := buildStub(ShareInfoLevel1, []testShare{
		{name: "public", typ: STYPE_DISKTREE, comment: "everyone"},
		{name: "private", typ: STYPE_IPC | STYPE_SPECIAL, comment: ""},
	}, 0)

	for i := range full {
		for _, v := range []byte{0x00, 0x01, 0x7f, 0xff} {
			b := append([]byte(nil), full...)
			b[i] = v

			d := NetShareEnumAllResponseDecoder(b)
			require.NotPanics(t, func() {
				d.Level()
				d.Decode()
			}, "byte %d set to %#x", i, v)
		}
	}
}

func TestNetShareEnumAllRequestEncode(t *testing.T) {
	stub := &NetShareEnumAllRequest{ServerName: "fileserver", Level: ShareInfoLevel1}
	req := &msrpc.Request{CallId: 99, Opnum: OP_NET_SHARE_ENUM, Stub: stub}

	b := make([]byte, req.Size())
	req.Encode(b)

	require.Equal(t, uint8(msrpc.RPC_TYPE_REQUEST), b[2])
	require.Equal(t, uint16(len(b)), le.Uint16(b[8:10]), "frag length covers the whole PDU")
	require.Equal(t, uint32(99), le.Uint32(b[12:16]))
	require.Equal(t, uint32(stub.Size()), le.Uint32(b[16:20]), "alloc hint is the stub length")
	require.Equal(t, uint16(OP_NET_SHARE_ENUM), le.Uint16(b[22:24]))

	s := b[msrpc.StubOffset:]
	require.Equal(t, uint32(0x20000), le.Uint32(s[0:4]))
	require.Equal(t, uint32(len("fileserver")+1), le.Uint32(s[4:8]), "max count includes the NUL")
	require.Equal(t, uint32(len("fileserver")+1), le.Uint32(s[12:16]))
	require.Equal(t, "fileserver", string(utf16.Decode(decodeU16(s[16:16+len("fileserver")*2]))))
	levelOff := roundup(16+(len("fileserver")+1)*2, 4)
	require.Equal(t, uint32(ShareInfoLevel1), le.Uint32(s[levelOff:levelOff+4]))
	require.Equal(t, uint32(ShareInfoLevel1), le.Uint32(s[levelOff+4:levelOff+8]), "union switch")
}

func TestNetShareEnumAllRequestUnionSwitch(t *testing.T) {
	for _, level := range []ShareInfoLevel{ShareInfoLevel0, ShareInfoLevel1} {
		r := &NetShareEnumAllRequest{ServerName: "srv", Level: level}
		b := make([]byte, r.Size())
		r.Encode(b)

		levelOff := roundup(16+(len("srv")+1)*2, 4)
		require.Equal(t, uint32(level), le.Uint32(b[levelOff:levelOff+4]), "level %d", level)
		require.Equal(t, uint32(level), le.Uint32(b[levelOff+4:levelOff+8]), "union switch for level %d", level)
	}
}

// Encode must not assume that the caller zeroed b: it writes the string's
// terminating NUL and the padding that follows it.
func TestNetShareEnumAllRequestDirtyBuffer(t *testing.T) {
	names := []string{"fileserver", "srv", "a", "", "ünïcødé-host", "abc😀"}

	for _, name := range names {
		for _, level := range []ShareInfoLevel{ShareInfoLevel0, ShareInfoLevel1} {
			r := &NetShareEnumAllRequest{ServerName: name, Level: level}

			zeroed := make([]byte, r.Size())
			r.Encode(zeroed)

			dirty := bytes.Repeat([]byte{0xff}, r.Size())
			r.Encode(dirty)

			require.Equal(t, zeroed, dirty, "server name %q at level %d", name, level)
		}
	}
}

func decodeU16(b []byte) []uint16 {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le.Uint16(b[2*i : 2*i+2])
	}
	return u
}

func TestGoldenEncoding(t *testing.T) {
	// The want values are the bytes these PDUs encoded to before the msrpc and
	// srvsvc packages were split.
	tests := []struct {
		name string
		enc  msrpc.Encoder
		want string
	}{
		{
			name: "bind",
			enc: &msrpc.Bind{
				CallId:                0xcafebabe,
				InterfaceUUID:         UUID,
				InterfaceVersion:      VERSION,
				InterfaceVersionMinor: VERSION_MINOR,
			},
			want: "05000b031000000048000000bebafecab810b810000000000100000000000100" +
				"c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe80800" +
				"2b10486002000000",
		},
		{
			name: "net share enum all, level 1",
			enc: &msrpc.Request{
				CallId: 0xdeadbeef,
				Opnum:  OP_NET_SHARE_ENUM,
				Stub:   &NetShareEnumAllRequest{ServerName: "fileserver", Level: ShareInfoLevel1},
			},
			want: "05000003100000005c000000efbeadde4400000000000f0000000200" +
				"0b000000000000000b000000660069006c00650073006500720076006500" +
				"7200000000000100000001000000040002000000000000000000ffffffff" +
				"00000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := make([]byte, tt.enc.Size())
			tt.enc.Encode(b)

			require.Equal(t, tt.want, hex.EncodeToString(b))
		})
	}
}

// capturedSambaNetShareEnumResponse is a level 1 NetrShareEnum response PDU
// from a Samba server.
const capturedSambaNetShareEnumResponse = "" +
	"050002031000000048020000f1aba5bd30020000000000000100000001000000" +
	"08000200060000000c0002000600000010000200000000001400020018000200" +
	"000000001c00020020000200000000002400020028000200000000002c000200" +
	"30000200000000003400020038000200030000803c0002000700000000000000" +
	"070000007000720069006e007400240000000000100000000000000010000000" +
	"5000720069006e00740065007200200044007200690076006500720073000000" +
	"06000000000000000600000061007500640069006f0000000c00000000000000" +
	"0c00000041007500640069006f00200073006800610072006500000006000000" +
	"000000000600000076006900640065006f0000000c000000000000000c000000" +
	"56006900640065006f0020007300680061007200650000000700000000000000" +
	"0700000069006d006100670065007300000000000d000000000000000d000000" +
	"49006d0061006700650073002000730068006100720065000000000005000000" +
	"00000000050000007400650078007400000000000b000000000000000b000000" +
	"5400650078007400200073006800610072006500000000000500000000000000" +
	"0500000049005000430024000000000030000000000000003000000049005000" +
	"4300200053006500720076006900630065002000280064006500650070006300" +
	"69002d0073006d00620020007300650072007600650072002000280053006100" +
	"6d00620061002c0020005500620075006e007400750029002900000006000000" +
	"0000000000000000"

func TestNetShareEnumAllResponseFromSamba(t *testing.T) {
	b, err := hex.DecodeString(capturedSambaNetShareEnumResponse)
	require.NoError(t, err)

	pdu := msrpc.NewResponseDecoder(b)
	require.False(t, pdu.IsInvalid())
	require.NotZero(t, pdu.PacketFlags()&msrpc.RPC_PACKET_FLAG_LAST)

	d := NetShareEnumAllResponseDecoder(pdu.Stub())
	level, ok := d.Level()
	require.True(t, ok)
	require.Equal(t, ShareInfoLevel1, level)

	shares, rv, ok := d.Decode()
	require.True(t, ok)
	require.Zero(t, rv)

	require.Equal(t, []ShareInfo1{
		{Name: "print$", Type: STYPE_DISKTREE, Comment: "Printer Drivers"},
		{Name: "audio", Type: STYPE_DISKTREE, Comment: "Audio share"},
		{Name: "video", Type: STYPE_DISKTREE, Comment: "Video share"},
		{Name: "images", Type: STYPE_DISKTREE, Comment: "Images share"},
		{Name: "text", Type: STYPE_DISKTREE, Comment: "Text share"},
		{
			Name: "IPC$", Type: STYPE_IPC | STYPE_SPECIAL,
			Comment: "IPC Service (deepci-smb server (Samba, Ubuntu))",
		},
	}, shares)
}

// capturedWindowsNetShareEnumResponse is a level 1 NetrShareEnum response PDU
// from a Windows 11 server.
const capturedWindowsNetShareEnumResponse = "" +
	"050002031000000050010000ad8b173438010000000000000100000001000000" +
	"0000020004000000040002000400000008000200000000800c00020010000200" +
	"000000801400020018000200030000801c000200200002000000000024000200" +
	"070000000000000007000000410044004d0049004e002400000000000d000000" +
	"000000000d000000520065006d006f00740065002000410064006d0069006e00" +
	"0000000003000000000000000300000043002400000000000e00000000000000" +
	"0e000000440065006600610075006c0074002000730068006100720065000000" +
	"0500000000000000050000004900500043002400000000000b00000000000000" +
	"0b000000520065006d006f007400650020004900500043000000000006000000" +
	"0000000006000000550073006500720073000000010000000000000001000000" +
	"00000000040000000000000000000000"

func TestNetShareEnumAllResponseFromWindows(t *testing.T) {
	b, err := hex.DecodeString(capturedWindowsNetShareEnumResponse)
	require.NoError(t, err)

	pdu := msrpc.NewResponseDecoder(b)
	require.False(t, pdu.IsInvalid())

	d := NetShareEnumAllResponseDecoder(pdu.Stub())
	level, ok := d.Level()
	require.True(t, ok)
	require.Equal(t, ShareInfoLevel1, level)

	shares, rv, ok := d.Decode()
	require.True(t, ok)
	require.Zero(t, rv)
	require.Equal(t, []ShareInfo1{
		{Name: "ADMIN$", Type: STYPE_DISKTREE | STYPE_SPECIAL, Comment: "Remote Admin"},
		{Name: "C$", Type: STYPE_DISKTREE | STYPE_SPECIAL, Comment: "Default share"},
		{Name: "IPC$", Type: STYPE_IPC | STYPE_SPECIAL, Comment: "Remote IPC"},
		{Name: "Users", Type: STYPE_DISKTREE},
	}, shares)
}

func TestNetShareEnumAllResponseFromOneFS(t *testing.T) {
	// onefs_netshareenum.bin is a level 1 NetrShareEnum response PDU from a Dell
	// PowerScale (OneFS) server, with each share name and comment replaced by
	// placeholder text of the same length.
	b, err := os.ReadFile(filepath.Join("testdata", "onefs_netshareenum.bin"))
	require.NoError(t, err)

	pdu := msrpc.NewResponseDecoder(b)
	require.False(t, pdu.IsInvalid())

	d := NetShareEnumAllResponseDecoder(pdu.Stub())
	level, ok := d.Level()
	require.True(t, ok)
	require.Equal(t, ShareInfoLevel1, level)

	shares, rv, ok := d.Decode()
	require.True(t, ok)
	require.Zero(t, rv)
	require.Equal(t, []ShareInfo1{
		{Name: "share00", Type: STYPE_DISKTREE},
		{Name: "share01xxxx", Type: STYPE_DISKTREE},
		{Name: "aaaaac", Type: STYPE_DISKTREE},
		{Name: "aaaad", Type: STYPE_DISKTREE},
		{Name: "share04xxxxxxxxxxx", Type: STYPE_DISKTREE, Comment: "comment 04 text text text text  "},
		{Name: "aaaaaf", Type: STYPE_DISKTREE},
		{Name: "share06xxxxxxx", Type: STYPE_DISKTREE, Comment: "comment 06 text text text"},
		{Name: "share07", Type: STYPE_DISKTREE, Comment: "comment 07 text text "},
		{Name: "aaaai", Type: STYPE_DISKTREE},
		{Name: "aj", Type: STYPE_DISKTREE},
		{Name: "aaaaak", Type: STYPE_DISKTREE},
		{Name: "share11x", Type: STYPE_DISKTREE},
		{Name: "share12", Type: STYPE_DISKTREE},
		{Name: "share13x", Type: STYPE_DISKTREE},
		{Name: "aaaao", Type: STYPE_DISKTREE},
		{Name: "share15xxxxxxxxxxxxxx", Type: STYPE_DISKTREE, Comment: "comment 15 text text text text text text text text"},
		{Name: "share16xxxxx", Type: STYPE_DISKTREE, Comment: "comment 16 tex"},
		{Name: "share17", Type: STYPE_DISKTREE},
		{Name: "share18xxxxxxxxx", Type: STYPE_DISKTREE},
		{Name: "aaaaat", Type: STYPE_DISKTREE},
		{Name: "share20x", Type: STYPE_DISKTREE},
		{Name: "aav", Type: STYPE_DISKTREE},
		{Name: "share22x", Type: STYPE_DISKTREE},
		{Name: "aaaaax", Type: STYPE_DISKTREE},
		{Name: "share24xx", Type: STYPE_DISKTREE, Comment: "comment 24 text text text te"},
		{Name: "share25x", Type: STYPE_DISKTREE},
	}, shares)
}

func TestNetShareEnumAllResponseFromServersTruncated(t *testing.T) {
	samba, err := hex.DecodeString(capturedSambaNetShareEnumResponse)
	require.NoError(t, err)
	onefs, err := os.ReadFile(filepath.Join("testdata", "onefs_netshareenum.bin"))
	require.NoError(t, err)
	windows, err := hex.DecodeString(capturedWindowsNetShareEnumResponse)
	require.NoError(t, err)

	for name, pdu := range map[string][]byte{"samba": samba, "onefs": onefs, "windows": windows} {
		t.Run(name, func(t *testing.T) {
			stub := msrpc.NewResponseDecoder(pdu).Stub()
			require.NotEmpty(t, stub)

			for n := range len(stub) {
				requireInvalid(t, stub[:n], "prefix of %d bytes", n)
			}
		})
	}
}
