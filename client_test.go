package smb2

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/cloudsoda/go-smb2/internal/erref"
	"github.com/cloudsoda/go-smb2/internal/smb2"
	"github.com/cloudsoda/go-smb2/internal/utf16le"
	"github.com/stretchr/testify/require"
)

type partialReader struct {
	buf *bytes.Buffer
}

func (p *partialReader) Read(b []byte) (int, error) {
	if len(b) < 2 {
		return p.buf.Read(b)
	}
	// read partial of b
	return p.buf.Read(b[:len(b)/2])
}

func TestCopyBufferPartialRead(t *testing.T) {
	bufIn := []byte("this is a partial read test data")
	bufR := make([]byte, len(bufIn))
	copy(bufR, bufIn)
	p := &partialReader{
		buf: bytes.NewBuffer(bufR),
	}
	var bufW bytes.Buffer
	n, err := copyBuffer(p, &bufW, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(bufIn)) {
		t.Fatal("size not equal")
	}
	if !bytes.Equal(bufIn, bufW.Bytes()) {
		t.Fatal("data not equal")
	}
}

const (
	reqCreate   = "CREATE"
	reqQueryAll = "QUERY_INFO FileAllInformation"
	reqQueryTag = "QUERY_INFO FileAttributeTagInformation"
	reqClose    = "CLOSE"
)

type rawEncoder []byte

func (b rawEncoder) Size() int       { return len(b) }
func (b rawEncoder) Encode(p []byte) { copy(p, b) }

// A statServer responds to CREATE, QUERY_INFO and CLOSE requests for a single
// file, and records the name of each request it receives.
type statServer struct {
	attrs     uint32         // FileAttributes in the CREATE and FileAllInformation responses
	tag       uint32         // ReparseTag in the FileAttributeTagInformation response
	tagStatus erref.NtStatus // if nonzero, the error status for FileAttributeTagInformation

	mu       sync.Mutex
	requests []string
}

func (s *statServer) record(req string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, req)
}

func (s *statServer) recorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

func (s *statServer) serve(t transport) {
	// Closing the connection makes a request that gets no response fail
	// instead of block.
	defer t.Close()

	for {
		n, err := t.ReadSize()
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		if _, err := t.Read(pkt); err != nil {
			return
		}

		p := smb2.PacketCodec(pkt)
		hdr := smb2.PacketHeader{
			Flags:                 smb2.SMB2_FLAGS_SERVER_TO_REDIR,
			MessageId:             p.MessageId(),
			CreditRequestResponse: p.CreditRequest(),
		}

		var res smb2.Encoder
		switch p.Command() {
		case smb2.SMB2_CREATE:
			s.record(reqCreate)
			res = &smb2.CreateResponse{
				PacketHeader:   hdr,
				CreationTime:   &smb2.Filetime{},
				LastAccessTime: &smb2.Filetime{},
				LastWriteTime:  &smb2.Filetime{},
				ChangeTime:     &smb2.Filetime{},
				FileAttributes: s.attrs,
				FileId:         &smb2.FileId{},
			}
		case smb2.SMB2_QUERY_INFO:
			switch smb2.QueryInfoRequestDecoder(p.Data()).FileInfoClass() {
			case smb2.FileAllInformation:
				s.record(reqQueryAll)
				// 96 bytes of fixed-size fields, then a FileNameInformation
				// with an empty name.
				out := make([]byte, 100)
				binary.LittleEndian.PutUint32(out[32:36], s.attrs) // BasicInformation.FileAttributes
				res = &smb2.QueryInfoResponse{PacketHeader: hdr, Output: rawEncoder(out)}
			case smb2.FileAttributeTagInformation:
				s.record(reqQueryTag)
				if s.tagStatus != 0 {
					hdr.Status = uint32(s.tagStatus)
					hdr.Command = smb2.SMB2_QUERY_INFO
					res = &smb2.ErrorResponse{PacketHeader: hdr}
					break
				}
				out := make([]byte, 8)
				binary.LittleEndian.PutUint32(out[0:4], s.attrs)
				binary.LittleEndian.PutUint32(out[4:8], s.tag)
				res = &smb2.QueryInfoResponse{PacketHeader: hdr, Output: rawEncoder(out)}
			default:
				return
			}
		case smb2.SMB2_CLOSE:
			s.record(reqClose)
			res = &smb2.CloseResponse{
				PacketHeader:   hdr,
				CreationTime:   &smb2.Filetime{},
				LastAccessTime: &smb2.Filetime{},
				LastWriteTime:  &smb2.Filetime{},
				ChangeTime:     &smb2.Filetime{},
			}
		default:
			return
		}

		buf := make([]byte, res.Size())
		res.Encode(buf)
		if _, err := t.Write(buf); err != nil {
			return
		}
	}
}

// newStatShare returns a Share connected to s.
func newStatShare(t *testing.T, s *statServer) *Share {
	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	t.Cleanup(cleanup)

	c.session.Store(&session{
		conn:         c,
		sessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST,
	})

	go s.serve(direct(serverConn))

	return &Share{
		treeConn: &treeConn{session: c.session.Load()},
		ctx:      context.Background(),
	}
}

func TestStatFillsReparseTag(t *testing.T) {
	ops := []struct {
		name   string
		before []string // requests sent before the tag query
		stat   func(fs *Share) (os.FileInfo, error)
	}{
		{"Lstat", []string{reqCreate}, func(fs *Share) (os.FileInfo, error) {
			return fs.Lstat("file")
		}},
		{"Stat", []string{reqCreate}, func(fs *Share) (os.FileInfo, error) {
			return fs.Stat("file")
		}},
		{"File.Stat", []string{reqCreate, reqQueryAll}, func(fs *Share) (os.FileInfo, error) {
			f, err := fs.Open("file")
			if err != nil {
				return nil, err
			}
			defer f.Close()
			return f.Stat()
		}},
	}

	servers := []struct {
		name      string
		attrs     uint32
		tagStatus erref.NtStatus
		want      ReparseTag
	}{
		{"PlainFile", smb2.FILE_ATTRIBUTE_ARCHIVE, 0, 0},
		{"ReparsePoint", smb2.FILE_ATTRIBUTE_REPARSE_POINT, 0, IOReparseTagDedup},
		{"QueryUnsupported", smb2.FILE_ATTRIBUTE_REPARSE_POINT, erref.STATUS_INVALID_INFO_CLASS, 0},
		{"QueryDenied", smb2.FILE_ATTRIBUTE_REPARSE_POINT, erref.STATUS_ACCESS_DENIED, 0},
	}

	for _, op := range ops {
		for _, srv := range servers {
			t.Run(op.name+"/"+srv.name, func(t *testing.T) {
				s := &statServer{
					attrs:     srv.attrs,
					tag:       uint32(IOReparseTagDedup),
					tagStatus: srv.tagStatus,
				}

				fi, err := op.stat(newStatShare(t, s))
				require.NoError(t, err)

				st, ok := fi.Sys().(*FileStat)
				require.True(t, ok, "expected *FileStat")
				require.Equal(t, srv.want, st.ReparsePointTag)
				require.Equal(t, srv.attrs, st.FileAttributes)

				want := append([]string(nil), op.before...)
				if srv.attrs&smb2.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
					want = append(want, reqQueryTag)
				}
				want = append(want, reqClose)
				require.Equal(t, want, s.recorded())
			})
		}
	}
}

// symlinkErrorData returns the error data of a STATUS_STOPPED_ON_SYMLINK
// response (MS-SMB2 2.2.2.2.1) whose substitute and print names are both
// target. It lays out the bytes itself because smb2.SymbolicLinkErrorResponse
// writes Flags over the start of the path buffer.
func symlinkErrorData(target string, flags uint32, unparsedPath string) []byte {
	name := utf16le.Encode(target, utf16le.MapCharsNone)
	unparsedLen := len(utf16le.Encode(unparsedPath, utf16le.MapCharsNone))
	reparseDataLen := 12 + 2*len(name)

	b := make([]byte, 16+reparseDataLen)
	le := binary.LittleEndian
	le.PutUint32(b[0:4], uint32(12+reparseDataLen)) // SymLinkLength
	le.PutUint32(b[4:8], 0x4c4d5953)                // SymLinkErrorTag
	le.PutUint32(b[8:12], smb2.IO_REPARSE_TAG_SYMLINK)
	le.PutUint16(b[12:14], uint16(reparseDataLen))
	le.PutUint16(b[14:16], uint16(unparsedLen))
	le.PutUint16(b[16:18], 0)                 // SubstituteNameOffset
	le.PutUint16(b[18:20], uint16(len(name))) // SubstituteNameLength
	le.PutUint16(b[20:22], uint16(len(name))) // PrintNameOffset
	le.PutUint16(b[22:24], uint16(len(name))) // PrintNameLength
	le.PutUint32(b[24:28], flags)
	copy(b[28:], name)
	copy(b[28+len(name):], name)

	return b
}

func TestEvalSymlinkError(t *testing.T) {
	cases := []struct {
		name     string
		path     string // path of the CREATE that stopped on the symlink
		target   string
		flags    uint32
		unparsed string // part of path after the symlink
		want     string
	}{
		{"RelativeAtRoot", `link`, `file`, smb2.SYMLINK_FLAG_RELATIVE, ``, `file`},
		{"RelativeInDirectory", `dir\link`, `file`, smb2.SYMLINK_FLAG_RELATIVE, ``, `dir\file`},
		{"RelativeWithSubdirectory", `dir\link`, `sub\file`, smb2.SYMLINK_FLAG_RELATIVE, ``, `dir\sub\file`},
		{"RelativeIntermediate", `dir\link\file`, `sub`, smb2.SYMLINK_FLAG_RELATIVE, `\file`, `dir\sub\file`},
		{"Absolute", `dir\link`, `\??\C:\file`, 0, ``, `C:\file`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := evalSymlinkError(c.path, symlinkErrorData(c.target, c.flags, c.unparsed), utf16le.MapCharsNone)
			require.NoError(t, err)
			require.Equal(t, c.want, got)
		})
	}
}
