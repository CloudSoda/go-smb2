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
		scenario string
		before   []string // requests sent before the tag query
		stat     func(fs *Share) (os.FileInfo, error)
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

	testData := []struct {
		scenario  string
		attrs     uint32
		tagStatus erref.NtStatus
		expected  ReparseTag
	}{
		{"PlainFile", smb2.FILE_ATTRIBUTE_ARCHIVE, 0, 0},
		{"ReparsePoint", smb2.FILE_ATTRIBUTE_REPARSE_POINT, 0, IOReparseTagDedup},
		{"QueryUnsupported", smb2.FILE_ATTRIBUTE_REPARSE_POINT, erref.STATUS_INVALID_INFO_CLASS, 0},
		{"QueryDenied", smb2.FILE_ATTRIBUTE_REPARSE_POINT, erref.STATUS_ACCESS_DENIED, 0},
	}

	for _, op := range ops {
		for _, td := range testData {
			t.Run(op.scenario+"/"+td.scenario, func(t *testing.T) {
				s := &statServer{
					attrs:     td.attrs,
					tag:       uint32(IOReparseTagDedup),
					tagStatus: td.tagStatus,
				}

				fi, err := op.stat(newStatShare(t, s))
				require.NoError(t, err)

				st, ok := fi.Sys().(*FileStat)
				require.True(t, ok, "expected *FileStat")
				require.Equal(t, td.expected, st.ReparsePointTag)
				require.Equal(t, td.attrs, st.FileAttributes)

				expectedRequests := append([]string(nil), op.before...)
				if td.attrs&smb2.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
					expectedRequests = append(expectedRequests, reqQueryTag)
				}
				expectedRequests = append(expectedRequests, reqClose)
				require.Equal(t, expectedRequests, s.recorded())
			})
		}
	}
}

func TestFileStatMode(t *testing.T) {
	const (
		dir      = smb2.FILE_ATTRIBUTE_DIRECTORY
		readOnly = smb2.FILE_ATTRIBUTE_READONLY
		reparse  = smb2.FILE_ATTRIBUTE_REPARSE_POINT
	)

	testData := []struct {
		scenario string
		attrs    uint32
		tag      ReparseTag
		expected os.FileMode
	}{
		{"File", smb2.FILE_ATTRIBUTE_ARCHIVE, 0, 0o666},
		{"ReadOnlyFile", readOnly, 0, 0o444},
		{"Directory", dir, 0, os.ModeDir | 0o777},
		{"Symlink", reparse, IOReparseTagSymlink, os.ModeSymlink | 0o666},
		{"DirectorySymlink", reparse | dir, IOReparseTagSymlink, os.ModeSymlink | 0o666},
		{"Junction", reparse | dir, IOReparseTagMountPoint, os.ModeIrregular | 0o666},
		{"LxSymlink", reparse, IOReparseTagLxSymlink, os.ModeIrregular | 0o666},
		{"ThirdPartyNameSurrogateDirectory", reparse | dir, 0x2000ABCD, os.ModeIrregular | 0o666},
		{"UnknownTagFile", reparse, 0, os.ModeIrregular | 0o666},
		{"UnknownTagDirectory", reparse | dir, 0, os.ModeIrregular | 0o666},
		{"Dedup", reparse, IOReparseTagDedup, 0o666},
		{"ReadOnlyDedup", reparse | readOnly, IOReparseTagDedup, 0o444},
		{"StorageSync", reparse, IOReparseTagStorageSync, 0o666},
		{"StorageSyncFolder", reparse | dir, IOReparseTagStorageSyncFolder, os.ModeDir | 0o777},
		{"CloudDirectory", reparse | dir, IOReparseTagCloud, os.ModeDir | 0o777},
		{"ThirdPartyFile", reparse, 0x0000ABCD, 0o666},
		{"AFUnix", reparse, IOReparseTagAFUnix, os.ModeSocket | 0o666},
		{"LxFIFO", reparse, IOReparseTagLxFIFO, os.ModeNamedPipe | 0o666},
		{"LxChr", reparse, IOReparseTagLxChr, os.ModeDevice | os.ModeCharDevice | 0o666},
		{"LxBlk", reparse, IOReparseTagLxBlk, os.ModeDevice | 0o666},
	}

	for _, td := range testData {
		t.Run(td.scenario, func(t *testing.T) {
			fi := &FileStat{FileAttributes: td.attrs, ReparsePointTag: td.tag}
			require.Equal(t, td.expected, fi.Mode())
			require.Equal(t, td.expected.IsDir(), fi.IsDir())
		})
	}
}
