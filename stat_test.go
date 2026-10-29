package smb2

import (
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
