package smb2

import (
	"testing"

	"github.com/cloudsoda/go-smb2/internal/utf16le"
	"github.com/stretchr/testify/require"
)

// buildIdBothDirInfo encodes a FILE_ID_BOTH_DIR_INFORMATION entry (MS-FSCC
// 2.4.22) with the given file id and name, so the decoder's offsets can be
// checked against an independently laid-out buffer.
func buildIdBothDirInfo(fileID uint64, name string) []byte {
	nameBytes := utf16le.Encode(name, utf16le.MapCharsNone)

	b := make([]byte, 104+len(nameBytes))
	le.PutUint32(b[0:4], 0)      // NextEntryOffset
	le.PutUint32(b[4:8], 7)      // FileIndex (resume cookie, not the file id)
	le.PutUint64(b[40:48], 1234) // EndOfFile
	le.PutUint64(b[48:56], 4096) // AllocationSize
	le.PutUint32(b[56:60], 0x20) // FileAttributes
	le.PutUint32(b[60:64], uint32(len(nameBytes)))
	le.PutUint64(b[96:104], fileID)
	copy(b[104:], nameBytes)

	return b
}

func TestFileIdBothDirectoryInformationDecoder(t *testing.T) {
	const (
		fileID = uint64(0x0004000000047FD3)
		name   = "hello.txt"
	)

	require := require.New(t)

	c := FileIdBothDirectoryInformationDecoder(buildIdBothDirInfo(fileID, name))

	require.False(c.IsInvalid())
	require.Equal(fileID, c.FileId())
	require.Equal(name, c.FileName(utf16le.MapCharsNone))
	require.EqualValues(7, c.FileIndex())
	require.EqualValues(1234, c.EndOfFile())
	require.EqualValues(4096, c.AllocationSize())
	require.EqualValues(0x20, c.FileAttributes())
}

// MS-FSCC 2.4.22 overloads EaSize as the reparse tag, but only when the
// reparse attribute is set. Both readings must be decoded from the same bytes
// without one bleeding into the other. The tag value itself is never
// interpreted, so one tag exercises the whole path.
func TestFileIdBothDirectoryInformationDecoderReparsePointTag(t *testing.T) {
	require := require.New(t)

	b := buildIdBothDirInfo(1, "entry")
	c := FileIdBothDirectoryInformationDecoder(b)

	le.PutUint32(b[56:60], FILE_ATTRIBUTE_REPARSE_POINT)
	le.PutUint32(b[64:68], IO_REPARSE_TAG_SYMLINK)
	require.EqualValues(IO_REPARSE_TAG_SYMLINK, c.ReparsePointTag())
	require.EqualValues(IO_REPARSE_TAG_SYMLINK, c.EaSize(), "EaSize must still report the raw field")

	// Without the attribute the same field is a genuine EA size, not a tag.
	le.PutUint32(b[56:60], FILE_ATTRIBUTE_NORMAL)
	le.PutUint32(b[64:68], 128)
	require.Zero(c.ReparsePointTag())
	require.EqualValues(128, c.EaSize())
}

// A truncated entry must be rejected rather than panicking, since the buffer
// comes straight off the wire.
func TestFileIdBothDirectoryInformationDecoderIsInvalid(t *testing.T) {
	require := require.New(t)

	full := buildIdBothDirInfo(1, "hello.txt")

	for _, n := range []int{0, 63, 64, 103, len(full) - 1} {
		require.True(FileIdBothDirectoryInformationDecoder(full[:n]).IsInvalid(),
			"truncation to %d bytes not reported invalid", n)
	}
}

// IsInvalid is the guard that makes a buffer safe to read, so it has to be
// safe to call on a buffer of any length. These three measure a variable-length
// field before checking the fixed part is present at all, which is a panic in
// the one function whose job is to prevent one.
//
// The resume-key decoder is the reachable case: client.go hands it the ioctl
// output buffer straight from the server during a server-side copy.
func TestIsInvalidOnTruncatedBuffers(t *testing.T) {
	tests := []struct {
		name string
		// fixed is the size of the fixed part, below which the buffer cannot
		// describe its own variable part.
		fixed     int
		isInvalid func(b []byte) bool
	}{
		{
			name:      "SrvRequestResumeKeyResponse",
			fixed:     28,
			isInvalid: func(b []byte) bool { return SrvRequestResumeKeyResponseDecoder(b).IsInvalid() },
		},
		{
			name:      "FileDirectoryInformation",
			fixed:     64,
			isInvalid: func(b []byte) bool { return FileDirectoryInformationDecoder(b).IsInvalid() },
		},
		{
			name:      "FileQuotaInformation",
			fixed:     40,
			isInvalid: func(b []byte) bool { return FileQuotaInformationDecoder(b).IsInvalid() },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for n := 0; n < tt.fixed; n++ {
				b := make([]byte, n)
				// Fill with 0xff so a length field read out of bounds would
				// also be the largest possible value, not a quiet zero.
				for i := range b {
					b[i] = 0xff
				}
				if !tt.isInvalid(b) {
					t.Errorf("%d bytes accepted, fixed part is %d", n, tt.fixed)
				}
			}

			// The fixed part alone, with a zero variable length, is valid.
			if tt.isInvalid(make([]byte, tt.fixed)) {
				t.Errorf("%d bytes rejected, which is the whole fixed part", tt.fixed)
			}
		})
	}
}
