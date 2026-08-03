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
// without one bleeding into the other.
func TestFileIdBothDirectoryInformationDecoderReparsePointTag(t *testing.T) {
	const eaSizeOffset = 64

	tests := []struct {
		name       string
		attributes uint32
		field      uint32
		wantTag    uint32
	}{
		{"symlink", FILE_ATTRIBUTE_REPARSE_POINT, IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_SYMLINK},
		{"junction", FILE_ATTRIBUTE_REPARSE_POINT, IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_MOUNT_POINT},
		{"hsm", FILE_ATTRIBUTE_REPARSE_POINT, IO_REPARSE_TAG_HSM, IO_REPARSE_TAG_HSM},
		// Without the attribute the field is a genuine EA size, not a tag.
		{"plain file with EAs", FILE_ATTRIBUTE_NORMAL, 128, 0},
		{"plain file", FILE_ATTRIBUTE_NORMAL, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)

			b := buildIdBothDirInfo(1, "entry")
			le.PutUint32(b[56:60], tt.attributes)
			le.PutUint32(b[eaSizeOffset:eaSizeOffset+4], tt.field)

			c := FileIdBothDirectoryInformationDecoder(b)

			require.False(c.IsInvalid())
			require.Equal(tt.wantTag, c.ReparsePointTag())
			require.Equal(tt.field, c.EaSize(), "EaSize must still report the raw field")
		})
	}
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
