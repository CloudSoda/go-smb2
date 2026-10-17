package smb2

import (
	"testing"

	"github.com/cloudsoda/go-smb2/internal/utf16le"
)

// The file information structures are the surface GO-2026-5051 was found on:
// a directory listing decoded straight from whatever the server sent, with a
// length check that overflowed before it could reject anything. This target
// holds the whole family to the same contract as the response decoders — if
// IsInvalid reports the buffer usable, reading every field out of it must not
// panic, for any input.
func FuzzFileInfoDecoders(f *testing.F) {
	addSeeds(f)

	// FiletimeDecoder is deliberately absent: it carries no IsInvalid of its
	// own, and every caller slices exactly eight bytes out of a parent whose
	// bounds have already been checked. Those slice expressions are exercised
	// here anyway, through the accessors that return one.

	// A directory entry whose name length is the fuzzer's to choose, which is
	// the shape the advisory turned on.
	entry := make([]byte, 64)
	entry[60] = 0xff
	entry[61] = 0xff
	entry[62] = 0xff
	entry[63] = 0xff
	f.Add(entry)

	f.Fuzz(func(t *testing.T, data []byte) {
		t.Run("SymbolicLinkReparseDataBufferDecoder", func(t *testing.T) {
			d := SymbolicLinkReparseDataBufferDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.Flags()
			_ = d.PathBuffer()
			_ = d.PrintName(utf16le.MapCharsNone)
			_ = d.PrintNameLength()
			_ = d.PrintNameOffset()
			_ = d.ReparseDataLength()
			_ = d.ReparseTag()
			_ = d.SubstituteName(utf16le.MapCharsNone)
			_ = d.SubstituteNameLength()
			_ = d.SubstituteNameOffset()
		})
		t.Run("SrvRequestResumeKeyResponseDecoder", func(t *testing.T) {
			d := SrvRequestResumeKeyResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.Context()
			_ = d.ContextLength()
			_ = d.ResumeKey()
		})
		t.Run("SrvCopychunkResponseDecoder", func(t *testing.T) {
			d := SrvCopychunkResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.ChunksBytesWritten()
			_ = d.ChunksWritten()
			_ = d.TotalBytesWritten()
		})
		t.Run("FileDirectoryInformationDecoder", func(t *testing.T) {
			d := FileDirectoryInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.AllocationSize()
			_ = d.ChangeTime()
			_ = d.CreationTime()
			_ = d.EndOfFile()
			_ = d.FileAttributes()
			_ = d.FileIndex()
			_ = d.FileName(utf16le.MapCharsNone)
			_ = d.FileNameLength()
			_ = d.LastAccessTime()
			_ = d.LastWriteTime()
			_ = d.NextEntryOffset()
		})
		t.Run("FileIdBothDirectoryInformationDecoder", func(t *testing.T) {
			d := FileIdBothDirectoryInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.AllocationSize()
			_ = d.ChangeTime()
			_ = d.CreationTime()
			_ = d.EaSize()
			_ = d.EndOfFile()
			_ = d.FileAttributes()
			_ = d.FileId()
			_ = d.FileIndex()
			_ = d.FileName(utf16le.MapCharsNone)
			_ = d.FileNameLength()
			_ = d.LastAccessTime()
			_ = d.LastWriteTime()
			_ = d.NextEntryOffset()
			_ = d.ReparsePointTag()
			_ = d.ShortNameLength()
		})
		t.Run("FileFsFullSizeInformationDecoder", func(t *testing.T) {
			d := FileFsFullSizeInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.ActualAvailableAllocationUnits()
			_ = d.BytesPerSector()
			_ = d.CallerAvailableAllocationUnits()
			_ = d.SectorsPerAllocationUnit()
			_ = d.TotalAllocationUnits()
		})
		t.Run("FileQuotaInformationDecoder", func(t *testing.T) {
			d := FileQuotaInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.ChangeTime()
			_ = d.NextEntryOffset()
			_ = d.QuotaLimit()
			_ = d.QuotaThreshold()
			_ = d.QuotaUsed()
			_ = d.Sid()
			_ = d.SidLength()
		})
		t.Run("FileEndOfFileInformationDecoder", func(t *testing.T) {
			d := FileEndOfFileInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.EndOfFile()
		})
		t.Run("FileAllInformationDecoder", func(t *testing.T) {
			d := FileAllInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.AccessInformation()
			_ = d.AlignmentInformation()
			_ = d.BasicInformation()
			_ = d.EaInformation()
			_ = d.InternalInformation()
			_ = d.ModeInformation()
			_ = d.NameInformation()
			_ = d.PositionInformation()
			_ = d.StandardInformation()
		})
		t.Run("FileBasicInformationDecoder", func(t *testing.T) {
			d := FileBasicInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.ChangeTime()
			_ = d.CreationTime()
			_ = d.FileAttributes()
			_ = d.LastAccessTime()
			_ = d.LastWriteTime()
		})
		t.Run("FileStandardInformationDecoder", func(t *testing.T) {
			d := FileStandardInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.AllocationSize()
			_ = d.DeletePending()
			_ = d.Directory()
			_ = d.EndOfFile()
			_ = d.NumberOfLinks()
		})
		t.Run("FileInternalInformationDecoder", func(t *testing.T) {
			d := FileInternalInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.IndexNumber()
		})
		t.Run("FileEaInformationDecoder", func(t *testing.T) {
			d := FileEaInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.EaSize()
		})
		t.Run("FileAccessInformationDecoder", func(t *testing.T) {
			d := FileAccessInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.AccessFlags()
		})
		t.Run("FilePositionInformationDecoder", func(t *testing.T) {
			d := FilePositionInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.CurrentByteOffset()
		})
		t.Run("FileModeInformationDecoder", func(t *testing.T) {
			d := FileModeInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.Mode()
		})
		t.Run("FileAlignmentInformationDecoder", func(t *testing.T) {
			d := FileAlignmentInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.AlignmentRequirement()
		})
		t.Run("FileNameInformationDecoder", func(t *testing.T) {
			d := FileNameInformationDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.FileName(utf16le.MapCharsNone)
			_ = d.FileNameLength()
		})
		t.Run("SidDecoder", func(t *testing.T) {
			d := SidDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.Decode()
			_ = d.IdentifierAuthority()
			_ = d.Revision()
			_ = d.SubAuthority()
			_ = d.SubAuthorityCount()
		})
	})
}
