package smb2

import (
	"testing"

	"github.com/cloudsoda/go-smb2/internal/utf16le"
)

// Every decoder here guards its accessors with IsInvalid. These targets hold
// that contract to its word: for any input at all, if IsInvalid reports the
// buffer usable then reading every field out of it must not panic.
//
// hirochachacha#98 reports four zero bytes crashing the process and
// hirochachacha#101 an out-of-range slice in the packet header, so the seed
// corpus starts from those shapes.

func addSeeds(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xfe, 'S', 'M', 'B'})
	f.Add(make([]byte, 63))
	f.Add(make([]byte, 64))

	// A well-formed header, which is where the interesting inputs start.
	header := make([]byte, 64)
	copy(header, []byte{0xfe, 'S', 'M', 'B'})
	header[4] = 64 // StructureSize

	f.Add(header)

	// The same with a body, whose lengths and offsets are the fuzzer's to
	// choose.
	f.Add(append(append([]byte{}, header...), make([]byte, 64)...))
}

// FuzzPacketCodec covers the SMB2 header accessors, which the receive path
// reaches for every packet the server sends.
func FuzzPacketCodec(f *testing.F) {
	addSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		p := PacketCodec(data)
		if p.IsInvalid() {
			return
		}
		_ = p.AsyncId()
		_ = p.ChannelSequence()
		_ = p.Command()
		_ = p.CreditCharge()
		_ = p.CreditRequest()
		_ = p.CreditResponse()
		_ = p.Data()
		_ = p.Flags()
		_ = p.MessageId()
		_ = p.NextCommand()
		_ = p.ProtocolId()
		_ = p.SessionId()
		_ = p.Signature()
		_ = p.Status()
		_ = p.StructureSize()
		_ = p.TreeId()
	})
}

// FuzzTransformCodec covers the SMB3 transform header, which is read before
// anything has been decrypted, and so before anything has been authenticated.
func FuzzTransformCodec(f *testing.F) {
	addSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		tc := TransformCodec(data)
		if tc.IsInvalid() {
			return
		}
		_ = tc.AssociatedData()
		_ = tc.EncryptedData()
		_ = tc.EncryptionAlgorithm()
		_ = tc.Flags()
		_ = tc.OriginalMessageSize()
		_ = tc.ProtocolId()
		_ = tc.SessionId()
		_ = tc.Signature()
	})
}

// FuzzResponseDecoders covers every response body the client decodes.
func FuzzResponseDecoders(f *testing.F) {
	addSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		t.Run("ErrorResponseDecoder", func(t *testing.T) {
			d := ErrorResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.ByteCount()
			_ = d.ErrorContextCount()
			_ = d.ErrorData()
			_ = d.StructureSize()
		})
		t.Run("ErrorContextResponseDecoder", func(t *testing.T) {
			d := ErrorContextResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.ErrorContextData()
			_ = d.ErrorDataLength()
			_ = d.ErrorId()
			_ = d.Next()
		})
		t.Run("SmallBufferErrorResponseDecoder", func(t *testing.T) {
			d := SmallBufferErrorResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.RequiredBufferLength()
		})
		t.Run("SymbolicLinkErrorResponseDecoder", func(t *testing.T) {
			d := SymbolicLinkErrorResponseDecoder(data)
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
			_, _ = d.SplitUnparsedPath("name")
			_ = d.SubstituteName(utf16le.MapCharsNone)
			_ = d.SubstituteNameLength()
			_ = d.SubstituteNameOffset()
			_ = d.SymLinkErrorTag()
			_ = d.SymLinkLength()
			_ = d.UnparsedPathLength()
		})
		t.Run("NegotiateResponseDecoder", func(t *testing.T) {
			d := NegotiateResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.Capabilities()
			_ = d.DialectRevision()
			_ = d.MaxReadSize()
			_ = d.MaxTransactSize()
			_ = d.MaxWriteSize()
			_ = d.NegotiateContextCount()
			_ = d.NegotiateContextList()
			_ = d.NegotiateContextOffset()
			_ = d.SecurityBuffer()
			_ = d.SecurityBufferLength()
			_ = d.SecurityBufferOffset()
			_ = d.SecurityMode()
			_ = d.ServerGuid()
			_ = d.ServerStartTime()
			_ = d.StructureSize()
			_ = d.SystemTime()
		})
		t.Run("SessionSetupResponseDecoder", func(t *testing.T) {
			d := SessionSetupResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.SecurityBuffer()
			_ = d.SecurityBufferLength()
			_ = d.SecurityBufferOffset()
			_ = d.SessionFlags()
			_ = d.StructureSize()
		})
		t.Run("LogoffResponseDecoder", func(t *testing.T) {
			d := LogoffResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.StructureSize()
		})
		t.Run("EchoResponseDecoder", func(t *testing.T) {
			d := EchoResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.StructureSize()
		})
		t.Run("TreeConnectResponseDecoder", func(t *testing.T) {
			d := TreeConnectResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.Capabilities()
			_ = d.MaximalAccess()
			_ = d.ShareFlags()
			_ = d.ShareType()
			_ = d.StructureSize()
		})
		t.Run("TreeDisconnectResponseDecoder", func(t *testing.T) {
			d := TreeDisconnectResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.StructureSize()
		})
		t.Run("CreateResponseDecoder", func(t *testing.T) {
			d := CreateResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.AllocationSize()
			_ = d.ChangeTime()
			_ = d.CreateAction()
			_ = d.CreateContexts()
			_ = d.CreateContextsLength()
			_ = d.CreateContextsOffset()
			_ = d.CreationTime()
			_ = d.EndofFile()
			_ = d.FileAttributes()
			_ = d.FileId()
			_ = d.Flags()
			_ = d.LastAccessTime()
			_ = d.LastWriteTime()
			_ = d.OplockLevel()
			_ = d.StructureSize()
		})
		t.Run("CloseResponseDecoder", func(t *testing.T) {
			d := CloseResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.AllocationSize()
			_ = d.ChangeTime()
			_ = d.CreationTime()
			_ = d.EndofFile()
			_ = d.FileAttributes()
			_ = d.Flags()
			_ = d.LastAccessTime()
			_ = d.LastWriteTime()
			_ = d.StructureSize()
		})
		t.Run("FlushResponseDecoder", func(t *testing.T) {
			d := FlushResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.StructureSize()
		})
		t.Run("ReadResponseDecoder", func(t *testing.T) {
			d := ReadResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.Data()
			_ = d.DataLength()
			_ = d.DataOffset()
			_ = d.DataRemaining()
			_ = d.StructureSize()
		})
		t.Run("WriteResponseDecoder", func(t *testing.T) {
			d := WriteResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.Count()
			_ = d.Remaining()
			_ = d.StructureSize()
			_ = d.WriteChannelInfoLength()
			_ = d.WriteChannelInfoOffset()
		})
		t.Run("IoctlResponseDecoder", func(t *testing.T) {
			d := IoctlResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.CtlCode()
			_ = d.FileId()
			_ = d.Flags()
			_ = d.Input()
			_ = d.InputCount()
			_ = d.InputOffset()
			_ = d.Output()
			_ = d.OutputCount()
			_ = d.OutputOffset()
			_ = d.StructureSize()
		})
		t.Run("QueryDirectoryResponseDecoder", func(t *testing.T) {
			d := QueryDirectoryResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.OutputBuffer()
			_ = d.OutputBufferLength()
			_ = d.OutputBufferOffset()
			_ = d.StructureSize()
		})
		t.Run("QueryInfoResponseDecoder", func(t *testing.T) {
			d := QueryInfoResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.OutputBuffer()
			_ = d.OutputBufferLength()
			_ = d.OutputBufferOffset()
			_ = d.StructureSize()
		})
		t.Run("SetInfoResponseDecoder", func(t *testing.T) {
			d := SetInfoResponseDecoder(data)
			if d.IsInvalid() {
				return
			}
			_ = d.StructureSize()
		})
	})
}
