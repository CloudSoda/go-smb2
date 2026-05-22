package smb2

// Tests for security finding #2: integer overflow in IsInvalid() length
// checks across SMB2 response decoders.
//
// Each sub-test constructs a minimal buffer where an attacker-controlled
// length field, when added to a small constant using the *old* uint16/uint32
// arithmetic, would wrap around to a small value and falsely pass the
// IsInvalid() guard — allowing a subsequent accessor to panic with
// "slice bounds out of range".
//
// After the fix, every such buffer must be rejected (IsInvalid() == true).

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIsInvalidOverflowResponseDecoders covers the overflow-vulnerable
// IsInvalid() implementations in response.go.
func TestIsInvalidOverflowResponseDecoders(t *testing.T) {
	t.Run("ErrorResponseDecoder_ByteCountOverflow", func(t *testing.T) {
		// Body: 8 bytes (minimum to pass the len < 8 guard).
		// ByteCount = 0xFFFFFFF8: old uint32 check: 8 < (8 + 0xFFFFFFF8) = 0 → false (bug).
		// New uint64 check: 8 < (8 + 0xFFFFFFF8) = 0x100000000 → true (fixed).
		buf := make([]byte, 8)
		buf[0] = 9 // StructureSize low byte = 9
		le.PutUint32(buf[4:], 0xFFFFFFF8) // ByteCount
		require.True(t, ErrorResponseDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing ByteCount")
	})

	t.Run("NegotiateResponseDecoder_SecurityBufferOverflow", func(t *testing.T) {
		// Body: 64 bytes. SecurityBufferOffset=0xFFF0, SecurityBufferLength=0x0020.
		// Old uint16 sum: 0xFFF0 + 0x0020 = 0x10010 wraps to 0x0010 → check passes (bug).
		// New uint64: 64+64=128 < 0xFFF0+0x0020=0x10010 → true (fixed).
		buf := make([]byte, 64)
		buf[0] = 65 // StructureSize = 65
		le.PutUint16(buf[56:], 0xFFF0) // SecurityBufferOffset
		le.PutUint16(buf[58:], 0x0020) // SecurityBufferLength
		require.True(t, NegotiateResponseDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing SecurityBuffer fields")
	})

	t.Run("SessionSetupResponseDecoder_SecurityBufferOverflow", func(t *testing.T) {
		// Body: 8 bytes. SecurityBufferOffset=0xFFF0, SecurityBufferLength=0x0020.
		// Old uint16 sum wraps; check passes (bug). New: correctly rejected.
		buf := make([]byte, 8)
		buf[0] = 9 // StructureSize = 9
		le.PutUint16(buf[4:], 0xFFF0) // SecurityBufferOffset
		le.PutUint16(buf[6:], 0x0020) // SecurityBufferLength
		require.True(t, SessionSetupResponseDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing SecurityBuffer fields")
	})

	t.Run("CreateResponseDecoder_CreateContextsOverflow", func(t *testing.T) {
		// Body: 88 bytes. CreateContextsOffset=0xFFFFFFC0 (multiple of 8), Length=0x40.
		// Old uint32 sum: 0xFFFFFFC0 + 0x40 = 0 → check passes (bug).
		// New uint64: 88+64=152 < 0x100000000 → true (fixed).
		buf := make([]byte, 88)
		buf[0] = 89 // StructureSize = 89
		le.PutUint32(buf[80:], 0xFFFFFFC0) // CreateContextsOffset (8-byte aligned)
		le.PutUint32(buf[84:], 0x00000040) // CreateContextsLength
		require.True(t, CreateResponseDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing CreateContexts fields")
	})

	t.Run("ReadResponseDecoder_DataOverflow", func(t *testing.T) {
		// Body: 16 bytes. DataOffset=0x50 (80, which is 64+16), DataLength=0xFFFFFF00.
		// Old: uint32(0x50) + 0xFFFFFF00 = 0xFF500050... actually that doesn't wrap.
		// Use DataOffset=16+64=80=0x50, DataLength=0xFFFFFFD0:
		//   0x50 + 0xFFFFFFD0 = 0x100000020 → wraps in uint32 to 0x20=32; 32-64=-32 < 16 passes (bug).
		// New uint64: 16+64=80 < 0x50+0xFFFFFFD0=0x100000020 → true (fixed).
		buf := make([]byte, 16)
		buf[0] = 17 // StructureSize = 17
		buf[2] = 0x50 // DataOffset = 80 (= 64+16)
		le.PutUint32(buf[4:], 0xFFFFFFD0) // DataLength
		require.True(t, ReadResponseDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing Data fields")
	})

	t.Run("IoctlResponseDecoder_InputOverflow", func(t *testing.T) {
		// Body: 48 bytes. InputOffset=0xFFFFFFC0, InputCount=0x40.
		// Old uint32: wraps to 0 → passes (bug). New: correctly rejected.
		buf := make([]byte, 48)
		buf[0] = 49 // StructureSize = 49
		le.PutUint32(buf[24:], 0xFFFFFFC0) // InputOffset
		le.PutUint32(buf[28:], 0x00000040) // InputCount (= InputOffset's complement)
		require.True(t, IoctlResponseDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing Input fields")
	})

	t.Run("IoctlResponseDecoder_OutputOverflow", func(t *testing.T) {
		// OutputOffset=0xFFFFFFC0, OutputCount=0x40 → wraps to 0 in uint32.
		buf := make([]byte, 48)
		buf[0] = 49 // StructureSize = 49
		le.PutUint32(buf[32:], 0xFFFFFFC0) // OutputOffset
		le.PutUint32(buf[36:], 0x00000040) // OutputCount
		require.True(t, IoctlResponseDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing Output fields")
	})

	t.Run("QueryDirectoryResponseDecoder_OutputBufferOverflow", func(t *testing.T) {
		// Body: 8 bytes. OutputBufferOffset=0xFFF0 (uint16), OutputBufferLength=0xFFFFFF20.
		// Old: uint32(0xFFF0) + 0xFFFFFF20 = 0x10FF10; int conversion still large.
		// Use OutputBufferOffset=0x0010, OutputBufferLength=0xFFFFFF00:
		//   0x0010 + 0xFFFFFF00 = 0xFFFFFF10; int(0xFFFFFF10)-64 = large positive > 8 → passes.
		// Wait, on 64-bit int(0xFFFFFF10) = 4294967056 which IS > 8, so check fails correctly even old code?
		// Let me use values that wrap in uint32:
		// OutputBufferOffset(uint16)=0x0050 → widened to uint32, OutputBufferLength(uint32)=0xFFFFFFB0
		//   0x0050 + 0xFFFFFFB0 = 0x100000000 → wraps to 0 in uint32; int(0)-64 = -64 < 8 → passes (bug).
		// New uint64: 8+64=72 < 0x0050+0xFFFFFFB0=0x100000000 → true (fixed).
		buf := make([]byte, 8)
		buf[0] = 9 // StructureSize = 9
		le.PutUint16(buf[2:], 0x0050)       // OutputBufferOffset
		le.PutUint32(buf[4:], 0xFFFFFFB0)   // OutputBufferLength
		require.True(t, QueryDirectoryResponseDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing OutputBuffer fields")
	})

	t.Run("QueryInfoResponseDecoder_OutputBufferOverflow", func(t *testing.T) {
		// Same layout as QueryDirectory.
		buf := make([]byte, 8)
		buf[0] = 9
		le.PutUint16(buf[2:], 0x0050)
		le.PutUint32(buf[4:], 0xFFFFFFB0)
		require.True(t, QueryInfoResponseDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing OutputBuffer fields")
	})

	t.Run("ErrorContextResponseDecoder_ErrorDataLengthOverflow", func(t *testing.T) {
		// Buffer: 8 bytes (passes len < 8 guard).
		// ErrorDataLength = 0xFFFFFFF8: old uint32 sum 8+0xFFFFFFF8 = 0 → check passes (bug).
		// New uint64: 8 < 8 + 0xFFFFFFF8 = 0x100000000 → true (fixed).
		buf := make([]byte, 8)
		le.PutUint32(buf[0:], 0xFFFFFFF8) // ErrorDataLength
		require.True(t, ErrorContextResponseDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing ErrorDataLength")
	})

	t.Run("NegotiateResponseDecoder_SMB311_NoffBelowHeader", func(t *testing.T) {
		// noff = 8 (< 64): points into the SMB2 header region — invalid.
		// Old check: int(8)-64 = -56; len(r) < -56 is always false → passes (bug).
		// New check: noff < 64 → true (fixed).
		buf := make([]byte, 128)
		buf[0] = 65                    // StructureSize = 65
		le.PutUint16(buf[4:], SMB311)  // DialectRevision = 0x311
		le.PutUint32(buf[60:], 8)      // NegotiateContextOffset = 8 (8 < 64, invalid)
		require.True(t, NegotiateResponseDecoder(buf).IsInvalid(), "expected IsInvalid() == true for noff < 64 in SMB311 negotiate context")
	})
}

// TestIsInvalidOverflowFsccDecoders covers the overflow-vulnerable
// IsInvalid() implementations in fscc.go.
func TestIsInvalidOverflowFsccDecoders(t *testing.T) {
	t.Run("SrvRequestResumeKeyResponseDecoder_ContextLengthOverflow", func(t *testing.T) {
		// Buffer: 28 bytes. ContextLength = 0xFFFFFFE4: 28 + 0xFFFFFFE4 wraps to 0.
		// Old int(0) = 0 ≤ 28 → IsInvalid returns false (bug).
		// New uint64: 28 < 28 + 0xFFFFFFE4 = 0x100000000 → true (fixed).
		buf := make([]byte, 28)
		le.PutUint32(buf[24:], 0xFFFFFFE4) // ContextLength
		require.True(t, SrvRequestResumeKeyResponseDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing ContextLength")
	})

	t.Run("FileDirectoryInformationDecoder_FileNameLengthOverflow", func(t *testing.T) {
		// Buffer: 64 bytes. FileNameLength = 0xFFFFFFC0: 64 + 0xFFFFFFC0 wraps to 0.
		// Old int(0) = 0 ≤ 64 → IsInvalid returns false (bug).
		// New uint64: 64 < 64 + 0xFFFFFFC0 = 0x100000000 → true (fixed).
		buf := make([]byte, 64)
		le.PutUint32(buf[60:], 0xFFFFFFC0) // FileNameLength
		require.True(t, FileDirectoryInformationDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing FileNameLength")
	})

	t.Run("FileQuotaInformationDecoder_SidLengthOverflow", func(t *testing.T) {
		// Buffer: 40 bytes. SidLength = 0xFFFFFFD8: 40 + 0xFFFFFFD8 wraps to 0.
		// Old int(0) = 0 ≤ 40 → IsInvalid returns false (bug).
		// New uint64: 40 < 40 + 0xFFFFFFD8 = 0x100000000 → true (fixed).
		buf := make([]byte, 40)
		le.PutUint32(buf[4:], 0xFFFFFFD8) // SidLength
		require.True(t, FileQuotaInformationDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing SidLength")
	})

	t.Run("FileNameInformationDecoder_FileNameLengthOverflow", func(t *testing.T) {
		// Buffer: 4 bytes. FileNameLength = 0xFFFFFFFC: 4 + 0xFFFFFFFC wraps to 0.
		// Old int(0) = 0 ≤ 4 → IsInvalid returns false (bug).
		// New uint64: 4 < 4 + 0xFFFFFFFC = 0x100000000 → true (fixed).
		buf := make([]byte, 4)
		le.PutUint32(buf[0:], 0xFFFFFFFC) // FileNameLength
		require.True(t, FileNameInformationDecoder(buf).IsInvalid(), "expected IsInvalid() == true for overflowing FileNameLength")
	})
}

// TestIsInvalidValidBuffers verifies that IsInvalid() returns false (and
// accessors do not panic) for legitimately sized buffers after the fix.
func TestIsInvalidValidBuffers(t *testing.T) {
	t.Run("ErrorResponseDecoder_Valid", func(t *testing.T) {
		// 8-byte body with ByteCount=0 (no error data).
		buf := make([]byte, 8)
		buf[0] = 9 // StructureSize
		require.False(t, ErrorResponseDecoder(buf).IsInvalid(), "valid buffer incorrectly rejected")
	})

	t.Run("NegotiateResponseDecoder_Valid", func(t *testing.T) {
		// Minimal 64-byte body with SecurityBuffer at offset 128 (64+64), length 0.
		buf := make([]byte, 64)
		buf[0] = 65
		le.PutUint16(buf[56:], 128) // SecurityBufferOffset = 64+64
		le.PutUint16(buf[58:], 0)   // SecurityBufferLength = 0
		require.False(t, NegotiateResponseDecoder(buf).IsInvalid(), "valid buffer incorrectly rejected")
	})

	t.Run("SessionSetupResponseDecoder_Valid", func(t *testing.T) {
		buf := make([]byte, 8)
		buf[0] = 9
		le.PutUint16(buf[4:], 64+8)  // SecurityBufferOffset
		le.PutUint16(buf[6:], 0)     // SecurityBufferLength = 0
		require.False(t, SessionSetupResponseDecoder(buf).IsInvalid(), "valid buffer incorrectly rejected")
	})

	t.Run("FileDirectoryInformationDecoder_Valid", func(t *testing.T) {
		buf := make([]byte, 66)
		le.PutUint32(buf[60:], 2) // FileNameLength = 2
		require.False(t, FileDirectoryInformationDecoder(buf).IsInvalid(), "valid buffer incorrectly rejected")
	})

	t.Run("FileNameInformationDecoder_Valid", func(t *testing.T) {
		buf := make([]byte, 6)
		le.PutUint32(buf[0:], 2) // FileNameLength = 2
		require.False(t, FileNameInformationDecoder(buf).IsInvalid(), "valid buffer incorrectly rejected")
	})

	t.Run("ErrorContextResponseDecoder_Valid", func(t *testing.T) {
		// 10-byte body: 8-byte fixed header + 2 bytes of error data.
		buf := make([]byte, 10)
		le.PutUint32(buf[0:], 2) // ErrorDataLength = 2
		require.False(t, ErrorContextResponseDecoder(buf).IsInvalid(), "valid buffer incorrectly rejected")
	})

	t.Run("NegotiateResponseDecoder_SMB311_ValidNoff", func(t *testing.T) {
		// Body 128 bytes; NegotiateContextOffset = 64+128 (points just past the body end
		// in a real packet, but for this test we just want IsInvalid to accept
		// noff=128+64=192 because len(r)=128 >= 192-64=128).
		buf := make([]byte, 128)
		buf[0] = 65                         // StructureSize = 65
		le.PutUint16(buf[4:], SMB311)       // DialectRevision = 0x311
		le.PutUint16(buf[56:], 64+128)      // SecurityBufferOffset (past body, length=0 so OK)
		le.PutUint32(buf[60:], 64+128)      // NegotiateContextOffset = 192 (= 64+128), aligned
		require.False(t, NegotiateResponseDecoder(buf).IsInvalid(), "valid buffer incorrectly rejected")
	})
}
