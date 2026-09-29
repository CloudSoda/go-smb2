package smb2

import (
	"bytes"
	"testing"
)

func TestKDF_16(t *testing.T) {
	expected := []byte{0xca, 0x39, 0x28, 0xa6, 0x66, 0x4e, 0x3c, 0xfd, 0xc8, 0x7e, 0xef, 0x2d, 0xff, 0x7c, 0x78, 0xac}
	if !bytes.Equal(kdf([]byte("foo"), []byte("bar"), []byte("baz"), 16), expected) {
		t.Error("kdf 16-byte: unexpected output")
	}
}

func TestKDF_32(t *testing.T) {
	// kdf with n=32 must produce a 32-byte output that differs from the
	// 16-byte output (different L encoding means a different PRF input).
	ki := []byte("foo")
	label := []byte("bar")
	ctx := []byte("baz")

	out32 := kdf(ki, label, ctx, 32)
	if len(out32) != 32 {
		t.Fatalf("kdf(32): expected 32 bytes, got %d", len(out32))
	}
	out16 := kdf(ki, label, ctx, 16)
	if bytes.Equal(out32[:16], out16) {
		t.Error("kdf(32) first 16 bytes must differ from kdf(16) — L is part of PRF input")
	}
}
