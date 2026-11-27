package cmac

import (
	"crypto/aes"
	"testing"
)

func BenchmarkCMAC1MiB(b *testing.B) {
	ciph, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatal(err)
	}
	h := New(ciph)
	msg := make([]byte, 1<<20+64)
	b.SetBytes(int64(len(msg)))
	for b.Loop() {
		h.Reset()
		h.Write(msg)
		h.Sum(nil)
	}
}
