package cmac

// RFC 4493 test vectors written whole and in pieces, and a comparison with
// the byte-wise Write of upstream (BackupZit patch, see NOTICE.BackupZit).

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"math/rand/v2"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRFC4493(t *testing.T) {
	ciph, err := aes.NewCipher(mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c"))
	if err != nil {
		t.Fatal(err)
	}
	msg := mustHex(t, "6bc1bee22e409f96e93d7e117393172a"+
		"ae2d8a571e03ac9c9eb76fac45af8e51"+
		"30c81c46a35ce411e5fbc1191a0a52ef"+
		"f69f2445df4f9b17ad2b417be66c3710")
	for _, ex := range []struct {
		len int
		mac string
	}{
		{0, "bb1d6929e95937287fa37d129b756746"},
		{16, "070a16b46b4d4144f79bdd9dd04a287c"},
		{40, "dfa66747de9ae63030ca32611497c827"},
		{64, "51f0bebf7e3b9d92fc49741779363cfe"},
	} {
		want := mustHex(t, ex.mac)
		h := New(ciph)
		// Whole, then in pieces of every size.
		for piece := 0; piece <= ex.len+1; piece++ {
			h.Reset()
			m := msg[:ex.len]
			if piece == 0 {
				h.Write(m)
			}
			for piece > 0 && len(m) > 0 {
				k := min(piece, len(m))
				h.Write(m[:k])
				m = m[k:]
			}
			if got := h.Sum(nil); !bytes.Equal(got, want) {
				t.Errorf("example of %d bytes in pieces of %d: %x, want %x", ex.len, piece, got, want)
			}
		}
	}
}

// byteWise is the CMAC of upstream go-smb2, which takes one byte at a time.
type byteWise struct {
	k1, k2, ci, digest []byte
	p                  int
	c                  cipher.Block
}

func newByteWise(c cipher.Block) *byteWise {
	d := New(c).(*cmac)
	return &byteWise{k1: d.k1, k2: d.k2, ci: make([]byte, 16), digest: make([]byte, 16), c: c}
}

func (d *byteWise) Write(p []byte) {
	for _, c := range p {
		if d.p >= len(d.ci) {
			d.c.Encrypt(d.ci, d.ci)
			d.p = 0
		}
		d.ci[d.p] ^= c
		d.p++
	}
}

func (d *byteWise) Sum() []byte {
	k := d.k1
	if d.p < len(d.digest) {
		k = d.k2
	}
	for i := range d.ci {
		d.digest[i] = d.ci[i] ^ k[i]
	}
	if d.p < len(d.digest) {
		d.digest[d.p] ^= 0x80
	}
	d.c.Encrypt(d.digest, d.digest)
	return append([]byte(nil), d.digest...)
}

func TestWriteMatchesByteWise(t *testing.T) {
	ciph, err := aes.NewCipher([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	rnd := rand.New(rand.NewPCG(1, 2))
	data := make([]byte, 5000)
	for i := range data {
		data[i] = byte(rnd.Uint32())
	}
	h := New(ciph)
	for range 2000 {
		ref := newByteWise(ciph)
		h.Reset()
		m := data[:rnd.IntN(len(data))]
		for len(m) > 0 {
			k := min(len(m), rnd.IntN(70))
			h.Write(m[:k])
			ref.Write(m[:k])
			m = m[k:]
			// Sum in between leaves the state alone.
			if rnd.IntN(4) == 0 {
				if got, want := h.Sum(nil), ref.Sum(); !bytes.Equal(got, want) {
					t.Fatalf("intermediate sum %x, want %x", got, want)
				}
			}
		}
		if got, want := h.Sum(nil), ref.Sum(); !bytes.Equal(got, want) {
			t.Fatalf("sum %x, want %x", got, want)
		}
	}
}
