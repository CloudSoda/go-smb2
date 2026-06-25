// ref: NIST SP 800-108 5.1

package smb2

import (
	"crypto/hmac"
	"crypto/sha256"
)

// kdf derives an n-byte key using counter mode KDF per NIST SP 800-108.
// n must be 16 or 32 (128 or 256 bits). The L field in the KDF input is set
// to n*8 so that 128-bit and 256-bit derived keys are cryptographically distinct.
func kdf(ki, label, context []byte, n int) []byte {
	h := hmac.New(sha256.New, ki)

	h.Write([]byte{0x00, 0x00, 0x00, 0x01})
	h.Write(label)
	h.Write([]byte{0x00})
	h.Write(context)
	bits := n * 8
	h.Write([]byte{byte(bits >> 24), byte(bits >> 16), byte(bits >> 8), byte(bits)})

	return h.Sum(nil)[:n]
}
