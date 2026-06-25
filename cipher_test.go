package smb2

import (
	"crypto/aes"
	"crypto/cipher"
	"slices"
	"testing"

	"github.com/cloudsoda/go-smb2/internal/crypto/ccm"
)

// TestClientCiphersOrder verifies that the client cipher preference list
// advertises AES-256 ciphers before AES-128 ciphers.
func TestClientCiphersOrder(t *testing.T) {
	if len(clientCiphers) != 4 {
		t.Fatalf("expected 4 client ciphers, got %d", len(clientCiphers))
	}
	want := []uint16{CipherAES256GCM, CipherAES256CCM, CipherAES128GCM, CipherAES128CCM}
	for i, c := range clientCiphers {
		if c != want[i] {
			t.Errorf("clientCiphers[%d]: got 0x%04x, want 0x%04x", i, c, want[i])
		}
	}
}

// TestAES256KeyDerivation checks that kdfN with n=32 produces keys accepted by
// crypto/aes.NewCipher (i.e. they are valid 256-bit AES keys), and that the CCM
// and GCM constructors succeed with those keys.
func TestAES256KeyDerivation(t *testing.T) {
	sessionKey := make([]byte, 16) // all-zero session key for unit test
	preauthHash := make([]byte, 64)

	encKey := kdf(sessionKey, []byte("SMBC2SCipherKey\x00"), preauthHash, 32)
	if len(encKey) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(encKey))
	}

	t.Run("AES256CCM", func(t *testing.T) {
		ciph, err := aes.NewCipher(encKey)
		if err != nil {
			t.Fatalf("aes.NewCipher(32): %v", err)
		}
		if _, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16); err != nil {
			t.Fatalf("ccm.NewCCMWithNonceAndTagSizes: %v", err)
		}
	})

	t.Run("AES256GCM", func(t *testing.T) {
		ciph, err := aes.NewCipher(encKey)
		if err != nil {
			t.Fatalf("aes.NewCipher(32): %v", err)
		}
		gcm, err := cipher.NewGCMWithNonceSize(ciph, 12)
		if err != nil {
			t.Fatalf("cipher.NewGCMWithNonceSize: %v", err)
		}
		if gcm.NonceSize() != 12 {
			t.Errorf("expected nonce size 12, got %d", gcm.NonceSize())
		}
	})
}

// TestNegotiatorEffectiveCiphers verifies the Negotiator.Ciphers field:
// nil/empty falls back to defaults; valid custom lists are accepted as-is;
// unknown IDs are rejected.
func TestNegotiatorEffectiveCiphers(t *testing.T) {
	t.Run("nil uses default", func(t *testing.T) {
		n := &Negotiator{}
		got, err := n.effectiveCiphers()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !slices.Equal(got, clientCiphers) {
			t.Errorf("expected default clientCiphers, got %v", got)
		}
	})

	t.Run("empty uses default", func(t *testing.T) {
		n := &Negotiator{Ciphers: []uint16{}}
		got, err := n.effectiveCiphers()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !slices.Equal(got, clientCiphers) {
			t.Errorf("expected default clientCiphers, got %v", got)
		}
	})

	t.Run("custom AES128GCM only", func(t *testing.T) {
		want := []uint16{CipherAES128GCM}
		n := &Negotiator{Ciphers: want}
		got, err := n.effectiveCiphers()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("expected %v, got %v", want, got)
		}
	})

	t.Run("custom AES256GCM+AES256CCM", func(t *testing.T) {
		want := []uint16{CipherAES256GCM, CipherAES256CCM}
		n := &Negotiator{Ciphers: want}
		got, err := n.effectiveCiphers()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("expected %v, got %v", want, got)
		}
	})

	t.Run("unknown cipher rejected", func(t *testing.T) {
		n := &Negotiator{Ciphers: []uint16{0x00FF}}
		_, err := n.effectiveCiphers()
		if err == nil {
			t.Fatal("expected error for unknown cipher, got nil")
		}
	})

	t.Run("mix of valid and unknown rejected", func(t *testing.T) {
		n := &Negotiator{Ciphers: []uint16{CipherAES128GCM, 0x00FF}}
		_, err := n.effectiveCiphers()
		if err == nil {
			t.Fatal("expected error for unknown cipher in mixed list, got nil")
		}
	})
}
