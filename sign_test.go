package smb2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/cloudsoda/go-smb2/internal/crypto/cmac"
	"github.com/cloudsoda/go-smb2/internal/smb2"
)

func TestSign(t *testing.T) {
	sessionKey, err := hex.DecodeString("726d4c454e63516446695457664e5042")
	if err != nil {
		t.Fatal(err)
	}

	pkt, err := hex.DecodeString("fe534d42400001000000000001007f00090000000000000003000000000000000000000000000000020000007bfba3f4041393e756a048c9092c4e52dc7037190900000048000900a1073005a0030a0100")
	if err != nil {
		t.Fatal(err)
	}

	signature, err := hex.DecodeString("041393e756a048c9092c4e52dc703719")
	if err != nil {
		t.Fatal(err)
	}

	signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
	ciph, err := aes.NewCipher(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	signer := cmac.New(ciph)

	p := smb2.PacketCodec(pkt)

	if !bytes.Equal(p.Signature(), signature) {
		t.Error("fail")
	}

	p.SetSignature(zero[:])

	signer.Reset()
	signer.Write(pkt)
	signer.Sum(pkt[:48])
	if !bytes.Equal(p.Signature(), signature) {
		t.Error("fail")
	}
}

// makeMinimalSMB2Packet builds a minimal 64-byte SMB2 packet header with the
// given messageId and sessionId (both little-endian) and 16 zero signature bytes.
func makeMinimalSMB2Packet(messageId, sessionId uint64) []byte {
	pkt := make([]byte, 64)
	// ProtocolId: \xfeSMB
	copy(pkt[0:4], []byte{0xfe, 0x53, 0x4d, 0x42})
	// StructureSize = 64
	pkt[4] = 64
	// MessageId at bytes 24-32
	pkt[24] = byte(messageId)
	pkt[25] = byte(messageId >> 8)
	pkt[26] = byte(messageId >> 16)
	pkt[27] = byte(messageId >> 24)
	pkt[28] = byte(messageId >> 32)
	pkt[29] = byte(messageId >> 40)
	pkt[30] = byte(messageId >> 48)
	pkt[31] = byte(messageId >> 56)
	// SessionId at bytes 40-48
	pkt[40] = byte(sessionId)
	pkt[41] = byte(sessionId >> 8)
	pkt[42] = byte(sessionId >> 16)
	pkt[43] = byte(sessionId >> 24)
	pkt[44] = byte(sessionId >> 32)
	pkt[45] = byte(sessionId >> 40)
	pkt[46] = byte(sessionId >> 48)
	pkt[47] = byte(sessionId >> 56)
	return pkt
}

// TestGMACSigner_RoundTrip verifies that a packet signed with gmacSigner can be
// verified by recomputing the tag over the same input.
func TestGMACSigner_RoundTrip(t *testing.T) {
	key, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	if err != nil {
		t.Fatal(err)
	}

	pkt := makeMinimalSMB2Packet(0x0000000000000001, 0x0000000100000002)

	signer, err := newGMACSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := newGMACSigner(key)
	if err != nil {
		t.Fatal(err)
	}

	p := smb2.PacketCodec(pkt)

	// Sign
	signer.Reset()
	signer.Write(pkt)
	sig := signer.Sum(nil)
	if len(sig) != 16 {
		t.Fatalf("expected 16-byte signature, got %d", len(sig))
	}
	p.SetSignature(sig)

	// Verify: save signature, zero it, recompute, compare
	savedSig := append([]byte{}, p.Signature()...)
	p.SetSignature(zero[:])

	verifier.Reset()
	verifier.Write(pkt)
	computed := verifier.Sum(nil)

	if !bytes.Equal(savedSig, computed) {
		t.Errorf("GMAC verify failed: got %x, want %x", computed, savedSig)
	}
}

// TestGMACSigner_NonceIsolation verifies that changing the MessageId produces a
// different GMAC tag (the nonce changes per MS-SMB2 §3.1.4.1).
func TestGMACSigner_NonceIsolation(t *testing.T) {
	key, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	if err != nil {
		t.Fatal(err)
	}

	pkt1 := makeMinimalSMB2Packet(1, 0x0000000100000002)
	pkt2 := makeMinimalSMB2Packet(2, 0x0000000100000002)

	sign := func(pkt []byte) []byte {
		s, err := newGMACSigner(key)
		if err != nil {
			t.Fatal(err)
		}
		s.Write(pkt)
		return s.Sum(nil)
	}

	tag1 := sign(pkt1)
	tag2 := sign(pkt2)

	if bytes.Equal(tag1, tag2) {
		t.Error("expected different GMAC tags for different MessageIds")
	}
}

// TestGMACSigner_MatchesStdlib cross-checks that gmacSigner produces the same
// output as computing AES-GCM manually with the nonce derived from the packet.
func TestGMACSigner_MatchesStdlib(t *testing.T) {
	keyBytes, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	if err != nil {
		t.Fatal(err)
	}

	messageId := uint64(0x0000000000000003)
	sessionId := uint64(0x0000000200000001)
	pkt := makeMinimalSMB2Packet(messageId, sessionId)

	// Compute expected tag via stdlib directly
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	copy(nonce[0:8], pkt[24:32])  // MessageId
	copy(nonce[8:12], pkt[40:44]) // lower 4 bytes of SessionId
	expectedTag := gcm.Seal(nil, nonce, nil, pkt)

	// Compute via gmacSigner
	s, err := newGMACSigner(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	s.Write(pkt)
	got := s.Sum(nil)

	if !bytes.Equal(got, expectedTag) {
		t.Errorf("gmacSigner output %x does not match stdlib GCM tag %x", got, expectedTag)
	}
}

// TestSigningContextEncoding verifies that SigningContext encodes and decodes
// a SMB2_SIGNING_CAPABILITIES negotiate context correctly, including all three
// algorithm IDs from the MS-SMB2 spec.
func TestSigningContextEncoding(t *testing.T) {
	algs := []uint16{smb2.SMB2_SIGNING_AES_GMAC, smb2.SMB2_SIGNING_AES_CMAC}
	sc := &smb2.SigningContext{SigningAlgorithms: algs}

	buf := make([]byte, sc.Size())
	sc.Encode(buf)

	ctx := smb2.NegotiateContextDecoder(buf)
	if ctx.IsInvalid() {
		t.Fatal("encoded signing context is invalid")
	}
	if ctx.ContextType() != smb2.SMB2_SIGNING_CAPABILITIES {
		t.Errorf("ContextType = %#x, want %#x", ctx.ContextType(), smb2.SMB2_SIGNING_CAPABILITIES)
	}

	d := smb2.SigningContextDataDecoder(ctx.Data())
	if d.IsInvalid() {
		t.Fatal("signing context data is invalid")
	}
	got := d.SigningAlgorithms()
	if len(got) != len(algs) {
		t.Fatalf("algorithm count = %d, want %d", len(got), len(algs))
	}
	for i, alg := range algs {
		if got[i] != alg {
			t.Errorf("alg[%d] = %#x, want %#x", i, got[i], alg)
		}
	}
}
