package smb2

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2/internal/smb2"
)

// A negotiate-only server: it answers the first request with resp and stops.
func negotiateServer(t *testing.T, mk func() *smb2.NegotiateResponse) net.Conn {
	t.Helper()
	cc, sc := net.Pipe()
	t.Cleanup(func() { cc.Close(); sc.Close() })
	go func() {
		st := direct(sc)
		n, err := st.ReadSize()
		if err != nil {
			return
		}
		buf := make([]byte, n)
		if _, err := st.Read(buf); err != nil {
			return
		}
		resp := mk()
		resp.Flags = smb2.SMB2_FLAGS_SERVER_TO_REDIR
		resp.MessageId = smb2.PacketCodec(buf).MessageId()
		resp.CreditRequestResponse = 1
		out := make([]byte, resp.Size())
		resp.Encode(out)
		st.Write(out)
	}()
	return cc
}

func dialNegotiate(t *testing.T, mk func() *smb2.NegotiateResponse, require bool) error {
	t.Helper()
	d := &Dialer{
		Negotiator: Negotiator{RequireEncryption: require},
		Initiator:  &NTLMInitiator{User: "u", Password: "p"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := d.DialConn(ctx, negotiateServer(t, mk), "h")
	return err
}

func baseNegotiate(dialect uint16, caps uint32) *smb2.NegotiateResponse {
	return &smb2.NegotiateResponse{
		DialectRevision: dialect,
		Capabilities:    caps,
		MaxTransactSize: 1 << 16,
		MaxReadSize:     1 << 16,
		MaxWriteSize:    1 << 16,
		SystemTime:      &smb2.Filetime{},
		ServerStartTime: &smb2.Filetime{},
	}
}

// RequireEncryption refuses, at negotiate, every server that cannot encrypt.
func TestRequireEncryptionRefusesAtNegotiate(t *testing.T) {
	salt := make([]byte, 32)
	rand.Read(salt)
	cases := map[string]func() *smb2.NegotiateResponse{
		"SMB 2.1": func() *smb2.NegotiateResponse {
			return baseNegotiate(smb2.SMB210, 0)
		},
		"SMB 3.0 without the encryption capability": func() *smb2.NegotiateResponse {
			return baseNegotiate(smb2.SMB300, smb2.SMB2_GLOBAL_CAP_LARGE_MTU)
		},
		"SMB 3.1.1 with no cipher context": func() *smb2.NegotiateResponse {
			r := baseNegotiate(smb2.SMB311, smb2.SMB2_GLOBAL_CAP_LARGE_MTU)
			r.Contexts = []smb2.Encoder{&smb2.HashContext{HashAlgorithms: []uint16{smb2.SHA512}, HashSalt: salt}}
			return r
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			err := dialNegotiate(t, mk, true)
			if !errors.Is(err, ErrEncryptionRequired) {
				t.Fatalf("want ErrEncryptionRequired, got %v", err)
			}
		})
	}
}

// Without the option the same servers are not refused for encryption: the
// failure, if any, comes later (session setup against a stub), never
// ErrEncryptionRequired.
func TestEncryptionNotRequiredByDefault(t *testing.T) {
	err := dialNegotiate(t, func() *smb2.NegotiateResponse { return baseNegotiate(smb2.SMB210, 0) }, false)
	if errors.Is(err, ErrEncryptionRequired) {
		t.Fatalf("refused for encryption without RequireEncryption: %v", err)
	}
}

// The accessors: nothing set, nothing encrypted; the session flag, the share
// flag and the dialer's requirement each say so, and a missing key never does.
func TestEncryptedAccessors(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	mk := func(flags uint16, require bool, withKey bool) *session {
		s := &session{conn: &conn{requireEncryption: require}, sessionFlags: flags}
		if withKey {
			s.encrypter = newGCM(key)
		}
		return s
	}
	share := func(s *session, sf uint32) *Share {
		return &Share{treeConn: &treeConn{session: s, shareFlags: sf}}
	}
	if (&Session{s: mk(0, false, true)}).Encrypted() {
		t.Error("plain session reported encrypted")
	}
	if !(&Session{s: mk(smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA, false, true)}).Encrypted() {
		t.Error("server-encrypted session not reported")
	}
	if !(&Session{s: mk(0, true, true)}).Encrypted() {
		t.Error("required encryption not reported")
	}
	if (&Session{s: mk(0, true, false)}).Encrypted() {
		t.Error("a session with no key reported encrypted")
	}
	if share(mk(0, false, true), 0).Encrypted() {
		t.Error("plain share reported encrypted")
	}
	if !share(mk(0, false, true), smb2.SMB2_SHAREFLAG_ENCRYPT_DATA).Encrypted() {
		t.Error("encrypted share not reported")
	}
	if !share(mk(0, true, true), 0).Encrypted() {
		t.Error("share of a required-encryption session not reported")
	}
}

// plainReplyServer decrypts the client's requests and answers IN CLEAR: what
// an attacker stripping the encryption, or a server that ignores it, does.
func plainReplyServer(t transport, dec interface {
	NonceSize() int
	Open(dst, nonce, ct, ad []byte) ([]byte, error)
}) {
	resp := &smb2.ReadResponse{
		PacketHeader: smb2.PacketHeader{Flags: smb2.SMB2_FLAGS_SERVER_TO_REDIR, SessionId: 0xdeadbeef},
		Data:         make([]byte, 16),
	}
	plain := make([]byte, resp.Size())
	resp.Encode(plain)
	plain[64+2] = 80
	buf := make([]byte, bufSize+52+16)
	for {
		n, err := t.ReadSize()
		if err != nil {
			return
		}
		if _, err := t.Read(buf[:n]); err != nil {
			return
		}
		tc := smb2.TransformCodec(buf[:n])
		ct := append(append([]byte(nil), tc.EncryptedData()...), tc.Signature()...)
		req, err := dec.Open(nil, tc.Nonce(dec.NonceSize()), ct, tc.AssociatedData())
		if err != nil {
			return
		}
		rp := smb2.PacketCodec(plain)
		rp.SetMessageId(smb2.PacketCodec(req).MessageId())
		rp.SetCreditResponse(smb2.PacketCodec(req).CreditRequest())
		if _, err := t.Write(plain); err != nil {
			return
		}
	}
}

func encryptedConn(t *testing.T, require bool, serverFlags uint16) (*conn, *Share, []byte, []byte, net.Conn) {
	t.Helper()
	cc, sc := net.Pipe()
	c, cleanup := newBenchConn(cc)
	t.Cleanup(cleanup)
	t.Cleanup(func() { sc.Close() })
	c.requireEncryption = require
	kc, ks := make([]byte, 16), make([]byte, 16)
	rand.Read(kc)
	rand.Read(ks)
	c.session.Store(&session{conn: c, sessionFlags: serverFlags, sessionId: 0xdeadbeef, encrypter: newGCM(kc), decrypter: newGCM(ks)})
	c.useSession.Store(true)
	return c, newBenchFile(c).fs, kc, ks, sc
}

// With RequireEncryption the client encrypts although the server never asked
// (session flags 0): a server that only accepts encrypted requests answers.
func TestRequireEncryptionEncryptsWithoutServerFlag(t *testing.T) {
	c, fs, kc, ks, sc := encryptedConn(t, true, 0)
	go fakeServerEncrypted(direct(sc), make([]byte, 16), newGCM(kc), newGCM(ks), 0xdeadbeef)
	f := &File{fs: fs, fd: &smb2.FileId{}}
	buf := make([]byte, 16)
	if n, err := f.readAt(buf, 0); err != nil || n != 16 {
		t.Fatalf("readAt: %d %v", n, err)
	}
	if !fs.Encrypted() || !(&Session{s: c.session.Load()}).Encrypted() {
		t.Fatal("accessors do not report the encryption in use")
	}
}

// A response in clear on an encrypted-only connection is refused, not delivered.
func TestRequireEncryptionRefusesAClearResponse(t *testing.T) {
	_, fs, kc, _, sc := encryptedConn(t, true, 0)
	go plainReplyServer(direct(sc), newGCM(kc))
	f := &File{fs: fs, fd: &smb2.FileId{}}
	buf := make([]byte, 16)
	_, err := f.readAt(buf, 0)
	var ir *InvalidResponseError
	if !errors.As(err, &ir) {
		t.Fatalf("want InvalidResponseError for a clear response, got %v", err)
	}
}

// FuzzRequireEncryptionNegotiate: whatever bytes a hostile server answers the
// negotiate with, a dial that requires encryption returns an error and does
// not panic or hang. (It can never succeed here: no session setup follows.)
func FuzzRequireEncryptionNegotiate(f *testing.F) {
	salt := make([]byte, 32)
	for _, mk := range []func() *smb2.NegotiateResponse{
		func() *smb2.NegotiateResponse { return baseNegotiate(smb2.SMB210, 0) },
		func() *smb2.NegotiateResponse {
			r := baseNegotiate(smb2.SMB311, smb2.SMB2_GLOBAL_CAP_ENCRYPTION)
			r.Contexts = []smb2.Encoder{&smb2.HashContext{HashAlgorithms: []uint16{smb2.SHA512}, HashSalt: salt}, &smb2.CipherContext{Ciphers: []uint16{smb2.AES128GCM}}}
			return r
		},
	} {
		r := mk()
		r.Flags = smb2.SMB2_FLAGS_SERVER_TO_REDIR
		out := make([]byte, r.Size())
		r.Encode(out)
		f.Add(out)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<16 {
			return
		}
		cc, sc := net.Pipe()
		defer cc.Close()
		defer sc.Close()
		go func() {
			st := direct(sc)
			n, err := st.ReadSize()
			if err != nil {
				return
			}
			if _, err := st.Read(make([]byte, n)); err != nil {
				return
			}
			st.Write(body)
		}()
		d := &Dialer{Negotiator: Negotiator{RequireEncryption: true}, Initiator: &NTLMInitiator{User: "u", Password: "p"}}
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		if s, err := d.DialConn(ctx, cc, "h"); err == nil {
			t.Fatalf("dial succeeded without a session setup: %v", s)
		}
	})
}

// checkEncryptionKeys: each way a required-encryption session can lack keys is
// refused, one at a time, and the same session is fine when nothing is required.
func TestCheckEncryptionKeys(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	mk := func(require bool, enc, dec bool, flags uint16) *session {
		s := &session{conn: &conn{requireEncryption: require}, sessionFlags: flags}
		if enc {
			s.encrypter = newGCM(key)
		}
		if dec {
			s.decrypter = newGCM(key)
		}
		return s
	}
	for name, tc := range map[string]struct {
		s       *session
		refused bool
	}{
		"keys, user session":      {mk(true, true, true, 0), false},
		"no encrypter":            {mk(true, false, true, 0), true},
		"no decrypter":            {mk(true, true, false, 0), true},
		"guest with keys":         {mk(true, true, true, smb2.SMB2_SESSION_FLAG_IS_GUEST), true},
		"anonymous with keys":     {mk(true, true, true, smb2.SMB2_SESSION_FLAG_IS_NULL), true},
		"nothing required, guest": {mk(false, false, false, smb2.SMB2_SESSION_FLAG_IS_GUEST), false},
	} {
		err := tc.s.checkEncryptionKeys()
		if tc.refused != errors.Is(err, ErrEncryptionRequired) || (!tc.refused && err != nil) {
			t.Errorf("%s: refused=%v, got %v", name, tc.refused, err)
		}
		got, aerr := tc.s.admit()
		if tc.refused && (got != nil || !errors.Is(aerr, ErrEncryptionRequired) || tc.s.useSession.Load()) {
			t.Errorf("%s: admit let a refused session through", name)
		}
		if !tc.refused && (got != tc.s || aerr != nil || !tc.s.useSession.Load()) {
			t.Errorf("%s: admit refused a good session: %v", name, aerr)
		}
	}
}
