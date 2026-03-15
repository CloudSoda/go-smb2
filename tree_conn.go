package smb2

import (
	"context"
	"fmt"

	"github.com/cloudsoda/go-smb2/internal/smb2"
	"github.com/cloudsoda/go-smb2/internal/utf16le"
)

type treeConn struct {
	*session
	treeId     uint32
	shareFlags uint32

	// path string
	// shareType  uint8
	// capabilities uint32
	// maximalAccess uint32
}

func treeConnect(ctx context.Context, s *session, path string, flags uint16, mc utf16le.MapChars) (*treeConn, error) {
	req := &smb2.TreeConnectRequest{
		Flags:   flags,
		Path:    path,
		Mapping: mc,
	}

	req.CreditCharge = 1

	rr, err := s.send(ctx, req)
	if err != nil {
		return nil, err
	}

	pkt, err := s.recv(rr)
	if err != nil {
		return nil, err
	}

	res, err := accept(smb2.SMB2_TREE_CONNECT, pkt)
	if err != nil {
		return nil, err
	}

	r := smb2.TreeConnectResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken tree connect response format"}
	}

	tc := &treeConn{
		session:    s,
		treeId:     smb2.PacketCodec(pkt).TreeId(),
		shareFlags: r.ShareFlags(),
		// path:    path,
		// shareType:  r.ShareType(),
		// capabilities: r.Capabilities(),
		// maximalAccess: r.MaximalAccess(),
	}

	return tc, nil
}

func (tc *treeConn) disconnect(ctx context.Context) error {
	req := new(smb2.TreeDisconnectRequest)

	req.CreditCharge = 1

	res, err := tc.sendRecv(ctx, smb2.SMB2_TREE_DISCONNECT, req)
	if err != nil {
		return err
	}

	r := smb2.TreeDisconnectResponseDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken tree disconnect response format"}
	}

	return nil
}

func (tc *treeConn) sendRecv(ctx context.Context, cmd uint16, req smb2.Packet) (res []byte, err error) {
	rr, err := tc.send(ctx, req)
	if err != nil {
		return nil, err
	}

	pkt, err := tc.recv(rr)
	if err != nil {
		return nil, err
	}

	return accept(cmd, pkt)
}

func (tc *treeConn) send(ctx context.Context, req smb2.Packet) (rr *requestResponse, err error) {
	return tc.sendWith(ctx, req, tc)
}

func (tc *treeConn) recv(rr *requestResponse) (pkt []byte, err error) {
	pkt, err = tc.session.recv(rr)
	if err != nil {
		return nil, err
	}
	if rr.asyncId != 0 {
		if asyncId := smb2.PacketCodec(pkt).AsyncId(); asyncId != rr.asyncId {
			return nil, &InvalidResponseError{fmt.Sprintf("expected async id: %v, got %v", rr.asyncId, asyncId)}
		}
	} else {
		if treeId := smb2.PacketCodec(pkt).TreeId(); treeId != tc.treeId {
			return nil, &InvalidResponseError{fmt.Sprintf("expected tree id: %v, got %v", tc.treeId, treeId)}
		}
	}
	return pkt, err
}
