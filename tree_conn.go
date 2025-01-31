package smb2

import (
	"context"
	"fmt"

	. "github.com/cloudsoda/go-smb2/internal/smb2"
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

func treeConnect(s *session, path string, flags uint16, mc utf16le.MapChars, ctx context.Context) (*treeConn, error) {
	req := &TreeConnectRequest{
		Flags:   flags,
		Path:    path,
		Mapping: mc,
	}

	req.CreditCharge = 1

	rr, err := s.send(req, ctx)
	if err != nil {
		return nil, err
	}

	pkts, err := s.recv(rr)
	if err != nil {
		return nil, err
	}
	if len(pkts) == 0 {
		return nil, &InvalidResponseError{"unexpected empty response"}
	}

	res, err := accept(pkts, SMB2_TREE_CONNECT)
	if err != nil {
		return nil, err
	}

	if len(res) == 0 {
		return nil, &InvalidResponseError{"unexpected empty response"}
	}

	r := TreeConnectResponseDecoder(res[0])
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken tree connect response format"}
	}

	tc := &treeConn{
		session:    s,
		treeId:     PacketCodec(pkts[0]).TreeId(),
		shareFlags: r.ShareFlags(),
		// path:    path,
		// shareType:  r.ShareType(),
		// capabilities: r.Capabilities(),
		// maximalAccess: r.MaximalAccess(),
	}

	return tc, nil
}

func (tc *treeConn) disconnect(ctx context.Context) error {
	req := new(TreeDisconnectRequest)

	req.CreditCharge = 1

	res, err := tc.sendRecv(ctx, req, SMB2_TREE_DISCONNECT)
	if err != nil {
		return err
	}
	if len(res) == 0 {
		return &InvalidResponseError{"unexpected empty response"}
	}

	r := TreeDisconnectResponseDecoder(res[0])
	if r.IsInvalid() {
		return &InvalidResponseError{"broken tree disconnect response format"}
	}

	return nil
}

func (tc *treeConn) sendRecv(ctx context.Context, req Packet, cmds ...uint16) (res [][]byte, err error) {
	rr, err := tc.send(req, ctx)
	if err != nil {
		return nil, err
	}

	pkts, err := tc.recv(rr)
	if err != nil {
		return nil, err
	}

	return accept(pkts, cmds...)
}

func (tc *treeConn) send(req Packet, ctx context.Context) (rr *requestResponse, err error) {
	return tc.sendWith(req, tc, ctx)
}

func (tc *treeConn) recv(rr *requestResponse) (pkts [][]byte, err error) {
	pkts, err = tc.session.recv(rr)
	if err != nil {
		return nil, err
	}
	if len(pkts) == 0 {
		return nil, &InvalidResponseError{"unexpected empty response"}
	}
	if rr.asyncId != 0 {
		if asyncId := PacketCodec(pkts[0]).AsyncId(); asyncId != rr.asyncId {
			return nil, &InvalidResponseError{fmt.Sprintf("expected async id: %v, got %v", rr.asyncId, asyncId)}
		}
	} else {
		if treeId := PacketCodec(pkts[0]).TreeId(); treeId != tc.treeId {
			return nil, &InvalidResponseError{fmt.Sprintf("expected tree id: %v, got %v", tc.treeId, treeId)}
		}
	}
	return pkts, err
}
