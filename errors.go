package smb2

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cloudsoda/go-smb2/internal/erref"
)

// ErrWindowsTooManyConnectionsStr is the error message that windows returns when there are more connections requested than the maximum allowed.
const ErrWindowsTooManyConnectionsStr = "No more connections can be made to this remote computer at this time because the computer has already accepted the maximum number of connections."

// ErrWindowsTooManyConnections represents the error that windows returns when there are more connections requested than the maximum allowed.
var ErrWindowsTooManyConnections = errors.New(strings.ToLower(ErrWindowsTooManyConnectionsStr))

// TransportError represents a error come from net.Conn layer.
type TransportError struct {
	Err error
}

func (err *TransportError) Error() string {
	return fmt.Sprintf("connection error: %v", err.Err)
}

// InternalError represents internal error.
type InternalError struct {
	Message string
}

func (err *InternalError) Error() string {
	return fmt.Sprintf("internal error: %s", err.Message)
}

// InvalidResponseError represents a data sent by the server is corrupted or unexpected.
type InvalidResponseError struct {
	Message string
}

func (err *InvalidResponseError) Error() string {
	return fmt.Sprintf("invalid response error: %s", err.Message)
}

// ResponseError represents a error with a nt status code sent by the server.
// The NTSTATUS is defined in [MS-ERREF].
// https://msdn.microsoft.com/en-au/library/cc704588.aspx
type ResponseError struct {
	Code uint32 // NTSTATUS
	data [][]byte
}

func (err *ResponseError) Error() string {
	return fmt.Sprintf("response error: %v", erref.NtStatus(err.Code))
}
