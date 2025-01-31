package smb2

import (
	"fmt"
	"strings"

	"github.com/cloudsoda/go-smb2/internal/erref"
)

// CommandName maps SMB2 command codes to their string representations
var CommandName = map[uint16]string{
	SMB2_NEGOTIATE:       "SMB2 NEGOTIATE",
	SMB2_SESSION_SETUP:   "SMB2 SESSION SETUP",
	SMB2_LOGOFF:          "SMB2 LOGOFF",
	SMB2_TREE_CONNECT:    "SMB2 TREE CONNECT",
	SMB2_TREE_DISCONNECT: "SMB2 TREE DISCONNECT",
	SMB2_CREATE:          "SMB2 CREATE",
	SMB2_CLOSE:           "SMB2 CLOSE",
	SMB2_FLUSH:           "SMB2 FLUSH",
	SMB2_READ:            "SMB2 READ",
	SMB2_WRITE:           "SMB2 WRITE",
	SMB2_LOCK:            "SMB2 LOCK",
	SMB2_IOCTL:           "SMB2 IOCTL",
	SMB2_CANCEL:          "SMB2 CANCEL",
	SMB2_ECHO:            "SMB2 ECHO",
	SMB2_QUERY_DIRECTORY: "SMB2 QUERY DIRECTORY",
	SMB2_CHANGE_NOTIFY:   "SMB2 CHANGE NOTIFY",
	SMB2_QUERY_INFO:      "SMB2 QUERY INFO",
	SMB2_SET_INFO:        "SMB2 SET INFO",
	SMB2_OPLOCK_BREAK:    "SMB2 OPLOCK BREAK",
}

// GetCommandName returns the string representation of an SMB2 command code
func GetCommandName(command uint16) string {
	if name, ok := CommandName[command]; ok {
		return name
	}
	return "UNKNOWN"
}

// StatusName maps NT status codes to their string representations
var StatusName = map[erref.NtStatus]string{
	erref.STATUS_SUCCESS:                  "STATUS_SUCCESS",
	erref.STATUS_PENDING:                  "STATUS_PENDING",
	erref.STATUS_NOTIFY_CLEANUP:           "STATUS_NOTIFY_CLEANUP",
	erref.STATUS_NOTIFY_ENUM_DIR:          "STATUS_NOTIFY_ENUM_DIR",
	erref.STATUS_NO_MORE_FILES:            "STATUS_NO_MORE_FILES",
	erref.STATUS_INFO_LENGTH_MISMATCH:     "STATUS_INFO_LENGTH_MISMATCH",
	erref.STATUS_INVALID_PARAMETER:        "STATUS_INVALID_PARAMETER",
	erref.STATUS_NO_SUCH_FILE:             "STATUS_NO_SUCH_FILE",
	erref.STATUS_END_OF_FILE:              "STATUS_END_OF_FILE",
	erref.STATUS_MORE_PROCESSING_REQUIRED: "STATUS_MORE_PROCESSING_REQUIRED",
	erref.STATUS_ACCESS_DENIED:            "STATUS_ACCESS_DENIED",
	erref.STATUS_OBJECT_NAME_NOT_FOUND:    "STATUS_OBJECT_NAME_NOT_FOUND",
	erref.STATUS_OBJECT_NAME_COLLISION:    "STATUS_OBJECT_NAME_COLLISION",
	erref.STATUS_OBJECT_PATH_NOT_FOUND:    "STATUS_OBJECT_PATH_NOT_FOUND",
	erref.STATUS_SHARING_VIOLATION:        "STATUS_SHARING_VIOLATION",
	erref.STATUS_LOCK_NOT_GRANTED:         "STATUS_LOCK_NOT_GRANTED",
	erref.STATUS_RANGE_NOT_LOCKED:         "STATUS_RANGE_NOT_LOCKED",
	erref.STATUS_INSTANCE_NOT_AVAILABLE:   "STATUS_INSTANCE_NOT_AVAILABLE",
	erref.STATUS_PIPE_NOT_AVAILABLE:       "STATUS_PIPE_NOT_AVAILABLE",
	erref.STATUS_INVALID_PIPE_STATE:       "STATUS_INVALID_PIPE_STATE",
	erref.STATUS_PIPE_BUSY:                "STATUS_PIPE_BUSY",
	erref.STATUS_PIPE_DISCONNECTED:        "STATUS_PIPE_DISCONNECTED",
	erref.STATUS_PIPE_CLOSING:             "STATUS_PIPE_CLOSING",
	erref.STATUS_FILE_IS_A_DIRECTORY:      "STATUS_FILE_IS_A_DIRECTORY",
	erref.STATUS_NOT_SUPPORTED:            "STATUS_NOT_SUPPORTED",
}

// GetStatusName returns the string representation of an NT status code
func GetStatusName(status erref.NtStatus) string {
	if name, ok := StatusName[status]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_STATUS_0x%08x", uint32(status))
}

// DumpPacket dumps a SMB2 packet to a string aligned in 32 bits
func DumpPacket(pkt []byte, indent string) string {
	result := &strings.Builder{}
	rowSize := 4
	rowNum := 0
	for {
		if len(pkt) < rowSize {
			rowSize = len(pkt)
		}
		row := pkt[:rowSize]
		pkt = pkt[rowSize:]
		rowAdjusted := row
		if rowSize < 4 {
			rowAdjusted = append(row, make([]byte, 4-rowSize)...)
		}
		result.WriteString(fmt.Sprintf("%4d [%04d:0x%04X:%08b %08b]: ", rowNum, rowNum*4, rowNum*4, (rowNum*4)>>8, (rowNum*4)&0x00FF))
		result.WriteString(fmt.Sprintf("0x%X\t| ", rowAdjusted))
		result.WriteString(fmt.Sprintf("%08b", row[0]))
		for i := 1; i < len(row); i++ {
			result.WriteString(fmt.Sprintf(" %08b", row[i]))
		}
		if len(pkt) > 0 {
			result.WriteString("\n")
			result.WriteString(indent)
		} else {
			break
		}
		rowNum++
	}
	return result.String()
}
