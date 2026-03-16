package smb2

import (
	"fmt"
	"os"
	"testing"

	"github.com/cloudsoda/go-smb2/internal/erref"
)

func TestIsFileDeleted(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"ErrNotExist", os.ErrNotExist, true},
		{"wrapped ErrNotExist", fmt.Errorf("open foo: %w", os.ErrNotExist), true},
		{"STATUS_OBJECT_NAME_NOT_FOUND", os.ErrNotExist, true}, // accept maps this to ErrNotExist
		{"STATUS_DELETE_PENDING", &ResponseError{Code: uint32(erref.STATUS_DELETE_PENDING)}, true},
		{"other ResponseError", &ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)}, false},
		{"unrelated error", fmt.Errorf("something else"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFileDeleted(tt.err); got != tt.want {
				t.Errorf("isFileDeleted(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
