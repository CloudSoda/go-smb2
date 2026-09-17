package smb2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShareInfoTypeFlags(t *testing.T) {
	tests := []struct {
		name      string
		typeFlags uint32
		want      ShareType
		str       string
		special   bool
		temporary bool
	}{
		{name: "disk tree", typeFlags: 0x00000000, want: ShareTypeDiskTree, str: "disktree"},
		{name: "print queue", typeFlags: 0x00000001, want: ShareTypePrintQueue, str: "printq"},
		{name: "device", typeFlags: 0x00000002, want: ShareTypeDevice, str: "device"},
		{name: "ipc", typeFlags: 0x00000003, want: ShareTypeIPC, str: "ipc"},
		{name: "special disk tree", typeFlags: 0x80000000, want: ShareTypeDiskTree, str: "disktree", special: true},
		{name: "special ipc", typeFlags: 0x80000003, want: ShareTypeIPC, str: "ipc", special: true},
		{name: "temporary print queue", typeFlags: 0x40000001, want: ShareTypePrintQueue, str: "printq", temporary: true},
		{name: "special and temporary disk tree", typeFlags: 0xc0000000, want: ShareTypeDiskTree, str: "disktree", special: true, temporary: true},
		{name: "undefined base type with special flag", typeFlags: 0x8000000f, want: ShareType(0xf), str: "unknown", special: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ShareInfo{Name: tt.name, TypeFlags: tt.typeFlags}

			require.Equal(t, tt.want, s.Type())
			require.Equal(t, tt.str, s.Type().String())
			require.Equal(t, tt.special, s.IsSpecial(), "IsSpecial")
			require.Equal(t, tt.temporary, s.IsTemporary(), "IsTemporary")
			require.Equal(t, tt.typeFlags, s.TypeFlags)
		})
	}
}
