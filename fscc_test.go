package smb2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReparseTagBits(t *testing.T) {
	cases := []struct {
		name                         string
		tag                          ReparseTag
		microsoft, surrogate, hasDir bool
	}{
		{"Symlink", IOReparseTagSymlink, true, true, false},
		{"MountPoint", IOReparseTagMountPoint, true, true, false},
		{"Cloud", IOReparseTagCloud, true, false, true},
		{"ProjFS", IOReparseTagProjFS, true, false, true},
		{"StorageSyncFolder", IOReparseTagStorageSyncFolder, true, false, true},
		{"Dedup", IOReparseTagDedup, true, false, false},
		{"HSM", IOReparseTagHSM, true, false, false}, // also sets the reserved R bit
		{"ThirdParty", 0x0000ABCD, false, false, false},
		{"ThirdPartySurrogate", 0x2000ABCD, false, true, false},
		{"ThirdPartyDirectory", 0x1000ABCD, false, false, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.microsoft, c.tag.IsMicrosoft(), "IsMicrosoft")
			require.Equal(t, c.surrogate, c.tag.IsNameSurrogate(), "IsNameSurrogate")
			require.Equal(t, c.hasDir, c.tag.IsDirectory(), "IsDirectory")
		})
	}
}
