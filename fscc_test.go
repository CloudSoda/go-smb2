package smb2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReparseTagBits(t *testing.T) {
	testData := []struct {
		scenario                     string
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

	for _, td := range testData {
		t.Run(td.scenario, func(t *testing.T) {
			require.Equal(t, td.microsoft, td.tag.IsMicrosoft(), "IsMicrosoft")
			require.Equal(t, td.surrogate, td.tag.IsNameSurrogate(), "IsNameSurrogate")
			require.Equal(t, td.hasDir, td.tag.IsDirectory(), "IsDirectory")
		})
	}
}
