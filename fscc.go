package smb2

import (
	"github.com/cloudsoda/go-smb2/internal/smb2"
)

// A ReparseTag uniquely identifies the owner of a reparse point. The owner is
// the implementer of the file system filter driver associated with a reparse
// tag.
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4
type ReparseTag uint32

const (
	// Reserved
	IOReparseTagReservedZero ReparseTag = smb2.IO_REPARSE_TAG_RESERVED_ZERO
	// Reserved
	IOReparseTagReservedOne ReparseTag = smb2.IO_REPARSE_TAG_RESERVED_ONE
	// Reserved
	IOReparseTagReservedTwo ReparseTag = smb2.IO_REPARSE_TAG_RESERVED_TWO
	// Used for mount point support. See MS-FSCC 2.1.2.5.
	IOReparseTagMountPoint ReparseTag = smb2.IO_REPARSE_TAG_MOUNT_POINT
	// Obsolete. Used by legacy Hierarchical Storage Management Product
	IOReparseTagHSM ReparseTag = smb2.IO_REPARSE_TAG_HSM
	// Home server drive extender
	IOReparseTagDriveExtender ReparseTag = smb2.IO_REPARSE_TAG_DRIVE_EXTENDER
	// Obsolete. Used by legacy Hierarchical Storage Management Product.
	IOReparseTagHSM2 ReparseTag = smb2.IO_REPARSE_TAG_HSM2
	// Used by single-instance storage (SIS) filter driver. Server-side
	// interpretation only, not meaningful over the wire.
	IOReparseTagSIS ReparseTag = smb2.IO_REPARSE_TAG_SIS
	// Used by the WIM Mount filter. Server-side interpretation only, not
	// meaningful over the wire.
	IOReparseTagWIM ReparseTag = smb2.IO_REPARSE_TAG_WIM
	// Obsolete. Used by Clustered Shared Volumes (CSV) version 1 in Windows
	// Server 2008 R2 operating system. Server-side interpretation only, not
	// meaningful over the wire.
	IOReparseTagCSV ReparseTag = smb2.IO_REPARSE_TAG_CSV
	// Used by the DFS filter. The DFS is described in the Distributed File
	// System (DFS): Referral Protocol Specification [MS-DFSC]. Server-side
	// interpretation only, not meaningful over the wire.
	IOReparseTagDFS ReparseTag = smb2.IO_REPARSE_TAG_DFS
	// Used by filter manager test harness.
	IOReparseTagFilterManager ReparseTag = smb2.IO_REPARSE_TAG_FILTER_MANAGER
	// Used for symbolic link support. See MS-FSCC 2.1.2.4.
	IOReparseTagSymlink ReparseTag = smb2.IO_REPARSE_TAG_SYMLINK
	// Used by Microsoft Internet Information Services (IIS) caching.
	// Server-side interpretation only, not meaningful over the wire.
	IOReparseTagIISCache ReparseTag = smb2.IO_REPARSE_TAG_IIS_CACHE
	// Used by the DFS filter. The DFS is described in [MS-DFSC]. Server-side
	// interpretation only, not meaningful over the wire.
	IOReparseTagDFSR ReparseTag = smb2.IO_REPARSE_TAG_DFSR
	// Used by the Data Deduplication (Dedup) filter. Server-side
	// interpretation only, not meaningful over the wire.
	IOReparseTagDedup ReparseTag = smb2.IO_REPARSE_TAG_DEDUP
	// Not used.
	IOReparseTagAppXStrm ReparseTag = smb2.IO_REPARSE_TAG_APPXSTRM
	// Used by the Network File System (NFS) component. Server-side
	// interpretation only, not meaningful over the wire.
	IOReparseTagNFS ReparseTag = smb2.IO_REPARSE_TAG_NFS
	// Obsolete. Used by Windows Shell for legacy placeholder files in Windows
	// 8.1. Server-side interpretation only, not meaningful over the wire.
	IOReparseTagFilePlaceholder ReparseTag = smb2.IO_REPARSE_TAG_FILE_PLACEHOLDER
	// Used by the Dynamic File filter. Server-side interpretation only, not
	// meaningful over the wire.
	IOReparseTagDFM ReparseTag = smb2.IO_REPARSE_TAG_DFM
	// Used by the Windows Overlay filter, for either WIMBoot or single-file
	// compression. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagWOF ReparseTag = smb2.IO_REPARSE_TAG_WOF
	// Used by the Windows Container Isolation filter. Server-side
	// interpretation only, not meaningful over the wire.
	IOReparseTagWCI ReparseTag = smb2.IO_REPARSE_TAG_WCI
	// Used by the Windows Container Isolation filter. Server-side
	// interpretation only, not meaningful over the wire.
	IOReparseTagWCI1 ReparseTag = smb2.IO_REPARSE_TAG_WCI_1
	// Used by NPFS to indicate a named pipe symbolic link from a server silo
	// into the host silo. Server-side interpretation only, not meaningful over
	// the wire.
	IOReparseTagGlobalReparse ReparseTag = smb2.IO_REPARSE_TAG_GLOBAL_REPARSE
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as Microsoft OneDrive. Server-side interpretation only, not meaningful
	// over the wire.
	IOReparseTagCloud ReparseTag = smb2.IO_REPARSE_TAG_CLOUD
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloud1 ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_1
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloud2 ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_2
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloud3 ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_3
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloud4 ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_4
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloud5 ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_5
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloud6 ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_6
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloud7 ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_7
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloud8 ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_8
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloud9 ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_9
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloudA ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_A
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloudB ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_B
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloudC ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_C
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloudD ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_D
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloudE ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_E
	// Used by the Cloud Files filter, for files managed by a sync engine such
	// as OneDrive. Server-side interpretation only, not meaningful over the
	// wire.
	IOReparseTagCloudF ReparseTag = smb2.IO_REPARSE_TAG_CLOUD_F
	// Used by Universal Windows Platform (UWP) packages to encode information
	// that allows the application to be launched by CreateProcess. Server-side
	// interpretation only, not meaningful over the wire.
	IOReparseTagAppExecLink ReparseTag = smb2.IO_REPARSE_TAG_APPEXECLINK
	// Used by the Windows Projected File System filter, for files managed by a
	// user mode provider such as VFS for Git. Server-side interpretation only,
	// not meaningful over the wire.
	IOReparseTagProjFS ReparseTag = smb2.IO_REPARSE_TAG_PROJFS
	// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX
	// symbolic link. See MS-FSCC 2.1.2.7.
	IOReparseTagLxSymlink ReparseTag = smb2.IO_REPARSE_TAG_LX_SYMLINK
	// Used by the Azure File Sync (AFS) filter. Server-side interpretation
	// only, not meaningful over the wire.
	IOReparseTagStorageSync ReparseTag = smb2.IO_REPARSE_TAG_STORAGE_SYNC
	// Used by the Azure File Sync (AFS) filter for folder. Server-side
	// interpretation only, not meaningful over the wire.
	IOReparseTagStorageSyncFolder ReparseTag = smb2.IO_REPARSE_TAG_STORAGE_SYNC_FOLDER
	// Used by the Windows Container Isolation filter. Server-side
	// interpretation only, not meaningful over the wire.
	IOReparseTagWCITombstone ReparseTag = smb2.IO_REPARSE_TAG_WCI_TOMBSTONE
	// Used by the Windows Container Isolation filter. Server-side
	// interpretation only, not meaningful over the wire.
	IOReparseTagUnhandled ReparseTag = smb2.IO_REPARSE_TAG_UNHANDLED
	// Not used.
	IOReparseTagOneDrive ReparseTag = smb2.IO_REPARSE_TAG_ONEDRIVE
	// Used by the Windows Projected File System filter, for files managed by a
	// user mode provider such as VFS for Git. Server-side interpretation only,
	// not meaningful over the wire.
	IOReparseTagProjFSTombstone ReparseTag = smb2.IO_REPARSE_TAG_PROJFS_TOMBSTONE
	// Used to represent a UNIX domain socket. Server-side interpretation only,
	// not meaningful over the wire. No defined structure.
	IOReparseTagAFUnix ReparseTag = smb2.IO_REPARSE_TAG_AF_UNIX
	// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX FIFO
	// (named pipe). Server-side interpretation only, not meaningful over the
	// wire. No defined structure.
	IOReparseTagLxFIFO ReparseTag = smb2.IO_REPARSE_TAG_LX_FIFO
	// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX
	// character special file. Server-side interpretation only, not meaningful
	// over the wire. No defined structure.
	IOReparseTagLxChr ReparseTag = smb2.IO_REPARSE_TAG_LX_CHR
	// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX block
	// special file. Server-side interpretation only, not meaningful over the
	// wire. No defined structure.
	IOReparseTagLxBlk ReparseTag = smb2.IO_REPARSE_TAG_LX_BLK
	// Used by the Windows Container Isolation filter. Server-side
	// interpretation only, not meaningful over the wire.
	IOReparseTagWCILink ReparseTag = smb2.IO_REPARSE_TAG_WCI_LINK
	// Used by the Windows Container Isolation filter. Server-side
	// interpretation only, not meaningful over the wire.
	IOReparseTagWCILink1 ReparseTag = smb2.IO_REPARSE_TAG_WCI_LINK_1
)

// Flag bits of a reparse tag (MS-FSCC 2.1.2.1). Useful for classifying a
// third-party tag.
const (
	reparseTagMicrosoftBit     ReparseTag = 0x80000000
	reparseTagNameSurrogateBit ReparseTag = 0x20000000
	reparseTagDirectoryBit     ReparseTag = 0x10000000
)

// IsMicrosoft reports whether the tag is owned by Microsoft (the M bit).
// Returns false for third-party tags.
func (t ReparseTag) IsMicrosoft() bool {
	return t&reparseTagMicrosoftBit != 0
}

// IsNameSurrogate is true if a file or directory with the tag represents
// another named entity in the system, as symbolic links and mount points do
// (the N bit).
func (t ReparseTag) IsNameSurrogate() bool {
	return t&reparseTagNameSurrogateBit != 0
}

// IsDirectory is true if a directory with this tag can have children (the
// D bit), as Cloud Files and ProjFS directories do. It does not report whether
// the file is a directory, and has no meaning for a file that is not one.
func (t ReparseTag) IsDirectory() bool {
	return t&reparseTagDirectoryBit != 0
}
