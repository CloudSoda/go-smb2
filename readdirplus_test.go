package smb2

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/cloudsoda/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

// newBatchFailingDir builds a directory File whose listing is already resolved
// (so Readdir performs no I/O) but whose tree conn cannot serve a compound
// security batch: the credit account holds fewer than the 3 credits one file's
// CREATE+QUERY_INFO+CLOSE triplet costs, so compoundSecurityInfoBatch fails
// before touching the wire.
func newBatchFailingDir(names []string) *File {
	c := &conn{account: openAccount(1)}
	s := &session{conn: c}
	tc := &treeConn{session: s}

	dirents := make([]os.FileInfo, len(names))
	for i, name := range names {
		dirents[i] = &FileStat{FileName: name}
	}

	return &File{
		fs:          &Share{treeConn: tc, ctx: context.Background()},
		fd:          &smb2.FileId{},
		name:        "testdir",
		dirents:     dirents,
		noMoreFiles: true,
	}
}

// TestReaddirPlusBatchFailureErrorShape pins the contract that a failed
// compound security batch is reported only on the per-entry Err, never folded
// into the returned error. The returned error describes the directory listing
// alone, so a caller can degrade per entry instead of abandoning a directory
// whose listing succeeded.
func TestReaddirPlusBatchFailureErrorShape(t *testing.T) {
	require := require.New(t)

	names := []string{"alpha.txt", "bravo.txt", "charlie.txt"}
	d := newBatchFailingDir(names)

	entries, err := d.ReaddirPlus(-1, 0)
	require.NoError(err, "listing succeeded, so the batch failure must not surface here")
	require.Len(entries, len(names))

	var secErr error
	for i, e := range entries {
		require.Equal(names[i], e.Name())
		require.Error(e.Err, "entry %s: batch failure must be stamped on the entry", e.Name())
		if secErr == nil {
			secErr = e.Err
		}
		require.Equal(secErr, e.Err, "every entry carries the same batch error")
		require.Nil(e.RawSecurityDescriptor, "no per-entry bytes exist when the batch failed")
		require.Nil(e.SecurityDescriptor)
	}

	// The read loop still terminates: the drained handle reports io.EOF rather
	// than a joined error that no longer compares equal to it.
	entries, err = d.ReaddirPlus(1, 0)
	require.Equal(io.EOF, err)
	require.Empty(entries)
}

// TestReaddirPlusBatchFailureIncremental exercises the same contract through an
// incremental read loop, the shape a caller actually uses.
func TestReaddirPlusBatchFailureIncremental(t *testing.T) {
	require := require.New(t)

	names := []string{"alpha.txt", "bravo.txt", "charlie.txt", "delta.txt", "echo.txt"}
	d := newBatchFailingDir(names)

	var all []DirEntryPlus
	for {
		entries, err := d.ReaddirPlus(2, 0)
		all = append(all, entries...)
		if err == io.EOF {
			break
		}
		require.NoError(err, "a batch failure must never terminate the listing loop")
		require.NotEmpty(entries)
	}

	require.Len(all, len(names))
	for i, e := range all {
		require.Equal(names[i], e.Name())
		require.Error(e.Err)
		require.Nil(e.RawSecurityDescriptor)
	}
}
