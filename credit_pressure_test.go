package smb2_test

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestConcurrentReaddirUnderCreditPressure lists large directories from many
// goroutines on one session while other goroutines read a large file. Together
// they want far more credits than the session's balance holds, so requests
// regularly get a short grant. A QUERY_DIRECTORY or QUERY_INFO whose
// CreditCharge does not cover its output buffer is failed by the server with
// STATUS_INVALID_PARAMETER (MS-SMB2 3.3.5.2.5).
func TestConcurrentReaddirUnderCreditPressure(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	if testing.Short() {
		t.Skip("skipping credit pressure test in short mode")
	}

	const (
		numDirs    = 4
		numEntries = 2500 // a full listing is ~500 KiB, several 64 KiB buffers
		numListers = 16
		numReaders = 4
		rounds     = 25
		fileSize   = 4 << 20
	)

	testDir := fmt.Sprintf("testDir-%d-TestConcurrentReaddirUnderCreditPressure", os.Getpid())
	require.NoError(t, fs.Mkdir(testDir, 0755))
	var names []string
	defer func() {
		_ = forEachConcurrently(names, fs.Remove)
		_ = fs.RemoveAll(testDir)
	}()

	pad := strings.Repeat("x", 40)
	dirs := make([]string, numDirs)
	for i := range dirs {
		dirs[i] = join(testDir, fmt.Sprintf("dir%d", i))
		require.NoError(t, fs.Mkdir(dirs[i], 0755))
		for j := range numEntries {
			names = append(names, join(dirs[i], fmt.Sprintf("entry-%05d-%s", j, pad)))
		}
	}

	require.NoError(t, forEachConcurrently(names, func(name string) error {
		f, err := fs.Create(name)
		if err != nil {
			return err
		}
		return f.Close()
	}))

	bigFile := join(testDir, "big")
	data := make([]byte, fileSize)
	for i := range data {
		data[i] = byte(i)
	}
	require.NoError(t, fs.WriteFile(bigFile, data, 0644))

	var wg sync.WaitGroup
	errs := make(chan error, numListers+numReaders)

	for l := range numListers {
		wg.Go(func() {
			for r := range rounds {
				dir := dirs[(l+r)%numDirs]
				if err := listAndStat(dir, numEntries); err != nil {
					errs <- fmt.Errorf("lister %d round %d: %w", l, r, err)
					return
				}
			}
		})
	}

	done := make(chan struct{})
	var readers sync.WaitGroup
	for i := range numReaders {
		readers.Go(func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				got, err := fs.ReadFile(bigFile)
				if err != nil {
					errs <- fmt.Errorf("reader %d: %w", i, err)
					return
				}
				if len(got) != fileSize {
					errs <- fmt.Errorf("reader %d: read %d bytes, want %d", i, len(got), fileSize)
					return
				}
			}
		})
	}

	wg.Wait()
	close(done)
	readers.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	// The session must still be usable afterwards.
	_, err := fs.Stat(testDir)
	require.NoError(t, err)
}

func listAndStat(dir string, want int) error {
	d, err := fs.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()

	if _, err := d.Stat(); err != nil {
		return err
	}

	fis, err := d.Readdir(-1)
	if err != nil {
		return err
	}
	if len(fis) != want {
		return fmt.Errorf("listed %d entries in %s, want %d", len(fis), dir, want)
	}
	seen := make(map[string]struct{}, len(fis))
	for _, fi := range fis {
		if _, dup := seen[fi.Name()]; dup {
			return fmt.Errorf("entry %s listed twice in %s", fi.Name(), dir)
		}
		seen[fi.Name()] = struct{}{}
	}
	return nil
}

// forEachConcurrently runs fn on each name from 16 goroutines, since one
// request at a time makes setup and cleanup the slowest part of the test on a
// remote server. It returns the first error.
func forEachConcurrently(names []string, fn func(string) error) error {
	work := make(chan string)
	errs := make(chan error, len(names))
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for name := range work {
				if err := fn(name); err != nil {
					errs <- err
				}
			}
		})
	}
	for _, name := range names {
		work <- name
	}
	close(work)
	wg.Wait()
	close(errs)
	return <-errs
}
