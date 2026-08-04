package smb2

import (
	"errors"
	"os"

	"github.com/cloudsoda/go-smb2/internal/erref"
	"github.com/cloudsoda/go-smb2/internal/smb2"
)

// Change actions reported by Notify, from FILE_NOTIFY_INFORMATION.Action.
const (
	ActionAdded           = smb2.FILE_ACTION_ADDED
	ActionRemoved         = smb2.FILE_ACTION_REMOVED
	ActionModified        = smb2.FILE_ACTION_MODIFIED
	ActionRenamedOldName  = smb2.FILE_ACTION_RENAMED_OLD_NAME
	ActionRenamedNewName  = smb2.FILE_ACTION_RENAMED_NEW_NAME
	ActionAddedStream     = smb2.FILE_ACTION_ADDED_STREAM
	ActionRemovedStream   = smb2.FILE_ACTION_REMOVED_STREAM
	ActionModifiedStream  = smb2.FILE_ACTION_MODIFIED_STREAM
	ActionRemovedByDelete = smb2.FILE_ACTION_REMOVED_BY_DELETE
)

// Completion filters selecting which changes the server reports. Combine with OR.
const (
	NotifyChangeFileName    = smb2.FILE_NOTIFY_CHANGE_FILE_NAME
	NotifyChangeDirName     = smb2.FILE_NOTIFY_CHANGE_DIR_NAME
	NotifyChangeAttributes  = smb2.FILE_NOTIFY_CHANGE_ATTRIBUTES
	NotifyChangeSize        = smb2.FILE_NOTIFY_CHANGE_SIZE
	NotifyChangeLastWrite   = smb2.FILE_NOTIFY_CHANGE_LAST_WRITE
	NotifyChangeLastAccess  = smb2.FILE_NOTIFY_CHANGE_LAST_ACCESS
	NotifyChangeCreation    = smb2.FILE_NOTIFY_CHANGE_CREATION
	NotifyChangeEA          = smb2.FILE_NOTIFY_CHANGE_EA
	NotifyChangeSecurity    = smb2.FILE_NOTIFY_CHANGE_SECURITY
	NotifyChangeStreamName  = smb2.FILE_NOTIFY_CHANGE_STREAM_NAME
	NotifyChangeStreamSize  = smb2.FILE_NOTIFY_CHANGE_STREAM_SIZE
	NotifyChangeStreamWrite = smb2.FILE_NOTIFY_CHANGE_STREAM_WRITE
)

// NotifyChangeDefault is a reasonable filter for tracking content: names,
// directory names, sizes, writes and creation times.
const NotifyChangeDefault = NotifyChangeFileName |
	NotifyChangeDirName |
	NotifyChangeSize |
	NotifyChangeLastWrite |
	NotifyChangeCreation

// defaultNotifyBufferSize is the output buffer requested from the server.
//
// 32 KiB, deliberately below 64 KiB: Windows limits change notification over the
// network to a 64 KiB buffer because of a packet-size limit in the underlying
// protocol, and a larger request is rejected outright.
const defaultNotifyBufferSize = 32 * 1024

// ErrNotifyEnumDir reports that more changes occurred than the server could
// describe in the requested buffer, so no individual records are available.
//
// This is not a failure of the request — it is the protocol telling the caller
// to re-enumerate the directory itself. Any design built on Notify must keep a
// full listing path for exactly this case.
var ErrNotifyEnumDir = errors.New("smb2: too many changes to report; re-enumerate the directory")

// FileNotification is a single change reported by Notify.
type FileNotification struct {
	// Action is one of the Action* constants.
	Action uint32
	// Name is the changed path, relative to the watched directory and separated
	// by backslashes, as the server reports it.
	Name string
}

// NotifyOptions tunes a Notify call.
type NotifyOptions struct {
	// Recursive watches the whole subtree beneath the directory, including
	// directories created after the watch begins.
	Recursive bool
	// Filter selects which changes are reported; zero means NotifyChangeDefault.
	Filter uint32
	// BufferSize is the output buffer requested from the server; zero means
	// 32 KiB. Values above 64 KiB are rejected by Windows over the network.
	BufferSize uint32
}

// Notify waits for changes to a directory and returns them.
//
// It issues a single SMB2 CHANGE_NOTIFY and blocks until the server reports a
// change, ctx is cancelled, or the connection drops — so a watcher calls it in a
// loop. The server buffers changes against the open handle between calls, but
// only up to the requested buffer: on overflow it answers STATUS_NOTIFY_ENUM_DIR
// and Notify returns ErrNotifyEnumDir, meaning records were lost and the caller
// must re-enumerate.
//
// The watch is bound to this handle. If the session drops, the handle dies with
// it and the caller must reopen and re-establish state; changes occurring in the
// gap are not reported.
//
// f must be a directory opened for reading, e.g. with Share.Open. Cancellation
// follows the library's convention: use Share.WithContext before opening the
// directory.
func (f *File) Notify(opts NotifyOptions) ([]FileNotification, error) {
	ns, err := f.notify(opts)
	if err != nil {
		return nil, &os.PathError{Op: "notify", Path: f.name, Err: err}
	}
	return ns, nil
}

func (f *File) notify(opts NotifyOptions) ([]FileNotification, error) {
	filter := opts.Filter
	if filter == 0 {
		filter = NotifyChangeDefault
	}
	bufSize := opts.BufferSize
	if bufSize == 0 {
		bufSize = defaultNotifyBufferSize
	}

	var flags uint16
	if opts.Recursive {
		flags = smb2.SMB2_WATCH_TREE
	}

	// The response can fill the whole output buffer, so it may span several
	// credits — the same accounting a large read does.
	creditCharge, _, err := f.fs.borrowCredits(int(bufSize))
	if err != nil {
		return nil, err
	}

	req := &smb2.ChangeNotifyRequest{
		Flags:              flags,
		OutputBufferLength: bufSize,
		FileId:             f.fd,
		CompletionFilter:   filter,
	}
	req.CreditCharge = creditCharge

	res, err := f.sendRecv(smb2.SMB2_CHANGE_NOTIFY, req)
	if err != nil {
		// The server ran out of room to describe the changes. Surface it as a
		// distinct sentinel: the caller has not failed, it just has to rescan.
		var rerr *ResponseError
		if errors.As(err, &rerr) && erref.NtStatus(rerr.Code) == erref.STATUS_NOTIFY_ENUM_DIR {
			return nil, ErrNotifyEnumDir
		}
		return nil, err
	}

	r := smb2.ChangeNotifyResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken change notify response format"}
	}

	out := r.Output()
	if len(out) == 0 {
		// Legal: the server reported that something changed without listing it.
		return nil, nil
	}

	var notifications []FileNotification
	for {
		info := smb2.FileNotifyInformationDecoder(out)
		if info.IsInvalid() {
			return nil, &InvalidResponseError{"broken file notify information format"}
		}

		notifications = append(notifications, FileNotification{
			Action: info.Action(),
			Name:   info.FileName(f.mapping),
		})

		next := info.NextEntryOffset()
		if next == 0 {
			break
		}
		out = out[next:]
	}

	return notifications, nil
}
