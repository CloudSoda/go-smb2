package smb2

import (
	"testing"

	"github.com/cloudsoda/go-smb2/internal/utf16le"
)

func TestChangeNotifyRequestEncode(t *testing.T) {
	req := &ChangeNotifyRequest{
		Flags:              SMB2_WATCH_TREE,
		OutputBufferLength: 32 * 1024,
		FileId: &FileId{
			Persistent: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
			Volatile:   [8]byte{9, 10, 11, 12, 13, 14, 15, 16},
		},
		CompletionFilter: FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
	}
	req.CreditCharge = 1

	pkt := make([]byte, req.Size())
	req.Encode(pkt)

	if got, want := req.Size(), 64+32; got != want {
		t.Errorf("Size() = %d, want %d", got, want)
	}

	d := ChangeNotifyRequestDecoder(pkt[64:])
	if d.IsInvalid() {
		t.Fatal("encoded request does not decode")
	}
	if got := d.StructureSize(); got != 32 {
		t.Errorf("StructureSize = %d, want 32 (MS-SMB2 2.2.35)", got)
	}
	if got := d.Flags(); got != SMB2_WATCH_TREE {
		t.Errorf("Flags = %#x, want SMB2_WATCH_TREE", got)
	}
	if got := d.OutputBufferLength(); got != 32*1024 {
		t.Errorf("OutputBufferLength = %d, want 32768", got)
	}
	if got, want := d.CompletionFilter(), uint32(FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_LAST_WRITE); got != want {
		t.Errorf("CompletionFilter = %#x, want %#x", got, want)
	}
	fid := d.FileId().Decode()
	if fid.Persistent != req.FileId.Persistent || fid.Volatile != req.FileId.Volatile {
		t.Errorf("FileId round-trip mismatch: got %+v", fid)
	}
}

// buildNotifyResponse assembles a CHANGE_NOTIFY response body (without the
// 64-byte header) carrying the given records.
func buildNotifyResponse(t *testing.T, names []string, actions []uint32) []byte {
	t.Helper()

	var buf []byte
	for i, name := range names {
		enc := utf16le.Encode(name, utf16le.MapCharsNone)

		rec := make([]byte, 12+len(enc))
		le.PutUint32(rec[4:8], actions[i])
		le.PutUint32(rec[8:12], uint32(len(enc)))
		copy(rec[12:], enc)

		// Records are 4-byte aligned; the last has NextEntryOffset == 0.
		for len(rec)%4 != 0 {
			rec = append(rec, 0)
		}
		if i < len(names)-1 {
			le.PutUint32(rec[:4], uint32(len(rec)))
		}
		buf = append(buf, rec...)
	}

	res := make([]byte, 8+len(buf))
	le.PutUint16(res[:2], 9)                 // StructureSize
	le.PutUint16(res[2:4], 64+8)             // OutputBufferOffset, from header start
	le.PutUint32(res[4:8], uint32(len(buf))) // OutputBufferLength
	copy(res[8:], buf)
	return res
}

func TestChangeNotifyResponseDecode(t *testing.T) {
	names := []string{"notes.txt", `Reports\2026\budget.csv`, "renamed.txt"}
	actions := []uint32{FILE_ACTION_MODIFIED, FILE_ACTION_ADDED, FILE_ACTION_RENAMED_NEW_NAME}

	res := buildNotifyResponse(t, names, actions)

	r := ChangeNotifyResponseDecoder(res)
	if r.IsInvalid() {
		t.Fatal("valid response reported invalid")
	}

	out := r.Output()
	if len(out) == 0 {
		t.Fatal("Output() is empty")
	}

	var gotNames []string
	var gotActions []uint32
	for {
		info := FileNotifyInformationDecoder(out)
		if info.IsInvalid() {
			t.Fatal("valid FILE_NOTIFY_INFORMATION reported invalid")
		}
		gotNames = append(gotNames, info.FileName(utf16le.MapCharsNone))
		gotActions = append(gotActions, info.Action())
		next := info.NextEntryOffset()
		if next == 0 {
			break
		}
		out = out[next:]
	}

	if len(gotNames) != len(names) {
		t.Fatalf("decoded %d records, want %d", len(gotNames), len(names))
	}
	for i := range names {
		if gotNames[i] != names[i] {
			t.Errorf("record %d name = %q, want %q", i, gotNames[i], names[i])
		}
		if gotActions[i] != actions[i] {
			t.Errorf("record %d action = %d, want %d", i, gotActions[i], actions[i])
		}
	}
}

// A server may report that changes occurred without enumerating them; that is
// legal and must not be mistaken for a malformed response.
func TestChangeNotifyResponseEmptyBufferIsValid(t *testing.T) {
	res := make([]byte, 8)
	le.PutUint16(res[:2], 9)
	le.PutUint16(res[2:4], 64+8)
	le.PutUint32(res[4:8], 0)

	r := ChangeNotifyResponseDecoder(res)
	if r.IsInvalid() {
		t.Error("empty output buffer should be valid")
	}
	if out := r.Output(); out != nil {
		t.Errorf("Output() = %v, want nil", out)
	}
}

func TestChangeNotifyResponseRejectsMalformed(t *testing.T) {
	t.Run("short", func(t *testing.T) {
		if !ChangeNotifyResponseDecoder([]byte{1, 2, 3}).IsInvalid() {
			t.Error("truncated response should be invalid")
		}
	})
	t.Run("wrong structure size", func(t *testing.T) {
		res := make([]byte, 8)
		le.PutUint16(res[:2], 8) // must be 9
		if !ChangeNotifyResponseDecoder(res).IsInvalid() {
			t.Error("wrong StructureSize should be invalid")
		}
	})
	t.Run("buffer beyond packet", func(t *testing.T) {
		res := make([]byte, 8)
		le.PutUint16(res[:2], 9)
		le.PutUint16(res[2:4], 64+8)
		le.PutUint32(res[4:8], 1<<20) // claims 1 MB we do not have
		if !ChangeNotifyResponseDecoder(res).IsInvalid() {
			t.Error("output length beyond the packet should be invalid")
		}
	})
}

// A record whose NextEntryOffset does not advance would loop forever; the
// decoder must reject it rather than hang the caller.
func TestFileNotifyInformationRejectsNonAdvancingOffset(t *testing.T) {
	rec := make([]byte, 16)
	le.PutUint32(rec[:4], 4) // less than the 12-byte header: cannot advance
	le.PutUint32(rec[4:8], FILE_ACTION_ADDED)
	le.PutUint32(rec[8:12], 2)

	if !FileNotifyInformationDecoder(rec).IsInvalid() {
		t.Error("non-advancing NextEntryOffset should be invalid")
	}
}

func TestFileNotifyInformationRejectsTruncatedName(t *testing.T) {
	rec := make([]byte, 14)
	le.PutUint32(rec[:4], 0)
	le.PutUint32(rec[4:8], FILE_ACTION_ADDED)
	le.PutUint32(rec[8:12], 64) // claims 64 bytes of name, only 2 present

	if !FileNotifyInformationDecoder(rec).IsInvalid() {
		t.Error("truncated file name should be invalid")
	}
}
