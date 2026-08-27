package smb2

import (
	"reflect"
	"testing"

	"github.com/cloudsoda/go-smb2/internal/smb2"
)

func TestNegotiatorDialects(t *testing.T) {
	tests := []struct {
		name    string
		min     uint16
		max     uint16
		want    []uint16
		wantErr bool
	}{
		{
			name: "unbounded offers everything",
			want: []uint16{SMB311, SMB302, SMB300, SMB210, SMB202},
		},
		{
			name: "a floor drops the dialects below it",
			min:  SMB300,
			want: []uint16{SMB311, SMB302, SMB300},
		},
		{
			name: "a ceiling drops the dialects above it",
			max:  SMB210,
			want: []uint16{SMB210, SMB202},
		},
		{
			name: "both bounds leave the range between them",
			min:  SMB210,
			max:  SMB300,
			want: []uint16{SMB300, SMB210},
		},
		{
			name: "a single dialect can be expressed as a range",
			min:  SMB311,
			max:  SMB311,
			want: []uint16{SMB311},
		},
		{
			name:    "an inverted range is rejected",
			min:     SMB311,
			max:     SMB202,
			wantErr: true,
		},
		{
			name:    "an unknown floor is rejected",
			min:     0x999,
			wantErr: true,
		},
		{
			name:    "an unknown ceiling is rejected",
			max:     0x999,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Negotiator{MinDialect: tt.min, MaxDialect: tt.max}

			got, err := n.dialects()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("dialects: %#x, want %#x", got, tt.want)
			}
		})
	}
}

// The negotiate contexts are an SMB 3.1.1 construct, so they belong in the
// request only when 3.1.1 is among the dialects offered.
func TestNegotiatorContextsFollowSMB311(t *testing.T) {
	tests := []struct {
		name         string
		max          uint16
		wantContexts bool
	}{
		{"3.1.1 offered", 0, true},
		{"3.1.1 excluded by the ceiling", SMB302, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Negotiator{MaxDialect: tt.max}

			req, err := n.makeRequest()
			if err != nil {
				t.Fatal(err)
			}
			if got := len(req.Contexts) > 0; got != tt.wantContexts {
				t.Errorf("contexts present: %v, want %v", got, tt.wantContexts)
			}
		})
	}
}

// The exported constants must keep matching the wire values they name.
func TestDialectConstants(t *testing.T) {
	for _, tt := range []struct {
		exported uint16
		internal uint16
	}{
		{SMB202, smb2.SMB202},
		{SMB210, smb2.SMB210},
		{SMB300, smb2.SMB300},
		{SMB302, smb2.SMB302},
		{SMB311, smb2.SMB311},
	} {
		if tt.exported != tt.internal {
			t.Errorf("exported 0x%03x does not match internal 0x%03x", tt.exported, tt.internal)
		}
	}
}
