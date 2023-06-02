package utf16le

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeSFU(t *testing.T) {
	in := "sod*asterisk.txt"
	out := EncodeStringToSFUBytes(in)
	fmt.Println("utf16:", hex.EncodeToString(out))
	decoded := DecodeToString(out)
	fmt.Println("utf8 :", hex.EncodeToString([]byte(decoded)))
	t.Fatal("all done")
}

func TestSFURoundtrip(t *testing.T) {
	reservedChars := []string{`"`, `*`, `:`, `<`, `>`, `?`, `|`, ` `, `.`}
	for _, c := range reservedChars {
		in := "a" + c + ".txt"
		encoded := EncodeStringToSFUBytes(in)
		decoded := DecodeSFUToString(encoded)
		require.Equal(t, in, decoded)
	}
}

func TestSFMRoundtrip(t *testing.T) {
	t.Run("reserved chars", func(t *testing.T) {
		reservedChars := []string{`"`, `*`, `:`, `<`, `>`, `?`, `|`, ` `, `.`}
		for _, c := range reservedChars {
			in := "a" + c + ".txt"
			encoded := EncodeStringToSFMBytes(in)
			decoded := DecodeSFMToString(encoded)
			require.Equal(t, in, decoded)
		}
	})

	t.Run("period at end", func(t *testing.T) {
		in := "file."
		encoded := EncodeStringToSFMBytes(in)
		decoded := DecodeSFMToString(encoded)
		require.Equal(t, in, decoded)
	})

	t.Run("space at end", func(t *testing.T) {
		in := "file "
		encoded := EncodeStringToSFMBytes(in)
		decoded := DecodeSFMToString(encoded)
		require.Equal(t, in, decoded)
	})
}

func TestEncodeSFM(t *testing.T) {
	in := "mac*asterisk.txt"
	out := EncodeStringToSFMBytes(in)
	fmt.Println("utf16:", hex.EncodeToString(out))
	decoded := DecodeToString(out)
	fmt.Println("utf8 :", hex.EncodeToString([]byte(decoded)))
	t.Fatal("all done")
}
