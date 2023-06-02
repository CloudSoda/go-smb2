package utf16le

import (
	"encoding/binary"
	"unicode/utf16"
)

var (
	le = binary.LittleEndian
)

const (
	SFMDoubleQuote uint16 = 0xF020
	SFMAsterisk    uint16 = 0xF021
	SFMColon       uint16 = 0xF022
	SFMLessThan    uint16 = 0xF023
	SFMGreaterThan uint16 = 0xF024
	SFMQuestion    uint16 = 0xF025
	SFMSlash       uint16 = 0xF026
	SFMPipe        uint16 = 0xF027
	SFMSpace       uint16 = 0xF028
	SFMPeriod      uint16 = 0xF029
)

const (
	SFUAsterisk    uint16 = '*' + 0xF000
	SFUQuestion    uint16 = '?' + 0xF000
	SFUColon       uint16 = ':' + 0xF000
	SFUGreaterThan uint16 = '>' + 0xF000
	SFULessThan    uint16 = '<' + 0xF000
	SFUPipe        uint16 = '|' + 0xF000
	SFUSlash       uint16 = '\\' + 0xF000
)

func EncodedStringLen(s string) int {
	l := 0
	for _, r := range s {
		if 0x10000 <= r && r <= '\U0010FFFF' {
			l += 4
		} else {
			l += 2
		}
	}
	return l
}

func EncodeString(dst []byte, src string) int {
	ws := utf16.Encode([]rune(src))
	for i, w := range ws {
		le.PutUint16(dst[2*i:2*i+2], w)
	}
	return len(ws) * 2
}

func EncodeStringToBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	ws := utf16.Encode([]rune(s))
	bs := make([]byte, len(ws)*2)
	for i, w := range ws {
		le.PutUint16(bs[2*i:2*i+2], w)
	}
	return bs
}

func DecodeToString(bs []byte) string {
	if len(bs) == 0 {
		return ""
	}
	ws := make([]uint16, len(bs)/2)
	for i := range ws {
		ws[i] = le.Uint16(bs[2*i : 2*i+2])
	}

	// Remove the null terminator
	if len(ws) > 0 && ws[len(ws)-1] == 0 {
		ws = ws[:len(ws)-1]
	}
	return string(utf16.Decode(ws))
}

func DecodeSFMToString(bs []byte) string {
	if len(bs) == 0 {
		return ""
	}

	ws := make([]uint16, len(bs)/2)
	for i := range ws {
		w := le.Uint16(bs[2*i : 2*i+2])
		if w >= 0xF001 && w <= 0xF01F {
			w -= 0xF000
		} else {
			switch w {
			case SFMDoubleQuote:
				w = '"'
			case SFMAsterisk:
				w = '*'
			case SFMColon:
				w = ':'
			case SFMLessThan:
				w = '<'
			case SFMGreaterThan:
				w = '>'
			case SFMQuestion:
				w = '?'
			case SFMPipe:
				w = '|'
			case SFMSpace:
				w = ' '
			case SFMPeriod:
				w = '.'
			}
		}
		ws[i] = w
	}

	// Remove the null terminator
	if len(ws) > 0 && ws[len(ws)-1] == 0 {
		ws = ws[:len(ws)-1]
	}

	return string(utf16.Decode(ws))
}

func DecodeSFUToString(bs []byte) string {
	if len(bs) == 0 {
		return ""
	}

	ws := make([]uint16, len(bs)/2)
	for i := range ws {
		w := le.Uint16(bs[2*i : 2*i+2])
		switch w {
		case SFUColon:
			w = ':'
		case SFUAsterisk:
			w = '*'
		case SFUQuestion:
			w = '?'
		case SFUPipe:
			w = '|'
		case SFUGreaterThan:
			w = '>'
		case SFULessThan:
			w = '<'
		}
		ws[i] = w
	}

	// Remove the null terminator
	if len(ws) > 0 && ws[len(ws)-1] == 0 {
		ws = ws[:len(ws)-1]
	}

	return string(utf16.Decode(ws))
}

func EncodeStringToSFMBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}

	ws := utf16.Encode([]rune(s))
	buf := make([]byte, len(ws)*2)
	for i, w := range ws {
		if w >= 0x01 && w <= 0x1F {
			w += 0xF000
		} else {
			switch w {
			case '"':
				w = SFMDoubleQuote
			case '*':
				w = SFMAsterisk
			case ':':
				w = SFMColon
			case '<':
				w = SFMLessThan
			case '>':
				w = SFMGreaterThan
			case '?':
				w = SFMQuestion
			case '|':
				w = SFMPipe
			case '.':
				if i == len(ws)-1 {
					w = SFMPeriod
				}
			case ' ':
				if i == len(ws)-1 {
					w = SFMSpace
				}
			}
			le.PutUint16(buf[2*i:2*i+2], w)
		}
	}

	return buf
}

func EncodeStringToSFUBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}

	ws := utf16.Encode([]rune(s))
	buf := make([]byte, len(ws)*2)
	for i, w := range ws {
		switch w {
		case ':', '*', '?', '<', '>', '|':
			w += 0xF000
		}
		le.PutUint16(buf[2*i:2*i+2], w)
	}

	return buf
}
