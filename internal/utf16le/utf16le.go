package utf16le

import (
	"encoding/binary"
	"unicode/utf16"
)

var le = binary.LittleEndian

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

func DecodeSFMToString(bs []byte) string {
	if len(bs) == 0 {
		return ""
	}

	u16s := make([]uint16, len(bs)/2)
	for i := range u16s {
		u16 := le.Uint16(bs[2*i : 2*i+2])
		if u16 >= 0xF001 && u16 <= 0xF01F {
			u16 -= 0xF000
		} else {
			switch u16 {
			case SFMDoubleQuote:
				u16 = '"'
			case SFMAsterisk:
				u16 = '*'
			case SFMColon:
				u16 = ':'
			case SFMLessThan:
				u16 = '<'
			case SFMGreaterThan:
				u16 = '>'
			case SFMQuestion:
				u16 = '?'
			case SFMPipe:
				u16 = '|'
			case SFMSpace:
				u16 = ' '
			case SFMPeriod:
				u16 = '.'
			}
		}
		u16s[i] = u16
	}

	// Remove the null terminator
	if len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}

	return string(utf16.Decode(u16s))
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

func EncodeStringSFM(dst []byte, src string) int {
	u16s := utf16.Encode([]rune(src))
	for i, u16 := range u16s {
		if u16 >= 0x01 && u16 <= 0x1F {
			u16 += 0xF000
		} else {
			switch u16 {
			case '"':
				u16 = SFMDoubleQuote
			case '*':
				u16 = SFMAsterisk
			case ':':
				u16 = SFMColon
			case '<':
				u16 = SFMLessThan
			case '>':
				u16 = SFMGreaterThan
			case '?':
				u16 = SFMQuestion
			case '|':
				u16 = SFMPipe
			case '.':
				if i == len(u16s)-1 {
					u16 = SFMPeriod
				}
			case ' ':
				if i == len(u16s)-1 {
					u16 = SFMSpace
				}
			}
		}
		le.PutUint16(dst[2*i:2*i+2], u16)
	}
	return len(u16s) * 2
}

func EncodeStringSFU(dst []byte, src string) int {
	ws := utf16.Encode([]rune(src))
	for i, w := range ws {
		switch w {
		case ':', '*', '?', '<', '>', '|':
			w += 0xF000
		}
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

func EncodeStringToSFMBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}

	u16s := make([]uint16, 0, EncodedStringLen(s)/2)
	for i, r := range s {
		if sfm := toSFM(r, i == len(s)-1); sfm != 0 {
			u16s = append(u16s, sfm)
		} else {
			u16s = utf16.AppendRune(u16s, r)
		}

	}
	dst := make([]byte, len(u16s)*2)
	for i, u16 := range u16s {
		le.PutUint16(dst[2*i:2*i+2], u16)
	}

	return dst
}

func EncodeStringToSFUBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}

	ws := utf16.Encode([]rune(s))
	dst := make([]byte, len(ws)*2)
	for i, w := range ws {
		switch w {
		case ':', '*', '?', '<', '>', '|':
			w += 0xF000
		}
		le.PutUint16(dst[2*i:2*i+2], w)
	}

	return dst
}

func toSFM(r rune, endOfString bool) uint16 {
	if r >= 0x01 && r <= 0x1F {
		return uint16(r) + 0xF000
	} else {
		switch r {
		case '"':
			return SFMDoubleQuote
		case '*':
			return SFMAsterisk
		case ':':
			return SFMColon
		case '<':
			return SFMLessThan
		case '>':
			return SFMGreaterThan
		case '?':
			return SFMQuestion
		case '|':
			return SFMPipe
		case '.':
			if endOfString {
				return SFMPeriod
			}
		case ' ':
			if endOfString {
				return SFMSpace
			}
		}
	}
	return 0
}
