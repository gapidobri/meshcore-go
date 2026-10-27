package meshcore

import (
	"math"
	"strconv"
)

// Text message types (TxtDataHelpers.h).
const (
	TxtTypePlain       = 0 // a plain text message
	TxtTypeCLIData     = 1 // a CLI command -or- reply
	TxtTypeSignedPlain = 2 // plain text, signed by sender
	TxtTypeCLICommand  = 3 // a CLI command (explicitly)
)

// Group datagram data types.
const (
	DataTypeReserved = 0x0000 // reserved for future use
	DataTypeDev      = 0xFFFF // developer namespace for experimenting with group/channel datagrams
)

// StrZCopy copies src into dst as a NUL-terminated string, truncating if
// needed and padding the remainder of dst with NULs (C++ StrHelper::strzcpy).
func StrZCopy(dst []byte, src string) {
	if len(dst) == 0 {
		return
	}
	n := copy(dst[:len(dst)-1], src)
	for i := 0; i < n; i++ {
		if src[i] == 0 {
			n = i
			break
		}
	}
	clear(dst[n:])
}

// CString returns the bytes of buf up to the first NUL as a string.
func CString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

// IsBlank reports whether s consists only of spaces.
func IsBlank(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			return false
		}
	}
	return true
}

// ParseHexUint32 parses leading hex digits of s, stopping at the first
// non-hex character.
func ParseHexUint32(s string) uint32 {
	var n uint32
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			n = n<<4 | uint32(c-'0')
		case c >= 'A' && c <= 'F':
			n = n<<4 | uint32(c-'A'+10)
		case c >= 'a' && c <= 'f':
			n = n<<4 | uint32(c-'a'+10)
		default:
			return n // non-hex char encountered, stop parsing
		}
	}
	return n
}

// Ftoa formats a float with up to 7 decimal places and trailing zeros
// trimmed, exactly like the C++ StrHelper::ftoa. Out-of-range values
// (|f| > 2147483520 or |f| < 1e-7) format as "0".
func Ftoa(f float32) string {
	if f == 0 {
		return "0.0"
	}
	bits := int32(math.Float32bits(f))
	exp2 := int16(uint8(bits>>23)) - 127
	mantissa := (bits & 0xFFFFFF) | 0x800000
	var intPart, fracPart int32

	switch {
	case exp2 >= 31:
		return "0" // too large
	case exp2 < -23:
		return "0" // too small
	case exp2 >= 23:
		intPart = mantissa << (exp2 - 23)
	case exp2 >= 0:
		intPart = mantissa >> (23 - exp2)
		fracPart = (mantissa << (exp2 + 1)) & 0xFFFFFF
	default:
		fracPart = (mantissa & 0xFFFFFF) >> -(exp2 + 1)
	}

	var buf [24]byte
	p := buf[:0]
	if bits < 0 {
		p = append(p, '-')
	}
	p = strconv.AppendInt(p, int64(intPart), 10)
	p = append(p, '.')
	if fracPart == 0 {
		p = append(p, '0')
	} else {
		for m := 0; m < 7; m++ {
			fracPart = (fracPart << 3) + (fracPart << 1)
			p = append(p, byte(fracPart>>24)+'0')
			fracPart &= 0xFFFFFF
		}
		// delete ending zeroes
		for len(p) > 2 && p[len(p)-1] == '0' && p[len(p)-2] != '.' {
			p = p[:len(p)-1]
		}
	}
	return string(p)
}

// Ftoa3 formats a float rounded to 3 decimal places with trailing zeros (and
// a trailing '.') removed, like the C++ StrHelper::ftoa3.
func Ftoa3(f float32) string {
	var r float32 = 0.5
	if f < 0 {
		r = -0.5
	}
	v := int32(f*1000.0 + r) // rounded x1000
	w := v / 1000            // whole
	d := v % 1000            // decimals
	if d < 0 {
		d = -d
	}
	var buf [24]byte
	s := strconv.AppendInt(buf[:0], int64(w), 10)
	s = append(s, '.', byte('0'+d/100), byte('0'+d/10%10), byte('0'+d%10))
	for len(s) > 1 && s[len(s)-1] == '0' {
		s = s[:len(s)-1]
	}
	if s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return string(s)
}
