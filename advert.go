package meshcore

import (
	"encoding/binary"
	"strconv"
)

// Advert node types (lower 4 bits of the advert flags).
const (
	AdvTypeNone     = 0
	AdvTypeChat     = 1
	AdvTypeRepeater = 2
	AdvTypeRoom     = 3
	AdvTypeSensor   = 4
	// FUTURE: 5..15
)

// Advert flag bits.
const (
	AdvLatLonMask = 0x10
	AdvFeat1Mask  = 0x20 // FUTURE
	AdvFeat2Mask  = 0x40 // FUTURE
	AdvNameMask   = 0x80
)

// AdvertData is the app data carried in an advertisement.
type AdvertData struct {
	Type   uint8
	Name   string
	HasLoc bool
	Lat    int32 // degrees * 1e6
	Lon    int32 // degrees * 1e6
	Feat1  uint16
	Feat2  uint16
}

// NewAdvertDataLatLon returns advert data with a location in degrees.
func NewAdvertDataLatLon(advType uint8, name string, lat, lon float64) AdvertData {
	return AdvertData{Type: advType, Name: name, HasLoc: true, Lat: int32(lat * 1e6), Lon: int32(lon * 1e6)}
}

// Encode writes the advert app data to dst and returns the encoded length.
func (a *AdvertData) Encode(dst *[MaxAdvertDataSize]byte) int {
	dst[0] = a.Type
	i := 1
	if a.HasLoc {
		dst[0] |= AdvLatLonMask
		binary.LittleEndian.PutUint32(dst[i:], uint32(a.Lat))
		binary.LittleEndian.PutUint32(dst[i+4:], uint32(a.Lon))
		i += 8
	}
	if a.Feat1 != 0 {
		dst[0] |= AdvFeat1Mask
		binary.LittleEndian.PutUint16(dst[i:], a.Feat1)
		i += 2
	}
	if a.Feat2 != 0 {
		dst[0] |= AdvFeat2Mask
		binary.LittleEndian.PutUint16(dst[i:], a.Feat2)
		i += 2
	}
	if a.Name != "" {
		n := ValidUTF8PrefixLength(a.Name, MaxAdvertDataSize-i)
		if n > 0 {
			dst[0] |= AdvNameMask
			i += copy(dst[i:], a.Name[:n])
		}
	}
	return i
}

// LatDegrees returns the latitude in degrees.
func (a *AdvertData) LatDegrees() float64 { return float64(a.Lat) / 1000000.0 }

// LonDegrees returns the longitude in degrees.
func (a *AdvertData) LonDegrees() float64 { return float64(a.Lon) / 1000000.0 }

// ParsedAdvert is the result of parsing advert app data. It keeps the name in
// a fixed buffer so parsing does not allocate.
type ParsedAdvert struct {
	Flags   uint8
	Valid   bool
	Lat     int32
	Lon     int32
	Feat1   uint16
	Feat2   uint16
	name    [MaxAdvertDataSize]byte
	nameLen int
}

// ParseAdvertData parses advert app data.
func ParseAdvertData(appData []byte) ParsedAdvert {
	var p ParsedAdvert
	if len(appData) == 0 {
		return p
	}
	p.Flags = appData[0]
	i := 1
	need := i
	if p.Flags&AdvLatLonMask != 0 {
		need += 8
	}
	if p.Flags&AdvFeat1Mask != 0 {
		need += 2
	}
	if p.Flags&AdvFeat2Mask != 0 {
		need += 2
	}
	if len(appData) < need {
		return p
	}
	if p.Flags&AdvLatLonMask != 0 {
		p.Lat = int32(binary.LittleEndian.Uint32(appData[i:]))
		p.Lon = int32(binary.LittleEndian.Uint32(appData[i+4:]))
		i += 8
	}
	if p.Flags&AdvFeat1Mask != 0 {
		p.Feat1 = binary.LittleEndian.Uint16(appData[i:])
		i += 2
	}
	if p.Flags&AdvFeat2Mask != 0 {
		p.Feat2 = binary.LittleEndian.Uint16(appData[i:])
		i += 2
	}
	if p.Flags&AdvNameMask != 0 {
		p.nameLen = copy(p.name[:MaxAdvertDataSize-1], appData[i:]) // remainder of app_data
	}
	p.Valid = true
	return p
}

func (p *ParsedAdvert) Type() uint8         { return p.Flags & 0x0F }
func (p *ParsedAdvert) HasName() bool       { return p.nameLen > 0 && p.name[0] != 0 }
func (p *ParsedAdvert) HasLatLon() bool     { return p.Flags&AdvLatLonMask != 0 }
func (p *ParsedAdvert) LatDegrees() float64 { return float64(p.Lat) / 1000000.0 }
func (p *ParsedAdvert) LonDegrees() float64 { return float64(p.Lon) / 1000000.0 }

// NameBytes returns the name as received (up to any NUL byte).
func (p *ParsedAdvert) NameBytes() []byte {
	for i := 0; i < p.nameLen; i++ {
		if p.name[i] == 0 {
			return p.name[:i]
		}
	}
	return p.name[:p.nameLen]
}

// Name returns the name as a string.
func (p *ParsedAdvert) Name() string { return string(p.NameBytes()) }

// IsValidAdvertName reports whether name has none of the reserved
// characters []\:,?*.
func IsValidAdvertName(name string) bool {
	for i := 0; i < len(name); i++ {
		switch name[i] {
		case '[', ']', '\\', ':', ',', '?', '*':
			return false
		}
	}
	return true
}

// FormatRelativeTimeDiff formats a time difference like "5 mins ago". With
// shortFmt the suffix is omitted (the trailing space is kept, as in the C++).
func FormatRelativeTimeDiff(secondsFromNow int32, shortFmt bool) string {
	var suffix string
	if secondsFromNow < 0 {
		if !shortFmt {
			suffix = " ago"
		}
		secondsFromNow = -secondsFromNow
	} else if !shortFmt {
		suffix = " from now"
	}

	n, unit := secondsFromNow, "secs"
	if secondsFromNow >= 60 {
		mins := secondsFromNow / 60
		n, unit = mins, "mins"
		if mins >= 60 {
			hours := mins / 60
			n, unit = hours, "hours"
			if hours >= 24 {
				n, unit = hours/24, "days"
			}
		}
	}
	return strconv.Itoa(int(n)) + " " + unit + " " + suffix
}

func isUTF8Continuation(b byte) bool { return b&0xC0 == 0x80 }

// ValidUTF8PrefixLength returns the length of the longest prefix of text, at
// most maxBytes long and stopping at any NUL, that is complete, valid UTF-8.
func ValidUTF8PrefixLength(text string, maxBytes int) int {
	offset := 0
	for offset < len(text) && text[offset] != 0 {
		first := text[offset]
		var seqLen int
		switch {
		case first <= 0x7F:
			seqLen = 1
		case first >= 0xC2 && first <= 0xDF:
			seqLen = 2
		case first >= 0xE0 && first <= 0xEF:
			seqLen = 3
		case first >= 0xF0 && first <= 0xF4:
			seqLen = 4
		default:
			return offset
		}
		if offset+seqLen > maxBytes || offset+seqLen > len(text) {
			return offset
		}
		for i := 1; i < seqLen; i++ {
			c := text[offset+i]
			if c == 0 || !isUTF8Continuation(c) {
				return offset
			}
		}
		if seqLen == 3 {
			second := text[offset+1]
			if (first == 0xE0 && second < 0xA0) || (first == 0xED && second > 0x9F) {
				return offset
			}
		} else if seqLen == 4 {
			second := text[offset+1]
			if (first == 0xF0 && second < 0x90) || (first == 0xF4 && second > 0x8F) {
				return offset
			}
		}
		offset += seqLen
	}
	return offset
}
