package meshcore

import "encoding/binary"

// Packet is the fundamental transmission unit.
//
// PathLen is the encoded path length byte: the lower 6 bits are the hash
// count and the upper 2 bits are (hash size - 1). For TRACE packets it is a
// plain count of SNR bytes.
type Packet struct {
	Header         uint8
	PayloadLen     int
	PathLen        uint8
	TransportCodes [2]uint16
	Path           [MaxPathSize]byte
	Payload        [MaxPacketPayload]byte
	SNRx4          int8 // SNR * 4, as received
}

// PayloadBytes returns the valid part of Payload.
func (p *Packet) PayloadBytes() []byte { return p.Payload[:p.PayloadLen] }

// PathBytes returns the valid part of Path.
func (p *Packet) PathBytes() []byte { return p.Path[:p.PathByteLen()] }

// CalculateHash computes the packet hash (of payload type + payload) used for
// de-duplication.
func (p *Packet) CalculateHash(dst *[MaxHashSize]byte) {
	var d sha256d
	d.reset()
	t := p.PayloadType()
	d.writeByte(t)
	if t == PayloadTypeTrace {
		// CAVEAT: TRACE packets can revisit same node on return path.
		// The C++ hashes path_len as a little-endian uint16.
		d.writeByte(p.PathLen)
		d.writeByte(0)
	}
	d.write(p.Payload[:p.PayloadLen])
	var sum [32]byte
	d.sum(&sum)
	copy(dst[:], sum[:MaxHashSize])
}

// RouteType returns one of the RouteType* values.
func (p *Packet) RouteType() uint8 { return p.Header & PHRouteMask }

func (p *Packet) IsRouteFlood() bool {
	rt := p.RouteType()
	return rt == RouteTypeFlood || rt == RouteTypeTransportFlood
}

func (p *Packet) IsRouteDirect() bool {
	rt := p.RouteType()
	return rt == RouteTypeDirect || rt == RouteTypeTransportDirect
}

func (p *Packet) HasTransportCodes() bool {
	rt := p.RouteType()
	return rt == RouteTypeTransportFlood || rt == RouteTypeTransportDirect
}

// PayloadType returns one of the PayloadType* values.
func (p *Packet) PayloadType() uint8 { return (p.Header >> PHTypeShift) & PHTypeMask }

// PayloadVer returns one of the PayloadVer* values.
func (p *Packet) PayloadVer() uint8 { return (p.Header >> PHVerShift) & PHVerMask }

func (p *Packet) PathHashSize() int  { return int(p.PathLen>>6) + 1 }
func (p *Packet) PathHashCount() int { return int(p.PathLen & 63) }
func (p *Packet) PathByteLen() int   { return p.PathHashCount() * p.PathHashSize() }

func (p *Packet) SetPathHashCount(n int) {
	p.PathLen &^= 63
	p.PathLen |= uint8(n) & 63
}

func (p *Packet) SetPathHashSizeAndCount(sz, n int) {
	p.PathLen = uint8(sz-1)<<6 | uint8(n)&63
}

func (p *Packet) MarkDoNotRetransmit()          { p.Header = 0xFF }
func (p *Packet) IsMarkedDoNotRetransmit() bool { return p.Header == 0xFF }

// SNR returns the receive SNR in dB.
func (p *Packet) SNR() float32 { return float32(p.SNRx4) / 4 }

// RawLength returns the encoded (wire format) length of this packet.
func (p *Packet) RawLength() int {
	n := 2 + p.PathByteLen() + p.PayloadLen
	if p.HasTransportCodes() {
		n += 4
	}
	return n
}

// IsValidPathLen reports whether an encoded path length byte is acceptable.
func IsValidPathLen(pathLen uint8) bool {
	count := int(pathLen & 63)
	size := int(pathLen>>6) + 1
	if size == 4 {
		return false // reserved for future
	}
	return count*size <= MaxPathSize
}

// WritePath copies the path bytes described by pathLen from src to dst and
// returns the number of bytes written (0 if pathLen is invalid).
func WritePath(dst, src []byte, pathLen uint8) int {
	n := int(pathLen&63) * (int(pathLen>>6) + 1)
	if n > MaxPathSize || n > len(src) || n > len(dst) {
		return 0
	}
	return copy(dst, src[:n])
}

// CopyPath copies the path and returns pathLen, for convenient assignment.
func CopyPath(dst, src []byte, pathLen uint8) uint8 {
	WritePath(dst, src, pathLen)
	return pathLen
}

// Encode writes the whole packet in wire format into dst (which should be at
// least MaxTransUnit bytes) and returns the length.
func (p *Packet) Encode(dst []byte) int {
	i := 0
	dst[i] = p.Header
	i++
	if p.HasTransportCodes() {
		binary.LittleEndian.PutUint16(dst[i:], p.TransportCodes[0])
		binary.LittleEndian.PutUint16(dst[i+2:], p.TransportCodes[1])
		i += 4
	}
	dst[i] = p.PathLen
	i++
	i += WritePath(dst[i:], p.Path[:], p.PathLen)
	i += copy(dst[i:], p.Payload[:p.PayloadLen])
	return i
}

// Decode restores this packet from a blob created by Encode. It accepts any
// payload version; see Mesh for the stricter on-air parser.
func (p *Packet) Decode(src []byte) bool {
	if len(src) < 2 {
		return false
	}
	i := 0
	p.Header = src[i]
	i++
	if p.HasTransportCodes() {
		if len(src) < i+4 {
			return false
		}
		p.TransportCodes[0] = binary.LittleEndian.Uint16(src[i:])
		p.TransportCodes[1] = binary.LittleEndian.Uint16(src[i+2:])
		i += 4
	} else {
		p.TransportCodes = [2]uint16{}
	}
	if i >= len(src) {
		return false
	}
	p.PathLen = src[i]
	i++
	if !IsValidPathLen(p.PathLen) {
		return false // bad encoding
	}
	bl := p.PathByteLen()
	if i+bl > len(src) {
		return false
	}
	copy(p.Path[:], src[i:i+bl])
	i += bl

	if i >= len(src) {
		return false // bad encoding
	}
	n := len(src) - i
	if n > MaxPacketPayload {
		return false // bad encoding
	}
	p.PayloadLen = copy(p.Payload[:], src[i:])
	return true
}
