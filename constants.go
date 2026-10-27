// Package meshcore is a TinyGo-compatible reimplementation of the MeshCore
// LoRa mesh networking library (https://github.com/meshcore-dev/meshcore).
//
// It is wire-compatible with the C++ implementation: packets, hashes,
// signatures and ciphertexts are byte-identical, so Go nodes can coexist with
// stock MeshCore nodes on the same mesh.
//
// The library is designed for a single-threaded poll loop (call Mesh.Loop
// repeatedly), mirroring the Arduino loop() model of the original. None of the
// types are safe for concurrent use.
package meshcore

// Sizes, from MeshCore.h.
const (
	MaxHashSize       = 8
	PubKeySize        = 32
	PrvKeySize        = 64
	SeedSize          = 32
	SignatureSize     = 64
	MaxAdvertDataSize = 32
	CipherKeySize     = 16
	CipherBlockSize   = 16

	// V1
	CipherMACSize = 2
	PathHashSize  = 1

	MaxPacketPayload   = 184
	MaxGroupDataLength = MaxPacketPayload - CipherBlockSize - 3
	MaxPathSize        = 64
	MaxTransUnit       = 255
)

// Packet header bit layout.
const (
	PHRouteMask = 0x03 // 2-bits
	PHTypeShift = 2
	PHTypeMask  = 0x0F // 4-bits
	PHVerShift  = 6
	PHVerMask   = 0x03 // 2-bits
)

// Route types (lower 2 bits of the header).
const (
	RouteTypeTransportFlood  = 0x00 // flood mode + transport codes
	RouteTypeFlood           = 0x01 // flood mode, needs 'path' to be built up (max 64 bytes)
	RouteTypeDirect          = 0x02 // direct route, 'path' is supplied
	RouteTypeTransportDirect = 0x03 // direct route + transport codes
)

// Payload types (bits 2..5 of the header).
const (
	PayloadTypeReq       = 0x00 // request (prefixed with dest/src hashes, MAC) (enc data: timestamp, blob)
	PayloadTypeResponse  = 0x01 // response to REQ or ANON_REQ (prefixed with dest/src hashes, MAC) (enc data: timestamp, blob)
	PayloadTypeTxtMsg    = 0x02 // a plain text message (prefixed with dest/src hashes, MAC) (enc data: timestamp, text)
	PayloadTypeAck       = 0x03 // a simple ack
	PayloadTypeAdvert    = 0x04 // a node advertising its Identity
	PayloadTypeGrpTxt    = 0x05 // an (unverified) group text message (prefixed with channel hash, MAC) (enc data: timestamp, "name: msg")
	PayloadTypeGrpData   = 0x06 // an (unverified) group datagram (prefixed with channel hash, MAC) (enc data: data_type(uint16), data_len, blob)
	PayloadTypeAnonReq   = 0x07 // generic request (prefixed with dest_hash, ephemeral pub_key, MAC) (enc data: ...)
	PayloadTypePath      = 0x08 // returned path (prefixed with dest/src hashes, MAC) (enc data: path, extra)
	PayloadTypeTrace     = 0x09 // trace a path, collecting SNR for each hop
	PayloadTypeMultipart = 0x0A // packet is one of a set of packets
	PayloadTypeControl   = 0x0B // a control/discovery packet
	PayloadTypeRawCustom = 0x0F // custom packet as raw bytes, for applications with custom encryption, payloads, etc
)

// Payload versions (upper 2 bits of the header).
const (
	PayloadVer1 = 0x00 // 1-byte src/dest hashes, 2-byte MAC
	PayloadVer2 = 0x01 // FUTURE (eg. 2-byte hashes, 4-byte MAC ??)
	PayloadVer3 = 0x02 // FUTURE
	PayloadVer4 = 0x03 // FUTURE
)

// Dispatcher error event flags.
const (
	ErrEventFull           = 1 << 0
	ErrEventCADTimeout     = 1 << 1
	ErrEventStartRxTimeout = 1 << 2
)
