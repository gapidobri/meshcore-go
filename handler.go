package meshcore

import "math"

// GroupChannel is a shared-secret group channel.
type GroupChannel struct {
	Hash   [PathHashSize]byte
	Secret [PubKeySize]byte
}

// Handler receives Mesh events and customises its behaviour. It replaces the
// virtual methods that C++ subclasses of mesh::Dispatcher and mesh::Mesh
// override.
//
// Implementations must embed *BaseHandler (or BaseHandler), which supplies
// the C++ default behaviour for every method and keeps implementations
// compiling when new hooks are added.
//
// Slices and pointers passed to the On* methods refer to Mesh-owned scratch
// buffers and are only valid for the duration of the call.
type Handler interface {
	// Dispatcher logging hooks.
	LogRxRaw(snr, rssi float32, raw []byte)
	LogRx(p *Packet, length int, score float32)
	LogTx(p *Packet, length int)
	LogTxFail(p *Packet, length int)

	// Dispatcher tuning.
	AirtimeBudgetFactor() float32
	CalcRxDelay(score float32, airTime uint32) int
	CADFailRetryDelay() uint32
	CADFailMaxDuration() uint32
	InterferenceThreshold() int
	CADEnabled() bool
	AGCResetInterval() int
	DutyCycleWindowMs() uint32

	// FilterRecvFloodPacket is called before a flood packet is dispatched to
	// the On* methods. Return true if it should NOT be processed.
	FilterRecvFloodPacket(p *Packet) bool

	// AllowPacketForward reports whether this packet should be forwarded
	// (re-transmitted). The default is false: forwarding is disabled.
	AllowPacketForward(p *Packet) bool

	// RetransmitDelay returns the delay in milliseconds to apply to
	// retransmitting a flood packet.
	RetransmitDelay(p *Packet) uint32

	// DirectRetransmitDelay is the same as RetransmitDelay, for direct mode.
	DirectRetransmitDelay(p *Packet) uint32

	// ExtraAckTransmitCount returns the number of extra (direct) ACK
	// transmissions wanted.
	ExtraAckTransmitCount() uint8

	// SearchPeersByHash searches the local peer/contact DB and returns the
	// number of peers with a matching hash.
	SearchPeersByHash(hash []byte) int

	// PeerSharedSecret stores the ECDH shared secret with the peer at
	// peerIdx in [0, n), where n is what SearchPeersByHash returned.
	PeerSharedSecret(dst *[PubKeySize]byte, peerIdx int)

	// OnPeerDataRecv is called with a decrypted data packet from a known
	// peer. typ is one of PayloadTypeTxtMsg, PayloadTypeReq,
	// PayloadTypeResponse. These can be received multiple times via
	// different routes.
	OnPeerDataRecv(p *Packet, typ uint8, senderIdx int, secret *[PubKeySize]byte, data []byte)

	// OnTraceRecv is called when a TRACE packet reaches the end of its
	// path. pathSNRs holds one SNR*4 byte per hop.
	OnTraceRecv(p *Packet, tag, authCode uint32, flags uint8, pathSNRs, pathHashes []byte)

	// OnPeerPathRecv is called when a path to peer senderIdx is received,
	// with optional extra data. path holds the path bytes and pathLen the
	// encoded path length. Return true if the path was accepted and a
	// reciprocal path should be sent.
	OnPeerPathRecv(p *Packet, senderIdx int, secret *[PubKeySize]byte, path []byte, pathLen uint8, extraType uint8, extra []byte) bool

	// OnAdvertRecv is called with a verified advertisement.
	OnAdvertRecv(p *Packet, id *Identity, timestamp uint32, appData []byte)

	// OnAnonDataRecv is called with a decrypted anonymous request.
	OnAnonDataRecv(p *Packet, secret *[PubKeySize]byte, sender *Identity, data []byte)

	// OnControlDataRecv is called with a zero-hop control packet.
	OnControlDataRecv(p *Packet)

	// OnRawDataRecv is called with a PayloadTypeRawCustom packet.
	OnRawDataRecv(p *Packet)

	// SearchChannelsByHash stores matching group channels in dst and
	// returns how many were stored.
	SearchChannelsByHash(hash []byte, dst []GroupChannel) int

	// OnGroupDataRecv is called with decrypted group data. typ is one of
	// PayloadTypeGrpTxt, PayloadTypeGrpData.
	OnGroupDataRecv(p *Packet, typ uint8, ch *GroupChannel, data []byte)

	// OnAckRecv is called when an ACK is received.
	OnAckRecv(p *Packet, ackCRC uint32)

	base() *BaseHandler
}

// BaseHandler implements Handler with the default C++ behaviour. Embed it in
// your own handler and override the methods you need.
type BaseHandler struct {
	mesh *Mesh
}

func (b *BaseHandler) base() *BaseHandler { return b }

// Mesh returns the Mesh this handler is attached to.
func (b *BaseHandler) Mesh() *Mesh { return b.mesh }

func (b *BaseHandler) LogRxRaw(snr, rssi float32, raw []byte)     {}
func (b *BaseHandler) LogRx(p *Packet, length int, score float32) {}
func (b *BaseHandler) LogTx(p *Packet, length int)                {}
func (b *BaseHandler) LogTxFail(p *Packet, length int)            {}

func (b *BaseHandler) AirtimeBudgetFactor() float32 { return 1.0 }

func (b *BaseHandler) CalcRxDelay(score float32, airTime uint32) int {
	return int((math.Pow(10, float64(0.85-score)) - 1.0) * float64(airTime))
}

func (b *BaseHandler) CADFailRetryDelay() uint32  { return b.mesh.nextInt(1, 4) * 120 }
func (b *BaseHandler) CADFailMaxDuration() uint32 { return 4000 } // 4 seconds
func (b *BaseHandler) InterferenceThreshold() int { return 0 }    // disabled by default
func (b *BaseHandler) CADEnabled() bool           { return false }
func (b *BaseHandler) AGCResetInterval() int      { return 0 } // disabled by default
func (b *BaseHandler) DutyCycleWindowMs() uint32  { return 3600000 }

func (b *BaseHandler) FilterRecvFloodPacket(p *Packet) bool { return false }
func (b *BaseHandler) AllowPacketForward(p *Packet) bool    { return false }

func (b *BaseHandler) RetransmitDelay(p *Packet) uint32 {
	t := (b.mesh.radio.EstAirtimeFor(p.RawLength()) * 52 / 50) / 2
	return b.mesh.nextInt(0, 5) * t
}

func (b *BaseHandler) DirectRetransmitDelay(p *Packet) uint32 { return 0 }
func (b *BaseHandler) ExtraAckTransmitCount() uint8           { return 0 }

func (b *BaseHandler) SearchPeersByHash(hash []byte) int                   { return 0 }
func (b *BaseHandler) PeerSharedSecret(dst *[PubKeySize]byte, peerIdx int) {}

func (b *BaseHandler) OnPeerDataRecv(p *Packet, typ uint8, senderIdx int, secret *[PubKeySize]byte, data []byte) {
}

func (b *BaseHandler) OnTraceRecv(p *Packet, tag, authCode uint32, flags uint8, pathSNRs, pathHashes []byte) {
}

func (b *BaseHandler) OnPeerPathRecv(p *Packet, senderIdx int, secret *[PubKeySize]byte, path []byte, pathLen uint8, extraType uint8, extra []byte) bool {
	return false
}

func (b *BaseHandler) OnAdvertRecv(p *Packet, id *Identity, timestamp uint32, appData []byte) {}

func (b *BaseHandler) OnAnonDataRecv(p *Packet, secret *[PubKeySize]byte, sender *Identity, data []byte) {
}

func (b *BaseHandler) OnControlDataRecv(p *Packet) {}
func (b *BaseHandler) OnRawDataRecv(p *Packet)     {}

func (b *BaseHandler) SearchChannelsByHash(hash []byte, dst []GroupChannel) int { return 0 }

func (b *BaseHandler) OnGroupDataRecv(p *Packet, typ uint8, ch *GroupChannel, data []byte) {}
func (b *BaseHandler) OnAckRecv(p *Packet, ackCRC uint32)                                  {}
