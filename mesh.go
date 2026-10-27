package meshcore

import "encoding/binary"

// Config holds the collaborators of a Mesh.
type Config struct {
	Radio   Radio
	Millis  MillisecondClock
	RNG     RNG
	RTC     RTCClock
	Packets PacketManager
	Tables  MeshTables
	// Handler receives events; defaults to a plain BaseHandler.
	Handler Handler
}

// Mesh recognises the payload types, routes packets (flood and direct),
// and dispatches received data to a Handler. It combines the C++
// mesh::Dispatcher and mesh::Mesh classes.
type Mesh struct {
	dispatcher

	// SelfID is this node's identity; set it before calling Begin.
	SelfID LocalIdentity

	radio  Radio
	ms     MillisecondClock
	rng    RNG
	rtc    RTCClock
	mgr    PacketManager
	tables MeshTables
	h      Handler

	// scratch buffers, so the receive path does not allocate
	secret   [PubKeySize]byte
	data     [MaxPacketPayload]byte
	build    [MaxPacketPayload]byte
	sigMsg   [PubKeySize + 4 + MaxAdvertDataSize]byte
	sig      [SignatureSize]byte
	channels [4]GroupChannel
	sender   Identity
	tmp      Packet
	rngBuf   [4]byte
}

// NewMesh creates a Mesh. All Config fields except Handler are required.
func NewMesh(cfg Config) *Mesh {
	m := &Mesh{
		radio:  cfg.Radio,
		ms:     cfg.Millis,
		rng:    cfg.RNG,
		rtc:    cfg.RTC,
		mgr:    cfg.Packets,
		tables: cfg.Tables,
		h:      cfg.Handler,
	}
	if m.h == nil {
		m.h = &BaseHandler{}
	}
	m.h.base().mesh = m
	m.nextTxTime = m.ms.Millis()
	m.prevIsRecvMode = true
	m.dutyCycleWindowMs = 3600000
	return m
}

func (m *Mesh) Begin() { m.beginDispatcher() }

// Loop must be called repeatedly from the main loop.
func (m *Mesh) Loop() { m.loopDispatcher() }

func (m *Mesh) RNG() RNG               { return m.rng }
func (m *Mesh) RTC() RTCClock          { return m.rtc }
func (m *Mesh) Radio() Radio           { return m.radio }
func (m *Mesh) Tables() MeshTables     { return m.tables }
func (m *Mesh) Packets() PacketManager { return m.mgr }

// nextInt is NextInt using a Mesh-owned buffer, so it does not allocate.
func (m *Mesh) nextInt(min, max uint32) uint32 {
	m.rng.Random(m.rngBuf[:])
	return binary.LittleEndian.Uint32(m.rngBuf[:])%(max-min) + min
}

func (m *Mesh) onRecvPacket(pkt *Packet) Action {
	if pkt.IsRouteDirect() && pkt.PayloadType() == PayloadTypeTrace {
		if pkt.PathLen < MaxPathSize && pkt.PayloadLen >= 9 {
			i := 0
			traceTag := binary.LittleEndian.Uint32(pkt.Payload[i:])
			i += 4
			authCode := binary.LittleEndian.Uint32(pkt.Payload[i:])
			i += 4
			flags := pkt.Payload[i]
			i++
			pathSz := flags & 0x03 // NEW v1.11+: lower 2 bits is path hash size

			n := pkt.PayloadLen - i
			offset := int(pkt.PathLen) << pathSz
			hashSize := 1 << pathSz
			if offset >= n { // TRACE has reached end of given path
				m.h.OnTraceRecv(pkt, traceTag, authCode, flags, pkt.Path[:pkt.PathLen], pkt.Payload[i:i+n])
			} else if offset+hashSize <= n && m.SelfID.IsHashMatch(pkt.Payload[i+offset:i+offset+hashSize]) &&
				m.h.AllowPacketForward(pkt) && !m.tables.WasSeen(pkt) {
				m.tables.MarkSeen(pkt)
				// append SNR (Not hash!)
				pkt.Path[pkt.PathLen] = byte(pkt.SNRx4)
				pkt.PathLen++

				d := m.h.DirectRetransmitDelay(pkt)
				return ActionRetransmitDelayed(5, d) // schedule with priority 5 (for now)
			}
		}
		return ActionRelease
	}

	if pkt.IsRouteDirect() && pkt.PayloadType() == PayloadTypeControl && pkt.PayloadLen > 0 && pkt.Payload[0]&0x80 != 0 {
		if pkt.PathHashCount() == 0 {
			m.h.OnControlDataRecv(pkt)
		}
		// just zero-hop control packets allowed (for this subset of payloads)
		return ActionRelease
	}

	if pkt.IsRouteDirect() && pkt.PathHashCount() > 0 {
		// check for 'early received' ACK
		if pkt.PayloadType() == PayloadTypeAck && pkt.PayloadLen >= 4 {
			m.h.OnAckRecv(pkt, binary.LittleEndian.Uint32(pkt.Payload[:]))
		}

		if m.SelfID.IsHashMatch(pkt.Path[:pkt.PathHashSize()]) && m.h.AllowPacketForward(pkt) {
			d := m.h.DirectRetransmitDelay(pkt)
			if pkt.PayloadType() == PayloadTypeMultipart {
				return m.forwardMultipartDirect(pkt, d)
			} else if pkt.PayloadType() == PayloadTypeAck {
				if !m.tables.WasSeen(pkt) { // don't retransmit!
					m.tables.MarkSeen(pkt)
					removeSelfFromPath(pkt)
					m.routeDirectRecvAcks(pkt, d)
				}
				return ActionRelease
			}

			if !m.tables.WasSeen(pkt) {
				m.tables.MarkSeen(pkt)
				removeSelfFromPath(pkt)
				return ActionRetransmitDelayed(0, d) // routed traffic is HIGHEST priority
			}
		}
		return ActionRelease // this node is NOT the next hop (or already forwarded), so discard
	}

	if pkt.IsRouteFlood() && m.h.FilterRecvFloodPacket(pkt) {
		return ActionRelease
	}

	action := ActionRelease

	switch pkt.PayloadType() {
	case PayloadTypeAck:
		if pkt.PayloadLen < 4 {
			break // incomplete ACK packet
		}
		if !m.tables.WasSeen(pkt) {
			m.tables.MarkSeen(pkt)
			m.h.OnAckRecv(pkt, binary.LittleEndian.Uint32(pkt.Payload[:]))
			action = m.routeRecvPacket(pkt)
		}

	case PayloadTypePath, PayloadTypeReq, PayloadTypeResponse, PayloadTypeTxtMsg:
		i := 0
		destHash := pkt.Payload[i : i+1]
		i++
		srcHash := pkt.Payload[i : i+1]
		i++

		if i+CipherMACSize >= pkt.PayloadLen {
			break // incomplete data packet
		}
		if m.tables.WasSeen(pkt) {
			break
		}
		m.tables.MarkSeen(pkt)
		// NOTE: this is a 'first packet wins' impl. When receiving from
		// multiple paths, the first to arrive wins. For flood mode, the path
		// may not be the 'best' in terms of hops.
		macAndData := pkt.Payload[i:pkt.PayloadLen]

		if m.SelfID.IsHashMatch(destHash) {
			// scan contacts DB for all matching hashes of srcHash
			num := m.h.SearchPeersByHash(srcHash)
			found := false
			for j := 0; j < num; j++ {
				m.h.PeerSharedSecret(&m.secret, j)

				// decrypt, checking MAC is valid
				n := MACThenDecrypt(m.secret[:], m.data[:], macAndData)
				if n == 0 {
					continue
				}
				if pkt.PayloadType() == PayloadTypePath {
					if !m.recvPeerPath(pkt, j, srcHash, m.data[:n]) {
						break // reject bad encoding
					}
				} else {
					m.h.OnPeerDataRecv(pkt, pkt.PayloadType(), j, &m.secret, m.data[:n])
				}
				found = true
				break
			}
			if found {
				pkt.MarkDoNotRetransmit() // packet was for this node, so don't retransmit
			}
		}
		action = m.routeRecvPacket(pkt)

	case PayloadTypeAnonReq:
		i := 0
		destHash := pkt.Payload[i : i+1]
		i++
		senderPubKey := pkt.Payload[i : i+PubKeySize]
		i += PubKeySize

		if i+2 >= pkt.PayloadLen {
			break // incomplete data packet
		}
		if m.tables.WasSeen(pkt) {
			break
		}
		m.tables.MarkSeen(pkt)
		if m.SelfID.IsHashMatch(destHash) {
			copy(m.sender.PubKey[:], senderPubKey)
			m.SelfID.SharedSecret(&m.secret, &m.sender.PubKey)

			// decrypt, checking MAC is valid
			n := MACThenDecrypt(m.secret[:], m.data[:], pkt.Payload[i:pkt.PayloadLen])
			if n > 0 {
				m.h.OnAnonDataRecv(pkt, &m.secret, &m.sender, m.data[:n])
				pkt.MarkDoNotRetransmit()
			}
		}
		action = m.routeRecvPacket(pkt)

	case PayloadTypeGrpData, PayloadTypeGrpTxt:
		i := 0
		channelHash := pkt.Payload[i : i+1]
		i++

		if i+2 >= pkt.PayloadLen {
			break // incomplete data packet
		}
		if m.tables.WasSeen(pkt) {
			break
		}
		m.tables.MarkSeen(pkt)
		// scan channels DB for all matching hashes of channelHash
		num := m.h.SearchChannelsByHash(channelHash, m.channels[:])
		if num > len(m.channels) {
			num = len(m.channels)
		}
		for j := 0; j < num; j++ {
			n := MACThenDecrypt(m.channels[j].Secret[:], m.data[:], pkt.Payload[i:pkt.PayloadLen])
			if n > 0 {
				m.h.OnGroupDataRecv(pkt, pkt.PayloadType(), &m.channels[j], m.data[:n])
				break
			}
		}
		action = m.routeRecvPacket(pkt)

	case PayloadTypeAdvert:
		i := 0
		var id Identity
		copy(id.PubKey[:], pkt.Payload[i:])
		i += PubKeySize
		timestamp := binary.LittleEndian.Uint32(pkt.Payload[i:])
		i += 4
		signature := pkt.Payload[i : i+SignatureSize]
		i += SignatureSize

		if i > pkt.PayloadLen {
			break // incomplete advertisement packet
		}
		if m.SelfID.Matches(&id) {
			break // receiving SELF advert packet
		}
		if m.tables.WasSeen(pkt) {
			break
		}
		m.tables.MarkSeen(pkt)
		appData := pkt.Payload[i:pkt.PayloadLen]
		if len(appData) > MaxAdvertDataSize {
			appData = appData[:MaxAdvertDataSize]
		}

		// check that signature is valid
		n := copy(m.sigMsg[:], id.PubKey[:])
		binary.LittleEndian.PutUint32(m.sigMsg[n:], timestamp)
		n += 4
		n += copy(m.sigMsg[n:], appData)
		if id.Verify(signature, m.sigMsg[:n]) {
			m.h.OnAdvertRecv(pkt, &id, timestamp, appData)
			action = m.routeRecvPacket(pkt)
		}
		// else: advertisement with forged signature!

	case PayloadTypeRawCustom:
		if pkt.IsRouteDirect() && !m.tables.WasSeen(pkt) {
			m.tables.MarkSeen(pkt)
			m.h.OnRawDataRecv(pkt)
			// don't flood route these (yet)
		}

	case PayloadTypeMultipart:
		if pkt.PayloadLen > 2 {
			typ := pkt.Payload[0] & 0x0F
			if typ == PayloadTypeAck && pkt.PayloadLen >= 5 { // a multipart ACK
				tmp := m.unwrapMultipart(pkt)
				if !m.tables.WasSeen(tmp) {
					m.tables.MarkSeen(tmp)
					m.h.OnAckRecv(tmp, binary.LittleEndian.Uint32(tmp.Payload[:]))
					// NOTE: routing not needed, as multipart ACKs not sent Flood
				}
			}
			// FUTURE: other multipart types??
		}

	default:
		// Don't flood route unknown packet types!
	}
	return action
}

// recvPeerPath handles a decrypted PATH payload. It returns false on a bad
// encoding.
func (m *Mesh) recvPeerPath(pkt *Packet, peerIdx int, srcHash []byte, data []byte) bool {
	k := 0
	pathLen := data[k]
	k++
	if !IsValidPathLen(pathLen) {
		return false
	}
	pathBytes := int(pathLen&63) * (int(pathLen>>6) + 1)
	if k+pathBytes+1 > len(data) {
		return false
	}
	path := data[k : k+pathBytes]
	k += pathBytes
	extraType := data[k] & 0x0F // upper 4 bits reserved for future use
	k++
	extra := data[k:] // remainder of packet (may be padded with zeroes!)
	if m.h.OnPeerPathRecv(pkt, peerIdx, &m.secret, path, pathLen, extraType, extra) {
		if pkt.IsRouteFlood() {
			// send a reciprocal return path to sender, but send DIRECTLY!
			rpath := m.CreatePathReturnHash(srcHash, m.secret[:], pkt.Path[:], pkt.PathLen, 0, nil)
			if rpath != nil {
				m.SendDirect(rpath, path, pathLen, 500)
			}
		}
	}
	return true
}

// unwrapMultipart copies the inner packet of a multipart packet into the
// scratch packet.
func (m *Mesh) unwrapMultipart(pkt *Packet) *Packet {
	tmp := &m.tmp
	tmp.Header = pkt.Header
	tmp.TransportCodes = pkt.TransportCodes
	tmp.PathLen = CopyPath(tmp.Path[:], pkt.Path[:], pkt.PathLen)
	tmp.PayloadLen = copy(tmp.Payload[:], pkt.Payload[1:pkt.PayloadLen])
	tmp.SNRx4 = pkt.SNRx4
	return tmp
}

func removeSelfFromPath(pkt *Packet) {
	// remove our hash from 'path'
	pkt.SetPathHashCount(pkt.PathHashCount() - 1) // decrement the count
	sz := pkt.PathHashSize()
	n := pkt.PathHashCount() * sz
	copy(pkt.Path[:n], pkt.Path[sz:n+sz]) // shuffle path by 1 'entry'
}

func (m *Mesh) routeRecvPacket(pkt *Packet) Action {
	n := pkt.PathHashCount()
	sz := pkt.PathHashSize()
	if pkt.IsRouteFlood() && !pkt.IsMarkedDoNotRetransmit() && (n+1)*sz <= MaxPathSize && m.h.AllowPacketForward(pkt) {
		// append this node's hash to 'path'
		m.SelfID.CopyHashTo(pkt.Path[n*sz:], sz)
		pkt.SetPathHashCount(n + 1)

		d := m.h.RetransmitDelay(pkt)
		// as this propagates outwards, give it lower and lower priority
		return ActionRetransmitDelayed(uint8(pkt.PathHashCount()), d) // give priority to closer sources
	}
	return ActionRelease
}

func (m *Mesh) forwardMultipartDirect(pkt *Packet, delayMillis uint32) Action {
	remaining := pkt.Payload[0] >> 4 // num of packets in this multipart sequence still to be sent
	typ := pkt.Payload[0] & 0x0F

	if typ == PayloadTypeAck && pkt.PayloadLen >= 5 { // a multipart ACK
		tmp := m.unwrapMultipart(pkt)
		if !m.tables.WasSeen(tmp) { // don't retransmit!
			m.tables.MarkSeen(tmp)
			removeSelfFromPath(tmp)
			m.routeDirectRecvAcks(tmp, delayMillis+(uint32(remaining)+1)*300) // expect multipart ACKs 300ms apart (x2)
		}
	}
	return ActionRelease
}

func (m *Mesh) routeDirectRecvAcks(pkt *Packet, delayMillis uint32) {
	if pkt.IsMarkedDoNotRetransmit() {
		return
	}
	for extra := m.h.ExtraAckTransmitCount(); extra > 0; extra-- {
		if a1 := m.CreateMultiAck(pkt.Payload[:pkt.PayloadLen], extra); a1 != nil {
			a1.PathLen = CopyPath(a1.Path[:], pkt.Path[:], pkt.PathLen)
			a1.Header &^= PHRouteMask
			a1.Header |= RouteTypeDirect
			m.SendPacket(a1, 0, delayMillis)
			delayMillis += 300
		}
	}

	if a2 := m.CreateAck(pkt.Payload[:pkt.PayloadLen]); a2 != nil {
		a2.PathLen = CopyPath(a2.Path[:], pkt.Path[:], pkt.PathLen)
		a2.Header &^= PHRouteMask
		a2.Header |= RouteTypeDirect
		m.SendPacket(a2, 0, delayMillis)
	}
}

// CreateAdvert creates a signed advertisement of id with optional appData
// (at most MaxAdvertDataSize bytes). It returns nil if appData is too long
// or the pool is empty.
func (m *Mesh) CreateAdvert(id *LocalIdentity, appData []byte) *Packet {
	if len(appData) > MaxAdvertDataSize {
		return nil
	}
	pkt := m.ObtainNewPacket()
	if pkt == nil {
		return nil
	}
	pkt.Header = PayloadTypeAdvert << PHTypeShift // ROUTE_TYPE_* is set later

	n := copy(pkt.Payload[:], id.PubKey[:])
	ts := m.rtc.CurrentTime()
	binary.LittleEndian.PutUint32(pkt.Payload[n:], ts)
	n += 4
	sigAt := n
	n += SignatureSize // filled in below
	n += copy(pkt.Payload[n:], appData)
	pkt.PayloadLen = n

	k := copy(m.sigMsg[:], id.PubKey[:])
	binary.LittleEndian.PutUint32(m.sigMsg[k:], ts)
	k += 4
	k += copy(m.sigMsg[k:], appData)
	id.Sign(&m.sig, m.sigMsg[:k])
	copy(pkt.Payload[sigAt:], m.sig[:])
	return pkt
}

const maxCombinedPath = MaxPacketPayload - 2 - CipherBlockSize

// CreatePathReturn creates a PATH packet returning path to dest.
func (m *Mesh) CreatePathReturn(dest *Identity, secret []byte, path []byte, pathLen uint8, extraType uint8, extra []byte) *Packet {
	return m.CreatePathReturnHash(dest.PubKey[:PathHashSize], secret, path, pathLen, extraType, extra)
}

// CreatePathReturnHash is CreatePathReturn addressed by destination hash.
// path holds the path bytes described by the encoded pathLen.
func (m *Mesh) CreatePathReturnHash(destHash []byte, secret []byte, path []byte, pathLen uint8, extraType uint8, extra []byte) *Packet {
	pathBytes := int(pathLen&63) * (int(pathLen>>6) + 1)
	if pathBytes+len(extra)+5 > maxCombinedPath || pathBytes > len(path) {
		return nil // too long!!
	}
	pkt := m.ObtainNewPacket()
	if pkt == nil {
		return nil
	}
	pkt.Header = PayloadTypePath << PHTypeShift // ROUTE_TYPE_* set later

	n := copy(pkt.Payload[:], destHash[:PathHashSize])      // dest hash
	n += m.SelfID.CopyHashTo(pkt.Payload[n:], PathHashSize) // src hash

	data := m.build[:]
	dn := 0
	data[dn] = pathLen
	dn++
	dn += copy(data[dn:], path[:pathBytes])
	if len(extra) > 0 {
		data[dn] = extraType
		dn++
		dn += copy(data[dn:], extra)
	} else {
		// append a random blob (to make packet_hash unique)
		data[dn] = 0xFF // dummy payload type
		dn++
		m.rng.Random(data[dn : dn+4])
		dn += 4
	}
	n += EncryptThenMAC(secret, pkt.Payload[n:], data[:dn])
	pkt.PayloadLen = n
	return pkt
}

// CreateDatagram creates an encrypted TXT_MSG, REQ or RESPONSE to dest.
func (m *Mesh) CreateDatagram(typ uint8, dest *Identity, secret []byte, data []byte) *Packet {
	if typ != PayloadTypeTxtMsg && typ != PayloadTypeReq && typ != PayloadTypeResponse {
		return nil // invalid type
	}
	if len(data)+CipherMACSize+CipherBlockSize-1 > MaxPacketPayload {
		return nil
	}
	pkt := m.ObtainNewPacket()
	if pkt == nil {
		return nil
	}
	pkt.Header = typ << PHTypeShift // ROUTE_TYPE_* set later

	n := dest.CopyHashTo(pkt.Payload[:], PathHashSize)      // dest hash
	n += m.SelfID.CopyHashTo(pkt.Payload[n:], PathHashSize) // src hash
	n += EncryptThenMAC(secret, pkt.Payload[n:], data)
	pkt.PayloadLen = n
	return pkt
}

// CreateAnonDatagram creates an ANON_REQ from sender to dest, carrying the
// sender's public key so dest can derive the shared secret.
func (m *Mesh) CreateAnonDatagram(typ uint8, sender *LocalIdentity, dest *Identity, secret []byte, data []byte) *Packet {
	if typ != PayloadTypeAnonReq {
		return nil // invalid type
	}
	if len(data)+1+PubKeySize+CipherBlockSize-1 > MaxPacketPayload {
		return nil
	}
	pkt := m.ObtainNewPacket()
	if pkt == nil {
		return nil
	}
	pkt.Header = typ << PHTypeShift // ROUTE_TYPE_* set later

	n := dest.CopyHashTo(pkt.Payload[:], PathHashSize) // dest hash
	n += copy(pkt.Payload[n:], sender.PubKey[:])       // sender pub_key
	n += EncryptThenMAC(secret, pkt.Payload[n:], data)
	pkt.PayloadLen = n
	return pkt
}

// CreateGroupDatagram creates an encrypted GRP_TXT or GRP_DATA packet.
func (m *Mesh) CreateGroupDatagram(typ uint8, ch *GroupChannel, data []byte) *Packet {
	if typ != PayloadTypeGrpTxt && typ != PayloadTypeGrpData {
		return nil // invalid type
	}
	if len(data)+1+CipherBlockSize-1 > MaxPacketPayload {
		return nil // too long
	}
	pkt := m.ObtainNewPacket()
	if pkt == nil {
		return nil
	}
	pkt.Header = typ << PHTypeShift // ROUTE_TYPE_* set later

	n := copy(pkt.Payload[:], ch.Hash[:])
	n += EncryptThenMAC(ch.Secret[:], pkt.Payload[n:], data)
	pkt.PayloadLen = n
	return pkt
}

// CreateAck creates an ACK packet with the given ack bytes.
func (m *Mesh) CreateAck(ack []byte) *Packet {
	pkt := m.ObtainNewPacket()
	if pkt == nil {
		return nil
	}
	pkt.Header = PayloadTypeAck << PHTypeShift // ROUTE_TYPE_* set later
	pkt.PayloadLen = copy(pkt.Payload[:], ack)
	return pkt
}

// CreateAckCRC creates an ACK packet for a 32-bit ack CRC.
func (m *Mesh) CreateAckCRC(ackCRC uint32) *Packet {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], ackCRC)
	return m.CreateAck(b[:])
}

// CreateMultiAck creates a multipart ACK, with remaining more to follow.
func (m *Mesh) CreateMultiAck(ack []byte, remaining uint8) *Packet {
	pkt := m.ObtainNewPacket()
	if pkt == nil {
		return nil
	}
	pkt.Header = PayloadTypeMultipart << PHTypeShift // ROUTE_TYPE_* set later
	pkt.Payload[0] = remaining<<4 | PayloadTypeAck
	pkt.PayloadLen = 1 + copy(pkt.Payload[1:], ack)
	return pkt
}

// CreateMultiAckCRC is CreateMultiAck for a 32-bit ack CRC.
func (m *Mesh) CreateMultiAckCRC(ackCRC uint32, remaining uint8) *Packet {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], ackCRC)
	return m.CreateMultiAck(b[:], remaining)
}

// CreateRawData creates a RAW_CUSTOM packet.
func (m *Mesh) CreateRawData(data []byte) *Packet {
	return m.createWithPayload(PayloadTypeRawCustom, data)
}

// CreateControlData creates a CONTROL packet.
func (m *Mesh) CreateControlData(data []byte) *Packet {
	return m.createWithPayload(PayloadTypeControl, data)
}

func (m *Mesh) createWithPayload(typ uint8, data []byte) *Packet {
	if len(data) > MaxPacketPayload {
		return nil // invalid arg
	}
	pkt := m.ObtainNewPacket()
	if pkt == nil {
		return nil
	}
	pkt.Header = typ << PHTypeShift // ROUTE_TYPE_* set later
	pkt.PayloadLen = copy(pkt.Payload[:], data)
	return pkt
}

// CreateTrace creates a TRACE packet. The path is appended by SendDirect.
func (m *Mesh) CreateTrace(tag, authCode uint32, flags uint8) *Packet {
	pkt := m.ObtainNewPacket()
	if pkt == nil {
		return nil
	}
	pkt.Header = PayloadTypeTrace << PHTypeShift // ROUTE_TYPE_* set later
	binary.LittleEndian.PutUint32(pkt.Payload[0:], tag)
	binary.LittleEndian.PutUint32(pkt.Payload[4:], authCode)
	pkt.Payload[8] = flags
	pkt.PayloadLen = 9 // NOTE: path will be appended to payload later
	return pkt
}

func floodPriority(pkt *Packet) uint8 {
	switch pkt.PayloadType() {
	case PayloadTypePath:
		return 2
	case PayloadTypeAdvert:
		return 3 // de-prioritise these
	}
	return 1
}

// SendFlood sends a locally-generated packet with flood routing.
// pathHashSize is 1..3 (1 is the classic default). Unlike the C++, an
// invalid packet is returned to the pool rather than leaked.
func (m *Mesh) SendFlood(pkt *Packet, delayMillis uint32, pathHashSize int) {
	m.sendFlood(pkt, RouteTypeFlood, [2]uint16{}, delayMillis, pathHashSize)
}

// SendFloodTransport is SendFlood with transport codes attached.
func (m *Mesh) SendFloodTransport(pkt *Packet, codes [2]uint16, delayMillis uint32, pathHashSize int) {
	m.sendFlood(pkt, RouteTypeTransportFlood, codes, delayMillis, pathHashSize)
}

func (m *Mesh) sendFlood(pkt *Packet, routeType uint8, codes [2]uint16, delayMillis uint32, pathHashSize int) {
	if pkt.PayloadType() == PayloadTypeTrace || pathHashSize < 1 || pathHashSize > 3 {
		m.ReleasePacket(pkt) // TRACE not supported, or invalid path hash size
		return
	}
	pkt.Header &^= PHRouteMask
	pkt.Header |= routeType
	if routeType == RouteTypeTransportFlood {
		pkt.TransportCodes = codes
	}
	pkt.SetPathHashSizeAndCount(pathHashSize, 0)

	m.tables.MarkSeen(pkt) // mark as already sent in case it is rebroadcast back to us
	m.SendPacket(pkt, floodPriority(pkt), delayMillis)
}

// SendDirect sends a locally-generated packet along a known path. path holds
// the path bytes described by the encoded pathLen. For TRACE packets the path
// is appended to the payload instead and pathLen is a plain byte count.
func (m *Mesh) SendDirect(pkt *Packet, path []byte, pathLen uint8, delayMillis uint32) {
	pkt.Header &^= PHRouteMask
	pkt.Header |= RouteTypeDirect

	var pri uint8
	if pkt.PayloadType() == PayloadTypeTrace { // TRACE packets are different
		// path is appended to end of PAYLOAD (path is used for SNRs);
		// pathLen here can be > 64, and NOT in the new scheme
		if pkt.PayloadLen+int(pathLen) > MaxPacketPayload || int(pathLen) > len(path) {
			m.ReleasePacket(pkt)
			return
		}
		pkt.PayloadLen += copy(pkt.Payload[pkt.PayloadLen:], path[:pathLen])
		pkt.PathLen = 0
		pri = 5 // maybe make this configurable
	} else {
		pkt.PathLen = CopyPath(pkt.Path[:], path, pathLen)
		if pkt.PayloadType() == PayloadTypePath {
			pri = 1 // slightly less priority
		} else {
			pri = 0
		}
	}
	m.tables.MarkSeen(pkt) // mark as already sent in case it is rebroadcast back to us
	m.SendPacket(pkt, pri, delayMillis)
}

// SendZeroHop sends a locally-generated packet to just neighbour nodes.
func (m *Mesh) SendZeroHop(pkt *Packet, delayMillis uint32) {
	pkt.Header &^= PHRouteMask
	pkt.Header |= RouteTypeDirect
	pkt.PathLen = 0 // path_len of zero means Zero Hop

	m.tables.MarkSeen(pkt)
	m.SendPacket(pkt, 0, delayMillis)
}

// SendZeroHopTransport is SendZeroHop with transport codes attached.
func (m *Mesh) SendZeroHopTransport(pkt *Packet, codes [2]uint16, delayMillis uint32) {
	pkt.Header &^= PHRouteMask
	pkt.Header |= RouteTypeTransportDirect
	pkt.TransportCodes = codes
	pkt.PathLen = 0 // path_len of zero means Zero Hop

	m.tables.MarkSeen(pkt)
	m.SendPacket(pkt, 0, delayMillis)
}
