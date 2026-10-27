package meshcore

import "encoding/binary"

// Action is what to do with a received packet after processing it.
type Action uint32

const (
	ActionRelease    Action = 0
	ActionManualHold Action = 1 // the handler holds the packet and will call ReleasePacket
)

// ActionRetransmit queues the packet for retransmission at a priority (lower
// is more important).
func ActionRetransmit(pri uint8) Action { return Action(1+uint32(pri)) << 24 }

// ActionRetransmitDelayed is ActionRetransmit after delay milliseconds (at
// most 0xFFFFFF).
func ActionRetransmitDelayed(pri uint8, delay uint32) Action {
	return ActionRetransmit(pri) | Action(delay&0xFFFFFF)
}

const (
	maxRxDelayMillis        = 32000 // 32 seconds
	minTxBudgetReserveMs    = 100   // min budget (ms) required before allowing next TX
	minTxBudgetAirtimeDiv   = 2     // require at least 1/N of estimated airtime as budget before TX
	noiseFloorCalibInterval = 2000  // 2 seconds
)

// dispatcher is the low-level task state that manages detecting incoming
// packets and the queueing and scheduling of outbound packets.
type dispatcher struct {
	outbound           *Packet // current outbound packet
	outboundExpiry     uint32
	outboundStart      uint32
	totalAirTime       uint32
	rxAirTime          uint32
	nextTxTime         uint32
	cadBusyStart       uint32
	radioNonRxStart    uint32
	nextFloorCalibTime uint32
	nextAGCResetTime   uint32
	prevIsRecvMode     bool
	nSentFlood         uint32
	nSentDirect        uint32
	nRecvFlood         uint32
	nRecvDirect        uint32
	txBudgetMs         uint32
	lastBudgetUpdate   uint32
	dutyCycleWindowMs  uint32

	// ErrFlags accumulates ErrEvent* flags.
	ErrFlags uint16

	rxBuf [MaxTransUnit + 1]byte
	txBuf [MaxTransUnit]byte
}

func (m *Mesh) dutyCycle() float32 { return 1.0 / (1.0 + m.h.AirtimeBudgetFactor()) }

func (m *Mesh) beginDispatcher() {
	m.nSentFlood, m.nSentDirect = 0, 0
	m.nRecvFlood, m.nRecvDirect = 0, 0
	m.ErrFlags = 0
	m.radioNonRxStart = m.ms.Millis()

	m.dutyCycleWindowMs = m.h.DutyCycleWindowMs()
	m.txBudgetMs = uint32(float32(m.dutyCycleWindowMs) * m.dutyCycle())
	m.lastBudgetUpdate = m.ms.Millis()

	m.radio.Begin()
	m.prevIsRecvMode = m.radio.IsInRecvMode()
}

func (m *Mesh) updateTxBudget() {
	now := m.ms.Millis()
	elapsed := now - m.lastBudgetUpdate

	dc := m.dutyCycle()
	maxBudget := uint32(float32(m.h.DutyCycleWindowMs()) * dc)
	refill := uint32(float32(elapsed) * dc)

	if refill > 0 {
		m.txBudgetMs += refill
		if m.txBudgetMs > maxBudget {
			m.txBudgetMs = maxBudget
		}
		m.lastBudgetUpdate = now
	}
}

func (m *Mesh) loopDispatcher() {
	if m.MillisHasNowPassed(m.nextFloorCalibTime) {
		m.radio.TriggerNoiseFloorCalibrate(m.h.InterferenceThreshold())
		m.radio.SetCADEnabled(m.h.CADEnabled())
		m.nextFloorCalibTime = m.FutureMillis(noiseFloorCalibInterval)
	}
	m.radio.Loop()

	// check for radio 'stuck' in mode other than Rx
	isRecv := m.radio.IsInRecvMode()
	if isRecv != m.prevIsRecvMode {
		m.prevIsRecvMode = isRecv
		if !isRecv {
			m.radioNonRxStart = m.ms.Millis()
		}
	}
	if !isRecv && m.ms.Millis()-m.radioNonRxStart > 8000 { // radio has not been in Rx mode for 8 seconds!
		m.ErrFlags |= ErrEventStartRxTimeout
	}

	if m.outbound != nil { // waiting for outbound send to be completed
		if m.radio.IsSendComplete() {
			t := m.ms.Millis() - m.outboundStart
			m.totalAirTime += t

			m.updateTxBudget()

			if t > m.txBudgetMs {
				m.txBudgetMs = 0
			} else {
				m.txBudgetMs -= t
			}

			if m.txBudgetMs < minTxBudgetReserveMs {
				needed := minTxBudgetReserveMs - m.txBudgetMs
				m.nextTxTime = m.FutureMillis(int(float32(needed) / m.dutyCycle()))
			} else {
				m.nextTxTime = m.ms.Millis()
			}

			m.radio.OnSendFinished()
			m.h.LogTx(m.outbound, 2+m.outbound.PathByteLen()+m.outbound.PayloadLen)
			if m.outbound.IsRouteFlood() {
				m.nSentFlood++
			} else {
				m.nSentDirect++
			}
			m.ReleasePacket(m.outbound) // return to pool
			m.outbound = nil
		} else if m.MillisHasNowPassed(m.outboundExpiry) {
			// outbound packet send timed out
			m.radio.OnSendFinished()
			m.h.LogTxFail(m.outbound, 2+m.outbound.PathByteLen()+m.outbound.PayloadLen)

			m.ReleasePacket(m.outbound) // return to pool
			m.outbound = nil
		} else {
			return // can't do any more radio activity until send is complete or timed out
		}

		// going back into receive mode now...
		m.nextAGCResetTime = m.FutureMillis(m.h.AGCResetInterval())
	}

	if m.h.AGCResetInterval() > 0 && m.MillisHasNowPassed(m.nextAGCResetTime) {
		m.radio.ResetAGC()
		m.nextAGCResetTime = m.FutureMillis(m.h.AGCResetInterval())
	}

	// check inbound (delayed) queue
	if pkt := m.mgr.NextInbound(m.ms.Millis()); pkt != nil {
		m.processRecvPacket(pkt)
	}
	m.checkRecv()
	m.checkSend()
}

// TryParsePacket parses a raw on-air packet into pkt.
func (m *Mesh) TryParsePacket(pkt *Packet, raw []byte) bool {
	if len(raw) < 2 {
		return false
	}
	i := 0
	pkt.Header = raw[i]
	i++
	if pkt.PayloadVer() > PayloadVer1 {
		return false // unsupported packet version
	}

	if pkt.HasTransportCodes() {
		if len(raw) < i+5 {
			return false
		}
		pkt.TransportCodes[0] = binary.LittleEndian.Uint16(raw[i:])
		pkt.TransportCodes[1] = binary.LittleEndian.Uint16(raw[i+2:])
		i += 4
	} else {
		pkt.TransportCodes = [2]uint16{}
	}

	pkt.PathLen = raw[i]
	i++
	if pkt.PathLen>>6 == 3 { // upper 2 bits (legacy firmware: 00); 3 is reserved for future
		return false
	}

	pathByteLen := pkt.PathByteLen()
	if pathByteLen > MaxPathSize || i+pathByteLen > len(raw) {
		return false // partial or corrupt packet received
	}
	copy(pkt.Path[:], raw[i:i+pathByteLen])
	i += pathByteLen

	n := len(raw) - i // payload is remainder
	if n > MaxPacketPayload {
		return false // packet payload too big
	}
	pkt.PayloadLen = copy(pkt.Payload[:], raw[i:])
	return true
}

func (m *Mesh) checkRecv() {
	n := m.radio.RecvRaw(m.rxBuf[:MaxTransUnit])
	if n <= 0 {
		return
	}
	raw := m.rxBuf[:n]
	m.h.LogRxRaw(m.radio.LastSNR(), m.radio.LastRSSI(), raw)

	pkt := m.mgr.AllocNew()
	if pkt == nil {
		return // received data, no unused packets available!
	}
	if !m.TryParsePacket(pkt, raw) {
		m.mgr.Free(pkt) // put back into pool
		return
	}
	pkt.SNRx4 = int8(m.radio.LastSNR() * 4)
	score := m.radio.PacketScore(m.radio.LastSNR(), n)
	airTime := m.radio.EstAirtimeFor(n)
	m.rxAirTime += airTime

	m.h.LogRx(pkt, pkt.RawLength(), score)

	if pkt.IsRouteFlood() {
		m.nRecvFlood++

		delay := m.h.CalcRxDelay(score, airTime)
		if delay < 50 {
			m.processRecvPacket(pkt) // below the score delay threshold, so process immediately
		} else {
			if delay > maxRxDelayMillis {
				delay = maxRxDelayMillis
			}
			m.mgr.QueueInbound(pkt, m.FutureMillis(delay)) // add to delayed inbound queue
		}
	} else {
		m.nRecvDirect++
		m.processRecvPacket(pkt)
	}
}

func (m *Mesh) processRecvPacket(pkt *Packet) {
	action := m.onRecvPacket(pkt)
	switch action {
	case ActionRelease:
		m.mgr.Free(pkt)
	case ActionManualHold:
		// the handler holds the packet and calls ReleasePacket at the appropriate time
	default: // ActionRetransmit*
		priority := uint8(action>>24) - 1
		delay := uint32(action & 0xFFFFFF)
		m.mgr.QueueOutbound(pkt, priority, m.FutureMillis(int(delay)))
	}
}

func (m *Mesh) checkSend() {
	if m.mgr.OutboundCount(m.ms.Millis()) == 0 {
		return
	}

	m.updateTxBudget()

	estAirtime := m.radio.EstAirtimeFor(MaxTransUnit)
	if m.txBudgetMs < estAirtime/minTxBudgetAirtimeDiv {
		needed := estAirtime/minTxBudgetAirtimeDiv - m.txBudgetMs
		m.nextTxTime = m.FutureMillis(int(float32(needed) / m.dutyCycle()))
		return
	}

	if !m.MillisHasNowPassed(m.nextTxTime) {
		return
	}
	if m.radio.IsReceiving() {
		if m.cadBusyStart == 0 {
			m.cadBusyStart = m.ms.Millis() // record when CAD busy state started
		}
		if m.ms.Millis()-m.cadBusyStart > m.h.CADFailMaxDuration() {
			// channel activity has gone on too long (radio might be in a bad
			// state), so force the pending transmit below
			m.ErrFlags |= ErrEventCADTimeout
		} else {
			m.nextTxTime = m.FutureMillis(int(m.h.CADFailRetryDelay()))
			return
		}
	}
	m.cadBusyStart = 0 // reset busy state

	m.outbound = m.mgr.NextOutbound(m.ms.Millis())
	if m.outbound == nil {
		return
	}
	out := m.outbound
	raw := m.txBuf[:]
	n := 0
	raw[n] = out.Header
	n++
	if out.HasTransportCodes() {
		binary.LittleEndian.PutUint16(raw[n:], out.TransportCodes[0])
		binary.LittleEndian.PutUint16(raw[n+2:], out.TransportCodes[1])
		n += 4
	}
	raw[n] = out.PathLen
	n++
	n += WritePath(raw[n:], out.Path[:], out.PathLen)

	if n+out.PayloadLen > MaxTransUnit {
		// invalid packet queued... too long
		m.mgr.Free(out)
		m.outbound = nil
		return
	}
	n += copy(raw[n:], out.Payload[:out.PayloadLen])

	maxAirtime := m.radio.EstAirtimeFor(n) * 3 / 2
	m.outboundStart = m.ms.Millis()
	if !m.radio.StartSendRaw(raw[:n]) {
		m.h.LogTxFail(out, out.RawLength())
		m.ReleasePacket(out) // return to pool
		m.outbound = nil
		return
	}
	m.outboundExpiry = m.FutureMillis(int(maxAirtime))
}

// ObtainNewPacket allocates a packet from the pool, or returns nil (and sets
// ErrEventFull) if the pool is empty.
func (m *Mesh) ObtainNewPacket() *Packet {
	pkt := m.mgr.AllocNew()
	if pkt == nil {
		m.ErrFlags |= ErrEventFull
		return nil
	}
	pkt.PayloadLen = 0
	pkt.PathLen = 0
	pkt.SNRx4 = 0
	return pkt
}

// ReleasePacket returns a packet to the pool.
func (m *Mesh) ReleasePacket(p *Packet) { m.mgr.Free(p) }

// SendPacket queues a packet for transmission at a priority (lower is more
// important) after delayMillis.
func (m *Mesh) SendPacket(p *Packet, priority uint8, delayMillis uint32) {
	if !IsValidPathLen(p.PathLen) || p.PayloadLen > MaxPacketPayload {
		m.mgr.Free(p) // invalid packet
		return
	}
	m.mgr.QueueOutbound(p, priority, m.FutureMillis(int(delayMillis)))
}

func (m *Mesh) TotalAirTime() uint32      { return m.totalAirTime }
func (m *Mesh) ReceiveAirTime() uint32    { return m.rxAirTime }
func (m *Mesh) RemainingTxBudget() uint32 { return m.txBudgetMs }
func (m *Mesh) NumSentFlood() uint32      { return m.nSentFlood }
func (m *Mesh) NumSentDirect() uint32     { return m.nSentDirect }
func (m *Mesh) NumRecvFlood() uint32      { return m.nRecvFlood }
func (m *Mesh) NumRecvDirect() uint32     { return m.nRecvDirect }

func (m *Mesh) ResetStats() {
	m.nSentFlood, m.nSentDirect, m.nRecvFlood, m.nRecvDirect = 0, 0, 0, 0
	m.ErrFlags = 0
}

// MillisHasNowPassed reports whether timestamp is in the past, handling
// wrap-around of the millisecond clock.
func (m *Mesh) MillisHasNowPassed(timestamp uint32) bool {
	return int32(m.ms.Millis()-timestamp) > 0
}

// FutureMillis returns the clock value millisFromNow in the future.
func (m *Mesh) FutureMillis(millisFromNow int) uint32 {
	return m.ms.Millis() + uint32(millisFromNow)
}
