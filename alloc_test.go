package meshcore

import "testing"

// TestForwardDoesNotAllocate checks the repeater hot path (receive, parse,
// dedup, route, transmit) of a flood packet this node cannot decrypt.
func TestForwardDoesNotAllocate(t *testing.T) {
	radio := &quietRadio{}
	ms := &fakeMillis{t: 1000}
	m := NewMesh(Config{
		Radio:   radio,
		Millis:  ms,
		RNG:     &xorShiftRNG{1},
		RTC:     &fakeRTC{t: 1700000000},
		Packets: NewStaticPoolPacketManager(16),
		Tables:  &SimpleMeshTables{},
		Handler: &forwarder{},
	})
	m.SelfID = LocalIdentityFromSeed(pattern(32, 1, 1))
	m.Begin()

	var ch GroupChannel
	ch.Hash[0] = 0x42
	tmpl := m.CreateGroupDatagram(PayloadTypeGrpTxt, &ch, []byte("not for us"))
	setFlood(tmpl)
	raw := rawOf(tmpl)
	m.ReleasePacket(tmpl)

	seq := byte(0)
	allocs := testing.AllocsPerRun(100, func() {
		raw[len(raw)-1] = seq // make each packet unique so it is not deduped
		seq++
		radio.pending = raw
		for k := 0; k < 100; k++ {
			ms.t += 10
			m.Loop()
		}
	})
	if m.NumSentFlood() < 100 {
		t.Fatalf("only %d packets forwarded", m.NumSentFlood())
	}
	if allocs != 0 {
		t.Errorf("forward path: %v allocs per packet", allocs)
	}
}

type forwarder struct{ BaseHandler }

func (f *forwarder) AllowPacketForward(p *Packet) bool { return true }

// quietRadio delivers one pending packet and completes sends immediately.
type quietRadio struct {
	RadioBase
	pending []byte
	sending bool
}

func (r *quietRadio) RecvRaw(buf []byte) int {
	n := copy(buf, r.pending)
	r.pending = nil
	return n
}
func (r *quietRadio) EstAirtimeFor(n int) uint32             { return uint32(n * 2) }
func (r *quietRadio) PacketScore(snr float32, n int) float32 { return 1 }
func (r *quietRadio) StartSendRaw(b []byte) bool             { r.sending = true; return true }
func (r *quietRadio) IsSendComplete() bool {
	done := r.sending
	r.sending = false
	return done
}
func (r *quietRadio) OnSendFinished()    {}
func (r *quietRadio) IsInRecvMode() bool { return !r.sending }
