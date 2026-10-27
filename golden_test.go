package meshcore

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
)

// The golden vectors are produced by tools/golden/gen.sh from the upstream
// C++ sources. The scenario below must stay in sync with harness.cpp.

type golden struct {
	Keys []struct {
		Seed, Pub, Prv string
		Valid          bool
	}
	Signs []struct {
		Key        int
		Msg, Sig   string
		OK         bool `json:"ok"`
		TamperedOK bool `json:"tampered_ok"`
	}
	ECDH []struct {
		Prv, Pub, Secret string
	}
	Validate []struct {
		Prv   string
		Valid bool
	}
	Cipher []struct {
		Key, Plain, Enc, ETM, Dec string
		BadLen                    int `json:"bad_len"`
	}
	SHA []struct {
		Msg, Frag, Hash string
		Hash2           string `json:"hash2_8"`
	}
	Packets []struct {
		Raw, Hash, Encoded string
		OK                 bool `json:"ok"`
		RawLen             int  `json:"raw_len"`
	}
	Adverts []struct {
		Type     uint8
		Name     string
		Loc      bool
		Lat, Lon float64
		F1, F2   uint16
		Enc      string
		PValid   bool   `json:"p_valid"`
		PType    uint8  `json:"p_type"`
		PName    string `json:"p_name"`
		PLat     int32  `json:"p_lat"`
		PLon     int32  `json:"p_lon"`
		PF1      uint16 `json:"p_f1"`
		PF2      uint16 `json:"p_f2"`
	}
	RelTime []struct {
		Secs  int32
		Short bool
		S     string
	}
	Ftoa []struct {
		Bits  uint32
		Ftoa  string
		Ftoa3 string
	}
	Scenario []struct {
		Name string
		Log  []string
	}
	ScenarioMeta struct {
		SeedA, SeedB, SeedC, PubA, PubB, SecretAB string
	} `json:"scenario_meta"`
}

func loadGolden(t *testing.T) *golden {
	t.Helper()
	b, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return &g
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func h(b []byte) string { return ToHex(b) }

func TestGoldenKeys(t *testing.T) {
	g := loadGolden(t)
	var keys []LocalIdentity
	for i, k := range g.Keys {
		li := LocalIdentityFromSeed(unhex(t, k.Seed))
		prv := li.PrivateKey()
		if h(li.PubKey[:]) != k.Pub || h(prv[:]) != k.Prv {
			t.Errorf("key %d: got pub %s prv %s, want %s %s", i, h(li.PubKey[:]), h(prv[:]), k.Pub, k.Prv)
		}
		if ValidatePrivateKey(&prv) != k.Valid {
			t.Errorf("key %d: ValidatePrivateKey != %v", i, k.Valid)
		}
		// round trip through both persisted forms
		blob, _ := li.AppendBinary(nil)
		for _, src := range [][]byte{blob, blob[:PrvKeySize]} {
			back, err := LoadLocalIdentity(src)
			if err != nil || back != li {
				t.Errorf("key %d: LoadLocalIdentity(%d bytes) mismatch", i, len(src))
			}
		}
		keys = append(keys, li)
	}
	for i, s := range g.Signs {
		var sig [SignatureSize]byte
		msg := unhex(t, s.Msg)
		keys[s.Key].Sign(&sig, msg)
		if h(sig[:]) != s.Sig {
			t.Errorf("sign %d: got %s want %s", i, h(sig[:]), s.Sig)
		}
		if keys[s.Key].Verify(sig[:], msg) != s.OK {
			t.Errorf("sign %d: verify != %v", i, s.OK)
		}
		sig[5] ^= 1
		if keys[s.Key].Verify(sig[:], msg) != s.TamperedOK {
			t.Errorf("sign %d: tampered verify != %v", i, s.TamperedOK)
		}
	}
	for i, e := range g.ECDH {
		li, err := LoadLocalIdentity(unhex(t, e.Prv))
		if err != nil {
			t.Fatal(err)
		}
		var pub, secret [PubKeySize]byte
		copy(pub[:], unhex(t, e.Pub))
		li.SharedSecret(&secret, &pub)
		if h(secret[:]) != e.Secret {
			t.Errorf("ecdh %d (pub %s): got %s want %s", i, e.Pub, h(secret[:]), e.Secret)
		}
	}
	for i, v := range g.Validate {
		var prv [PrvKeySize]byte
		copy(prv[:], unhex(t, v.Prv))
		if ValidatePrivateKey(&prv) != v.Valid {
			t.Errorf("validate %d: != %v", i, v.Valid)
		}
	}
}

func TestGoldenCipher(t *testing.T) {
	g := loadGolden(t)
	for i, c := range g.Cipher {
		key, plain := unhex(t, c.Key), unhex(t, c.Plain)
		var enc, etm, dec [80]byte
		n := Encrypt(key, enc[:], plain)
		if h(enc[:n]) != c.Enc {
			t.Errorf("cipher %d: enc %s want %s", i, h(enc[:n]), c.Enc)
		}
		n = EncryptThenMAC(key, etm[:], plain)
		if h(etm[:n]) != c.ETM {
			t.Errorf("cipher %d: etm %s want %s", i, h(etm[:n]), c.ETM)
		}
		d := MACThenDecrypt(key, dec[:], etm[:n])
		if h(dec[:d]) != c.Dec {
			t.Errorf("cipher %d: dec %s want %s", i, h(dec[:d]), c.Dec)
		}
		etm[n-1] ^= 0x80
		if bad := MACThenDecrypt(key, dec[:], etm[:n]); bad != c.BadLen {
			t.Errorf("cipher %d: tampered dec len %d want %d", i, bad, c.BadLen)
		}
	}
	for i, s := range g.SHA {
		var h1 [32]byte
		var h2 [8]byte
		msg, frag := unhex(t, s.Msg), unhex(t, s.Frag)
		SHA256(h1[:], msg)
		SHA256(h2[:], msg, frag)
		if h(h1[:]) != s.Hash || h(h2[:]) != s.Hash2 {
			t.Errorf("sha %d: got %s %s", i, h(h1[:]), h(h2[:]))
		}
	}
}

func TestGoldenPackets(t *testing.T) {
	g := loadGolden(t)
	for i, c := range g.Packets {
		var p Packet
		ok := p.Decode(unhex(t, c.Raw))
		if ok != c.OK {
			t.Errorf("packet %d (%s): Decode = %v want %v", i, c.Raw, ok, c.OK)
			continue
		}
		if !ok {
			continue
		}
		var hash [MaxHashSize]byte
		p.CalculateHash(&hash)
		var buf [MaxTransUnit]byte
		n := p.Encode(buf[:])
		if h(hash[:]) != c.Hash || h(buf[:n]) != c.Encoded || p.RawLength() != c.RawLen {
			t.Errorf("packet %d: hash %s enc %s len %d, want %s %s %d", i, h(hash[:]), h(buf[:n]), p.RawLength(), c.Hash, c.Encoded, c.RawLen)
		}
	}
}

func TestGoldenAdverts(t *testing.T) {
	g := loadGolden(t)
	for i, c := range g.Adverts {
		a := AdvertData{Type: c.Type, Name: string(unhex(t, c.Name)), Feat1: c.F1, Feat2: c.F2}
		if c.Loc {
			a = NewAdvertDataLatLon(c.Type, a.Name, c.Lat, c.Lon)
			a.Feat1, a.Feat2 = c.F1, c.F2
		}
		var buf [MaxAdvertDataSize]byte
		n := a.Encode(&buf)
		if h(buf[:n]) != c.Enc {
			t.Errorf("advert %d: enc %s want %s", i, h(buf[:n]), c.Enc)
		}
		p := ParseAdvertData(buf[:n])
		if p.Valid != c.PValid || p.Type() != c.PType || h(p.NameBytes()) != c.PName ||
			p.Lat != c.PLat || p.Lon != c.PLon || p.Feat1 != c.PF1 || p.Feat2 != c.PF2 {
			t.Errorf("advert %d: parsed %+v name %s", i, p, h(p.NameBytes()))
		}
	}
	for _, c := range g.RelTime {
		if s := FormatRelativeTimeDiff(c.Secs, c.Short); s != c.S {
			t.Errorf("reltime %d %v: %q want %q", c.Secs, c.Short, s, c.S)
		}
	}
	for _, c := range g.Ftoa {
		f := math.Float32frombits(c.Bits)
		if s := Ftoa(f); s != c.Ftoa {
			t.Errorf("Ftoa(%g) = %q want %q", f, s, c.Ftoa)
		}
		if s := Ftoa3(f); s != c.Ftoa3 {
			t.Errorf("Ftoa3(%g) = %q want %q", f, s, c.Ftoa3)
		}
	}
}

// ------------------------------------------------------------ scenario

type xorShiftRNG struct{ s uint32 }

func (r *xorShiftRNG) Random(dst []byte) {
	for i := range dst {
		r.s ^= r.s << 13
		r.s ^= r.s >> 17
		r.s ^= r.s << 5
		dst[i] = byte(r.s)
	}
}

type fakeMillis struct{ t uint32 }

func (c *fakeMillis) Millis() uint32 { return c.t }

type fakeRTC struct{ t uint32 }

func (c *fakeRTC) CurrentTime() uint32     { return c.t }
func (c *fakeRTC) SetCurrentTime(t uint32) { c.t = t }
func (c *fakeRTC) Tick()                   {}

type scenarioLog struct{ lines []string }

func (l *scenarioLog) add(s string) { l.lines = append(l.lines, s) }

type fakeRadio struct {
	RadioBase
	tag     string
	log     *scenarioLog
	rxq     [][]byte
	peer    *fakeRadio
	sending bool
}

func (r *fakeRadio) RecvRaw(buf []byte) int {
	if len(r.rxq) == 0 {
		return 0
	}
	b := r.rxq[0]
	r.rxq = r.rxq[1:]
	return copy(buf, b)
}
func (r *fakeRadio) EstAirtimeFor(n int) uint32             { return uint32(n * 2) }
func (r *fakeRadio) PacketScore(snr float32, n int) float32 { return 0.3 }
func (r *fakeRadio) StartSendRaw(b []byte) bool {
	c := append([]byte(nil), b...)
	r.log.add(r.tag + ":TX " + h(c))
	if r.peer != nil {
		r.peer.rxq = append(r.peer.rxq, c)
	}
	r.sending = true
	return true
}
func (r *fakeRadio) IsSendComplete() bool {
	if r.sending {
		r.sending = false
		return true
	}
	return false
}
func (r *fakeRadio) OnSendFinished()    {}
func (r *fakeRadio) IsInRecvMode() bool { return !r.sending }
func (r *fakeRadio) LastRSSI() float32  { return -80 }
func (r *fakeRadio) LastSNR() float32   { return 5.25 }

type testHandler struct {
	BaseHandler
	tag      string
	log      *scenarioLog
	contacts []Identity
	channels []GroupChannel
	matches  [8]int
}

func (th *testHandler) ev(format string, args ...any) {
	th.log.add(th.tag + ":" + fmt.Sprintf(format, args...))
}

func (th *testHandler) AllowPacketForward(p *Packet) bool { return true }
func (th *testHandler) ExtraAckTransmitCount() uint8      { return 1 }

func (th *testHandler) SearchPeersByHash(hash []byte) int {
	n := 0
	for i := range th.contacts {
		if n < len(th.matches) && th.contacts[i].IsHashMatch(hash) {
			th.matches[n] = i
			n++
		}
	}
	return n
}

func (th *testHandler) PeerSharedSecret(dst *[PubKeySize]byte, idx int) {
	th.Mesh().SelfID.SharedSecret(dst, &th.contacts[th.matches[idx]].PubKey)
}

func (th *testHandler) SearchChannelsByHash(hash []byte, dst []GroupChannel) int {
	n := 0
	for _, ch := range th.channels {
		if n < len(dst) && ch.Hash[0] == hash[0] {
			dst[n] = ch
			n++
		}
	}
	return n
}

func (th *testHandler) OnPeerDataRecv(p *Packet, typ uint8, idx int, secret *[PubKeySize]byte, data []byte) {
	th.ev("PEERDATA type=%d idx=%d data=%s", typ, idx, h(data))
}

func (th *testHandler) OnTraceRecv(p *Packet, tag, auth uint32, flags uint8, snrs, hashes []byte) {
	th.ev("TRACE tag=%d auth=%d flags=%d snrs=%s hashes=%s", tag, auth, flags, h(snrs), h(hashes))
}

func (th *testHandler) OnPeerPathRecv(p *Packet, idx int, secret *[PubKeySize]byte, path []byte, pathLen uint8, extraType uint8, extra []byte) bool {
	th.ev("PATHRECV idx=%d path_len=%d path=%s extra_type=%d extra=%s", idx, pathLen, h(path), extraType, h(extra))
	return true
}

func (th *testHandler) OnAdvertRecv(p *Packet, id *Identity, ts uint32, app []byte) {
	th.ev("ADVERT pub=%s ts=%d app=%s", h(id.PubKey[:]), ts, h(app))
}

func (th *testHandler) OnAnonDataRecv(p *Packet, secret *[PubKeySize]byte, sender *Identity, data []byte) {
	th.ev("ANON sender=%s data=%s", h(sender.PubKey[:]), h(data))
}

func (th *testHandler) OnControlDataRecv(p *Packet) { th.ev("CONTROL payload=%s", h(p.PayloadBytes())) }
func (th *testHandler) OnRawDataRecv(p *Packet)     { th.ev("RAW payload=%s", h(p.PayloadBytes())) }

func (th *testHandler) OnGroupDataRecv(p *Packet, typ uint8, ch *GroupChannel, data []byte) {
	th.ev("GROUP type=%d ch=%s data=%s", typ, h(ch.Hash[:]), h(data))
}

func (th *testHandler) OnAckRecv(p *Packet, crc uint32) { th.ev("ACK crc=%08X", crc) }

type node struct {
	radio *fakeRadio
	ms    *fakeMillis
	rtc   *fakeRTC
	h     *testHandler
	mesh  *Mesh
}

func newNode(tag string, rngSeed uint32, idSeed []byte, log *scenarioLog) *node {
	n := &node{
		radio: &fakeRadio{tag: tag, log: log},
		ms:    &fakeMillis{t: 1000},
		rtc:   &fakeRTC{t: 1700000000},
		h:     &testHandler{tag: tag, log: log},
	}
	n.mesh = NewMesh(Config{
		Radio:   n.radio,
		Millis:  n.ms,
		RNG:     &xorShiftRNG{rngSeed},
		RTC:     n.rtc,
		Packets: NewStaticPoolPacketManager(16),
		Tables:  &SimpleMeshTables{},
		Handler: n.h,
	})
	n.mesh.SelfID = LocalIdentityFromSeed(idSeed)
	return n
}

func pattern(n, a, b int) []byte {
	v := make([]byte, n)
	for i := range v {
		v[i] = byte(a + i*b)
	}
	return v
}

func chatMsg(ts uint32, flags uint8, text string) []byte {
	v := binary.LittleEndian.AppendUint32(nil, ts)
	return append(append(v, flags), text...)
}

func rawOf(p *Packet) []byte {
	var buf [MaxTransUnit + 8]byte
	return append([]byte(nil), buf[:p.Encode(buf[:])]...)
}

func setFlood(p *Packet) { p.Header = p.Header&^PHRouteMask | RouteTypeFlood }

func TestGoldenScenario(t *testing.T) {
	g := loadGolden(t)
	meta := g.ScenarioMeta
	log := &scenarioLog{}

	a := newNode("A", 0x12345678, unhex(t, meta.SeedA), log)
	b := newNode("B", 0x9ABCDEF0, unhex(t, meta.SeedB), log)
	a.radio.peer, b.radio.peer = b.radio, a.radio
	a.h.contacts = []Identity{b.mesh.SelfID.Identity}
	b.h.contacts = []Identity{a.mesh.SelfID.Identity}
	var chanSecret [PubKeySize]byte
	copy(chanSecret[:], pattern(16, 0x42, 9))
	ch := GroupChannel{Secret: chanSecret}
	SHA256(ch.Hash[:], ch.Secret[:16])
	a.h.channels = []GroupChannel{ch}
	b.h.channels = []GroupChannel{ch}
	c := LocalIdentityFromSeed(unhex(t, meta.SeedC))

	if h(a.mesh.SelfID.PubKey[:]) != meta.PubA || h(b.mesh.SelfID.PubKey[:]) != meta.PubB {
		t.Fatal("scenario identities differ")
	}
	var secretAB [PubKeySize]byte
	a.mesh.SelfID.SharedSecret(&secretAB, &b.mesh.SelfID.PubKey)
	if h(secretAB[:]) != meta.SecretAB {
		t.Fatal("scenario shared secret differs")
	}
	bHash, aHash := b.mesh.SelfID.PubKey[0], a.mesh.SelfID.PubKey[0]
	am := a.mesh

	a.mesh.Begin()
	b.mesh.Begin()

	inject := func(n *node, raw []byte) {
		log.add(n.h.tag + ":INJECT " + h(raw))
		n.radio.rxq = append(n.radio.rxq, raw)
	}
	appData := func(ad AdvertData) []byte {
		var buf [MaxAdvertDataSize]byte
		return append([]byte(nil), buf[:ad.Encode(&buf)]...)
	}

	steps := []struct {
		name string
		fn   func()
	}{
		{"advert", func() {
			am.SendFlood(am.CreateAdvert(&am.SelfID, appData(NewAdvertDataLatLon(AdvTypeChat, "Alice", 46.05, 14.5))), 0, 1)
		}},
		{"advert_hash2", func() {
			a.rtc.t += 10
			am.SendFlood(am.CreateAdvert(&am.SelfID, appData(AdvertData{Type: AdvTypeRepeater, Name: "Alice2"})), 0, 2)
		}},
		{"advert_from_c", func() {
			am.SendFlood(am.CreateAdvert(&c, appData(AdvertData{Type: AdvTypeSensor, Name: "Carol"})), 100, 1)
		}},
		{"txt_flood", func() {
			am.SendFlood(am.CreateDatagram(PayloadTypeTxtMsg, &b.mesh.SelfID.Identity, secretAB[:], chatMsg(0x04030201, 0, "hello B")), 0, 1)
		}},
		{"req_zero_hop_direct", func() {
			am.SendDirect(am.CreateDatagram(PayloadTypeReq, &b.mesh.SelfID.Identity, secretAB[:], pattern(20, 1, 1)), nil, 0, 0)
		}},
		{"response_flood", func() {
			am.SendFlood(am.CreateDatagram(PayloadTypeResponse, &b.mesh.SelfID.Identity, secretAB[:], pattern(150, 9, 2)), 0, 1)
		}},
		{"anon", func() {
			am.SendFlood(am.CreateAnonDatagram(PayloadTypeAnonReq, &am.SelfID, &b.mesh.SelfID.Identity, secretAB[:], []byte("login:password")), 0, 1)
		}},
		{"group", func() {
			am.SendFlood(am.CreateGroupDatagram(PayloadTypeGrpTxt, &ch, chatMsg(0x40302010, 0, "Alice: hi all")), 0, 1)
		}},
		{"path_return_extra", func() {
			am.SendFlood(am.CreatePathReturn(&b.mesh.SelfID.Identity, secretAB[:], []byte{0x33, 0x44}, 2, 3, []byte("xyz")), 0, 1)
		}},
		{"path_return_plain", func() {
			am.SendFlood(am.CreatePathReturn(&b.mesh.SelfID.Identity, secretAB[:], []byte{0x55}, 1, 0, nil), 0, 1)
		}},
		{"ack_flood", func() { am.SendFlood(am.CreateAckCRC(0xDEADBEEF), 0, 1) }},
		{"trace", func() {
			am.SendDirect(am.CreateTrace(0x01020304, 0x0A0B0C0D, 0), []byte{bHash, aHash}, 2, 0)
		}},
		{"control_zero_hop", func() { am.SendZeroHop(am.CreateControlData([]byte{0x81, 1, 2, 3}), 0) }},
		{"raw_direct", func() { am.SendDirect(am.CreateRawData([]byte{0xCA, 0xFE, 0x00, 0x01}), nil, 0, 0) }},
		{"transport_flood", func() {
			am.SendFloodTransport(am.CreateGroupDatagram(PayloadTypeGrpTxt, &ch, chatMsg(0x41302010, 0, "Alice: transport")), [2]uint16{0x1234, 0xABCD}, 0, 1)
		}},
		{"transport_zero_hop", func() {
			am.SendZeroHopTransport(am.CreateAckCRC(0x01020304), [2]uint16{0x0102, 0x0304}, 0)
		}},
		{"multiack_direct", func() { am.SendDirect(am.CreateMultiAckCRC(0xCAFEBABE, 1), []byte{bHash}, 1, 0) }},
		{"ack_direct_hop", func() { am.SendDirect(am.CreateAckCRC(0x11223344), []byte{bHash, 0x99}, 2, 0) }},
		{"txt_direct_hop", func() {
			am.SendDirect(am.CreateDatagram(PayloadTypeTxtMsg, &b.mesh.SelfID.Identity, secretAB[:], []byte("relay me")), []byte{bHash, 0x98, 0x97}, 3, 0)
		}},
		{"dup", func() {
			p := am.CreateGroupDatagram(PayloadTypeGrpTxt, &ch, chatMsg(0x44332211, 0, "dup"))
			setFlood(p)
			p.PathLen = 0
			raw := rawOf(p)
			am.ReleasePacket(p)
			inject(b, raw)
			inject(b, raw)
		}},
		{"bad_sig_advert", func() {
			p := am.CreateAdvert(&c, appData(AdvertData{Type: AdvTypeChat, Name: "Mallory"}))
			setFlood(p)
			p.PathLen = 0
			p.Payload[40] ^= 0x01
			raw := rawOf(p)
			am.ReleasePacket(p)
			inject(b, raw)
		}},
		{"invalid", func() {
			inject(b, []byte{0x55, 0x00, 0x01, 0x02})
			inject(b, []byte{0x15, 0xC1, 0x01, 0x02, 0x03})
			inject(b, []byte{0x15})
			inject(b, []byte{0x15, 0x05, 0x01})
			inject(b, []byte{0x0D, 0x00, 0x01, 0x02})
			inject(b, []byte{0x09, 0x00, 0x00, 0x01, 0x02})
			inject(b, []byte{0x11, 0x00, 0x01})
		}},
		{"full_path_flood", func() {
			p := am.CreateGroupDatagram(PayloadTypeGrpTxt, &ch, []byte("full"))
			setFlood(p)
			p.SetPathHashSizeAndCount(1, 64)
			for i := 0; i < 64; i++ {
				p.Path[i] = byte(0x60 + i)
			}
			raw := rawOf(p)
			am.ReleasePacket(p)
			inject(b, raw)
		}},
		{"flood_hash3", func() {
			p := am.CreateGroupDatagram(PayloadTypeGrpData, &ch, []byte("three"))
			setFlood(p)
			p.SetPathHashSizeAndCount(3, 2)
			for i := 0; i < 6; i++ {
				p.Path[i] = byte(0x70 + i)
			}
			raw := rawOf(p)
			am.ReleasePacket(p)
			inject(b, raw)
		}},
		{"trace_hash2_end", func() {
			p := am.CreateTrace(77, 88, 1)
			p.PayloadLen += copy(p.Payload[p.PayloadLen:], []byte{0x01, 0x02, bHash, 0x04})
			p.Header = p.Header&^PHRouteMask | RouteTypeDirect
			p.PathLen = 2
			p.Path[0], p.Path[1] = 0x10, 0x20
			raw := rawOf(p)
			am.ReleasePacket(p)
			inject(b, raw)
		}},
		{"rtc_change_advert", func() {
			a.rtc.t = 1700000500
			am.SendFlood(am.CreateAdvert(&am.SelfID, nil), 0, 1)
		}},
	}

	if len(steps) != len(g.Scenario) {
		t.Fatalf("scenario has %d steps, golden has %d", len(steps), len(g.Scenario))
	}
	for i, st := range steps {
		want := g.Scenario[i]
		if st.name != want.Name {
			t.Fatalf("step %d: name %q, golden %q", i, st.name, want.Name)
		}
		log.lines = nil
		st.fn()
		for k := 0; k < 300; k++ {
			a.ms.t += 10
			b.ms.t += 10
			a.mesh.Loop()
			b.mesh.Loop()
		}
		got := strings.Join(log.lines, "\n")
		exp := strings.Join(want.Log, "\n")
		if got != exp {
			t.Errorf("step %q differs:\n--- got\n%s\n--- want\n%s", st.name, got, exp)
		}
	}
}
