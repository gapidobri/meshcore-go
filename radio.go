package meshcore

// Radio is an abstraction of this device's packet radio. Embed RadioBase to
// get no-op defaults for the optional methods.
type Radio interface {
	Begin()

	// RecvRaw polls for an incoming raw packet, storing it in buf. It returns
	// 0 if there is no incoming data, otherwise the length of the packet.
	RecvRaw(buf []byte) int

	// EstAirtimeFor returns the estimated transmit air-time for a packet of
	// lenBytes, in milliseconds.
	EstAirtimeFor(lenBytes int) uint32

	PacketScore(snr float32, packetLen int) float32

	// StartSendRaw starts sending a raw packet without waiting, returning
	// true if successfully started.
	StartSendRaw(b []byte) bool

	// IsSendComplete reports whether the previous StartSendRaw completed.
	IsSendComplete() bool

	// OnSendFinished is a hook for clean up after transmit.
	OnSendFinished()

	// Loop does any processing needed on each loop cycle.
	Loop()

	NoiseFloor() int
	TriggerNoiseFloorCalibrate(threshold int)
	SetCADEnabled(enable bool)
	ResetAGC()

	IsInRecvMode() bool

	// IsReceiving reports whether the radio is currently mid-receive of a
	// packet (or otherwise detects channel activity).
	IsReceiving() bool

	LastRSSI() float32
	LastSNR() float32
}

// RadioBase provides default implementations of the optional Radio methods.
type RadioBase struct{}

func (RadioBase) Begin()                         {}
func (RadioBase) Loop()                          {}
func (RadioBase) NoiseFloor() int                { return 0 }
func (RadioBase) TriggerNoiseFloorCalibrate(int) {}
func (RadioBase) SetCADEnabled(bool)             {}
func (RadioBase) ResetAGC()                      {}
func (RadioBase) IsReceiving() bool              { return false }
func (RadioBase) LastRSSI() float32              { return 0 }
func (RadioBase) LastSNR() float32               { return 0 }

// LoRaParams describes a LoRa modulation, for air-time estimates.
type LoRaParams struct {
	SF             uint8   // spreading factor, 5..12
	BandwidthKHz   float32 // e.g. 62.5
	CR             uint8   // coding rate denominator, 5..8 (4/5 .. 4/8)
	Preamble       uint16  // preamble length in symbols
	CRC            bool
	ImplicitHeader bool
	LDRO           bool // low data rate optimisation
}

// AutoLDRO reports whether low data rate optimisation should be on (symbol
// time of 16ms or more), as RadioLib decides automatically.
func (lp *LoRaParams) AutoLDRO() bool {
	return float32(uint32(1)<<lp.SF)/lp.BandwidthKHz >= 16.0
}

// TimeOnAirMicros returns the on-air time of a packet of length n in
// microseconds, using RadioLib's SX126x formula.
func (lp *LoRaParams) TimeOnAirMicros(n int) uint32 {
	sf := uint32(lp.SF)
	symbolUs := (uint32(1000*10) << sf) / uint32(lp.BandwidthKHz*10)
	sfCoeff1x4 := int32(17) // 4.25 * 4
	sfCoeff2 := int32(8)
	if sf == 5 || sf == 6 {
		sfCoeff1x4 = 25 // 6.25 * 4
		sfCoeff2 = 0
	}
	sfDivisor := int32(4 * sf)
	if lp.LDRO {
		sfDivisor = int32(4 * (sf - 2))
	}
	crc := int32(0)
	if lp.CRC {
		crc = 16
	}
	header := int32(20)
	if lp.ImplicitHeader {
		header = 0
	}
	bitCount := int32(8*n) + crc - int32(4*sf) + sfCoeff2 + header
	if bitCount < 0 {
		bitCount = 0
	}
	preCoded := uint32((bitCount + sfDivisor - 1) / sfDivisor)
	nSymbolx4 := (uint32(lp.Preamble)+8)*4 + uint32(sfCoeff1x4) + preCoded*uint32(lp.CR)*4
	return symbolUs * nSymbolx4 / 4
}

// PreambleLengthForSF returns the preamble length MeshCore uses for an SF
// (longer preamble for lower SF improves reliability).
func PreambleLengthForSF(sf uint8) uint16 {
	if sf <= 8 {
		return 32
	}
	return 16
}

// Approximate SNR threshold per SF for successful reception (based on
// Semtech datasheets), SF7..SF12.
var snrThreshold = [...]float32{-7.5, -10, -12.5, -15, -17.5, -20}

// PacketScoreSF returns a 0..1 score of a received packet's quality.
func PacketScoreSF(snr float32, sf int, packetLen int) float32 {
	if sf < 7 || sf > 12 {
		return 0
	}
	th := snrThreshold[sf-7]
	if snr < th {
		return 0 // below threshold, no chance of success
	}
	successRate := float64(snr-th) / 10.0
	collisionPenalty := 1 - float64(packetLen)/256.0 // assuming max packet of 256 bytes
	v := successRate * collisionPenalty
	if v > 1 {
		v = 1
	}
	if v < 0 {
		v = 0
	}
	return float32(v)
}

// PacketScore is the score function used by the stock radio wrappers, which
// assume SF10.
func PacketScore(snr float32, packetLen int) float32 { return PacketScoreSF(snr, 10, packetLen) }
