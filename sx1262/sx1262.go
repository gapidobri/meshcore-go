//go:build tinygo

// Package sx1262 adapts the tinygo.org/x/drivers/sx126x driver to the
// non-blocking meshcore.Radio interface, configured like the C++ MeshCore
// CustomSX1262 / RadioLibWrapper.
//
// The driver's own Tx/Rx calls block and allocate, so this package drives the
// chip with its low-level commands instead. DIO1 is polled (it stays high
// while an enabled IRQ is pending), so no interrupt handler is needed.
package sx1262

import (
	"machine"
	"time"

	"tinygo.org/x/drivers"
	"tinygo.org/x/drivers/lora"
	"tinygo.org/x/drivers/sx126x"

	meshcore "github.com/gapidobri/meshcore-go"
)

// Config describes the wiring and LoRa parameters.
type Config struct {
	SPI   drivers.SPI
	NSS   machine.Pin
	Busy  machine.Pin
	DIO1  machine.Pin
	Reset machine.Pin // machine.NoPin if not connected

	FrequencyHz  uint32  // e.g. 869618000
	BandwidthKHz float32 // e.g. 62.5
	SF           uint8   // e.g. 8
	CR           uint8   // coding rate denominator 5..8 (4/5 .. 4/8)
	TxPowerDBm   int8    // -9..22

	TCXOVoltage    float32 // DIO3 TCXO supply voltage, 0 if no TCXO
	DIO2AsRFSwitch bool
	RxBoostedGain  bool
}

const (
	stateIdle   = 0
	stateRx     = 1
	stateTxWait = 3

	numNoiseFloorSamples = 64
	samplingThreshold    = 14

	irqDIO1 = sx126x.SX126X_IRQ_RX_DONE | sx126x.SX126X_IRQ_TX_DONE |
		sx126x.SX126X_IRQ_TIMEOUT | sx126x.SX126X_IRQ_CRC_ERR | sx126x.SX126X_IRQ_HEADER_ERR
	irqAll = irqDIO1 | sx126x.SX126X_IRQ_PREAMBLE_DETECTED | sx126x.SX126X_IRQ_HEADER_VALID |
		sx126x.SX126X_IRQ_SYNC_WORD_VALID
	irqActivity = sx126x.SX126X_IRQ_PREAMBLE_DETECTED | sx126x.SX126X_IRQ_HEADER_VALID |
		sx126x.SX126X_IRQ_HEADER_ERR | sx126x.SX126X_IRQ_SYNC_WORD_VALID
)

// Radio is a meshcore.Radio backed by an SX1262.
type Radio struct {
	cfg    Config
	dev    *sx126x.Device
	ctl    controller
	params meshcore.LoRaParams
	start  time.Time

	state      uint8
	lastRSSI   float32
	lastSNR    float32
	nRecv      uint32
	nSent      uint32
	nRecvErrs  uint32
	noiseFloor int16
	threshold  int16
	nSamples   uint16
	sampleSum  int32

	activityAt       uint32
	headerSeen       bool
	preambleMillis   uint32
	maxPayloadMillis uint32

	hdr [3]byte
	buf [meshcore.MaxTransUnit + 1]byte
}

// New returns a Radio; call meshcore.Mesh.Begin (which calls Begin) to
// initialise the chip.
func New(cfg Config) *Radio {
	r := &Radio{cfg: cfg, start: time.Now()}
	r.ctl = controller{nss: cfg.NSS, busy: cfg.Busy, dio1: cfg.DIO1}
	r.params = meshcore.LoRaParams{
		SF:           cfg.SF,
		BandwidthKHz: cfg.BandwidthKHz,
		CR:           cfg.CR,
		Preamble:     meshcore.PreambleLengthForSF(cfg.SF),
		CRC:          true,
	}
	r.params.LDRO = r.params.AutoLDRO()
	r.preambleMillis, r.maxPayloadMillis = r.calcMaxPacketMillis()
	return r
}

func (r *Radio) millis() uint32 { return uint32(time.Since(r.start).Milliseconds()) }

// Params returns the LoRa modulation in use.
func (r *Radio) Params() meshcore.LoRaParams { return r.params }

func bandwidthCode(khz float32) uint8 {
	switch {
	case khz < 9:
		return sx126x.SX126X_LORA_BW_7_8
	case khz < 13:
		return sx126x.SX126X_LORA_BW_10_4
	case khz < 18:
		return sx126x.SX126X_LORA_BW_15_6
	case khz < 26:
		return sx126x.SX126X_LORA_BW_20_8
	case khz < 36:
		return sx126x.SX126X_LORA_BW_31_25
	case khz < 52:
		return sx126x.SX126X_LORA_BW_41_7
	case khz < 93:
		return sx126x.SX126X_LORA_BW_62_5
	case khz < 187:
		return sx126x.SX126X_LORA_BW_125_0
	case khz < 375:
		return sx126x.SX126X_LORA_BW_250_0
	}
	return sx126x.SX126X_LORA_BW_500_0
}

func tcxoCode(v float32) uint8 {
	switch {
	case v < 1.65:
		return sx126x.SX126X_DIO3_OUTPUT_1_6
	case v < 1.75:
		return sx126x.SX126X_DIO3_OUTPUT_1_7
	case v < 2.0:
		return sx126x.SX126X_DIO3_OUTPUT_1_8
	case v < 2.3:
		return sx126x.SX126X_DIO3_OUTPUT_2_2
	case v < 2.55:
		return sx126x.SX126X_DIO3_OUTPUT_2_4
	case v < 2.85:
		return sx126x.SX126X_DIO3_OUTPUT_2_7
	case v < 3.15:
		return sx126x.SX126X_DIO3_OUTPUT_3_0
	}
	return sx126x.SX126X_DIO3_OUTPUT_3_3
}

// Begin initialises the chip and starts receiving.
func (r *Radio) Begin() {
	if r.cfg.Reset != machine.NoPin {
		r.cfg.Reset.Configure(machine.PinConfig{Mode: machine.PinOutput})
		r.cfg.Reset.Low()
		time.Sleep(10 * time.Millisecond)
		r.cfg.Reset.High()
		time.Sleep(10 * time.Millisecond)
	}

	r.dev = sx126x.New(r.cfg.SPI)
	r.dev.SetDeviceType(sx126x.DEVICE_TYPE_SX1262)
	r.dev.SetRadioController(&r.ctl)

	d := r.dev
	d.SetStandby()
	if r.cfg.TCXOVoltage > 0 {
		// 5ms startup delay, in 15.625us steps
		const delay = 320
		d.ExecSetCommand(sx126x.SX126X_CMD_SET_DIO3_AS_TCXO_CTRL, []uint8{tcxoCode(r.cfg.TCXOVoltage), 0, delay >> 8, delay & 0xFF})
	}
	d.Calibrate(sx126x.SX126X_CALIBRATE_ALL)
	time.Sleep(5 * time.Millisecond)
	d.SetRegulatorMode(sx126x.SX126X_REGULATOR_DC_DC)
	if r.cfg.DIO2AsRFSwitch {
		d.ExecSetCommand(sx126x.SX126X_CMD_SET_DIO2_AS_RF_SWITCH_CTRL, []uint8{sx126x.SX126X_DIO2_AS_RF_SWITCH})
	}
	d.SetPacketType(sx126x.SX126X_PACKET_TYPE_LORA)
	d.SetRfFrequency(r.cfg.FrequencyHz)
	d.CalibrateImage(r.cfg.FrequencyHz)

	var ldro uint8
	if r.params.LDRO {
		ldro = 1
	}
	d.SetModulationParams(r.cfg.SF, bandwidthCode(r.cfg.BandwidthKHz), r.cfg.CR-4, ldro)
	d.SetPacketParam(r.params.Preamble, lora.HeaderExplicit, lora.CRCOn, 0xFF, lora.IQStandard)
	d.SetTxParams(r.cfg.TxPowerDBm, sx126x.SX126X_PA_RAMP_200U) // also sets PA config and 140mA OCP
	d.SetSyncWord(sx126x.SX126X_LORA_MAC_PRIVATE_SYNCWORD)      // RadioLib private sync word 0x12
	if r.cfg.RxBoostedGain {
		d.WriteRegister(sx126x.SX126X_REG_RX_GAIN, []uint8{0x96})
	}
	d.SetBufferBaseAddress(0, 0)
	d.SetDioIrqParams(irqAll, irqDIO1, 0, 0)

	r.state = stateIdle
	r.noiseFloor, r.threshold = 0, 0
	r.nSamples, r.sampleSum = 0, 0
}

func (r *Radio) startRecv() {
	r.dev.SetPacketParam(r.params.Preamble, lora.HeaderExplicit, lora.CRCOn, 0xFF, lora.IQStandard)
	r.dev.ClearIrqStatus(sx126x.SX126X_IRQ_ALL)
	r.dev.SetRx(0xFFFFFF) // continuous
	r.state = stateRx
}

func (r *Radio) idle() {
	r.dev.SetStandby()
	r.state = stateIdle // need another startRecv()
}

func (r *Radio) RecvRaw(buf []byte) int {
	n := 0
	if r.state == stateRx && r.cfg.DIO1.Get() {
		st := r.dev.GetIrqStatus()
		if st&sx126x.SX126X_IRQ_RX_DONE != 0 && st&(sx126x.SX126X_IRQ_CRC_ERR|sx126x.SX126X_IRQ_HEADER_ERR) == 0 {
			length, start := r.dev.GetRxBufferStatus()
			n = int(length)
			if n > len(buf) {
				n = len(buf)
			}
			r.readBuffer(start, buf[:n])
			ps := r.dev.ExecGetCommand(sx126x.SX126X_CMD_GET_PACKET_STATUS, 3)
			r.lastRSSI = -float32(ps[0]) / 2
			r.lastSNR = float32(int8(ps[1])) / 4
			r.nRecv++
		} else if st&irqDIO1 != 0 {
			r.nRecvErrs++
		}
		r.state = stateIdle // need another startRecv()
	}
	if r.state != stateRx {
		r.startRecv()
	}
	return n
}

// readBuffer reads the chip's data buffer without allocating.
func (r *Radio) readBuffer(offset uint8, dst []byte) {
	r.ctl.WaitWhileBusy()
	r.ctl.SetNss(false)
	r.hdr = [3]byte{sx126x.SX126X_CMD_READ_BUFFER, offset, 0}
	r.cfg.SPI.Tx(r.hdr[:], nil)
	r.cfg.SPI.Tx(nil, dst)
	r.ctl.SetNss(true)
	r.ctl.WaitWhileBusy()
}

// writeBuffer writes the chip's data buffer at offset 0 without allocating.
func (r *Radio) writeBuffer(src []byte) {
	r.ctl.WaitWhileBusy()
	r.ctl.SetNss(false)
	r.hdr = [3]byte{sx126x.SX126X_CMD_WRITE_BUFFER, 0}
	r.cfg.SPI.Tx(r.hdr[:2], nil)
	r.cfg.SPI.Tx(src, nil)
	r.ctl.SetNss(true)
	r.ctl.WaitWhileBusy()
}

func (r *Radio) EstAirtimeFor(n int) uint32 { return r.params.TimeOnAirMicros(n) / 1000 }

func (r *Radio) PacketScore(snr float32, n int) float32 { return meshcore.PacketScore(snr, n) }

func (r *Radio) StartSendRaw(b []byte) bool {
	r.dev.SetStandby()
	r.dev.SetPacketParam(r.params.Preamble, lora.HeaderExplicit, lora.CRCOn, uint8(len(b)), lora.IQStandard)
	r.writeBuffer(b)
	r.dev.ClearIrqStatus(sx126x.SX126X_IRQ_ALL)
	r.dev.SetTx(0) // no timeout; the dispatcher times out on its own
	r.state = stateTxWait
	return true
}

func (r *Radio) IsSendComplete() bool {
	if r.state != stateTxWait || !r.cfg.DIO1.Get() {
		return false
	}
	if r.dev.GetIrqStatus()&sx126x.SX126X_IRQ_TX_DONE == 0 {
		return false
	}
	r.state = stateIdle
	r.nSent++
	return true
}

func (r *Radio) OnSendFinished() {
	r.dev.ClearIrqStatus(sx126x.SX126X_IRQ_ALL)
	r.idle()
}

func (r *Radio) IsInRecvMode() bool { return r.state == stateRx }

func (r *Radio) currentRSSI() int {
	return -int(r.dev.ExecGetCommand(sx126x.SX126X_CMD_GET_RSSI_INST, 1)[0]) / 2
}

// isReceivingPacket mirrors CustomSX1262::isReceiving(): preamble/header
// detection, with timeouts so stale flags do not block transmit forever.
func (r *Radio) isReceivingPacket() bool {
	if r.state != stateRx {
		return false
	}
	irq := r.dev.GetIrqStatus()
	preamble := irq&sx126x.SX126X_IRQ_PREAMBLE_DETECTED != 0
	header := irq&sx126x.SX126X_IRQ_HEADER_VALID != 0
	now := r.millis()
	if irq&sx126x.SX126X_IRQ_HEADER_ERR != 0 {
		r.dev.ClearIrqStatus(irqActivity)
		r.activityAt, r.headerSeen = 0, false
		return false
	}
	if !header && r.headerSeen {
		// something cleared the header flag, reset our state
		r.activityAt, r.headerSeen = 0, false
		return false
	}
	if header {
		if !r.headerSeen {
			r.headerSeen, r.activityAt = true, now
		}
		if now-r.activityAt > r.maxPayloadMillis {
			r.dev.ClearIrqStatus(irqActivity)
			r.activityAt, r.headerSeen = 0, false
			return false
		}
		return true
	}
	if preamble {
		if r.activityAt == 0 {
			r.activityAt = now
		}
		if now-r.activityAt > r.preambleMillis {
			r.dev.ClearIrqStatus(sx126x.SX126X_IRQ_PREAMBLE_DETECTED)
			r.activityAt = 0
			return false
		}
		return true
	}
	r.activityAt, r.headerSeen = 0, false
	return false
}

// IsReceiving reports a packet being received, or RSSI-based interference
// above the noise floor + threshold. Hardware CAD is not supported.
func (r *Radio) IsReceiving() bool {
	if r.isReceivingPacket() {
		return true
	}
	return r.threshold != 0 && r.state == stateRx && r.currentRSSI() > int(r.noiseFloor)+int(r.threshold)
}

func (r *Radio) calcMaxPacketMillis() (preambleMs, payloadMs uint32) {
	// based on RadioLib's calculateTimeOnAir(), as in RadioLibWrapper
	sf := uint32(r.params.SF)
	tsymUs := (uint32(10000) << sf) / uint32(r.params.BandwidthKHz*10)
	sfCoeff1x4 := uint32(17)
	if sf == 5 || sf == 6 {
		sfCoeff1x4 = 25
	}
	preambleUs := ((uint32(r.params.Preamble)+8)*4 + sfCoeff1x4) * tsymUs / 4
	totalUs := r.params.TimeOnAirMicros(meshcore.MaxTransUnit)
	var payloadUs uint32
	if totalUs > preambleUs {
		payloadUs = totalUs - preambleUs
	} else {
		payloadUs = 4000 - preambleUs
	}
	if cr := uint32(r.params.CR); cr >= 5 && cr < 8 {
		payloadUs = payloadUs * 8 / cr
	}
	return (preambleUs + 999) / 1000, (payloadUs + 999) / 1000
}

func (r *Radio) Loop() {
	if r.state == stateRx && r.nSamples < numNoiseFloorSamples {
		if !r.isReceivingPacket() {
			rssi := r.currentRSSI()
			if rssi < int(r.noiseFloor)+samplingThreshold {
				r.nSamples++
				r.sampleSum += int32(rssi)
			}
		}
	} else if r.nSamples >= numNoiseFloorSamples && r.sampleSum != 0 {
		r.noiseFloor = int16(r.sampleSum / numNoiseFloorSamples)
		if r.noiseFloor < -120 {
			r.noiseFloor = -120 // clamp to lower bound of -120dBi
		}
		r.sampleSum = 0
	}
}

func (r *Radio) NoiseFloor() int { return int(r.noiseFloor) }

func (r *Radio) TriggerNoiseFloorCalibrate(threshold int) {
	r.threshold = int16(threshold)
	if r.nSamples >= numNoiseFloorSamples { // ignore trigger if currently sampling
		r.nSamples, r.sampleSum = 0, 0
	}
}

func (r *Radio) SetCADEnabled(bool) {}

func (r *Radio) ResetAGC() {
	// make sure we're not mid-receive of packet!
	if r.cfg.DIO1.Get() || r.isReceivingPacket() {
		return
	}
	r.dev.SetSleep() // warm sleep to reset analog frontend
	r.state = stateIdle
	r.noiseFloor, r.nSamples, r.sampleSum = 0, 0, 0
}

func (r *Radio) LastRSSI() float32 { return r.lastRSSI }
func (r *Radio) LastSNR() float32  { return r.lastSNR }

// Stats returns packets received, receive errors, and packets sent.
func (r *Radio) Stats() (recv, recvErrs, sent uint32) { return r.nRecv, r.nRecvErrs, r.nSent }

// Random returns radio-noise entropy (slow; use for seeding only).
func (r *Radio) Random(dst []byte) {
	for i := range dst {
		var b byte
		for bit := 0; bit < 8; bit++ {
			b = b<<1 | byte(r.currentRSSI()&1)
		}
		dst[i] = b
	}
}

// controller implements sx126x.RadioController for directly wired pins.
// The RF switch is driven by DIO2 (if configured) and DIO1 is polled, so no
// interrupt is installed.
type controller struct {
	nss, busy, dio1 machine.Pin
}

func (c *controller) Init() error {
	c.nss.Configure(machine.PinConfig{Mode: machine.PinOutput})
	c.nss.High()
	c.busy.Configure(machine.PinConfig{Mode: machine.PinInput})
	c.dio1.Configure(machine.PinConfig{Mode: machine.PinInputPulldown})
	return nil
}

func (c *controller) SetRfSwitchMode(mode int) error { return nil }

func (c *controller) SetNss(state bool) error {
	c.nss.Set(state)
	return nil
}

func (c *controller) WaitWhileBusy() error {
	deadline := time.Now().Add(100 * time.Millisecond)
	for c.busy.Get() {
		if time.Now().After(deadline) {
			return errBusyTimeout
		}
	}
	return nil
}

func (c *controller) SetupInterrupts(handler func()) error { return nil }

type busyTimeout struct{}

func (busyTimeout) Error() string { return "sx1262: busy timeout" }

var errBusyTimeout error = busyTimeout{}
