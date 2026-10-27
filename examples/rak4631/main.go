//go:build tinygo

// Command rak4631 is a minimal MeshCore node for the RAKwireless RAK4631
// WisBlock core (RAK4630 module: nRF52840 + SX1262). It forwards flood and
// direct traffic like a repeater, logs adverts it hears to the USB serial
// console, and advertises itself.
//
// Build and flash (double-tap reset to enter the UF2 bootloader first):
//
//	tinygo flash -target rak4631 ./examples/rak4631
//
// The identity is regenerated on every boot; persist it with
// LocalIdentity.AppendBinary / meshcore.LoadLocalIdentity for real use.
package main

import (
	"machine"
	"time"

	meshcore "github.com/gapidobri/meshcore-go"
	"github.com/gapidobri/meshcore-go/sx1262"
)

// RAK4630 SX1262 wiring (variants/rak4631 in the C++ repo), as named by
// TinyGo's rak4631 board.
const (
	pinLoRaSCK   = machine.LORA_SCK
	pinLoRaMISO  = machine.LORA_MISO
	pinLoRaMOSI  = machine.LORA_MOSI
	pinLoRaNSS   = machine.LORA_NSS
	pinLoRaRST   = machine.LORA_NRESET
	pinLoRaBusy  = machine.LORA_BUSY
	pinLoRaDIO1  = machine.LORA_DIO1
	pinLoRaPower = machine.LORA_POWER // SX126X_POWER_EN
	pinTxLED     = machine.LED1       // green
)

const (
	nodeName       = "TinyGo RAK4631"
	advertInterval = 12 * time.Hour
)

// hwRNG uses the nRF52840 true random number generator.
type hwRNG struct{}

func (hwRNG) Random(dst []byte) {
	for i := 0; i < len(dst); i += 4 {
		v, _ := machine.GetRNG()
		for j := 0; j < 4 && i+j < len(dst); j++ {
			dst[i+j] = byte(v >> (8 * j))
		}
	}
}

type node struct {
	meshcore.BaseHandler
}

func (n *node) AllowPacketForward(p *meshcore.Packet) bool { return true }

func (n *node) OnAdvertRecv(p *meshcore.Packet, id *meshcore.Identity, ts uint32, appData []byte) {
	ad := meshcore.ParseAdvertData(appData)
	println("advert", id.String()[:16], "name:", ad.Name(), "type:", ad.Type(), "snr:", int(p.SNR()), "hops:", p.PathHashCount())
}

func main() {
	time.Sleep(2 * time.Second) // give the USB console time to attach

	pinTxLED.Configure(machine.PinConfig{Mode: machine.PinOutput})

	// the SX1262 supply is switched on the RAK4630
	pinLoRaPower.Configure(machine.PinConfig{Mode: machine.PinOutput})
	pinLoRaPower.High()
	time.Sleep(10 * time.Millisecond)

	// SPIM2 is not shared with a TWI peripheral, so I2C stays free for sensors
	spi := machine.SPI2
	if err := spi.Configure(machine.SPIConfig{
		Frequency: 8_000_000,
		SCK:       pinLoRaSCK,
		SDO:       pinLoRaMOSI,
		SDI:       pinLoRaMISO,
	}); err != nil {
		println("spi:", err.Error())
	}

	radio := sx1262.New(sx1262.Config{
		SPI:            spi,
		NSS:            pinLoRaNSS,
		Busy:           pinLoRaBusy,
		DIO1:           pinLoRaDIO1,
		Reset:          pinLoRaRST,
		FrequencyHz:    869_618_000, // EU/UK narrow preset
		BandwidthKHz:   62.5,
		SF:             8,
		CR:             5,
		TxPowerDBm:     22,
		TCXOVoltage:    1.8,
		DIO2AsRFSwitch: true,
		RxBoostedGain:  true,
	})

	ms := meshcore.NewSystemMillis()
	rtc := meshcore.NewVolatileRTCClock(ms)
	h := &node{}
	mesh := meshcore.NewMesh(meshcore.Config{
		Radio:   radio,
		Millis:  ms,
		RNG:     hwRNG{},
		RTC:     rtc,
		Packets: meshcore.NewStaticPoolPacketManager(16),
		Tables:  &meshcore.SimpleMeshTables{},
		Handler: h,
	})
	mesh.SelfID = meshcore.NewLocalIdentity(hwRNG{})
	println("meshcore node", mesh.SelfID.String())

	mesh.Begin()

	ad := meshcore.AdvertData{Type: meshcore.AdvTypeRepeater, Name: nodeName}
	var appData [meshcore.MaxAdvertDataSize]byte
	n := ad.Encode(&appData)
	sendAdvert := func() {
		if p := mesh.CreateAdvert(&mesh.SelfID, appData[:n]); p != nil {
			mesh.SendFlood(p, 0, 1)
		}
	}
	sendAdvert()
	nextAdvert := time.Now().Add(advertInterval)

	for {
		mesh.Loop()
		rtc.Tick()
		pinTxLED.Set(!radio.IsInRecvMode())
		if time.Now().After(nextAdvert) {
			sendAdvert()
			nextAdvert = time.Now().Add(advertInterval)
		}
		time.Sleep(time.Millisecond)
	}
}
