//go:build tinygo

// Command t3s3 is a minimal MeshCore node for the LilyGo T3S3 (ESP32-S3 +
// SX1262). It forwards flood and direct traffic like a repeater, logs
// adverts it hears to the serial console, and advertises itself.
//
// Build and flash:
//
//	tinygo flash -target esp32s3-generic ./examples/t3s3
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

// LilyGo T3S3 SX1262 wiring (variants/lilygo_t3s3 in the C++ repo).
const (
	pinLoRaSCK  = machine.GPIO5
	pinLoRaMISO = machine.GPIO3
	pinLoRaMOSI = machine.GPIO6
	pinLoRaNSS  = machine.GPIO7
	pinLoRaRST  = machine.GPIO8
	pinLoRaBusy = machine.GPIO34
	pinLoRaDIO1 = machine.GPIO33
	pinTxLED    = machine.GPIO37
)

const (
	nodeName       = "TinyGo T3S3"
	advertInterval = 12 * time.Hour
)

// hwRNG uses the ESP32-S3 true random number generator.
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

	spi := machine.SPI0
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
