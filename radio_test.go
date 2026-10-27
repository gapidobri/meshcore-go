package meshcore

import "testing"

func TestTimeOnAir(t *testing.T) {
	// MeshCore EU narrow preset: SF8, 62.5kHz, CR 4/5, 32 symbol preamble.
	lp := LoRaParams{SF: 8, BandwidthKHz: 62.5, CR: 5, Preamble: PreambleLengthForSF(8), CRC: true}
	lp.LDRO = lp.AutoLDRO()
	if lp.LDRO {
		t.Fatal("LDRO should be off at SF8/62.5kHz")
	}
	// symbol = 4096us; payload symbols = ceil((8*255+16-32+8+20)/32)*5 = 325
	// total = (32+8+4.25+325) symbols
	if got, want := lp.TimeOnAirMicros(MaxTransUnit), uint32(4096*1477/4); got != want {
		t.Errorf("TimeOnAirMicros(255) = %d, want %d", got, want)
	}

	slow := LoRaParams{SF: 12, BandwidthKHz: 125, CR: 5}
	if !slow.AutoLDRO() {
		t.Error("LDRO should be on at SF12/125kHz")
	}
}
