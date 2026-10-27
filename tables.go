package meshcore

import "encoding/binary"

// MeshTables is an abstraction of the data tables the mesh maintains.
type MeshTables interface {
	WasSeen(p *Packet) bool
	MarkSeen(p *Packet)
	Clear(p *Packet) // remove this packet hash from table
}

// MaxPacketHashes is the number of recent packet hashes SimpleMeshTables
// remembers.
const MaxPacketHashes = 128 + 32

// SimpleMeshTables is a MeshTables backed by a ring buffer of packet hashes.
type SimpleMeshTables struct {
	hashes     [MaxPacketHashes][MaxHashSize]byte
	nextIdx    int
	directDups uint32
	floodDups  uint32
}

func (t *SimpleMeshTables) WasSeen(p *Packet) bool {
	var h [MaxHashSize]byte
	p.CalculateHash(&h)
	for i := range t.hashes {
		if t.hashes[i] == h {
			if p.IsRouteDirect() {
				t.directDups++
			} else {
				t.floodDups++
			}
			return true
		}
	}
	return false
}

func (t *SimpleMeshTables) MarkSeen(p *Packet) {
	p.CalculateHash(&t.hashes[t.nextIdx])
	t.nextIdx = (t.nextIdx + 1) % MaxPacketHashes
}

func (t *SimpleMeshTables) Clear(p *Packet) {
	var h [MaxHashSize]byte
	p.CalculateHash(&h)
	for i := range t.hashes {
		if t.hashes[i] == h {
			t.hashes[i] = [MaxHashSize]byte{}
			break
		}
	}
}

func (t *SimpleMeshTables) NumDirectDups() uint32 { return t.directDups }
func (t *SimpleMeshTables) NumFloodDups() uint32  { return t.floodDups }
func (t *SimpleMeshTables) ResetStats()           { t.directDups, t.floodDups = 0, 0 }

// SimpleMeshTablesStateSize is the length of the blob from AppendState.
const SimpleMeshTablesStateSize = MaxPacketHashes*MaxHashSize + 4

// AppendState appends the table state (hashes followed by the little-endian
// int32 next index, the same layout as the C++ saveTo) to dst.
func (t *SimpleMeshTables) AppendState(dst []byte) []byte {
	for i := range t.hashes {
		dst = append(dst, t.hashes[i][:]...)
	}
	return binary.LittleEndian.AppendUint32(dst, uint32(t.nextIdx))
}

// RestoreState loads state produced by AppendState.
func (t *SimpleMeshTables) RestoreState(src []byte) bool {
	if len(src) < SimpleMeshTablesStateSize {
		return false
	}
	for i := range t.hashes {
		copy(t.hashes[i][:], src[i*MaxHashSize:])
	}
	idx := int(binary.LittleEndian.Uint32(src[MaxPacketHashes*MaxHashSize:]))
	if idx < 0 || idx >= MaxPacketHashes {
		idx = 0
	}
	t.nextIdx = idx
	return true
}
