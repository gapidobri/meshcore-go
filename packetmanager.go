package meshcore

// PacketManager manages Packet instances (e.g. in a static pool) and the
// outbound and delayed inbound packet queues.
type PacketManager interface {
	AllocNew() *Packet
	Free(p *Packet)

	QueueOutbound(p *Packet, priority uint8, scheduledFor uint32)
	NextOutbound(now uint32) *Packet // by priority
	OutboundCount(now uint32) int
	OutboundTotal() int
	FreeCount() int
	OutboundByIdx(i int) *Packet
	RemoveOutboundByIdx(i int) *Packet
	QueueInbound(p *Packet, scheduledFor uint32)
	NextInbound(now uint32) *Packet
}

// CountAll may be passed to OutboundCount to count entries regardless of
// their schedule.
const CountAll = 0xFFFFFFFF

// PacketQueue is a fixed-capacity priority queue of packets.
type PacketQueue struct {
	table    []*Packet
	pri      []uint8
	schedule []uint32
	num      int
}

// NewPacketQueue returns a queue that holds up to maxEntries packets.
func NewPacketQueue(maxEntries int) *PacketQueue {
	return &PacketQueue{
		table:    make([]*Packet, maxEntries),
		pri:      make([]uint8, maxEntries),
		schedule: make([]uint32, maxEntries),
	}
}

func (q *PacketQueue) Count() int { return q.num }

// CountBefore returns the number of entries scheduled at or before now.
func (q *PacketQueue) CountBefore(now uint32) int {
	if now == CountAll {
		return q.num // sentinel: count all entries regardless of schedule
	}
	n := 0
	for j := 0; j < q.num; j++ {
		if int32(q.schedule[j]-now) > 0 {
			continue // scheduled for future... ignore for now
		}
		n++
	}
	return n
}

// Get removes and returns the most important (lowest priority value) entry
// whose schedule has passed, or nil.
func (q *PacketQueue) Get(now uint32) *Packet {
	minPri := uint8(0xFF)
	best := -1
	for j := 0; j < q.num; j++ {
		if int32(q.schedule[j]-now) > 0 {
			continue // scheduled for future... ignore for now
		}
		if q.pri[j] < minPri { // select most important priority amongst non-future entries
			minPri = q.pri[j]
			best = j
		}
	}
	if best < 0 {
		return nil // empty, or all items are still in the future
	}
	return q.RemoveByIdx(best)
}

func (q *PacketQueue) ItemAt(i int) *Packet {
	if i < 0 || i >= q.num {
		return nil
	}
	return q.table[i]
}

func (q *PacketQueue) RemoveByIdx(i int) *Packet {
	if i < 0 || i >= q.num {
		return nil // invalid index
	}
	item := q.table[i]
	q.num--
	copy(q.table[i:q.num], q.table[i+1:q.num+1])
	copy(q.pri[i:q.num], q.pri[i+1:q.num+1])
	copy(q.schedule[i:q.num], q.schedule[i+1:q.num+1])
	q.table[q.num] = nil
	return item
}

func (q *PacketQueue) Add(p *Packet, priority uint8, scheduledFor uint32) bool {
	if q.num == len(q.table) {
		return false
	}
	q.table[q.num] = p
	q.pri[q.num] = priority
	q.schedule[q.num] = scheduledFor
	q.num++
	return true
}

// StaticPoolPacketManager is a PacketManager backed by a fixed pool of
// packets allocated up front.
type StaticPoolPacketManager struct {
	unused, sendQueue, rxQueue *PacketQueue
}

// NewStaticPoolPacketManager allocates a pool of poolSize packets.
func NewStaticPoolPacketManager(poolSize int) *StaticPoolPacketManager {
	m := &StaticPoolPacketManager{
		unused:    NewPacketQueue(poolSize),
		sendQueue: NewPacketQueue(poolSize),
		rxQueue:   NewPacketQueue(poolSize),
	}
	pool := make([]Packet, poolSize)
	for i := range pool {
		m.unused.Add(&pool[i], 0, 0)
	}
	return m
}

func (m *StaticPoolPacketManager) AllocNew() *Packet {
	return m.unused.RemoveByIdx(0) // just get first one (nil if empty)
}

func (m *StaticPoolPacketManager) Free(p *Packet) {
	if p == nil {
		return
	}
	m.unused.Add(p, 0, 0) // fails only on a double-free
}

func (m *StaticPoolPacketManager) QueueOutbound(p *Packet, priority uint8, scheduledFor uint32) {
	if p == nil {
		return
	}
	if !m.sendQueue.Add(p, priority, scheduledFor) {
		m.Free(p) // send queue full, dropping packet
	}
}

func (m *StaticPoolPacketManager) NextOutbound(now uint32) *Packet { return m.sendQueue.Get(now) }
func (m *StaticPoolPacketManager) OutboundCount(now uint32) int    { return m.sendQueue.CountBefore(now) }
func (m *StaticPoolPacketManager) OutboundTotal() int              { return m.sendQueue.Count() }
func (m *StaticPoolPacketManager) FreeCount() int                  { return m.unused.Count() }
func (m *StaticPoolPacketManager) OutboundByIdx(i int) *Packet     { return m.sendQueue.ItemAt(i) }
func (m *StaticPoolPacketManager) RemoveOutboundByIdx(i int) *Packet {
	return m.sendQueue.RemoveByIdx(i)
}

func (m *StaticPoolPacketManager) QueueInbound(p *Packet, scheduledFor uint32) {
	if p == nil {
		return
	}
	if !m.rxQueue.Add(p, 0, scheduledFor) {
		m.Free(p) // rx queue full, dropping packet
	}
}

func (m *StaticPoolPacketManager) NextInbound(now uint32) *Packet { return m.rxQueue.Get(now) }
