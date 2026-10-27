package meshcore

import (
	"encoding/binary"
	"time"
)

// RNG is a source of random bytes.
type RNG interface {
	Random(dst []byte)
}

// NextInt returns a random number in [min, max).
func NextInt(rng RNG, min, max uint32) uint32 {
	var b [4]byte
	rng.Random(b[:])
	return binary.LittleEndian.Uint32(b[:])%(max-min) + min
}

// MillisecondClock is a local, volatile clock with millisecond granularity.
// It is expected to wrap around at 2^32 like Arduino's millis().
type MillisecondClock interface {
	Millis() uint32
}

// RTCClock is the device's real-time clock, in UNIX epoch seconds.
type RTCClock interface {
	CurrentTime() uint32
	SetCurrentTime(t uint32)
	// Tick is called periodically by clocks that need to update internal state.
	Tick()
}

// UniqueTime wraps an RTCClock to hand out strictly increasing timestamps.
type UniqueTime struct {
	Clock      RTCClock
	lastUnique uint32
}

// CurrentTimeUnique returns the current time, bumped as needed so that it is
// greater than every value previously returned.
func (u *UniqueTime) CurrentTimeUnique() uint32 {
	t := u.Clock.CurrentTime()
	if t <= u.lastUnique {
		u.lastUnique++
		return u.lastUnique
	}
	u.lastUnique = t
	return t
}

// SystemMillis is a MillisecondClock based on the Go monotonic clock.
type SystemMillis struct {
	start time.Time
}

// NewSystemMillis returns a SystemMillis that starts counting from now.
func NewSystemMillis() *SystemMillis { return &SystemMillis{start: time.Now()} }

func (c *SystemMillis) Millis() uint32 { return uint32(time.Since(c.start).Milliseconds()) }

// VolatileRTCClock is an RTCClock that keeps time from a MillisecondClock,
// starting at a fixed base time. It loses time on reset.
type VolatileRTCClock struct {
	ms          MillisecondClock
	baseTime    uint32
	accumulator uint64
	prevMillis  uint32
}

// NewVolatileRTCClock returns a clock starting at 15 May 2024, 8:50pm, like
// the C++ VolatileRTCClock.
func NewVolatileRTCClock(ms MillisecondClock) *VolatileRTCClock {
	return &VolatileRTCClock{ms: ms, baseTime: 1715770351, prevMillis: ms.Millis()}
}

func (c *VolatileRTCClock) CurrentTime() uint32 {
	return c.baseTime + uint32(c.accumulator/1000)
}

func (c *VolatileRTCClock) SetCurrentTime(t uint32) {
	c.baseTime = t
	c.accumulator = 0
	c.prevMillis = c.ms.Millis()
}

func (c *VolatileRTCClock) Tick() {
	now := c.ms.Millis()
	c.accumulator += uint64(now - c.prevMillis)
	c.prevMillis = now
}
