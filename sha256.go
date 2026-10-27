package meshcore

import (
	"encoding/binary"
	"math/bits"
)

// sha256d is a minimal SHA-256 used on the receive hot path (packet hashes,
// HMAC). Unlike crypto/sha256, it does not allocate under TinyGo, whose
// escape analysis heap-allocates the stdlib digest on every Sum256 call.
// It is validated against the C++ implementation by the golden tests.
type sha256d struct {
	h   [8]uint32
	x   [64]byte
	nx  int
	len uint64
}

var sha256K = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func (d *sha256d) reset() {
	d.h = [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	d.nx = 0
	d.len = 0
}

func (d *sha256d) write(p []byte) {
	d.len += uint64(len(p))
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		p = p[n:]
		if d.nx == 64 {
			d.block(d.x[:])
			d.nx = 0
		}
	}
	for len(p) >= 64 {
		d.block(p[:64])
		p = p[64:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
}

func (d *sha256d) writeByte(b byte) {
	d.x[d.nx] = b
	d.nx++
	d.len++
	if d.nx == 64 {
		d.block(d.x[:])
		d.nx = 0
	}
}

func (d *sha256d) sum(out *[32]byte) {
	n := d.len
	d.writeByte(0x80)
	for d.nx != 56 {
		d.writeByte(0)
	}
	binary.BigEndian.PutUint64(d.x[56:], n<<3)
	d.block(d.x[:])
	for i, v := range d.h {
		binary.BigEndian.PutUint32(out[i*4:], v)
	}
}

func (d *sha256d) block(p []byte) {
	var w [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(p[i*4:])
	}
	for i := 16; i < 64; i++ {
		v1 := w[i-2]
		t1 := bits.RotateLeft32(v1, -17) ^ bits.RotateLeft32(v1, -19) ^ (v1 >> 10)
		v2 := w[i-15]
		t2 := bits.RotateLeft32(v2, -7) ^ bits.RotateLeft32(v2, -18) ^ (v2 >> 3)
		w[i] = t1 + w[i-7] + t2 + w[i-16]
	}
	a, b, c, e, f, g, h, dd := d.h[0], d.h[1], d.h[2], d.h[4], d.h[5], d.h[6], d.h[7], d.h[3]
	for i := 0; i < 64; i++ {
		t1 := h + (bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)) +
			((e & f) ^ (^e & g)) + sha256K[i] + w[i]
		t2 := (bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)) +
			((a & b) ^ (a & c) ^ (b & c))
		h = g
		g = f
		f = e
		e = dd + t1
		dd = c
		c = b
		b = a
		a = t1 + t2
	}
	d.h[0] += a
	d.h[1] += b
	d.h[2] += c
	d.h[3] += dd
	d.h[4] += e
	d.h[5] += f
	d.h[6] += g
	d.h[7] += h
}

// hmacSHA256 computes HMAC-SHA256 of msg keyed with key (at most 64 bytes),
// truncated to len(dst).
func hmacSHA256(dst, key, msg []byte) {
	var pad [64]byte
	copy(pad[:], key)
	var d sha256d
	d.reset()
	for i := range pad {
		pad[i] ^= 0x36
	}
	d.write(pad[:])
	d.write(msg)
	var inner [32]byte
	d.sum(&inner)

	for i := range pad {
		pad[i] ^= 0x36 ^ 0x5c
	}
	d.reset()
	d.write(pad[:])
	d.write(inner[:])
	var out [32]byte
	d.sum(&out)
	copy(dst, out[:])
}
