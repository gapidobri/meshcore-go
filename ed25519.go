package meshcore

import (
	"crypto/sha512"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// The C++ uses orlp/ed25519, whose 64-byte private key is the *expanded*
// secret: the clamped scalar (32 bytes) followed by the nonce prefix
// (32 bytes), i.e. clamp(SHA512(seed)). Go's crypto/ed25519 cannot sign with
// that format, so signing and key exchange are implemented here directly.

// expandSeed returns the orlp private key for a 32-byte seed.
func expandSeed(prv *[PrvKeySize]byte, seed []byte) {
	*prv = sha512.Sum512(seed)
	prv[0] &= 248
	prv[31] &= 63
	prv[31] |= 64
}

// secretScalar interprets prv[:32] as a little-endian integer reduced mod l,
// matching orlp's sc_muladd / ge_scalarmult_base (which do not re-clamp).
func secretScalar(prv *[PrvKeySize]byte) *edwards25519.Scalar {
	var wide [64]byte
	copy(wide[:32], prv[:32])
	s, _ := edwards25519.NewScalar().SetUniformBytes(wide[:])
	return s
}

func derivePub(pub *[PubKeySize]byte, prv *[PrvKeySize]byte) {
	A := new(edwards25519.Point).ScalarBaseMult(secretScalar(prv))
	copy(pub[:], A.Bytes())
}

// orlpSign is ed25519_sign() from orlp/ed25519.
func orlpSign(sig *[SignatureSize]byte, msg []byte, pub *[PubKeySize]byte, prv *[PrvKeySize]byte) {
	var digest [64]byte

	h := sha512.New()
	h.Write(prv[32:])
	h.Write(msg)
	h.Sum(digest[:0])
	r, _ := edwards25519.NewScalar().SetUniformBytes(digest[:])

	R := new(edwards25519.Point).ScalarBaseMult(r)
	copy(sig[:32], R.Bytes())

	h.Reset()
	h.Write(sig[:32])
	h.Write(pub[:])
	h.Write(msg)
	h.Sum(digest[:0])
	k, _ := edwards25519.NewScalar().SetUniformBytes(digest[:])

	S := edwards25519.NewScalar().MultiplyAdd(k, secretScalar(prv), r)
	copy(sig[32:], S.Bytes())
}

// orlpKeyExchange is ed25519_key_exchange() from orlp/ed25519: the Ed25519
// public key is converted to its Montgomery u-coordinate and an X25519
// ladder is run with the clamped private scalar. Unlike crypto/ecdh it never
// rejects low-order results, which keeps it byte-identical to the C++.
func orlpKeyExchange(secret *[PubKeySize]byte, pub *[PubKeySize]byte, prv *[PrvKeySize]byte) {
	var e [32]byte
	copy(e[:], prv[:32])
	e[0] &= 248
	e[31] &= 63
	e[31] |= 64

	// montgomeryX = (edwardsY + 1)*inverse(1 - edwardsY) mod p
	var x1, tmp0, tmp1 field.Element
	x1.SetBytes(pub[:]) // ignores the top (sign) bit, like fe_frombytes
	one := new(field.Element).One()
	tmp0.Add(&x1, one)
	tmp1.Subtract(one, &x1)
	tmp1.Invert(&tmp1)
	x1.Multiply(&tmp0, &tmp1)

	var x2, z2, x3, z3 field.Element
	x2.One()
	z2.Zero()
	x3.Set(&x1)
	z3.One()

	swap := 0
	for pos := 254; pos >= 0; pos-- {
		b := int(e[pos/8]>>(pos&7)) & 1
		swap ^= b
		x2.Swap(&x3, swap)
		z2.Swap(&z3, swap)
		swap = b

		tmp0.Subtract(&x3, &z3)
		tmp1.Subtract(&x2, &z2)
		x2.Add(&x2, &z2)
		z2.Add(&x3, &z3)
		z3.Multiply(&tmp0, &x2)
		z2.Multiply(&z2, &tmp1)
		tmp0.Square(&tmp1)
		tmp1.Square(&x2)
		x3.Add(&z3, &z2)
		z2.Subtract(&z3, &z2)
		x2.Multiply(&tmp1, &tmp0)
		tmp1.Subtract(&tmp1, &tmp0)
		z2.Square(&z2)
		z3.Mult32(&tmp1, 121666)
		x3.Square(&x3)
		tmp0.Add(&tmp0, &z3)
		z3.Multiply(&x1, &z2)
		z2.Multiply(&tmp1, &tmp0)
	}
	x2.Swap(&x3, swap)
	z2.Swap(&z3, swap)

	z2.Invert(&z2)
	x2.Multiply(&x2, &z2)
	copy(secret[:], x2.Bytes())
}
