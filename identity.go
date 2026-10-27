package meshcore

import (
	"bytes"
	"crypto/ed25519"
	"errors"
)

// Identity is a party in the mesh identified by its Ed25519 public key,
// i.e. a party whose signatures can be verified.
type Identity struct {
	PubKey [PubKeySize]byte
}

// IdentityFromHex parses a hex-encoded public key.
func IdentityFromHex(pubHex string) (Identity, bool) {
	var id Identity
	ok := FromHex(id.PubKey[:], pubHex)
	return id, ok
}

// CopyHashTo copies the first n bytes of the public key (the node hash) to
// dst and returns n.
func (id *Identity) CopyHashTo(dst []byte, n int) int {
	return copy(dst[:n], id.PubKey[:n])
}

// IsHashMatch reports whether hash is a prefix of the public key.
func (id *Identity) IsHashMatch(hash []byte) bool {
	return len(hash) <= PubKeySize && bytes.Equal(hash, id.PubKey[:len(hash)])
}

// Verify performs Ed25519 signature verification of msg.
func (id *Identity) Verify(sig, msg []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}
	return ed25519.Verify(id.PubKey[:], msg, sig)
}

// Matches reports whether both identities have the same public key.
func (id *Identity) Matches(other *Identity) bool { return id.PubKey == other.PubKey }

// MatchesKey reports whether the public key equals pub.
func (id *Identity) MatchesKey(pub []byte) bool { return bytes.Equal(id.PubKey[:], pub) }

// String returns the public key in hex.
func (id *Identity) String() string { return ToHex(id.PubKey[:]) }

// LocalIdentity is an Identity generated on this device, holding the private
// key. The private key uses the 64-byte expanded orlp/ed25519 format of the
// C++ implementation.
type LocalIdentity struct {
	Identity
	prvKey [PrvKeySize]byte
}

// NewLocalIdentity creates a new random identity.
func NewLocalIdentity(rng RNG) LocalIdentity {
	var seed [SeedSize]byte
	rng.Random(seed[:])
	return LocalIdentityFromSeed(seed[:])
}

// LocalIdentityFromSeed derives an identity from a 32-byte seed, like
// ed25519_create_keypair().
func LocalIdentityFromSeed(seed []byte) LocalIdentity {
	var li LocalIdentity
	expandSeed(&li.prvKey, seed)
	derivePub(&li.PubKey, &li.prvKey)
	return li
}

// LocalIdentityFromHex parses hex-encoded private and public keys.
func LocalIdentityFromHex(prvHex, pubHex string) (LocalIdentity, bool) {
	var li LocalIdentity
	ok := FromHex(li.prvKey[:], prvHex) && FromHex(li.PubKey[:], pubHex)
	return li, ok
}

var errIdentityLen = errors.New("meshcore: identity blob must be 64 or 96 bytes")

// LoadLocalIdentity restores an identity from the blob produced by
// AppendBinary: either the private key alone (the public key is then
// derived) or the private key followed by the public key.
func LoadLocalIdentity(src []byte) (LocalIdentity, error) {
	var li LocalIdentity
	switch len(src) {
	case PrvKeySize + PubKeySize:
		copy(li.prvKey[:], src)
		copy(li.PubKey[:], src[PrvKeySize:])
	case PrvKeySize:
		copy(li.prvKey[:], src)
		derivePub(&li.PubKey, &li.prvKey)
	default:
		return li, errIdentityLen
	}
	return li, nil
}

// AppendBinary appends the private key followed by the public key (96 bytes,
// the same layout as the C++ LocalIdentity::writeTo) to dst.
func (li *LocalIdentity) AppendBinary(dst []byte) ([]byte, error) {
	dst = append(dst, li.prvKey[:]...)
	return append(dst, li.PubKey[:]...), nil
}

// PrivateKey returns a copy of the 64-byte expanded private key.
func (li *LocalIdentity) PrivateKey() [PrvKeySize]byte { return li.prvKey }

// Sign produces an Ed25519 signature of msg.
func (li *LocalIdentity) Sign(sig *[SignatureSize]byte, msg []byte) {
	orlpSign(sig, msg, &li.PubKey, &li.prvKey)
}

// SharedSecret performs ECDH with the other party's Ed25519 public key
// (transposed to X25519) and stores the 32-byte secret.
func (li *LocalIdentity) SharedSecret(secret *[PubKeySize]byte, otherPub *[PubKeySize]byte) {
	orlpKeyExchange(secret, otherPub, &li.prvKey)
}

// testClient is a known good keypair used by ValidatePrivateKey.
var (
	testClientPrv = [PrvKeySize]byte{
		0x70, 0x65, 0xe1, 0x8f, 0xd9, 0xfa, 0xbb, 0x70,
		0xc1, 0xed, 0x90, 0xdc, 0xa1, 0x99, 0x07, 0xde,
		0x69, 0x8c, 0x88, 0xb7, 0x09, 0xea, 0x14, 0x6e,
		0xaf, 0xd9, 0x3d, 0x9b, 0x83, 0x0c, 0x7b, 0x60,
		0xc4, 0x68, 0x11, 0x93, 0xc7, 0x9b, 0xbc, 0x39,
		0x94, 0x5b, 0xa8, 0x06, 0x41, 0x04, 0xbb, 0x61,
		0x8f, 0x8f, 0xd7, 0xa8, 0x4a, 0x0a, 0xf6, 0xf5,
		0x70, 0x33, 0xd6, 0xe8, 0xdd, 0xcd, 0x64, 0x71,
	}
	testClientPub = [PubKeySize]byte{
		0x1e, 0xc7, 0x71, 0x75, 0xb0, 0x91, 0x8e, 0xd2,
		0x06, 0xf9, 0xae, 0x04, 0xec, 0x13, 0x6d, 0x6d,
		0x5d, 0x43, 0x15, 0xbb, 0x26, 0x30, 0x54, 0x27,
		0xf6, 0x45, 0xb4, 0x92, 0xe9, 0x35, 0x0c, 0x10,
	}
)

// ValidatePrivateKey reports whether prv can be used for ECDH / shared-secret
// operations (and so for login).
func ValidatePrivateKey(prv *[PrvKeySize]byte) bool {
	var pub [PubKeySize]byte
	derivePub(&pub, prv)

	// disallow 00 or FF prefixed public keys
	if pub[0] == 0x00 || pub[0] == 0xFF {
		return false
	}

	var ss1, ss2 [PubKeySize]byte
	orlpKeyExchange(&ss1, &testClientPub, prv)
	orlpKeyExchange(&ss2, &pub, &testClientPrv)
	if ss1 != ss2 {
		return false
	}
	return !IsZeroes(ss1[:]) // reject all-zero shared secret
}
