package meshcore

import (
	"crypto/aes"
	"crypto/subtle"
)

// SHA256 computes the SHA256 hash of the concatenation of frags, truncated
// to len(dst) bytes (at most 32).
func SHA256(dst []byte, frags ...[]byte) {
	var d sha256d
	d.reset()
	for _, f := range frags {
		d.write(f)
	}
	var sum [32]byte
	d.sum(&sum)
	copy(dst, sum[:])
}

// Encrypt encrypts src with AES-128-ECB using the first CipherKeySize bytes of
// secret as the key. The final block is zero padded. It returns the number of
// bytes written to dst, which is always a multiple of the block size.
func Encrypt(secret, dst, src []byte) int {
	c, err := aes.NewCipher(secret[:CipherKeySize])
	if err != nil {
		return 0
	}
	n := 0
	for len(src) >= CipherBlockSize {
		c.Encrypt(dst[n:n+CipherBlockSize], src[:CipherBlockSize])
		n += CipherBlockSize
		src = src[CipherBlockSize:]
	}
	if len(src) > 0 { // remaining partial block
		var tmp [CipherBlockSize]byte
		copy(tmp[:], src)
		c.Encrypt(dst[n:n+CipherBlockSize], tmp[:])
		n += CipherBlockSize
	}
	return n
}

// Decrypt decrypts src (a multiple of the block size) with AES-128-ECB. dst
// may contain trailing zero bytes from the final block's padding. It returns
// the number of bytes written to dst.
func Decrypt(secret, dst, src []byte) int {
	c, err := aes.NewCipher(secret[:CipherKeySize])
	if err != nil {
		return 0
	}
	n := 0
	for n+CipherBlockSize <= len(src) {
		c.Decrypt(dst[n:n+CipherBlockSize], src[n:n+CipherBlockSize])
		n += CipherBlockSize
	}
	return n
}

// EncryptThenMAC encrypts src into dst after a CipherMACSize byte MAC, which
// is an HMAC-SHA256 (keyed with the full PubKeySize secret) of the ciphertext.
// It returns the total bytes written (MAC + ciphertext).
func EncryptThenMAC(secret, dst, src []byte) int {
	encLen := Encrypt(secret, dst[CipherMACSize:], src)
	hmacSHA256(dst[:CipherMACSize], secret[:PubKeySize], dst[CipherMACSize:CipherMACSize+encLen])
	return CipherMACSize + encLen
}

// MACThenDecrypt checks the leading MAC of src and, if valid, decrypts the
// rest into dst. It returns 0 if the MAC is invalid or the ciphertext is not
// block aligned, otherwise the decrypted length.
func MACThenDecrypt(secret, dst, src []byte) int {
	if len(src) <= CipherMACSize {
		return 0 // invalid src bytes
	}
	enc := src[CipherMACSize:]
	if len(enc)%CipherBlockSize != 0 {
		return 0 // reject non-block-aligned ciphertext
	}
	var mac [CipherMACSize]byte
	hmacSHA256(mac[:], secret[:PubKeySize], enc)
	if subtle.ConstantTimeCompare(mac[:], src[:CipherMACSize]) != 1 {
		return 0 // invalid HMAC
	}
	return Decrypt(secret, dst, enc)
}

const hexChars = "0123456789ABCDEF"

// AppendHex appends the upper-case hex representation of src to dst.
func AppendHex(dst, src []byte) []byte {
	for _, b := range src {
		dst = append(dst, hexChars[b>>4], hexChars[b&0x0F])
	}
	return dst
}

// ToHex returns the upper-case hex representation of src.
func ToHex(src []byte) string {
	return string(AppendHex(make([]byte, 0, len(src)*2), src))
}

func hexVal(c byte) byte {
	switch {
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= '0' && c <= '9':
		return c - '0'
	}
	return 0
}

// IsHexChar reports whether c is a hex digit.
func IsHexChar(c byte) bool { return c == '0' || hexVal(c) > 0 }

// FromHex decodes hex into dst. The hex string must be exactly 2*len(dst)
// characters. Like the C++, invalid characters decode as zero nibbles.
func FromHex(dst []byte, hex string) bool {
	if len(hex) != len(dst)*2 {
		return false // incorrect length
	}
	for i := range dst {
		dst[i] = hexVal(hex[2*i])<<4 | hexVal(hex[2*i+1])
	}
	return true
}

// IsZeroes reports whether every byte of buf is zero.
func IsZeroes(buf []byte) bool {
	for _, b := range buf {
		if b != 0 {
			return false
		}
	}
	return true
}
