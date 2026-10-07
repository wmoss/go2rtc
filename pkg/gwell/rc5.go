// Package gwell implements the client side of the Gwell/IoTVideo P2P protocol
// used by newer Wyze cameras (Wyze Cam OG, Cam OG Telephoto, Cam Pan v4 and
// Gwell firmware revisions of other models).
//
// The protocol was reverse-engineered from the vendor libiotp2pav.so SDK.
// Frame formats, the RC5 frame crypto, the checksum algorithm, the Mars
// (P2P relay) session handshake, the MTP media transport and the KCP based
// AV streaming are re-implemented in pure Go.
//
// Protocol overview:
//
//  1. Mars server discovery (UDP ListFrmRequest to list servers, port 51701)
//  2. GUTES session with a Mars server: DETECT, CERTIFY, INIT_INFO, SUBSCRIBE
//  3. CALLING the camera (routed by Mars), LAN/relay transport negotiation
//  4. MTP frames carrying a meter keepalive and two KCP streams (data/ctrl)
//  5. AVSTREAMCTL handshake (INITREQ/ACCEPT/START) and RC5 encrypted H.264
package gwell

import "encoding/binary"

// RC5-32/6 and RC5-64/6 implementation matching the vendor SDK
// (rc5_ctx_new(8, 6) and rc5_ctx_new(16, 6)).

const (
	rc5Rounds  = 6
	rc5SubLen  = 2 * (rc5Rounds + 1)
	rc5P32     = 0xB7E15163
	rc5Q32     = 0x9E3779B9
	rc5P64     = uint64(0xB7E151628AED2A6B)
	rc5Q64     = uint64(0x9E3779B97F4A7C15)
	passwordWd = "www.gwell.cc" // static SDK key used for frame ID encryption
)

// RC5Key holds the expanded subkey table of the 8-byte block variant.
type RC5Key struct {
	S [rc5SubLen]uint32
}

// NewRC5Key expands a variable length key for RC5-32.
func NewRC5Key(key []byte) *RC5Key {
	b := len(key)
	u := 4
	c := b / u
	if b%u != 0 {
		c++
	}
	if c == 0 {
		c = 1
	}

	L := make([]uint32, c)
	for i := b - 1; i >= 0; i-- {
		L[i/u] = (L[i/u] << 8) + uint32(key[i])
	}

	t := rc5SubLen
	var k RC5Key
	k.S[0] = rc5P32
	for i := 1; i < t; i++ {
		k.S[i] = k.S[i-1] + rc5Q32
	}

	var A, B uint32
	var i, j int
	n := 3 * t
	if 3*c > n {
		n = 3 * c
	}
	for s := 0; s < n; s++ {
		A = rotl32(k.S[i]+A+B, 3)
		k.S[i] = A
		B = rotl32(L[j]+A+B, (A+B)&31)
		L[j] = B
		i = (i + 1) % t
		j = (j + 1) % c
	}

	return &k
}

// NewPasswordKey returns the RC5 key from the hardcoded SDK password.
func NewPasswordKey() *RC5Key {
	return NewRC5Key([]byte(passwordWd))
}

// EncryptBlock encrypts one 8-byte block in place.
func (k *RC5Key) EncryptBlock(block []byte) {
	A := binary.LittleEndian.Uint32(block[0:4])
	B := binary.LittleEndian.Uint32(block[4:8])

	A += k.S[0]
	B += k.S[1]
	for i := 1; i <= rc5Rounds; i++ {
		A = rotl32(A^B, B&31) + k.S[2*i]
		B = rotl32(B^A, A&31) + k.S[2*i+1]
	}

	binary.LittleEndian.PutUint32(block[0:4], A)
	binary.LittleEndian.PutUint32(block[4:8], B)
}

// DecryptBlock decrypts one 8-byte block in place.
func (k *RC5Key) DecryptBlock(block []byte) {
	A := binary.LittleEndian.Uint32(block[0:4])
	B := binary.LittleEndian.Uint32(block[4:8])

	for i := rc5Rounds; i >= 1; i-- {
		B = rotr32(B-k.S[2*i+1], A&31) ^ A
		A = rotr32(A-k.S[2*i], B&31) ^ B
	}
	B -= k.S[1]
	A -= k.S[0]

	binary.LittleEndian.PutUint32(block[0:4], A)
	binary.LittleEndian.PutUint32(block[4:8], B)
}

// FrameKey derives the per-frame RC5 key: frame[0:4] + frame[0x14:0x17] + 0x00.
func FrameKey(frame []byte) *RC5Key {
	if len(frame) < 0x17 {
		return nil
	}
	key := [8]byte{
		frame[0], frame[1], frame[2], frame[3],
		frame[0x14], frame[0x15], frame[0x16], 0,
	}
	return NewRC5Key(key[:])
}

func rotl32(x uint32, n uint32) uint32 {
	n &= 31
	return (x << n) | (x >> (32 - n))
}

func rotr32(x uint32, n uint32) uint32 {
	n &= 31
	return (x >> n) | (x << (32 - n))
}

// RC5Key64 holds the expanded subkey table of the 16-byte block variant
// (W=64) used for the CertifyReq random key encryption.
type RC5Key64 struct {
	S [rc5SubLen]uint64
}

func rotl64(x uint64, n uint64) uint64 {
	n &= 63
	return (x << n) | (x >> (64 - n))
}

func rotr64(x uint64, n uint64) uint64 {
	n &= 63
	return (x >> n) | (x << (64 - n))
}

// NewRC5Key64 expands a variable length key for RC5-64.
func NewRC5Key64(key []byte) *RC5Key64 {
	b := len(key)
	u := 8
	c := b / u
	if b%u != 0 {
		c++
	}
	if c == 0 {
		c = 1
	}

	L := make([]uint64, c)
	for i := b - 1; i >= 0; i-- {
		L[i/u] = (L[i/u] << 8) + uint64(key[i])
	}

	t := rc5SubLen
	var k RC5Key64
	k.S[0] = rc5P64
	for i := 1; i < t; i++ {
		k.S[i] = k.S[i-1] + rc5Q64
	}

	var A, B uint64
	var i, j int
	n := 3 * t
	if 3*c > n {
		n = 3 * c
	}
	for s := 0; s < n; s++ {
		A = rotl64(k.S[i]+A+B, 3)
		k.S[i] = A
		B = rotl64(L[j]+A+B, (A+B)&63)
		L[j] = B
		i = (i + 1) % t
		j = (j + 1) % c
	}

	return &k
}

// EncryptBlock16 encrypts one 16-byte block in place.
func (k *RC5Key64) EncryptBlock16(block []byte) {
	A := binary.LittleEndian.Uint64(block[0:8])
	B := binary.LittleEndian.Uint64(block[8:16])

	A += k.S[0]
	B += k.S[1]
	for i := 1; i <= rc5Rounds; i++ {
		A = rotl64(A^B, B&63) + k.S[2*i]
		B = rotl64(B^A, A&63) + k.S[2*i+1]
	}

	binary.LittleEndian.PutUint64(block[0:8], A)
	binary.LittleEndian.PutUint64(block[8:16], B)
}

// DecryptBlock16 decrypts one 16-byte block in place.
func (k *RC5Key64) DecryptBlock16(block []byte) {
	A := binary.LittleEndian.Uint64(block[0:8])
	B := binary.LittleEndian.Uint64(block[8:16])

	for i := rc5Rounds; i >= 1; i-- {
		B = rotr64(B-k.S[2*i+1], A&63) ^ A
		A = rotr64(A-k.S[2*i], B&63) ^ B
	}
	B -= k.S[1]
	A -= k.S[0]

	binary.LittleEndian.PutUint64(block[0:8], A)
	binary.LittleEndian.PutUint64(block[8:16], B)
}
