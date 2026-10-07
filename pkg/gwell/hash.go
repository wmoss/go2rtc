package gwell

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
)

// GiotHashString is the hash used inside CertifyReq frames, decompiled from
// giot_hash_string. Modified DJB2 variant with seed 0x4e67c6a7:
//
//	hash = hash ^ (byte + hash*0x20 + (hash >> 2))
func GiotHashString(data []byte) uint32 {
	var hash uint32 = 0x4e67c6a7
	for _, b := range data {
		hash = hash ^ (uint32(b) + hash*0x20 + (hash >> 2))
	}
	return hash
}

// deriveAESKey expands a non-standard-length key into a 16-byte AES key by
// concatenating four independent 32-bit hashes.
func deriveAESKey(key []byte) [16]byte {
	var hash1 uint32
	var hash2 uint32 = 0x4e67c6a7 // same seed as GiotHashString
	var hash3 uint32 = 0x1505     // djb2 seed
	var hash4 uint32

	for _, b := range key {
		v := uint32(b)
		hash1 = hash1*0x83 + v
		hash2 = hash2 ^ (v + hash2*0x20 + (hash2 >> 2))
		hash3 = v + hash3*0x21
		hash4 = v + hash4*0x1003f
	}

	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:4], hash1)
	binary.LittleEndian.PutUint32(out[4:8], hash2)
	binary.LittleEndian.PutUint32(out[8:12], hash3)
	binary.LittleEndian.PutUint32(out[12:16], hash4)
	return out
}

// aesEncryptCBC encrypts data in place with AES-128-CBC, the vendor IV
// ("iotVideo" + zeros) and a derived key for non-standard key lengths.
func aesEncryptCBC(data, key []byte) {
	var aesKey []byte
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		derived := deriveAESKey(key)
		aesKey = derived[:]
	} else {
		aesKey = key
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return
	}

	iv := append([]byte("iotVideo"), make([]byte, 8)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
}

// hmacMD5 returns the HMAC-MD5 of data with the given key.
func hmacMD5(key, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// getSignatureCheckval sums 16-bit little-endian words, from get_chkval.
func getSignatureCheckval(data []byte) uint16 {
	var sum uint16
	for i := 0; i+2 <= len(data); i += 2 {
		sum += binary.LittleEndian.Uint16(data[i : i+2])
	}
	return sum
}
