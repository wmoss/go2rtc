package gwell

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRC5PasswordKeyEncryptVector(t *testing.T) {
	// Known vector from the vendor binary analysis:
	// RC5_6_encrypt(0x001be2f4, 0x930186d6) with key "www.gwell.cc" = (0xb9692bdb, 0x84c73060)
	k := NewPasswordKey()

	block := make([]byte, 8)
	binary.LittleEndian.PutUint32(block[0:4], 0x001be2f4)
	binary.LittleEndian.PutUint32(block[4:8], 0x930186d6)

	k.EncryptBlock(block)

	gotA := binary.LittleEndian.Uint32(block[0:4])
	gotB := binary.LittleEndian.Uint32(block[4:8])
	if gotA != 0xb9692bdb || gotB != 0x84c73060 {
		t.Errorf("PasswordKey encrypt = (0x%08x, 0x%08x), want (0xb9692bdb, 0x84c73060)", gotA, gotB)
	}
}

func TestRC5PasswordKeyDecryptVector(t *testing.T) {
	k := NewPasswordKey()

	block := make([]byte, 8)
	binary.LittleEndian.PutUint32(block[0:4], 0xb9692bdb)
	binary.LittleEndian.PutUint32(block[4:8], 0x84c73060)

	k.DecryptBlock(block)

	gotA := binary.LittleEndian.Uint32(block[0:4])
	gotB := binary.LittleEndian.Uint32(block[4:8])
	if gotA != 0x001be2f4 || gotB != 0x930186d6 {
		t.Errorf("PasswordKey decrypt = (0x%08x, 0x%08x), want (0x001be2f4, 0x930186d6)", gotA, gotB)
	}
}

func TestRC5RoundTrip(t *testing.T) {
	keys := [][]byte{
		{0x42, 0x13, 0x37, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE},
		[]byte(passwordWd),
		make([]byte, 8),
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}
	for _, key := range keys {
		k := NewRC5Key(key)
		original := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
		block := make([]byte, 8)
		copy(block, original)

		k.EncryptBlock(block)
		if bytes.Equal(block, original) {
			t.Error("EncryptBlock did not change the data")
		}

		k.DecryptBlock(block)
		if !bytes.Equal(block, original) {
			t.Errorf("round-trip failed: got %x, want %x", block, original)
		}
	}
}

func TestFrameKeyDerivation(t *testing.T) {
	frame := make([]byte, 40)
	frame[0] = 0x7F
	frame[1] = 0x15
	frame[2] = 0x28
	frame[3] = 0x00
	frame[0x14] = 0xAA
	frame[0x15] = 0xBB
	frame[0x16] = 0xCC

	k := FrameKey(frame)
	if k == nil {
		t.Fatal("FrameKey returned nil")
	}

	manualKey := []byte{0x7F, 0x15, 0x28, 0x00, 0xAA, 0xBB, 0xCC, 0x00}
	k2 := NewRC5Key(manualKey)
	for i := 0; i < rc5SubLen; i++ {
		if k.S[i] != k2.S[i] {
			t.Errorf("S[%d] mismatch", i)
		}
	}
}

func TestEncryptDecryptFrameRoundTrip(t *testing.T) {
	frame := make([]byte, 40)
	frame[0] = 0x7F
	frame[1] = 0x15
	binary.LittleEndian.PutUint16(frame[2:4], 40)
	binary.LittleEndian.PutUint32(frame[4:8], 0xDEADBEEF)
	binary.LittleEndian.PutUint32(frame[8:12], 0xCAFEBABE)
	binary.LittleEndian.PutUint32(frame[12:16], 1)
	frame[0x14] = 0x11
	frame[0x15] = 0x22
	frame[0x16] = 0x33
	frame[0x17] = 0x44
	for i := 24; i < 40; i++ {
		frame[i] = byte(i)
	}

	original := make([]byte, len(frame))
	copy(original, frame)

	EncryptFrame(frame)

	// plaintext regions unchanged
	if !bytes.Equal(frame[0:12], original[0:12]) {
		t.Error("frame[0:12] changed")
	}
	if !bytes.Equal(frame[20:24], original[20:24]) {
		t.Error("frame[20:24] changed")
	}
	// encrypted regions changed
	if bytes.Equal(frame[12:20], original[12:20]) {
		t.Error("frame[12:20] was NOT encrypted")
	}
	if bytes.Equal(frame[24:], original[24:]) {
		t.Error("frame[24:] was NOT encrypted")
	}

	DecryptFrame(frame)
	if !bytes.Equal(frame, original) {
		t.Errorf("round-trip failed:\n  got  %x\n  want %x", frame, original)
	}
}

func TestEncryptIDRoundTrip(t *testing.T) {
	frame := make([]byte, 48)
	frame[0] = 0x7F
	frame[1] = 0x01
	binary.LittleEndian.PutUint16(frame[2:4], 48)
	binary.LittleEndian.PutUint32(frame[4:8], 0x12345678)
	binary.LittleEndian.PutUint32(frame[8:12], 0x00000000)
	binary.LittleEndian.PutUint32(frame[12:16], 0x00000001)
	binary.LittleEndian.PutUint32(frame[20:24], 0x00010000)
	for i := 24; i < 48; i++ {
		frame[i] = byte(i)
	}

	original := make([]byte, len(frame))
	copy(original, frame)

	pwdKey := NewPasswordKey()
	EncryptFrameFull(frame, pwdKey)

	if !bytes.Equal(frame[0:4], original[0:4]) {
		t.Error("frame[0:4] changed")
	}
	if !bytes.Equal(frame[20:24], original[20:24]) {
		t.Error("frame[20:24] changed")
	}
	if bytes.Equal(frame[4:20], original[4:20]) {
		t.Error("frame[4:20] was not encrypted")
	}

	if !DecryptFrameFull(frame, pwdKey) {
		t.Error("checksum invalid after full decrypt")
	}
	if binary.LittleEndian.Uint32(frame[4:8]) != 0x12345678 {
		t.Errorf("word1 not restored")
	}
	if binary.LittleEndian.Uint32(frame[8:12]) != 0x00000000 {
		t.Errorf("word2 not restored")
	}
	if binary.LittleEndian.Uint32(frame[12:16]) != 0x00000001 {
		t.Errorf("sqnum not restored")
	}
}

func TestGetEncryptDataLen(t *testing.T) {
	tests := []struct {
		totalLen uint16
		flags    uint32
		want     int
	}{
		{68, 0x00010000, 44},
		{164, 0x014d9092, 44}, // 164-24-80-16=44
		{164, 0x00410000, 60}, // 164-24-80
		{164, 0x01010000, 124},
		{32, 0x00010000, 8},
		{24, 0x00010000, 0},
	}
	for _, tt := range tests {
		frame := make([]byte, tt.totalLen)
		frame[0] = 0x7F
		frame[1] = 0x0C
		binary.LittleEndian.PutUint16(frame[2:4], tt.totalLen)
		binary.LittleEndian.PutUint32(frame[20:24], tt.flags)
		if got := GetEncryptDataLen(frame); got != tt.want {
			t.Errorf("GetEncryptDataLen(totalLen=%d, flags=0x%08X) = %d, want %d",
				tt.totalLen, tt.flags, got, tt.want)
		}
	}
}

func TestEncryptFrameRespectsSignatureFlags(t *testing.T) {
	// The NTP time and signature trailers must not be encrypted
	frame := make([]byte, 164)
	frame[0] = 0x7F
	frame[1] = 0x0C
	binary.LittleEndian.PutUint16(frame[2:4], 164)
	binary.LittleEndian.PutUint32(frame[4:8], 0x12345678)
	binary.LittleEndian.PutUint32(frame[12:16], 1)
	binary.LittleEndian.PutUint32(frame[20:24], FlagHasSignature|FlagHasNTPTime|0x00010000)
	for i := 24; i < 164; i++ {
		frame[i] = byte(i)
	}

	original := make([]byte, 164)
	copy(original, frame)

	pwdKey := NewPasswordKey()
	EncryptFrameFull(frame, pwdKey)

	if !bytes.Equal(frame[68:84], original[68:84]) {
		t.Error("NTP time region [68:84] was encrypted — should be plaintext")
	}
	if !bytes.Equal(frame[84:164], original[84:164]) {
		t.Error("Signature region [84:164] was encrypted — should be plaintext")
	}
	if bytes.Equal(frame[24:64], original[24:64]) {
		t.Error("Encrypted payload [24:64] was NOT encrypted")
	}

	if !DecryptFrameFull(frame, pwdKey) {
		t.Error("checksum invalid after full decrypt")
	}
	if binary.LittleEndian.Uint32(frame[4:8]) != 0x12345678 {
		t.Error("word1 not restored")
	}
	for i := 24; i < 64; i++ {
		if frame[i] != original[i] {
			t.Errorf("payload byte [%d] not restored", i)
			break
		}
	}
}

func TestChkvalRoundTrip(t *testing.T) {
	frame := BuildDetectReq2()
	if !VerifyChkval(frame) {
		t.Error("chkval invalid for freshly built frame")
	}
	frame[30] ^= 0xFF
	if VerifyChkval(frame) {
		t.Error("chkval valid after corruption")
	}
}

func TestMode2RoundTrip(t *testing.T) {
	tokenBytes := make([]byte, 64)
	for i := range tokenBytes {
		tokenBytes[i] = byte(i)
	}
	token, err := ParseAccessToken("12345678901234", hexEncode(tokenBytes))
	if err != nil {
		t.Fatal(err)
	}

	sessionKey := NewRC5Key([]byte("0123456789abcdef0123456789abcdef"))
	pwdKey := NewPasswordKey()

	frame := BuildHeartbeat(token, 0, 5, sessionKey, pwdKey)
	if frame[0] != ProtoPlain || frame[1] != SubTypeHeartbeat {
		t.Fatalf("unexpected frame header: %x %x", frame[0], frame[1])
	}

	decrypted := TryDecrypt(frame, sessionKey, pwdKey)
	if decrypted == nil {
		t.Fatal("TryDecrypt failed for mode-2 frame")
	}
	if binary.LittleEndian.Uint32(decrypted[12:16]) != 5 {
		t.Errorf("sqnum not restored: %d", binary.LittleEndian.Uint32(decrypted[12:16]))
	}
	if binary.LittleEndian.Uint32(decrypted[4:8]) != token.Word1() {
		t.Error("word1 not restored")
	}
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, hexdigits[v>>4], hexdigits[v&0xF])
	}
	return string(out)
}
