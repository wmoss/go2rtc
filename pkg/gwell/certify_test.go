package gwell

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestGiotHashString(t *testing.T) {
	if h := GiotHashString([]byte{}); h != 0x4e67c6a7 {
		t.Errorf("empty hash: got 0x%08X, want 0x4e67c6a7", h)
	}

	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}
	if GiotHashString(data) != GiotHashString(data) {
		t.Error("hash not deterministic")
	}

	data2 := make([]byte, 32)
	for i := range data2 {
		data2[i] = byte(i + 1)
	}
	if GiotHashString(data) == GiotHashString(data2) {
		t.Error("different inputs produced same hash")
	}
}

func TestRC5Key64RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 0x30)
	}
	k := NewRC5Key64(key)

	var original [16]byte
	for i := range original {
		original[i] = byte(i * 0x11)
	}

	block := make([]byte, 16)
	copy(block, original[:])
	k.EncryptBlock16(block)

	if block[0] == original[0] && block[8] == original[8] {
		t.Error("encrypted block appears unchanged")
	}

	k.DecryptBlock16(block)
	for i := range block {
		if block[i] != original[i] {
			t.Fatalf("round-trip failed at byte %d", i)
		}
	}
}

func TestParseAccessToken(t *testing.T) {
	tokenBytes := make([]byte, 64)
	for i := range tokenBytes {
		tokenBytes[i] = byte(i)
	}

	token, err := ParseAccessToken("12345678901234", hex.EncodeToString(tokenBytes))
	if err != nil {
		t.Fatalf("ParseAccessToken failed: %v", err)
	}

	if token.AccessID != 12345678901234 {
		t.Errorf("AccessID: got %d", token.AccessID)
	}
	if token.Word1() != uint32(12345678901234&0xFFFFFFFF) {
		t.Errorf("Word1: got 0x%08X", token.Word1())
	}
	if token.Word2() != uint32(12345678901234>>32) {
		t.Errorf("Word2: got 0x%08X", token.Word2())
	}
	for i := 0; i < 16; i++ {
		if token.TokenKeyRaw[i] != byte(48+i) {
			t.Errorf("TokenKeyRaw[%d]: got 0x%02X", i, token.TokenKeyRaw[i])
		}
	}
}

func TestParseAccessTokenShort(t *testing.T) {
	if _, err := ParseAccessToken("123", "abcd"); err == nil {
		t.Error("expected error for short token")
	}
}

func TestParseAccessTokenExtraData(t *testing.T) {
	base := make([]byte, 64)
	for i := range base {
		base[i] = byte(i)
	}
	extra := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	tokenStr := hex.EncodeToString(base) + encodeBase64(extra)

	token, err := ParseAccessToken("42", tokenStr)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if len(token.ExtraTokenData) != len(extra) {
		t.Fatalf("ExtraTokenData: got %x, want %x", token.ExtraTokenData, extra)
	}
}

func TestBuildCertifyReq(t *testing.T) {
	tokenBytes := make([]byte, 64)
	for i := range tokenBytes {
		tokenBytes[i] = byte(i)
	}
	token, err := ParseAccessToken("10593094227361022708", hex.EncodeToString(tokenBytes))
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}

	frame, randomKey := BuildCertifyReq(token, 1)

	if len(frame) != 164 {
		t.Fatalf("frame size: got %d, want 164", len(frame))
	}

	allZero := true
	for _, b := range randomKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("random key is all zeros")
	}

	// decrypt and verify structure
	pwdKey := NewPasswordKey()
	DecryptID(frame, pwdKey)
	DecryptFrame(frame)

	if frame[0] != ProtoPlain || frame[1] != SubTypeSessionInit {
		t.Errorf("header: got %02X %02X", frame[0], frame[1])
	}
	if binary.LittleEndian.Uint16(frame[2:4]) != 164 {
		t.Errorf("frame_len: got %d", binary.LittleEndian.Uint16(frame[2:4]))
	}
	if binary.LittleEndian.Uint32(frame[4:8]) != token.Word1() {
		t.Error("word1 mismatch")
	}
	if binary.LittleEndian.Uint32(frame[8:12]) != token.Word2() {
		t.Error("word2 mismatch")
	}

	flags := binary.LittleEndian.Uint32(frame[20:24])
	if (flags>>FlagEncryptMode)&3 != 1 {
		t.Errorf("encrypt_mode: got %d", (flags>>FlagEncryptMode)&3)
	}
	if flags&FlagHasSignature == 0 || flags&FlagHasNTPTime == 0 {
		t.Error("signature/NTP flags not set")
	}

	if GetEncryptDataLen(frame) != 44 {
		t.Errorf("encrypt_data_len: got %d, want 44", GetEncryptDataLen(frame))
	}
	if binary.LittleEndian.Uint32(frame[24:28])&1 != 1 {
		t.Error("opt_flags has_version not set")
	}
	if binary.LittleEndian.Uint32(frame[28:32]) != GiotHashString(randomKey[:]) {
		t.Error("random key hash mismatch")
	}

	// inner-encrypted random key must decrypt with the token key
	var decKey [32]byte
	copy(decKey[:], frame[32:64])
	token.TokenKey.DecryptBlock16(decKey[0:16])
	token.TokenKey.DecryptBlock16(decKey[16:32])
	if decKey != randomKey {
		t.Error("inner-decrypted random key does not match original")
	}

	if binary.LittleEndian.Uint32(frame[64:68]) != 1032 {
		t.Errorf("MTU: got %d", binary.LittleEndian.Uint32(frame[64:68]))
	}
}

func TestBuildCertifyReqFullDecrypt(t *testing.T) {
	tokenBytes := make([]byte, 64)
	for i := range tokenBytes {
		tokenBytes[i] = byte(i * 3)
	}
	token, _ := ParseAccessToken("1234567890", hex.EncodeToString(tokenBytes))

	frame, _ := BuildCertifyReq(token, 42)

	pwdKey := NewPasswordKey()
	if !DecryptFrameFull(frame, pwdKey) {
		t.Error("CertifyReq frame checksum invalid after decryption")
	}
}

func TestBuildInitInfoMsg(t *testing.T) {
	tokenBytes := make([]byte, 64)
	for i := range tokenBytes {
		tokenBytes[i] = byte(i)
	}
	token, _ := ParseAccessToken("12345678901234", hex.EncodeToString(tokenBytes))

	sessionKey := NewRC5Key([]byte("session-key-session-key-session-32!!"))
	pwdKey := NewPasswordKey()

	var sessionID uint64 = 0x1234567890ABCDEF
	frame := BuildInitInfoMsg(token, sessionID, 1, sessionKey, pwdKey)

	if len(frame) != 62 {
		t.Fatalf("frame size: got %d, want 62", len(frame))
	}

	decrypted := TryDecrypt(frame, sessionKey, pwdKey)
	if decrypted == nil {
		t.Fatal("failed to decrypt InitInfoMsg")
	}

	if decrypted[1] != SubTypeInitInfoMsg {
		t.Errorf("sub_type: got 0x%02X", decrypted[1])
	}
	if binary.LittleEndian.Uint64(decrypted[4:12]) != sessionID {
		// note: word1/word2 hold the accessId in InitInfoMsg, not sessionID
		if binary.LittleEndian.Uint64(decrypted[4:12]) != token.AccessID {
			t.Errorf("word1/word2: got 0x%016X", binary.LittleEndian.Uint64(decrypted[4:12]))
		}
	}
	if decrypted[27] != 2 {
		t.Errorf("sub_mode: got %d", decrypted[27])
	}
}

func TestBuildNetworkDetectProbe(t *testing.T) {
	tokenBytes := make([]byte, 64)
	for i := range tokenBytes {
		tokenBytes[i] = byte(i * 3)
	}
	token, _ := ParseAccessToken("1234567890", hex.EncodeToString(tokenBytes))

	routingSessionID := uint64(0xDEADBEEF12345678)
	dstID := uint64(0x0000AABBCCDDEEFF)
	pwdKey := NewPasswordKey()

	frame := BuildNetworkDetectProbe(token, routingSessionID, 42, dstID, pwdKey, "192.168.1.100", 5, 3000)

	if len(frame) != 208 {
		t.Fatalf("frame size: got %d, want 208", len(frame))
	}

	if !DecryptFrameFull(frame, pwdKey) {
		t.Fatal("checksum invalid after decryption")
	}

	if frame[0] != ProtoSession {
		t.Errorf("proto: got 0x%02X", frame[0])
	}
	if frame[1] != SubTypeNetworkDetect {
		t.Errorf("sub_type: got 0x%02X", frame[1])
	}
	if binary.LittleEndian.Uint64(frame[28:36]) != dstID {
		t.Error("dst_id mismatch")
	}
	if binary.LittleEndian.Uint64(frame[36:44]) != token.AccessID {
		t.Error("caller_id mismatch")
	}
	if frame[52] != 5 {
		t.Errorf("type: got %d", frame[52])
	}
	if binary.LittleEndian.Uint16(frame[76:78]) != 3000 {
		t.Error("timeoutMs mismatch")
	}
	if binary.LittleEndian.Uint16(frame[78:80]) != 5 {
		t.Error("probeCount mismatch")
	}
	if string(frame[80:93]) != "192.168.1.100" || frame[93] != 0 {
		t.Error("IP string mismatch")
	}
}

func TestBuildCallingMsg(t *testing.T) {
	tokenBytes := make([]byte, 64)
	for i := range tokenBytes {
		tokenBytes[i] = byte(i * 7)
	}
	token, _ := ParseAccessToken("9876543210", hex.EncodeToString(tokenBytes))

	sessionKey := NewRC5Key([]byte("session-key-session-key-session-32!!"))
	pwdKey := NewPasswordKey()
	mtpKey := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	frame := BuildCallingMsg(token, 0x1122334455667788, 7, 0xCAFEF00D, 0xAAABBBCCEEDD,
		sessionKey, pwdKey, nil, 0, mtpKey)

	if len(frame) != 128 {
		t.Fatalf("frame size: got %d, want 128", len(frame))
	}

	decrypted := TryDecrypt(frame, sessionKey, pwdKey)
	if decrypted == nil {
		t.Fatal("failed to decrypt CALLING")
	}

	if decrypted[1] != SubTypeCalling {
		t.Errorf("sub_type: got 0x%02X", decrypted[1])
	}
	if binary.LittleEndian.Uint32(decrypted[28:32]) != 0xCAFEF00D {
		t.Error("link_id mismatch")
	}
	if binary.LittleEndian.Uint64(decrypted[32:40]) != token.AccessID {
		t.Error("src_id mismatch")
	}
	if binary.LittleEndian.Uint64(decrypted[40:48]) != 0xAAABBBCCEEDD {
		t.Error("dst_id mismatch")
	}
	for i := 0; i < 8; i++ {
		if decrypted[120+i] != mtpKey[i] {
			t.Error("MTP RC5 key mismatch")
			break
		}
	}
}

func TestParseInitInfoResp(t *testing.T) {
	// two devices, one entry with an offline flag byte
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint32(payload[0:4], 0)
	binary.LittleEndian.PutUint16(payload[4:6], 2)
	binary.LittleEndian.PutUint16(payload[6:8], 0)

	entry := make([]byte, 44)
	binary.LittleEndian.PutUint64(entry[0:8], 0x1111222233334444)
	copy(entry[12:], "GW_GC1_D03F2775AC2F")
	payload = append(payload, entry...)

	entry2 := make([]byte, 44)
	binary.LittleEndian.PutUint64(entry2[0:8], 0x5555666677778888)
	copy(entry2[12:], "GW_BE1_AABBCCDDEEFF")
	payload = append(payload, entry2...)

	devices := ParseInitInfoResp(payload)
	if len(devices) != 2 {
		t.Fatalf("got %d devices, want 2", len(devices))
	}
	if devices[0].TID != 0x1111222233334444 {
		t.Errorf("TID: got 0x%016X", devices[0].TID)
	}
	if devices[0].Name != "GW_GC1_D03F2775AC2F" {
		t.Errorf("Name: got %q", devices[0].Name)
	}
	if devices[1].TID != 0x5555666677778888 {
		t.Errorf("TID: got 0x%016X", devices[1].TID)
	}
}

func TestParseInitInfoRespBadCount(t *testing.T) {
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[4:6], 500)
	if devices := ParseInitInfoResp(payload); devices != nil {
		t.Errorf("expected nil for bad count, got %d devices", len(devices))
	}
}

func encodeBase64(b []byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, 0, (len(b)+2)/3*4)
	for i := 0; i < len(b); i += 3 {
		var n, count int
		n = int(b[i]) << 16
		count = 1
		if i+1 < len(b) {
			n |= int(b[i+1]) << 8
			count = 2
		}
		if i+2 < len(b) {
			n |= int(b[i+2])
			count = 3
		}
		out = append(out, chars[(n>>18)&63], chars[(n>>12)&63])
		if count > 1 {
			out = append(out, chars[(n>>6)&63])
		} else {
			out = append(out, '=')
		}
		if count > 2 {
			out = append(out, chars[n&63])
		} else {
			out = append(out, '=')
		}
	}
	return string(out)
}
