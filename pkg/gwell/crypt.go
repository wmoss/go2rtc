package gwell

import "encoding/binary"

// EncryptFrame applies mode-1 encryption in place: the sqnum+chkval field
// [0x0C:0x14] and payload 8-byte blocks inside the encrypted region are
// encrypted with the per-frame RC5 key. The ID field is not touched.
func EncryptFrame(frame []byte) {
	k := FrameKey(frame)
	if k == nil {
		return
	}
	if len(frame) >= 0x14 {
		k.EncryptBlock(frame[0x0C:0x14])
	}
	end := FrameHeader + GetEncryptDataLen(frame)
	if end > len(frame) {
		end = len(frame)
	}
	for off := 0x18; off+8 <= end; off += 8 {
		k.EncryptBlock(frame[off : off+8])
	}
}

// DecryptFrame reverses mode-1 encryption in place.
func DecryptFrame(frame []byte) {
	k := FrameKey(frame)
	if k == nil {
		return
	}
	if len(frame) >= 0x14 {
		k.DecryptBlock(frame[0x0C:0x14])
	}
	end := FrameHeader + GetEncryptDataLen(frame)
	if end > len(frame) {
		end = len(frame)
	}
	for off := 0x18; off+8 <= end; off += 8 {
		k.DecryptBlock(frame[off : off+8])
	}
}

// EncryptID encrypts word1/word2 in place with the password key:
//
//  1. RC5 encrypt frame[4:12]
//  2. frame[4:8] ^= encrypted sqnum, frame[8:12] ^= encrypted chkval
//
// Must be called AFTER EncryptFrame/EncryptFrameMode2.
func EncryptID(frame []byte, pwdKey *RC5Key) {
	if len(frame) < 0x14 || pwdKey == nil {
		return
	}
	pwdKey.EncryptBlock(frame[4:12])

	w1 := binary.LittleEndian.Uint32(frame[4:8])
	w2 := binary.LittleEndian.Uint32(frame[8:12])
	encSq := binary.LittleEndian.Uint32(frame[0x0C:0x10])
	encCk := binary.LittleEndian.Uint32(frame[0x10:0x14])
	binary.LittleEndian.PutUint32(frame[4:8], w1^encSq)
	binary.LittleEndian.PutUint32(frame[8:12], w2^encCk)
}

// DecryptID reverses EncryptID. Must be called BEFORE DecryptFrame.
func DecryptID(frame []byte, pwdKey *RC5Key) {
	if len(frame) < 0x14 || pwdKey == nil {
		return
	}
	w1 := binary.LittleEndian.Uint32(frame[4:8])
	w2 := binary.LittleEndian.Uint32(frame[8:12])
	encSq := binary.LittleEndian.Uint32(frame[0x0C:0x10])
	encCk := binary.LittleEndian.Uint32(frame[0x10:0x14])
	binary.LittleEndian.PutUint32(frame[4:8], w1^encSq)
	binary.LittleEndian.PutUint32(frame[8:12], w2^encCk)

	pwdKey.DecryptBlock(frame[4:12])
}

// EncryptFrameFull applies the complete mode-1 pipeline:
// checksum, frame encryption and ID encryption.
func EncryptFrameFull(frame []byte, pwdKey *RC5Key) {
	InitChkval(frame)
	EncryptFrame(frame)
	EncryptID(frame, pwdKey)
}

// DecryptFrameFull reverses the mode-1 pipeline and verifies the checksum
// (unless the opt_resp flag at bit 21 is set).
func DecryptFrameFull(frame []byte, pwdKey *RC5Key) bool {
	DecryptID(frame, pwdKey)
	DecryptFrame(frame)
	if len(frame) >= FrameHeader {
		if binary.LittleEndian.Uint32(frame[20:24])&FlagResponse != 0 {
			return true
		}
	}
	return VerifyChkval(frame)
}

// EncryptFrameMode2 applies mode-2 (session key) encryption: checksum, then
// sqnum+chkval and payload encrypted with the session key, then ID encryption.
func EncryptFrameMode2(frame []byte, sessionKey, pwdKey *RC5Key) {
	InitChkval(frame)
	if len(frame) >= 0x14 {
		sessionKey.EncryptBlock(frame[0x0C:0x14])
	}
	end := FrameHeader + GetEncryptDataLen(frame)
	if end > len(frame) {
		end = len(frame)
	}
	for off := 0x18; off+8 <= end; off += 8 {
		sessionKey.EncryptBlock(frame[off : off+8])
	}
	EncryptID(frame, pwdKey)
}

// DecryptFrameMode2 reverses mode-2 encryption and verifies the checksum
// (unless the opt_resp flag at bit 21 is set).
func DecryptFrameMode2(frame []byte, sessionKey, pwdKey *RC5Key) bool {
	DecryptID(frame, pwdKey)
	if len(frame) >= 0x14 {
		sessionKey.DecryptBlock(frame[0x0C:0x14])
	}
	end := FrameHeader + GetEncryptDataLen(frame)
	if end > len(frame) {
		end = len(frame)
	}
	for off := 0x18; off+8 <= end; off += 8 {
		sessionKey.DecryptBlock(frame[off : off+8])
	}
	if len(frame) >= FrameHeader {
		if binary.LittleEndian.Uint32(frame[20:24])&FlagResponse != 0 {
			return true
		}
	}
	return VerifyChkval(frame)
}

// TryDecrypt attempts to decrypt a frame with the mode indicated by its
// flags, falling back to the other modes. Returns the decrypted copy.
func TryDecrypt(raw []byte, sessionKey, pwdKey *RC5Key) []byte {
	if len(raw) < FrameHeader {
		return nil
	}
	flags := binary.LittleEndian.Uint32(raw[20:24])
	encMode := (flags >> FlagEncryptMode) & 3
	trial := make([]byte, len(raw))
	copy(trial, raw)

	switch encMode {
	case 2:
		if DecryptFrameMode2(trial, sessionKey, pwdKey) {
			return trial
		}
		copy(trial, raw)
		if DecryptFrameFull(trial, pwdKey) {
			return trial
		}
	case 1:
		if DecryptFrameFull(trial, pwdKey) {
			return trial
		}
		copy(trial, raw)
		if DecryptFrameMode2(trial, sessionKey, pwdKey) {
			return trial
		}
	case 0:
		DecryptID(trial, pwdKey)
		if VerifyChkval(trial) {
			return trial
		}
	}

	copy(trial, raw)
	if DecryptFrameFull(trial, pwdKey) {
		return trial
	}
	copy(trial, raw)
	if DecryptFrameMode2(trial, sessionKey, pwdKey) {
		return trial
	}
	copy(trial, raw)
	DecryptID(trial, pwdKey)
	if VerifyChkval(trial) {
		return trial
	}
	return nil
}
