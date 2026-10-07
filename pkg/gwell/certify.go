package gwell

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"net"
	"strconv"
	"time"
)

// AccessToken holds the Mars credentials issued per camera by the Wyze cloud
// (regist_gw_user). The accessToken hex string is decoded into 64 bytes, and
// the RC5-64 key for CertifyReq inner encryption is taken from bytes [48:64].
type AccessToken struct {
	AccessID       uint64
	TokenBytes     [64]byte
	TokenKey       *RC5Key64
	TokenKeyRaw    [16]byte
	ExtraTokenData []byte // base64-decoded data after the first 128 hex chars
}

// ParseAccessToken parses the accessId (decimal string) and accessToken
// (hex string, at least 128 chars) from the Wyze Mars API.
func ParseAccessToken(accessID, accessToken string) (*AccessToken, error) {
	id, err := strconv.ParseUint(accessID, 10, 64)
	if err != nil {
		signedID, err2 := strconv.ParseInt(accessID, 10, 64)
		if err2 != nil {
			return nil, fmt.Errorf("parse accessId %q: %w", accessID, err)
		}
		id = uint64(signedID)
	}

	if len(accessToken) < 128 {
		return nil, fmt.Errorf("accessToken too short: %d hex chars (need >= 128)", len(accessToken))
	}

	decoded, err := hex.DecodeString(accessToken[:128])
	if err != nil {
		return nil, fmt.Errorf("decode accessToken hex: %w", err)
	}

	at := &AccessToken{AccessID: id}
	copy(at.TokenBytes[:], decoded)
	copy(at.TokenKeyRaw[:], decoded[48:64])
	at.TokenKey = NewRC5Key64(at.TokenKeyRaw[:])

	if len(accessToken) > 128 {
		extraBytes, err := base64.StdEncoding.DecodeString(accessToken[128:])
		if err != nil {
			extraBytes, err = base64.RawStdEncoding.DecodeString(accessToken[128:])
		}
		if err == nil && len(extraBytes) > 0 {
			at.ExtraTokenData = extraBytes
		}
	}

	return at, nil
}

// Word1 returns the low 32 bits of the AccessID.
func (at *AccessToken) Word1() uint32 { return uint32(at.AccessID) }

// Word2 returns the high 32 bits of the AccessID.
func (at *AccessToken) Word2() uint32 { return uint32(at.AccessID >> 32) }

// CertifyResult holds the output of a successful CertifyReq/CertifyResp
// exchange with the Mars server.
type CertifyResult struct {
	SessionID  uint64   // 8-byte session ID from CertifyResp
	SessionKey *RC5Key  // the random key from CertifyReq, used as RC5-32 key
	RandomKey  [32]byte // raw 32-byte random key
}

// BuildCertifyReq constructs the 164-byte CertifyReq frame (sub=0x0C):
//
//	[24:28]  opt_flags (bit 0 = has_version)
//	[28:32]  hash of the random key
//	[32:64]  random key encrypted with the token RC5-64 key (2x16 bytes)
//	[64:68]  version/MTU (1032)
//	[68:84]  NTP time (plaintext)
//	[84:164] 80-byte signature (plaintext)
func BuildCertifyReq(token *AccessToken, sqnum uint32) ([]byte, [32]byte) {
	const totalSize = FrameHeader + 44 + 16 + 80

	frame := make([]byte, totalSize)
	frame[0] = ProtoPlain
	frame[1] = SubTypeSessionInit
	binary.LittleEndian.PutUint16(frame[2:4], uint16(totalSize))
	binary.LittleEndian.PutUint32(frame[4:8], token.Word1())
	binary.LittleEndian.PutUint32(frame[8:12], token.Word2())
	binary.LittleEndian.PutUint32(frame[12:16], sqnum)

	randBits := uint32(mrand.Intn(0x7FFF)) << 1
	flags := randBits | (1 << FlagEncryptMode) | (3 << FlagSendType) | FlagHasSignature | FlagHasNTPTime
	binary.LittleEndian.PutUint32(frame[20:24], flags)

	binary.LittleEndian.PutUint32(frame[24:28], 0x00000001) // has_version

	var randomKey [32]byte
	_, _ = rand.Read(randomKey[:])

	binary.LittleEndian.PutUint32(frame[28:32], GiotHashString(randomKey[:]))

	copy(frame[32:64], randomKey[:])
	token.TokenKey.EncryptBlock16(frame[32:48])
	token.TokenKey.EncryptBlock16(frame[48:64])

	binary.LittleEndian.PutUint32(frame[64:68], 1032) // MTU

	ntpTime := uint64(time.Now().UnixMilli())
	binary.LittleEndian.PutUint64(frame[68:76], ntpTime)

	// Order matters: checksum feeds the signature HMAC, then encrypt
	InitChkval(frame)
	buildSignature(frame, token, sqnum)

	pwdKey := NewPasswordKey()
	EncryptFrame(frame)
	EncryptID(frame, pwdKey)

	return frame, randomKey
}

// buildSignature generates the 80-byte signature of a CertifyReq frame:
//
//	[0:2]   header {0x01, nonce[0]|0x01}
//	[2:4]   checkval of nonce(12) + plaintext token data (48 bytes)
//	[4:16]  nonce
//	[16:64] AES-CBC encrypted token data (decoded token bytes [0:48])
//	[64:80] HMAC-MD5 of sqnum + chkval + sig[0:64] with plaintext token data
func buildSignature(frame []byte, token *AccessToken, sqnum uint32) {
	sig := frame[len(frame)-80:]

	var nonce [12]byte
	_, _ = rand.Read(nonce[:])

	sig[0] = 0x01
	sig[1] = nonce[0] | 0x01
	copy(sig[4:16], nonce[:])

	var tokenData [48]byte
	copy(tokenData[:], token.TokenBytes[:48])

	// Place plaintext token data for the nonce checkval computation
	copy(sig[16:64], tokenData[:])
	binary.LittleEndian.PutUint16(sig[2:4], getSignatureCheckval(sig[4:64]))

	// HMAC over sqnum + chkval + sig[0:64] with PLAINTEXT token data
	var hmacData [72]byte
	binary.LittleEndian.PutUint32(hmacData[0:4], sqnum)
	copy(hmacData[4:8], frame[16:20])
	copy(hmacData[8:72], sig[0:64])
	copy(sig[64:80], hmacMD5(token.TokenKeyRaw[:], hmacData[:]))

	// Now AES encrypt the token data with the nonce as key
	aesEncryptCBC(tokenData[:], nonce[:])
	copy(sig[16:64], tokenData[:])
}

// BuildCertifyReqRaw is like BuildCertifyReq but skips the outer mode-1
// frame encryption, keeping only the ID encryption. Some servers reject
// the outer encryption; the client retries with this variant.
func BuildCertifyReqRaw(token *AccessToken, sqnum uint32) ([]byte, [32]byte) {
	const totalSize = FrameHeader + 44 + 16 + 80

	frame := make([]byte, totalSize)
	frame[0] = ProtoPlain
	frame[1] = SubTypeSessionInit
	binary.LittleEndian.PutUint16(frame[2:4], uint16(totalSize))
	binary.LittleEndian.PutUint32(frame[4:8], token.Word1())
	binary.LittleEndian.PutUint32(frame[8:12], token.Word2())
	binary.LittleEndian.PutUint32(frame[12:16], sqnum)

	randBits := uint32(mrand.Intn(0x7FFF)) << 1
	flags := randBits | (1 << FlagEncryptMode) | (3 << FlagSendType) | FlagHasSignature | FlagHasNTPTime
	binary.LittleEndian.PutUint32(frame[20:24], flags)

	binary.LittleEndian.PutUint32(frame[24:28], 0x00000001)

	var randomKey [32]byte
	_, _ = rand.Read(randomKey[:])

	binary.LittleEndian.PutUint32(frame[28:32], GiotHashString(randomKey[:]))

	copy(frame[32:64], randomKey[:])
	token.TokenKey.EncryptBlock16(frame[32:48])
	token.TokenKey.EncryptBlock16(frame[48:64])

	binary.LittleEndian.PutUint32(frame[64:68], 1032)

	ntpTime := uint64(time.Now().UnixMilli())
	binary.LittleEndian.PutUint64(frame[68:76], ntpTime)

	pwdKey := NewPasswordKey()
	InitChkval(frame)
	buildSignature(frame, token, sqnum)
	EncryptID(frame, pwdKey)

	return frame, randomKey
}

// ParseCertifyResp parses a decrypted CertifyResp frame:
// err_code at [26:28] (0 = success), session_id at [28:36].
// On success the session key is the random key from our CertifyReq.
func ParseCertifyResp(frame []byte, randomKey [32]byte, pwdKey *RC5Key) (*CertifyResult, error) {
	if len(frame) < 28 {
		return nil, fmt.Errorf("CertifyResp too short: %d bytes", len(frame))
	}

	DecryptID(frame, pwdKey)
	DecryptFrame(frame)

	errCode := binary.LittleEndian.Uint16(frame[26:28])
	if errCode != 0 {
		return nil, fmt.Errorf("CertifyResp: error code %d (0x%04X)", errCode, errCode)
	}

	result := &CertifyResult{RandomKey: randomKey}
	if len(frame) >= 36 {
		result.SessionID = binary.LittleEndian.Uint64(frame[28:36])
	}
	result.SessionKey = NewRC5Key(randomKey[:])

	return result, nil
}

// DeviceInfo holds a device TID and name from InitInfoResp.
type DeviceInfo struct {
	TID  uint64
	Name string
}

// ParseInitInfoResp parses an InitInfoResp (0xA7) payload:
//
//	[0:4]   opt_flags
//	[4:6]   device_count (uint16 LE)
//	[6:8]   flags (non-zero when some devices are offline)
//	per device (44 bytes): TID(8), field(2), attr(2), name(32, null-padded)
func ParseInitInfoResp(payload []byte) []DeviceInfo {
	if len(payload) < 8 {
		return nil
	}

	count := int(binary.LittleEndian.Uint16(payload[4:6]))
	if count < 1 || count > 32 {
		return nil
	}

	const nameFieldLen = 32
	const entryLen = 8 + 2 + 2 + nameFieldLen

	var devices []DeviceInfo
	off := 8
	for i := 0; i < count; i++ {
		if off+entryLen > len(payload) {
			break
		}
		tidLow := binary.LittleEndian.Uint32(payload[off : off+4])
		tidHigh := binary.LittleEndian.Uint32(payload[off+4 : off+8])
		tid := uint64(tidHigh)<<32 | uint64(tidLow)
		off += 12

		nameBytes := payload[off : off+nameFieldLen]
		name := ""
		for j, b := range nameBytes {
			if b == 0 {
				name = string(nameBytes[:j])
				break
			}
			if j == len(nameBytes)-1 {
				name = string(nameBytes)
			}
		}
		off += nameFieldLen

		devices = append(devices, DeviceInfo{TID: tid, Name: name})
	}
	return devices
}

// BuildInitInfoMsg constructs the 62-byte init_info_msg (sub=0xA6).
func BuildInitInfoMsg(token *AccessToken, sessionID uint64, sqnum uint32, sessionKey, pwdKey *RC5Key) []byte {
	const totalSize = 62

	frame := make([]byte, totalSize)
	frame[0] = ProtoPlain
	frame[1] = SubTypeInitInfoMsg
	binary.LittleEndian.PutUint16(frame[2:4], totalSize)
	binary.LittleEndian.PutUint32(frame[4:8], token.Word1())
	binary.LittleEndian.PutUint32(frame[8:12], token.Word2())
	binary.LittleEndian.PutUint32(frame[12:16], sqnum)
	binary.LittleEndian.PutUint32(frame[20:24], uint32(2<<FlagEncryptMode))

	binary.LittleEndian.PutUint32(frame[24:28], 0x3E)
	frame[27] = 2 // sub_mode

	EncryptFrameMode2(frame, sessionKey, pwdKey)
	return frame
}

// BuildSubscribeDevID constructs a device subscribe frame (sub=0xB0).
func BuildSubscribeDevID(token *AccessToken, sessionID uint64, sqnum uint32, devID uint64, useSessionID bool, sessionKey, pwdKey *RC5Key) []byte {
	const totalSize = 36

	frame := make([]byte, totalSize)
	if useSessionID {
		frame[0] = ProtoSession
		binary.LittleEndian.PutUint32(frame[4:8], uint32(sessionID))
		binary.LittleEndian.PutUint32(frame[8:12], uint32(sessionID>>32))
	} else {
		frame[0] = ProtoPlain
		binary.LittleEndian.PutUint32(frame[4:8], token.Word1())
		binary.LittleEndian.PutUint32(frame[8:12], token.Word2())
	}

	frame[1] = SubTypeSubscribe
	binary.LittleEndian.PutUint16(frame[2:4], totalSize)
	binary.LittleEndian.PutUint32(frame[12:16], sqnum)
	binary.LittleEndian.PutUint32(frame[20:24], uint32(2<<FlagEncryptMode))

	frame[25] = 0x01 // devid mode
	binary.LittleEndian.PutUint64(frame[28:36], devID)

	EncryptFrameMode2(frame, sessionKey, pwdKey)
	return frame
}

// BuildSubscribeTokens constructs a token-mode subscribe frame (sub=0xB0).
func BuildSubscribeTokens(token *AccessToken, sessionID uint64, sqnum uint32, tokenData []byte, useSessionID bool, sessionKey, pwdKey *RC5Key) []byte {
	totalSize := len(tokenData) + 28

	frame := make([]byte, totalSize)
	if useSessionID {
		frame[0] = ProtoSession
		binary.LittleEndian.PutUint32(frame[4:8], uint32(sessionID))
		binary.LittleEndian.PutUint32(frame[8:12], uint32(sessionID>>32))
	} else {
		frame[0] = ProtoPlain
		binary.LittleEndian.PutUint32(frame[4:8], token.Word1())
		binary.LittleEndian.PutUint32(frame[8:12], token.Word2())
	}

	frame[1] = SubTypeSubscribe
	binary.LittleEndian.PutUint16(frame[2:4], uint16(totalSize))
	binary.LittleEndian.PutUint32(frame[12:16], sqnum)
	binary.LittleEndian.PutUint32(frame[20:24], uint32(2<<FlagEncryptMode))

	frame[24] = byte(len(tokenData) / 80)
	copy(frame[28:], tokenData)

	EncryptFrameMode2(frame, sessionKey, pwdKey)
	return frame
}

// BuildCallingMsg constructs the 128-byte CALLING frame (sub=0xA4):
//
//	[24:26]  opt_flags (bit 0 always, bit 1 for LAN call)
//	[28:32]  link_id
//	[32:40]  src_id = accessId
//	[40:48]  dst_id = target device TID
//	[54:56]  our LAN port
//	[64:68]  our LAN IPv4
//	[120:128] MTP session RC5 key (8 bytes)
func BuildCallingMsg(token *AccessToken, routingSessionID uint64, sqnum uint32,
	linkID uint32, dstID uint64, sessionKey, pwdKey *RC5Key,
	lanIP net.IP, lanPort uint16, mtpRC5Key []byte,
) []byte {
	const totalSize = 128

	frame := make([]byte, totalSize)
	frame[1] = SubTypeCalling
	binary.LittleEndian.PutUint16(frame[2:4], totalSize)
	binary.LittleEndian.PutUint32(frame[12:16], sqnum)

	if routingSessionID != 0 {
		frame[0] = ProtoSession
		binary.LittleEndian.PutUint32(frame[4:8], uint32(routingSessionID))
		binary.LittleEndian.PutUint32(frame[8:12], uint32(routingSessionID>>32))
	} else {
		frame[0] = ProtoPlain
		binary.LittleEndian.PutUint32(frame[4:8], token.Word1())
		binary.LittleEndian.PutUint32(frame[8:12], token.Word2())
	}

	binary.LittleEndian.PutUint32(frame[20:24], uint32(2<<FlagEncryptMode)|uint32(1<<FlagSendType))

	optFlags := uint16(0x0001)
	if ip4 := lanIP.To4(); ip4 != nil {
		optFlags |= 0x0002
	}
	binary.LittleEndian.PutUint16(frame[24:26], optFlags)

	binary.LittleEndian.PutUint32(frame[28:32], linkID)
	binary.LittleEndian.PutUint64(frame[32:40], token.AccessID)
	binary.LittleEndian.PutUint64(frame[40:48], dstID)

	frame[50] |= 0x01

	if ip4 := lanIP.To4(); ip4 != nil {
		copy(frame[64:68], ip4)
		binary.LittleEndian.PutUint16(frame[54:56], lanPort)
	}

	if len(mtpRC5Key) >= 8 {
		copy(frame[120:128], mtpRC5Key[:8])
	}

	EncryptFrameMode2(frame, sessionKey, pwdKey)
	return frame
}

// BuildNetworkDetectProbe constructs the 208-byte network detect probe
// (sub=0xB9) that tells the camera about our LAN presence through the
// Mars server. Mode-1 encrypted.
func BuildNetworkDetectProbe(token *AccessToken, routingSessionID uint64, sqnum uint32, dstID uint64, pwdKey *RC5Key, lanIP string, probeCount uint16, timeoutMs uint16) []byte {
	const baseSize = 0x4C
	const payloadSize = 0x84
	const totalSize = baseSize + payloadSize

	frame := make([]byte, totalSize)
	frame[0] = ProtoPlain
	frame[1] = SubTypeNetworkDetect
	binary.LittleEndian.PutUint16(frame[2:4], uint16(totalSize))

	if routingSessionID != 0 {
		frame[0] = ProtoSession
		binary.LittleEndian.PutUint32(frame[4:8], uint32(routingSessionID))
		binary.LittleEndian.PutUint32(frame[8:12], uint32(routingSessionID>>32))
	} else {
		binary.LittleEndian.PutUint32(frame[4:8], token.Word1())
		binary.LittleEndian.PutUint32(frame[8:12], token.Word2())
	}

	binary.LittleEndian.PutUint32(frame[12:16], sqnum)

	randBits := uint32(mrand.Intn(0x7FFF)) << 1
	binary.LittleEndian.PutUint32(frame[20:24], randBits|(1<<FlagEncryptMode)|(1<<FlagSendType)|(1<<25))

	binary.LittleEndian.PutUint32(frame[24:28], 0x03) // inner flags
	binary.LittleEndian.PutUint64(frame[28:36], dstID)
	binary.LittleEndian.PutUint64(frame[36:44], token.AccessID)
	frame[52] = 5 // type = network detect

	binary.LittleEndian.PutUint16(frame[baseSize:baseSize+2], timeoutMs)
	binary.LittleEndian.PutUint16(frame[baseSize+2:baseSize+4], probeCount)
	copy(frame[baseSize+4:], []byte(lanIP))

	EncryptFrameFull(frame, pwdKey)
	return frame
}

// BuildHeartbeat constructs the 44-byte heartbeat frame (sub=0xA0).
func BuildHeartbeat(token *AccessToken, sessionID uint64, sqnum uint32, sessionKey, pwdKey *RC5Key) []byte {
	const totalSize = 44

	frame := make([]byte, totalSize)
	frame[0] = ProtoPlain
	frame[1] = SubTypeHeartbeat
	binary.LittleEndian.PutUint16(frame[2:4], totalSize)
	binary.LittleEndian.PutUint32(frame[4:8], token.Word1())
	binary.LittleEndian.PutUint32(frame[8:12], token.Word2())
	binary.LittleEndian.PutUint32(frame[12:16], sqnum)
	binary.LittleEndian.PutUint32(frame[20:24], uint32(2<<FlagEncryptMode))

	EncryptFrameMode2(frame, sessionKey, pwdKey)
	return frame
}
