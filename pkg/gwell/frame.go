package gwell

import (
	"encoding/binary"
	"fmt"
	"math/rand"
)

// GUTES frame header (24 bytes):
//
//	Offset  Size  Field
//	0       1     proto (0x7F=plain, 0x7E=session)
//	1       1     sub_type
//	2       2     frame_len (LE, total frame size including header)
//	4       4     word1 (session ID or access ID, low 32 bits)
//	8       4     word2 (high 32 bits)
//	12      4     sqnum
//	16      4     chkval
//	20      4     flags
//	24+     N     payload

const (
	ProtoPlain       byte = 0x7F
	ProtoSession     byte = 0x7E
	FrameHeader           = 24
	FlagEncryptMode       = 16 // bits 16-17: encryption mode (0..3)
	FlagHasSignature      = 1 << 22
	FlagHasNTPTime        = 1 << 24
	FlagSendType          = 18 // bits 18-19
	FlagAck               = 1 << 20
	FlagResponse          = 1 << 21 // opt_resp: skip checksum verification
)

// Frame sub-types (byte 1).
const (
	SubTypeListRequest   byte = 0x15 // ListFrmRequest (to list servers, port 51701)
	SubTypeListResponse  byte = 0x16
	SubTypeDetectReq     byte = 0x17 // DetectRequest (to discovered servers)
	SubTypeDetectReq2    byte = 0x01 // DetectRequest2 (initial detect)
	SubTypeDetectResp    byte = 0x02
	SubTypeSessionInit   byte = 0x0C // CertifyReq
	SubTypeSessionResp   byte = 0x0D // CertifyResp / routing session
	SubTypeHeartbeat     byte = 0xA0
	SubTypeInitInfoMsg   byte = 0xA6 // registration + device list query
	SubTypeInitInfoResp  byte = 0xA7
	SubTypeMTPResResp    byte = 0xA3
	SubTypeCalling       byte = 0xA4
	SubTypeNetworkDetect byte = 0xB9
	SubTypeSubscribe     byte = 0xB0
	SubTypeSubscribeResp byte = 0xB1
	SubTypePortStatReq   byte = 0xCA
	SubTypePortStatResp  byte = 0xCB
)

// GetEncryptDataLen computes how many payload bytes are encrypted and
// checksummed. Signature (80 bytes) and NTP time (16 bytes) trailers are
// excluded.
func GetEncryptDataLen(frame []byte) int {
	if len(frame) < FrameHeader {
		return 0
	}
	totalLen := int(binary.LittleEndian.Uint16(frame[2:4]))
	flags := binary.LittleEndian.Uint32(frame[20:24])

	encLen := totalLen - FrameHeader
	if flags&FlagHasSignature != 0 {
		encLen -= 0x50
	}
	if flags&FlagHasNTPTime != 0 {
		encLen -= 0x10
	}
	if encLen < 0 {
		encLen = 0
	}
	return encLen
}

// InitChkval computes the frame checksum and stores it at offset 16:
//
//	chk = flags & 0xFFFFFF ^ dword[0] ^ dword[1] ^ dword[2] ^ dword[3]
//	      ^ every payload dword inside the encrypted region
func InitChkval(frame []byte) {
	if len(frame) < FrameHeader {
		return
	}

	chk := binary.LittleEndian.Uint32(frame[20:24]) & 0xFFFFFF
	chk ^= binary.LittleEndian.Uint32(frame[0:4])
	chk ^= binary.LittleEndian.Uint32(frame[4:8])
	chk ^= binary.LittleEndian.Uint32(frame[8:12])
	chk ^= binary.LittleEndian.Uint32(frame[12:16])

	end := FrameHeader + GetEncryptDataLen(frame)
	if end > len(frame) {
		end = len(frame)
	}
	for i := FrameHeader; i+4 <= end; i += 4 {
		chk ^= binary.LittleEndian.Uint32(frame[i : i+4])
	}

	binary.LittleEndian.PutUint32(frame[16:20], chk)
}

// VerifyChkval checks the frame checksum.
func VerifyChkval(frame []byte) bool {
	if len(frame) < FrameHeader {
		return false
	}
	stored := binary.LittleEndian.Uint32(frame[16:20])

	chk := binary.LittleEndian.Uint32(frame[20:24]) & 0xFFFFFF
	chk ^= binary.LittleEndian.Uint32(frame[0:4])
	chk ^= binary.LittleEndian.Uint32(frame[4:8])
	chk ^= binary.LittleEndian.Uint32(frame[8:12])
	chk ^= binary.LittleEndian.Uint32(frame[12:16])

	end := FrameHeader + GetEncryptDataLen(frame)
	if end > len(frame) {
		end = len(frame)
	}
	for i := FrameHeader; i+4 <= end; i += 4 {
		chk ^= binary.LittleEndian.Uint32(frame[i : i+4])
	}

	return chk == stored
}

// BuildListFrmRequest constructs a 40-byte ListFrmRequest frame.
func BuildListFrmRequest() []byte {
	buf := make([]byte, 40)
	buf[0] = ProtoPlain
	buf[1] = SubTypeListRequest
	binary.LittleEndian.PutUint16(buf[2:4], 40)
	binary.LittleEndian.PutUint32(buf[20:24], 0x00010000)
	for i := 4; i < 40; i += 4 {
		binary.LittleEndian.PutUint32(buf[i:i+4], rand.Uint32())
	}
	InitChkval(buf)
	return buf
}

// BuildDetectReq2 constructs the 68-byte initial DetectRequest2 frame.
func BuildDetectReq2() []byte {
	buf := make([]byte, 68)
	buf[0] = ProtoPlain
	buf[1] = SubTypeDetectReq2
	binary.LittleEndian.PutUint16(buf[2:4], 68)
	for i := 4; i < 64; i += 4 {
		binary.LittleEndian.PutUint32(buf[i:i+4], rand.Uint32())
	}
	binary.LittleEndian.PutUint32(buf[20:24], 0x00010000)
	binary.LittleEndian.PutUint32(buf[64:68], 0)
	InitChkval(buf)
	return buf
}

// BuildDetectRequest constructs the 44-byte DetectRequest frame sent to
// discovered P2P servers.
func BuildDetectRequest() []byte {
	buf := make([]byte, 44)
	buf[0] = ProtoPlain
	buf[1] = SubTypeDetectReq
	binary.LittleEndian.PutUint16(buf[2:4], 44)
	for i := 4; i < 40; i += 4 {
		binary.LittleEndian.PutUint32(buf[i:i+4], rand.Uint32())
	}
	binary.LittleEndian.PutUint32(buf[20:24], 0x00010000)
	binary.LittleEndian.PutUint32(buf[40:44], 0)
	InitChkval(buf)
	return buf
}

// subTypeName returns a readable name for a frame sub-type (debug logging).
func subTypeName(sub byte) string {
	switch sub {
	case SubTypeDetectReq2:
		return "DETECT_REQ"
	case SubTypeDetectResp:
		return "DETECT_RESP"
	case SubTypeSessionInit:
		return "SESSION_INIT"
	case SubTypeSessionResp:
		return "SESSION_RESP"
	case SubTypeHeartbeat:
		return "HEARTBEAT"
	case SubTypeInitInfoMsg:
		return "INIT_INFO"
	case SubTypeInitInfoResp:
		return "INIT_INFO_RESP"
	case SubTypeMTPResResp:
		return "MTP_RES"
	case SubTypeCalling:
		return "CALLING"
	case SubTypeNetworkDetect:
		return "PASSTHROUGH"
	case SubTypeSubscribe:
		return "SUBSCRIBE"
	case SubTypeSubscribeResp:
		return "SUBSCRIBE_RESP"
	case SubTypePortStatReq:
		return "PORT_STAT_REQ"
	case SubTypePortStatResp:
		return "PORT_STAT_RESP"
	}
	return fmt.Sprintf("0x%02X", sub)
}
