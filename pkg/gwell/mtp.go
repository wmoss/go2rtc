package gwell

import (
	"encoding/binary"
	"fmt"
	"time"
)

// MTP (Media Transport Protocol) frames exchanged directly with the camera
// (or via a relay). Header formats:
//
//	Standard (6 bytes):  [0]=0xC0 magic, [1]=flags, [2:4]=len, [4:6]=cksum^len
//	Extended (14 bytes): [6:14] = destination TID (UDP relay routing)
//
// flags: bit7=urgent, bits5-6=extended mode, bit4=control.

// MTPPayloadOffset returns where the payload starts for the given flags byte.
func MTPPayloadOffset(flags byte) int {
	if (flags>>5)&3 != 0 {
		return 14
	}
	return 6
}

// MTPChecksum computes the frame checksum over 12 words starting at offset 6,
// each rotated left by its index.
func MTPChecksum(frame []byte) uint16 {
	var cs uint16
	for i := 0; i < 12; i++ {
		off := 6 + i*2
		if off+2 > len(frame) {
			break
		}
		val := binary.LittleEndian.Uint16(frame[off : off+2])
		cs ^= (val << uint(i)) | (val >> uint(16-i))
	}
	return cs
}

// mtpMaxLen is the largest total frame length the 11-bit MTP length field
// can encode (3 bits in frame[2] plus 8 bits in frame[3]).
const mtpMaxLen = 2047

// BuildMTPFrame wraps a payload into a standard 6-byte MTP header.
func BuildMTPFrame(payload []byte, urgent bool) []byte {
	totalLen := len(payload) + 6
	if totalLen > mtpMaxLen {
		// unreachable in practice (KCP output stays under the MSS), but a
		// wrapped length field would corrupt every following frame
		debugf("gwell: MTP frame too long: %d bytes (max %d)", totalLen, mtpMaxLen)
		totalLen = mtpMaxLen
	}
	frame := make([]byte, totalLen)
	frame[0] = 0xC0
	flags := byte(0x10)
	if urgent {
		flags |= 0x80
	}
	frame[1] = flags
	frame[2] = byte(totalLen & 7)
	frame[3] = byte((totalLen >> 3) & 0xFF)
	copy(frame[6:], payload)
	cs := MTPChecksum(frame)
	lenField := binary.LittleEndian.Uint16(frame[2:4])
	binary.LittleEndian.PutUint16(frame[4:6], cs^lenField)
	return frame
}

// BuildExtendedMTPFrame wraps a payload into a 14-byte MTP header with the
// destination TID, used for UDP relay transport.
func BuildExtendedMTPFrame(payload []byte, destTID uint64, urgent bool) []byte {
	totalLen := len(payload) + 14
	if totalLen > mtpMaxLen {
		debugf("gwell: MTP frame too long: %d bytes (max %d)", totalLen, mtpMaxLen)
		totalLen = mtpMaxLen
	}
	frame := make([]byte, totalLen)
	frame[0] = 0xC0
	flags := byte(1 << 5)
	if urgent {
		flags |= 0x80
	}
	frame[1] = flags
	frame[2] = byte(totalLen & 7)
	frame[3] = byte((totalLen >> 3) & 0xFF)
	binary.LittleEndian.PutUint64(frame[6:14], destTID)
	copy(frame[14:], payload)
	cs := MTPChecksum(frame)
	lenField := binary.LittleEndian.Uint16(frame[2:4])
	binary.LittleEndian.PutUint16(frame[4:6], cs^lenField)
	return frame
}

// MTP session control commands (prefix of the MTP payload).
const (
	mtpCmdCreateKCP    = 0x01 // meter request
	mtpCmdKCPAck       = 0x02 // meter ack
	mtpCmdSessionCtl   = 0x04
	mtpCmdSessionCtl2  = 0x06
	mtpCmdSessionCtl3  = 0x21
	mtpCmdSessionCtl4  = 0x24
	mtpCmdCreateKCPReq = 0x25 // create KCP session
)

// isMTPSessionCmd reports whether the command byte is a session control one.
func isMTPSessionCmd(cmd byte) bool {
	switch cmd {
	case mtpCmdCreateKCP, mtpCmdKCPAck, mtpCmdSessionCtl, mtpCmdSessionCtl2,
		mtpCmdSessionCtl3, mtpCmdSessionCtl4, mtpCmdCreateKCPReq:
		return true
	}
	return false
}

// BuildCreateKCPSessionMsg builds the 28-byte create-KCP-session message.
func BuildCreateKCPSessionMsg(linkID uint32, callingID, calledID uint64) []byte {
	msg := make([]byte, 28)
	msg[0] = 0x00
	msg[1] = mtpCmdCreateKCPReq
	binary.LittleEndian.PutUint16(msg[2:4], 0x001C)
	binary.LittleEndian.PutUint32(msg[4:8], linkID)
	binary.LittleEndian.PutUint64(msg[12:20], callingID)
	binary.LittleEndian.PutUint64(msg[20:28], calledID)
	return msg
}

// BuildMeterAckFromRequest echoes a meter request (cmd=0x01) as an ack
// (cmd=0x02), swapping src/dst IDs.
func BuildMeterAckFromRequest(reqPayload []byte) []byte {
	if len(reqPayload) < 68 {
		padded := make([]byte, 68)
		copy(padded, reqPayload)
		reqPayload = padded
	}
	ack := make([]byte, 68)
	copy(ack, reqPayload[:68])
	ack[1] = mtpCmdKCPAck
	var tmp [8]byte
	copy(tmp[:], ack[12:20])
	copy(ack[12:20], ack[20:28])
	copy(ack[20:28], tmp[:])
	return ack
}

// BuildMeterProbe builds a meter probe (cmd=0x01) that we initiate. The camera
// kills the session if no meter probes arrive for ~119 seconds.
func BuildMeterProbe(linkID uint32, srcID, dstID uint64, round uint32) []byte {
	probe := make([]byte, 68)
	probe[0] = 0x00
	probe[1] = mtpCmdCreateKCP
	binary.LittleEndian.PutUint16(probe[2:4], 0x0044)
	binary.LittleEndian.PutUint32(probe[4:8], linkID)
	binary.LittleEndian.PutUint64(probe[12:20], srcID)
	binary.LittleEndian.PutUint64(probe[20:28], dstID)
	binary.LittleEndian.PutUint32(probe[28:32], round)
	binary.LittleEndian.PutUint64(probe[36:44], uint64(time.Now().UnixMilli()))
	return probe
}

// BuildKCPPushSegment builds a KCP PUSH segment (cmd=81).
func BuildKCPPushSegment(conv uint32, sn uint32, ts uint32, data []byte) []byte {
	seg := make([]byte, 24+len(data))
	binary.LittleEndian.PutUint32(seg[0:4], conv)
	seg[4] = 81
	seg[5] = 0
	binary.LittleEndian.PutUint16(seg[6:8], 128)
	binary.LittleEndian.PutUint32(seg[8:12], ts)
	binary.LittleEndian.PutUint32(seg[12:16], sn)
	binary.LittleEndian.PutUint32(seg[16:20], 0)
	binary.LittleEndian.PutUint32(seg[20:24], uint32(len(data)))
	copy(seg[24:], data)
	return seg
}

// BuildKCPAckSegment builds a KCP ACK segment (cmd=82).
func BuildKCPAckSegment(conv uint32, sn uint32, ts uint32, una uint32) []byte {
	seg := make([]byte, 24)
	binary.LittleEndian.PutUint32(seg[0:4], conv)
	seg[4] = 82
	binary.LittleEndian.PutUint16(seg[6:8], 128)
	binary.LittleEndian.PutUint32(seg[8:12], ts)
	binary.LittleEndian.PutUint32(seg[12:16], sn)
	binary.LittleEndian.PutUint32(seg[16:20], una)
	return seg
}

// BuildTCPRelayRegister builds the 74-byte TCP relay registration frame.
func BuildTCPRelayRegister(linkID uint32, callingID, calledID uint64) []byte {
	frame := make([]byte, 74)
	frame[0] = 0xC0
	frame[1] = 0x80
	frame[2] = byte(74 & 7)
	frame[3] = byte((74 >> 3) & 0xFF)
	frame[6] = 0x00
	frame[7] = 0x01
	binary.LittleEndian.PutUint16(frame[8:10], 0x0044)
	binary.LittleEndian.PutUint32(frame[10:14], linkID)
	binary.LittleEndian.PutUint64(frame[18:26], callingID)
	binary.LittleEndian.PutUint64(frame[26:34], calledID)
	binary.LittleEndian.PutUint64(frame[38:46], uint64(time.Now().UnixMilli()))
	cs := MTPChecksum(frame)
	lenField := binary.LittleEndian.Uint16(frame[2:4])
	binary.LittleEndian.PutUint16(frame[4:6], cs^lenField)
	return frame
}

// AVSTREAMCTL actions (type=0x03 messages on the KCP channels).
const (
	AVActionINITREQ = 1
	AVActionACCEPT  = 2
	AVActionREJECT  = 3
	AVActionSTOP    = 4
	AVActionCLOSE   = 5
	AVActionSTART   = 6
)

// BuildAVStreamCtlINITREQ builds the 76-byte AVSTREAMCTL INITREQ.
// avKey must be 32 bytes: [0x02, 0, ...]. A non-zero streamID is required.
func BuildAVStreamCtlINITREQ(sessionID uint32, connType uint32, callAction uint32, channelField uint16, avKey []byte) []byte {
	buf := make([]byte, 76)
	buf[0] = 3
	buf[1] = 0x02
	binary.LittleEndian.PutUint16(buf[2:4], 0x004C)
	binary.LittleEndian.PutUint32(buf[4:8], sessionID)
	binary.LittleEndian.PutUint32(buf[8:12], AVActionINITREQ)
	binary.LittleEndian.PutUint32(buf[12:16], 0)
	binary.LittleEndian.PutUint32(buf[16:20], connType)
	binary.LittleEndian.PutUint32(buf[20:24], callAction)
	if len(avKey) >= 32 {
		copy(buf[24:56], avKey[:32])
	}
	binary.LittleEndian.PutUint16(buf[62:64], channelField)
	return buf
}

// BuildAVStreamCtlSTART builds the 76-byte AVSTREAMCTL START.
func BuildAVStreamCtlSTART(sessionID uint32) []byte {
	buf := make([]byte, 76)
	buf[0] = 3
	binary.LittleEndian.PutUint16(buf[2:4], 0x004C)
	binary.LittleEndian.PutUint32(buf[4:8], sessionID)
	binary.LittleEndian.PutUint32(buf[8:12], AVActionSTART)
	return buf
}

// BuildAVStreamCtlAccept builds an ACCEPT reply echoing the INITREQ streamID
// and carrying a 32-byte key at [24:56].
func BuildAVStreamCtlAccept(sessionID uint32, key []byte) []byte {
	buf := make([]byte, 76)
	buf[0] = 3
	buf[1] = 0x02
	binary.LittleEndian.PutUint16(buf[2:4], 0x004C)
	binary.LittleEndian.PutUint32(buf[4:8], sessionID)
	binary.LittleEndian.PutUint32(buf[8:12], AVActionACCEPT)
	if len(key) >= 32 {
		copy(buf[24:56], key[:32])
	}
	return buf
}

// BuildMTPResRequest builds the GUTES MTP_RES_REQUEST (sub=0xA2) sent after
// CALLING to obtain the transport addresses.
func BuildMTPResRequest(token *AccessToken, linkID uint32, calledTID uint64, routingSessionID uint64, sessionKey, pwdKey *RC5Key) []byte {
	frame := make([]byte, 0x7A)
	frame[0] = ProtoSession
	frame[1] = 0xA2
	binary.LittleEndian.PutUint16(frame[2:4], 0x7A)
	binary.LittleEndian.PutUint32(frame[4:8], uint32(routingSessionID))
	binary.LittleEndian.PutUint32(frame[8:12], uint32(routingSessionID>>32))
	binary.LittleEndian.PutUint32(frame[12:16], 0)
	binary.LittleEndian.PutUint32(frame[20:24], uint32(2<<FlagEncryptMode)|uint32(1<<FlagSendType))
	binary.LittleEndian.PutUint16(frame[0x18:0x1A], 0)
	binary.LittleEndian.PutUint32(frame[0x1A:0x1E], linkID)
	binary.LittleEndian.PutUint64(frame[0x1E:0x26], token.AccessID)
	binary.LittleEndian.PutUint64(frame[0x26:0x2E], calledTID)
	InitChkval(frame)
	EncryptFrameMode2(frame, sessionKey, pwdKey)
	return frame
}

// BuildPortStatReq builds the GUTES PortStatReq (sub=0xCA) probe.
func BuildPortStatReq(token *AccessToken, routingSessionID uint64, sqnum uint32, linkID uint32, calledTID uint64, pwdKey *RC5Key) []byte {
	frame := make([]byte, 0x34)
	frame[0] = ProtoPlain
	frame[1] = SubTypePortStatReq
	binary.LittleEndian.PutUint16(frame[2:4], 0x34)
	binary.LittleEndian.PutUint32(frame[4:8], uint32(routingSessionID))
	binary.LittleEndian.PutUint32(frame[8:12], uint32(routingSessionID>>32))
	binary.LittleEndian.PutUint32(frame[20:24], uint32(1<<FlagEncryptMode))
	binary.LittleEndian.PutUint64(frame[28:36], calledTID)
	binary.LittleEndian.PutUint32(frame[36:40], linkID)
	frame[41] = 1
	InitChkval(frame)
	EncryptFrameFull(frame, pwdKey)
	return frame
}

// BuildPortStatResp builds the GUTES PortStatResp (sub=0xCB).
func BuildPortStatResp(token *AccessToken, routingSessionID uint64, sqnum uint32, linkID uint32, calledTID uint64, pwdKey *RC5Key) []byte {
	frame := make([]byte, 0x34)
	frame[0] = ProtoPlain
	frame[1] = SubTypePortStatResp
	binary.LittleEndian.PutUint16(frame[2:4], 0x34)
	binary.LittleEndian.PutUint32(frame[4:8], uint32(routingSessionID))
	binary.LittleEndian.PutUint32(frame[8:12], uint32(routingSessionID>>32))
	binary.LittleEndian.PutUint32(frame[20:24], uint32(1<<FlagEncryptMode))
	binary.LittleEndian.PutUint64(frame[28:36], calledTID)
	binary.LittleEndian.PutUint32(frame[36:40], linkID)
	frame[41] = 1
	InitChkval(frame)
	EncryptFrameFull(frame, pwdKey)
	return frame
}

// BuildSessionSocket builds a GUTES 0xCA frame used for relay port
// activation and the 10-second online keepalive (subType=3).
func BuildSessionSocket(token *AccessToken, routingSessionID uint64, sqnum uint32, linkID uint32, calledTID uint64, subType byte, relayPorts []uint16, pwdKey *RC5Key) []byte {
	frame := make([]byte, 0x34)
	frame[0] = ProtoPlain
	frame[1] = SubTypePortStatReq
	binary.LittleEndian.PutUint16(frame[2:4], 0x34)
	binary.LittleEndian.PutUint32(frame[4:8], uint32(routingSessionID))
	binary.LittleEndian.PutUint32(frame[8:12], uint32(routingSessionID>>32))
	binary.LittleEndian.PutUint32(frame[20:24], uint32(1<<FlagEncryptMode))
	binary.LittleEndian.PutUint64(frame[28:36], calledTID)
	binary.LittleEndian.PutUint32(frame[36:40], linkID)
	frame[40] = 1
	frame[41] = subType
	for i := 0; i < 4 && i < len(relayPorts); i++ {
		binary.LittleEndian.PutUint16(frame[44+i*2:46+i*2], relayPorts[i])
	}
	InitChkval(frame)
	EncryptFrameFull(frame, pwdKey)
	return frame
}

// BuildPassthroughControl builds a GUTES PASSTHROUGH control frame (sub=0xB9)
// sent through the Mars server, used to trigger KCP creation.
func BuildPassthroughControl(token *AccessToken, routingSessionID uint64, sqnum uint32, targetTID uint64, command byte, linkID uint32, sessionKey, pwdKey *RC5Key) []byte {
	const totalSize = 76
	frame := make([]byte, totalSize)
	frame[0] = ProtoSession
	frame[1] = SubTypeNetworkDetect
	binary.LittleEndian.PutUint16(frame[2:4], totalSize)
	binary.LittleEndian.PutUint32(frame[4:8], uint32(routingSessionID))
	binary.LittleEndian.PutUint32(frame[8:12], uint32(routingSessionID>>32))
	binary.LittleEndian.PutUint32(frame[12:16], sqnum)
	binary.LittleEndian.PutUint32(frame[20:24], uint32(2<<FlagEncryptMode)|uint32(1<<FlagSendType))
	binary.LittleEndian.PutUint32(frame[24:28], 3)
	binary.LittleEndian.PutUint64(frame[28:36], targetTID)
	binary.LittleEndian.PutUint64(frame[36:44], token.AccessID)
	frame[52] = command
	binary.LittleEndian.PutUint32(frame[56:60], linkID)
	EncryptFrameMode2(frame, sessionKey, pwdKey)
	return frame
}

// FeedMTPToKCP extracts KCP data from an MTP frame and feeds it to the
// matching KCP instance. Returns the session control command (0x10000|cmd)
// if a session control message was present, otherwise 0.
func FeedMTPToKCP(buf []byte, n int, dataKCP, ctrlKCP *KCPConn, convData, convCtrl uint32) uint32 {
	if n < 6 || buf[0] != 0xC0 {
		return 0
	}
	flags := buf[1]
	payOff := MTPPayloadOffset(flags)
	if n < payOff+4 {
		return 0
	}
	sessCmd := uint32(0)
	if n >= payOff+8 && buf[payOff] == 0x00 {
		cmd := buf[payOff+1]
		if isMTPSessionCmd(cmd) {
			sessLen := binary.LittleEndian.Uint16(buf[payOff+2 : payOff+4])
			sessCmd = 0x10000 | uint32(cmd)
			payOff += int(sessLen)
		}
	}
	if payOff+24 > n {
		return sessCmd
	}
	kcpData := buf[payOff:n]
	firstConv := binary.LittleEndian.Uint32(kcpData[0:4])
	allSameConv := true
	off := 0
	for off+24 <= len(kcpData) {
		segConv := binary.LittleEndian.Uint32(kcpData[off : off+4])
		segLen := binary.LittleEndian.Uint32(kcpData[off+20 : off+24])
		if segConv != firstConv {
			allSameConv = false
			break
		}
		off += 24 + int(segLen)
	}
	if allSameConv {
		if firstConv == convCtrl && ctrlKCP != nil {
			ctrlKCP.Input(kcpData)
		} else if firstConv == convData && dataKCP != nil {
			dataKCP.Input(kcpData)
		}
	} else {
		off = 0
		for off+24 <= len(kcpData) {
			segConv := binary.LittleEndian.Uint32(kcpData[off : off+4])
			segLen := binary.LittleEndian.Uint32(kcpData[off+20 : off+24])
			segEnd := off + 24 + int(segLen)
			if segEnd > len(kcpData) {
				break
			}
			seg := kcpData[off:segEnd]
			if segConv == convCtrl && ctrlKCP != nil {
				ctrlKCP.Input(seg)
			} else if segConv == convData && dataKCP != nil {
				dataKCP.Input(seg)
			}
			off = segEnd
		}
	}
	return sessCmd
}

// ParseMTPForAVSTREAMCTL scans an MTP frame for AVSTREAMCTL commands carried
// in KCP PUSH segments. Returns the action (1=INITREQ, 2=ACCEPT, 6=START),
// 0x10001 for meter requests, or 0. On ACCEPT the 32-byte key from [24:56]
// is written to acceptKeyOut if provided.
func ParseMTPForAVSTREAMCTL(buf []byte, n int, convCtrl, convData uint32, acceptKeyOut *[]byte) uint32 {
	if n < 6 || buf[0] != 0xC0 {
		return 0
	}
	flags := buf[1]
	payOff := MTPPayloadOffset(flags)
	if n < payOff+4 {
		return 0
	}

	sessionCtrlCmd := uint32(0)
	if n >= payOff+8 && buf[payOff] == 0x00 {
		sessCmd := buf[payOff+1]
		if isMTPSessionCmd(sessCmd) {
			sessLen := binary.LittleEndian.Uint16(buf[payOff+2 : payOff+4])
			sessionCtrlCmd = 0x10000 | uint32(sessCmd)
			payOff += int(sessLen)
			if payOff >= n {
				return sessionCtrlCmd
			}
		}
	}

	bestAvCmd := uint32(0)
	kcpStart := payOff
	for kcpStart+24 <= n {
		kcpCmd := buf[kcpStart+4]
		kcpLen := binary.LittleEndian.Uint32(buf[kcpStart+20 : kcpStart+24])

		kcpDataStart := kcpStart + 24
		if kcpCmd == 81 && kcpLen > 0 && n >= kcpDataStart+int(kcpLen) {
			kcpData := buf[kcpDataStart : kcpDataStart+int(kcpLen)]
			if kcpLen >= 12 && kcpData[0] == 3 {
				avCmd := binary.LittleEndian.Uint32(kcpData[8:12])
				if avCmd == AVActionACCEPT && kcpLen >= 56 && acceptKeyOut != nil {
					key := make([]byte, 32)
					copy(key, kcpData[24:56])
					*acceptKeyOut = key
				}
				if avCmd == AVActionACCEPT || bestAvCmd == 0 {
					bestAvCmd = avCmd
				}
			}
		}
		kcpStart += 24 + int(kcpLen)
		if kcpLen > 65536 {
			break
		}
	}

	if sessionCtrlCmd != 0 && bestAvCmd == 0 {
		return sessionCtrlCmd
	}
	if bestAvCmd != 0 {
		return bestAvCmd
	}
	return sessionCtrlCmd
}

// DecryptMTPPayload decrypts an MTP session TLV message received via KCP.
// Format: [type][flags][total_len LE][RC5-encrypted payload...].
// It returns the decrypted TLV payload for AV data frames (type 0x02 and
// 0x04): the multiplexed audio/video byte stream whose structure (audio
// sub-frames with 0xffffff88 head_info markers, H.264 Annex B video) is
// parsed by avMux. AVSTREAMCTL (0x03) frames are not encrypted and return
// nil.
func DecryptMTPPayload(data []byte, rc5Key *RC5Key) []byte {
	if len(data) < 4 {
		return nil
	}
	frameType := data[0]
	if frameType == 0x03 {
		return nil // AVSTREAMCTL: not encrypted, no media
	}
	if frameType != 0x02 && frameType != 0x04 {
		return nil
	}
	if rc5Key == nil {
		return nil
	}

	totalLen := int(binary.LittleEndian.Uint16(data[2:4]))

	payloadLen := totalLen - 4
	if payloadLen < 0 || totalLen > len(data) {
		payloadLen = len(data) - 4
	}
	numBlocks := payloadLen / 8
	for i := 0; i < numBlocks; i++ {
		off := 4 + i*8
		rc5Key.DecryptBlock(data[off : off+8])
	}

	avPayload := data[4:]
	if totalLen > 4 && totalLen <= len(data) {
		avPayload = data[4:totalLen]
	}

	// trace the decrypted TLV payload for the live-capture harness
	if len(avPayload) > 0 {
		tracef(fmt.Sprintf("mtp.%02x", frameType), avPayload)
	}

	return avPayload
}
