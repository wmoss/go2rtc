package gwell

// End-to-end test with a mock Mars server and a mock camera implementing
// the device side of the protocol. Validates the complete client flow:
// discovery, certify, initInfo, subscribe, CALLING, transport negotiation,
// the AVSTREAMCTL handshake and H.264 delivery over KCP.

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

const (
	mockCameraTID  = uint64(0x1122334455667788)
	mockDeviceName = "GW_HL_CAM4_D03F2775AC2F"
	mockMAC        = "D03F2775AC2F"
)

// test H.264 data (Annex B)
var (
	testSPS = []byte{0, 0, 0, 1, 0x67, 0x64, 0x00, 0x1f, 0xac, 0x24, 0x84, 0x01, 0x40, 0x16, 0xec, 0x04, 0x40, 0x00, 0x00, 0x03, 0x00, 0x40, 0x00, 0x00, 0x0c, 0x23, 0xc6, 0x0c, 0x92}
	testPPS = []byte{0, 0, 0, 1, 0x68, 0xee, 0x32, 0xc8, 0xb0}
	testIDR = append([]byte{0, 0, 0, 1, 0x65, 0xE5}, make([]byte, 4200)...)
	testP   = append([]byte{0, 0, 0, 1, 0x41, 0xE5}, make([]byte, 48)...)
)

// mockWorld plays both the Mars server and the camera.
type mockWorld struct {
	token *AccessToken

	marsConn *net.UDPConn
	camConn  *net.UDPConn

	pwdKey     *RC5Key
	sessionKey []byte // client's CertifyReq random key
	routingID  uint64

	// state filled by handleCalling
	cameraLinkID uint32
	cameraMTPKey []byte

	// camera state
	camMu        sync.Mutex
	camClient    *net.UDPAddr
	camDataKCP   *KCPConn
	camCtrlKCP   *KCPConn
	camKey       *RC5Key
	camStream    bool
	camStarted   bool
	silentCamera bool // simulates a sleeping battery camera: ignores CALLING
	lastMeter    time.Time

	marsClient *net.UDPAddr

	stop chan struct{}
	wg   sync.WaitGroup
}

func startMockWorld(t *testing.T, token *AccessToken) *mockWorld {
	t.Helper()

	w := &mockWorld{
		token:     token,
		pwdKey:    NewPasswordKey(),
		routingID: 0xAABBCCDD11223344,
		stop:      make(chan struct{}),
	}

	marsConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("mock mars listen: %v", err)
	}
	camConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("mock camera listen: %v", err)
	}
	w.marsConn = marsConn
	w.camConn = camConn

	w.wg.Add(2)
	go w.marsLoop()
	go w.cameraLoop()

	return w
}

func (w *mockWorld) close() {
	close(w.stop)
	_ = w.marsConn.Close()
	_ = w.camConn.Close()
	w.wg.Wait()
}

func (w *mockWorld) marsAddr() string {
	return w.marsConn.LocalAddr().String()
}

func (w *mockWorld) sessionKeyRC5() *RC5Key {
	if w.sessionKey == nil {
		return nil
	}
	return NewRC5Key(w.sessionKey)
}

// -------------------------------------------------------------- Mars role

func (w *mockWorld) marsLoop() {
	defer w.wg.Done()
	buf := make([]byte, 8192)

	for {
		select {
		case <-w.stop:
			return
		default:
		}
		_ = w.marsConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, addr, err := w.marsConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		w.marsClient = addr

		frame := make([]byte, n)
		copy(frame, buf[:n])
		if frame[0] == 0xC0 {
			continue
		}

		plain := TryDecrypt(frame, w.sessionKeyRC5(), w.pwdKey)
		if plain == nil {
			plain = frame
		}

		switch plain[1] {
		case SubTypeDetectReq2:
			w.sendDetectResp(addr)
		case SubTypeSessionInit:
			w.handleCertify(frame, addr)
		case SubTypeInitInfoMsg:
			w.handleInitInfo(addr)
		case SubTypeCalling:
			w.handleCalling(plain)
		}
	}
}

func (w *mockWorld) sendDetectResp(addr *net.UDPAddr) {
	resp := make([]byte, 56)
	resp[0] = ProtoPlain
	resp[1] = SubTypeDetectResp
	binary.LittleEndian.PutUint16(resp[2:4], 56)
	binary.LittleEndian.PutUint32(resp[20:24], FlagResponse)
	binary.LittleEndian.PutUint32(resp[0x1C:0x20], uint32(time.Now().Unix()))
	resp[0x24] = 88
	resp[0x26] = 86
	_, _ = w.marsConn.WriteToUDP(resp, addr)
}

// handleCertify verifies the client's random key and responds with a
// mode-1 CertifyResp carrying a session ID.
func (w *mockWorld) handleCertify(frame []byte, addr *net.UDPAddr) {
	work := make([]byte, len(frame))
	copy(work, frame)
	if !DecryptFrameFull(work, w.pwdKey) {
		return
	}

	var randomKey [32]byte
	copy(randomKey[:], work[32:64])
	w.token.TokenKey.DecryptBlock16(randomKey[0:16])
	w.token.TokenKey.DecryptBlock16(randomKey[16:32])

	if GiotHashString(randomKey[:]) != binary.LittleEndian.Uint32(work[28:32]) {
		return
	}
	w.sessionKey = randomKey[:]

	resp := make([]byte, 36)
	resp[0] = ProtoPlain
	resp[1] = SubTypeSessionResp
	binary.LittleEndian.PutUint16(resp[2:4], 36)
	binary.LittleEndian.PutUint32(resp[4:8], w.token.Word1())
	binary.LittleEndian.PutUint32(resp[8:12], w.token.Word2())
	binary.LittleEndian.PutUint32(resp[20:24], 1<<FlagEncryptMode)
	binary.LittleEndian.PutUint64(resp[28:36], 0x1234567890ABCDEF)

	InitChkval(resp)
	EncryptFrame(resp)
	EncryptID(resp, w.pwdKey)

	_, _ = w.marsConn.WriteToUDP(resp, addr)
}

// handleInitInfo responds with the routing session ID (0x0D) and the
// device list (0xA7), both mode-2 encrypted with the session key.
func (w *mockWorld) handleInitInfo(addr *net.UDPAddr) {
	sk := w.sessionKeyRC5()

	// 0x0D SessionResp with routing session ID
	resp := make([]byte, 36)
	resp[0] = ProtoSession
	resp[1] = SubTypeSessionResp
	binary.LittleEndian.PutUint16(resp[2:4], 36)
	binary.LittleEndian.PutUint32(resp[4:8], w.token.Word1())
	binary.LittleEndian.PutUint32(resp[8:12], w.token.Word2())
	binary.LittleEndian.PutUint32(resp[20:24], 2<<FlagEncryptMode)
	binary.LittleEndian.PutUint64(resp[28:36], w.routingID)
	EncryptFrameMode2(resp, sk, w.pwdKey)
	_, _ = w.marsConn.WriteToUDP(resp, addr)

	// 0xA7 device list with a single GW_ camera
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint32(payload[0:4], 0)
	binary.LittleEndian.PutUint16(payload[4:6], 1)

	entry := make([]byte, 44)
	binary.LittleEndian.PutUint64(entry[0:8], mockCameraTID)
	entry[8] = 1 // online
	copy(entry[12:], mockDeviceName)
	payload = append(payload, entry...)

	list := make([]byte, 24+len(payload))
	list[0] = ProtoSession
	list[1] = SubTypeInitInfoResp
	binary.LittleEndian.PutUint16(list[2:4], uint16(len(list)))
	binary.LittleEndian.PutUint32(list[4:8], w.token.Word1())
	binary.LittleEndian.PutUint32(list[8:12], w.token.Word2())
	binary.LittleEndian.PutUint32(list[20:24], 2<<FlagEncryptMode)
	copy(list[24:], payload)
	EncryptFrameMode2(list, sk, w.pwdKey)
	_, _ = w.marsConn.WriteToUDP(list, addr)
}

// handleCalling parses the CALLING frame, captures the MTP RC5 key for the
// camera role and responds with the CALLING ACK and MTP_RES_RESPONSE.
func (w *mockWorld) handleCalling(plain []byte) {
	w.camMu.Lock()
	silent := w.silentCamera
	w.camMu.Unlock()
	if silent {
		return // sleeping battery camera: never answers the call
	}

	sk := w.sessionKeyRC5()

	w.camMu.Lock()
	w.cameraLinkID = binary.LittleEndian.Uint32(plain[28:32])
	w.cameraMTPKey = make([]byte, 8)
	copy(w.cameraMTPKey, plain[120:128])
	cameraLinkID := w.cameraLinkID

	w.camKey = NewRC5Key(w.cameraMTPKey)
	w.camClient = w.marsClient
	w.camMu.Unlock()

	// CALLING ACK: camera address at [32:38]
	ack := make([]byte, 40)
	ack[0] = ProtoSession
	ack[1] = SubTypeCalling
	binary.LittleEndian.PutUint16(ack[2:4], 40)
	binary.LittleEndian.PutUint32(ack[20:24], uint32(2<<FlagEncryptMode)|uint32(FlagResponse))
	camAddr := w.camConn.LocalAddr().(*net.UDPAddr)
	copy(ack[32:36], camAddr.IP.To4())
	binary.LittleEndian.PutUint16(ack[36:38], uint16(camAddr.Port))
	EncryptFrameMode2(ack, sk, w.pwdKey)
	_, _ = w.marsConn.WriteToUDP(ack, w.marsClient)

	// MTP_RES_RESPONSE with camera ports
	res := make([]byte, 0x7A)
	res[0] = ProtoSession
	res[1] = SubTypeMTPResResp
	binary.LittleEndian.PutUint16(res[2:4], 0x7A)
	binary.LittleEndian.PutUint32(res[20:24], uint32(2<<FlagEncryptMode)|uint32(FlagResponse))
	binary.LittleEndian.PutUint32(res[0x1C:0x20], cameraLinkID)
	camPort := uint16(camAddr.Port)
	binary.LittleEndian.PutUint16(res[0x58:0x5A], camPort) // outer port
	binary.LittleEndian.PutUint16(res[0x5A:0x5C], camPort) // lan port
	binary.LittleEndian.PutUint16(res[0x5E:0x60], camPort) // session socket port
	copy(res[0x64:0x68], camAddr.IP.To4())                 // lan IP
	// relay counts at [0x78:0x7A] stay zero
	EncryptFrameMode2(res, sk, w.pwdKey)
	_, _ = w.marsConn.WriteToUDP(res, w.marsClient)
}

// ------------------------------------------------------------ camera role

func (w *mockWorld) cameraLoop() {
	defer w.wg.Done()
	buf := make([]byte, 8192)

	for {
		select {
		case <-w.stop:
			return
		default:
		}
		_ = w.camConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, addr, err := w.camConn.ReadFromUDP(buf)
		if err != nil {
			w.cameraPump()
			continue
		}

		w.camMu.Lock()
		w.camClient = addr
		w.camMu.Unlock()

		frame := make([]byte, n)
		copy(frame, buf[:n])

		if frame[0] == 0xC0 {
			w.cameraHandleMTP(frame)
		}
		w.cameraPump()
	}
}

func (w *mockWorld) cameraHandleMTP(frame []byte) {
	off := MTPPayloadOffset(frame[1])
	if off >= len(frame) {
		return
	}

	if len(frame) >= off+8 && frame[off] == 0x00 && isMTPSessionCmd(frame[off+1]) {
		switch frame[off+1] {
		case mtpCmdCreateKCP:
			// meter request from the client: reply with an ack
			end := off + 68
			if end > len(frame) {
				end = len(frame)
			}
			ack := BuildMeterAckFromRequest(frame[off:end])
			_, _ = w.camConn.WriteToUDP(BuildMTPFrame(ack, true), w.cameraClientSnapshot())
		case mtpCmdCreateKCPReq:
			// create KCP session
			w.camMu.Lock()
			w.cameraLinkID = binary.LittleEndian.Uint32(frame[off+4 : off+8])
			w.camMu.Unlock()
			w.cameraCreateKCP()
		}
		off += int(binary.LittleEndian.Uint16(frame[off+2 : off+4]))
	}

	w.camMu.Lock()
	dataKCP, ctrlKCP := w.camDataKCP, w.camCtrlKCP
	linkID := w.cameraLinkID
	w.camMu.Unlock()
	if dataKCP == nil || off+24 > len(frame) {
		return
	}

	convData := linkID & 0x7FFFFFFF
	convCtrl := linkID | 0x80000000

	kcpData := frame[off:]
	firstConv := binary.LittleEndian.Uint32(kcpData[0:4])
	if firstConv == convCtrl {
		ctrlKCP.Input(kcpData)
	} else if firstConv == convData {
		dataKCP.Input(kcpData)
	}
}

func (w *mockWorld) cameraClientSnapshot() *net.UDPAddr {
	w.camMu.Lock()
	defer w.camMu.Unlock()
	return w.camClient
}

func (w *mockWorld) cameraCreateKCP() {
	w.camMu.Lock()
	if w.camDataKCP != nil {
		w.camMu.Unlock()
		return
	}

	output := func(data []byte, size int) {
		if client := w.cameraClientSnapshot(); client != nil {
			_, _ = w.camConn.WriteToUDP(BuildMTPFrame(data[:size], false), client)
		}
	}

	linkID := w.cameraLinkID
	w.camDataKCP = NewKCPConn(linkID&0x7FFFFFFF, output)
	w.camCtrlKCP = NewKCPConn(linkID|0x80000000, output)
	w.camDataKCP.NoDelay(0, 5, 10, 1)
	w.camCtrlKCP.NoDelay(0, 5, 10, 1)
	w.camMu.Unlock()

	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-w.stop:
				return
			case <-ticker.C:
				now := uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
				w.camMu.Lock()
				d, c := w.camDataKCP, w.camCtrlKCP
				w.camMu.Unlock()
				if d != nil {
					d.Update(now)
					c.Update(now)
				}
			}
		}
	}()

	go w.cameraProcessKCP()
}

// cameraProcessKCP drains the camera KCP queues and reacts to control
// messages: INITREQ -> ACCEPT, START -> STARTED echo, AV_INIT -> video.
func (w *mockWorld) cameraProcessKCP() {
	for {
		select {
		case <-w.stop:
			return
		default:
		}

		w.camMu.Lock()
		d, c := w.camDataKCP, w.camCtrlKCP
		w.camMu.Unlock()
		if d == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}

		progress := false

		for {
			msg := c.Recv()
			if msg == nil {
				break
			}
			progress = true
			if len(msg) >= 12 && msg[0] == 0x03 {
				if binary.LittleEndian.Uint32(msg[8:12]) == AVActionINITREQ {
					sessionID := binary.LittleEndian.Uint32(msg[4:8])
					c.Send(BuildAVStreamCtlAccept(sessionID, make([]byte, 32)))
					c.Flush()
				}
			}
		}

		for {
			msg := d.Recv()
			if msg == nil {
				break
			}
			progress = true
			if len(msg) >= 12 && msg[0] == 0x03 {
				// the real camera sends STARTED once in reply to the
				// viewer's START and ignores the echoed copy
				if binary.LittleEndian.Uint32(msg[8:12]) == AVActionSTART && !w.camStarted {
					w.camMu.Lock()
					w.camStarted = true
					w.camMu.Unlock()
					d.Send(msg) // STARTED echo
					d.Flush()
				}
			}
			if len(msg) >= 4 && msg[0] == 0x04 {
				// viewer AV_INIT: start the media stream
				w.camMu.Lock()
				start := !w.camStream
				w.camStream = true
				w.camMu.Unlock()
				if start {
					go w.cameraStreamVideo()
				}
			}
		}

		if !progress {
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// cameraStreamVideo sends the multiplexed AV stream on DATA KCP, matching
// the real camera's wire format: video access units as [head_info][Annex B
// chunk...] messages interleaved with self-contained 350-byte audio
// sub-frames ([head_info][40 01][320 µ-law samples]).
func (w *mockWorld) cameraStreamVideo() {
	time.Sleep(50 * time.Millisecond)

	keyframe := append(append(append([]byte{}, testSPS...), testPPS...), testIDR...)

	// the first keyframe follows two audio sub-frames, exactly like the
	// live stream: audio, audio, video-head, video chunks
	subs := [][]byte{w.audioSubFrame(0), w.audioSubFrame(20000)}
	w.cameraSendAV(keyframe, subs)

	pts := uint32(20000)
	for i := 0; i < 100; i++ {
		select {
		case <-w.stop:
			return
		case <-time.After(50 * time.Millisecond):
		}
		pts += 20000
		w.cameraSendAV(testP, [][]byte{w.audioSubFrame(pts)})
	}
}

// audioSubFrame builds one 350-byte audio sub-frame: 28-byte head_info
// (audio marker, PTS in µs), the 40 01 prefix and 320 µ-law silence bytes.
func (w *mockWorld) audioSubFrame(pts uint32) []byte {
	sub := make([]byte, audioSubLen)
	copy(sub, []byte{0xFF, 0xFF, 0xFF, 0x88})
	binary.LittleEndian.PutUint32(sub[4:8], audioMarker)
	binary.LittleEndian.PutUint32(sub[20:24], pts)
	sub[28], sub[29] = 0x40, 0x01
	for i := 30; i < len(sub); i += 2 {
		sub[i] = 0x7E
		if i+1 < len(sub) {
			sub[i+1] = 0xFF
		}
	}
	return sub
}

// cameraSendAV sends one video access unit (preceded by packed audio
// sub-frames) as type=0x04 messages, RC5-encrypted with the MTP session key.
// Like the real camera, messages never exceed 1004 payload bytes: audio
// sub-frames stay atomic while video bytes split at any boundary, and the
// video head_info shares its message with the first chunk.
func (w *mockWorld) cameraSendAV(av []byte, audioSubs [][]byte) {
	w.camMu.Lock()
	key, d := w.camKey, w.camDataKCP
	w.camMu.Unlock()
	if key == nil || d == nil {
		return
	}

	const maxMsg = 1004

	var msg []byte
	flush := func() {
		if len(msg) > 0 {
			w.sendChunk(key, d, msg)
			msg = msg[:0]
		}
	}

	// audio sub-frames are atomic units
	for _, sub := range audioSubs {
		if len(msg)+len(sub) > maxMsg {
			flush()
		}
		msg = append(msg, sub...)
	}

	// video head_info: atomic, shares its message with the first chunk
	head := make([]byte, headInfoLen)
	copy(head, []byte{0xFF, 0xFF, 0xFF, 0x88})
	binary.LittleEndian.PutUint32(head[4:8], videoMarker)
	binary.LittleEndian.PutUint32(head[8:12], uint32(time.Now().UnixMilli()&0xFFFF))
	if len(msg)+len(head) > maxMsg {
		flush()
	}
	msg = append(msg, head...)

	// video bytes split freely across messages
	for off := 0; off < len(av); {
		if len(msg) >= maxMsg {
			flush()
		}
		n := minInt(maxMsg-len(msg), len(av)-off)
		msg = append(msg, av[off:off+n]...)
		off += n
	}
	flush()
}

func (w *mockWorld) sendChunk(key *RC5Key, d *KCPConn, chunk []byte) {
	msg := make([]byte, 4+len(chunk))
	msg[0] = 0x04
	msg[1] = 0x02
	binary.LittleEndian.PutUint16(msg[2:4], uint16(len(msg)))
	copy(msg[4:], chunk)

	numBlocks := len(chunk) / 8
	for i := 0; i < numBlocks; i++ {
		key.EncryptBlock(msg[4+i*8 : 4+i*8+8])
	}

	d.Send(msg)
	d.Flush()
}

// cameraPump sends meter requests to the client, which is how the real
// camera signals the CREATE_KCP phase.
func (w *mockWorld) cameraPump() {
	w.camMu.Lock()
	created := w.camDataKCP != nil
	hasKey := w.camKey != nil
	client := w.camClient
	linkID := w.cameraLinkID
	last := w.lastMeter
	w.camMu.Unlock()

	if client == nil || !hasKey {
		return
	}

	interval := 500 * time.Millisecond
	if created {
		interval = 2 * time.Second
	}
	if time.Since(last) < interval {
		return
	}
	w.camMu.Lock()
	w.lastMeter = time.Now()
	w.camMu.Unlock()

	probe := BuildMeterProbe(linkID, mockCameraTID, 0x9999999999999999, 1)
	_, _ = w.camConn.WriteToUDP(BuildMTPFrame(probe, true), client)
}
