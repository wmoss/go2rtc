package gwell

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMTPFrameRoundTrip(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	frame := BuildMTPFrame(payload, true)

	if frame[0] != 0xC0 {
		t.Errorf("magic: got 0x%02X", frame[0])
	}
	if frame[1]&0x80 == 0 {
		t.Error("urgent flag not set")
	}

	// length encoding: 3-bit + 8-bit shifted
	totalLen := int(frame[2]&7) | int(frame[3])<<3
	if totalLen != len(frame) {
		t.Errorf("length: got %d, want %d", totalLen, len(frame))
	}
	if !bytes.Equal(frame[6:], payload) {
		t.Error("payload mismatch")
	}

	// checksum must match the computed value XOR length field
	cs := MTPChecksum(frame)
	lenField := binary.LittleEndian.Uint16(frame[2:4])
	if binary.LittleEndian.Uint16(frame[4:6]) != cs^lenField {
		t.Error("checksum field mismatch")
	}
}

func TestMTPPayloadOffset(t *testing.T) {
	if MTPPayloadOffset(0x10) != 6 {
		t.Error("standard header offset should be 6")
	}
	if MTPPayloadOffset(0x20) != 14 {
		t.Error("extended header offset should be 14")
	}
}

func TestBuildMeterAckFromRequest(t *testing.T) {
	req := BuildMeterProbe(0x11223344, 0xAAAABBBBCCCCDDDD, 0x1111222233334444, 5)
	ack := BuildMeterAckFromRequest(req)

	if ack[1] != 0x02 {
		t.Errorf("ack cmd: got 0x%02X, want 0x02", ack[1])
	}
	if binary.LittleEndian.Uint64(ack[12:20]) != 0x1111222233334444 {
		t.Error("src/dst not swapped")
	}
	if binary.LittleEndian.Uint64(ack[20:28]) != 0xAAAABBBBCCCCDDDD {
		t.Error("src/dst not swapped")
	}
}

func TestBuildKCPPushSegment(t *testing.T) {
	data := []byte("hello kcp world")
	seg := BuildKCPPushSegment(0xDEADBEEF, 42, 1234, data)

	if len(seg) != 24+len(data) {
		t.Fatalf("segment size: got %d", len(seg))
	}
	if binary.LittleEndian.Uint32(seg[0:4]) != 0xDEADBEEF {
		t.Error("conv mismatch")
	}
	if seg[4] != 81 {
		t.Error("cmd mismatch")
	}
	if binary.LittleEndian.Uint32(seg[12:16]) != 42 {
		t.Error("sn mismatch")
	}
	if binary.LittleEndian.Uint32(seg[20:24]) != uint32(len(data)) {
		t.Error("length mismatch")
	}
	if !bytes.Equal(seg[24:], data) {
		t.Error("data mismatch")
	}
}

func TestFeedMTPToKCP(t *testing.T) {
	var gotData []byte
	output := func(data []byte, size int) {}

	ctrlConv := uint32(0x80000001)
	ctrl := NewKCPConn(ctrlConv, output)
	data := NewKCPConn(0x00000001, output)

	// build an MTP frame carrying one KCP PUSH segment on the ctrl conv
	kcpSeg := BuildKCPPushSegment(ctrlConv, 0, 1000, []byte("ctrl-payload"))
	frame := BuildMTPFrame(kcpSeg, false)

	sessCmd := FeedMTPToKCP(frame, len(frame), data, ctrl, 0x00000001, ctrlConv)
	if sessCmd != 0 {
		t.Errorf("unexpected session cmd: 0x%X", sessCmd)
	}

	gotData = ctrl.Recv()
	if string(gotData) != "ctrl-payload" {
		t.Errorf("ctrl KCP recv: got %q", gotData)
	}
}

func TestFeedMTPWithSessionCtlPrefix(t *testing.T) {
	ctrlConv := uint32(0x80000001)
	var captured [][]byte
	ctrl := NewKCPConn(ctrlConv, func(data []byte, size int) { captured = append(captured, data[:size]) })
	dataKCP := NewKCPConn(1, func(data []byte, size int) {})

	// meter request (session ctl cmd 0x01, len 68) followed by a KCP segment
	meter := BuildMeterProbe(9, 1, 2, 3)
	kcpSeg := BuildKCPPushSegment(ctrlConv, 0, 100, []byte("payload-after-meter"))
	frame := BuildMTPFrame(append(meter, kcpSeg...), true)

	sessCmd := FeedMTPToKCP(frame, len(frame), dataKCP, ctrl, 1, ctrlConv)
	if sessCmd != 0x10001 {
		t.Errorf("session cmd: got 0x%X, want 0x10001", sessCmd)
	}

	got := ctrl.Recv()
	if string(got) != "payload-after-meter" {
		t.Errorf("KCP data after session ctl: got %q", got)
	}
}

func TestParseMTPForAVSTREAMCTL(t *testing.T) {
	ctrlConv := uint32(0x80000001)
	dataConv := uint32(0x00000001)

	// ACCEPT on the ctrl conv with a 32-byte key
	accept := BuildAVStreamCtlAccept(77, bytes.Repeat([]byte{0xAB}, 32))
	seg := BuildKCPPushSegment(ctrlConv, 0, 1000, accept)
	frame := BuildMTPFrame(seg, false)

	var key []byte
	cmd := ParseMTPForAVSTREAMCTL(frame, len(frame), ctrlConv, dataConv, &key)
	if cmd != AVActionACCEPT {
		t.Errorf("cmd: got %d, want %d", cmd, AVActionACCEPT)
	}
	if len(key) != 32 || key[0] != 0xAB {
		t.Errorf("accept key: got %x", key)
	}

	// INITREQ
	initreq := BuildAVStreamCtlINITREQ(55, 1, 1, 0, append([]byte{0x02}, make([]byte, 31)...))
	seg = BuildKCPPushSegment(ctrlConv, 0, 1000, initreq)
	frame = BuildMTPFrame(seg, false)
	cmd = ParseMTPForAVSTREAMCTL(frame, len(frame), ctrlConv, dataConv, nil)
	if cmd != AVActionINITREQ {
		t.Errorf("cmd: got %d, want %d", cmd, AVActionINITREQ)
	}
}

func TestDecryptMTPPayloadVideo(t *testing.T) {
	mtpKey := NewRC5Key([]byte{9, 8, 7, 6, 5, 4, 3, 2})

	h264 := append([]byte{0, 0, 0, 1, 0x67, 0x64}, bytes.Repeat([]byte{0xEE}, 20)...)

	// first packet: head_info magic + 24 bytes codec params, then video
	first := append([]byte{0xFF, 0xFF, 0xFF, 0x88}, make([]byte, 24)...)
	first = append(first, h264...)

	msg := make([]byte, 4)
	msg[0] = 0x04 // AV data
	msg[1] = 0x02
	binary.LittleEndian.PutUint16(msg[2:4], uint16(4+len(first)))
	msg = append(msg, first...)

	// encrypt full 8-byte blocks like the camera does
	numBlocks := (len(msg) - 4) / 8
	for i := 0; i < numBlocks; i++ {
		mtpKey.EncryptBlock(msg[4+i*8 : 4+i*8+8])
	}

	got := DecryptMTPPayload(msg, mtpKey)
	if got == nil {
		t.Fatal("no payload extracted")
	}
	// returns the full TLV payload; the head is stripped by avMux
	if !bytes.Equal(got, first) {
		t.Errorf("payload mismatch:\n  got  %x\n  want %x", got, first)
	}
}

func TestDecryptMTPPayloadPartialBlock(t *testing.T) {
	mtpKey := NewRC5Key([]byte{9, 8, 7, 6, 5, 4, 3, 2})

	h264 := []byte{0, 0, 0, 1, 0x67, 0x64, 1, 2, 3} // 9 bytes: not a multiple of 8

	msg := make([]byte, 4)
	msg[0] = 0x04
	msg[1] = 0x02
	binary.LittleEndian.PutUint16(msg[2:4], uint16(4+len(h264)))
	msg = append(msg, h264...)

	numBlocks := (len(msg) - 4) / 8
	for i := 0; i < numBlocks; i++ {
		mtpKey.EncryptBlock(msg[4+i*8 : 4+i*8+8])
	}

	got := DecryptMTPPayload(msg, mtpKey)
	if got == nil {
		t.Fatal("no payload extracted")
	}
	if !bytes.Equal(got, h264) {
		t.Errorf("payload mismatch with partial block: got %x", got)
	}
}

func TestKCPBasicExchange(t *testing.T) {
	var received [][]byte

	var kcpA, kcpB *KCPConn
	kcpA = NewKCPConn(0x1234, func(data []byte, size int) {
		// A -> B: feed B's input
		kcpB.Input(append([]byte(nil), data[:size]...))
	})
	kcpB = NewKCPConn(0x1234, func(data []byte, size int) {
		// B -> A (ACKs)
		kcpA.Input(append([]byte(nil), data[:size]...))
	})
	kcpB.Output = func(data []byte, size int) {
		kcpA.Input(append([]byte(nil), data[:size]...))
	}
	_ = received

	kcpA.Send([]byte("hello world"))
	now := uint32(1000)
	kcpA.Update(now)
	kcpB.Update(now)

	// pump updates to flush ACKs
	for i := 0; i < 10; i++ {
		now += 10
		kcpA.Update(now)
		kcpB.Update(now)
	}

	got := kcpB.Recv()
	if string(got) != "hello world" {
		t.Errorf("KCP recv: got %q, want %q", got, "hello world")
	}
}

func TestKCPFragmentedMessage(t *testing.T) {
	var kcpA, kcpB *KCPConn
	kcpA = NewKCPConn(0x5678, func(data []byte, size int) {})
	kcpB = NewKCPConn(0x5678, func(data []byte, size int) {
		kcpA.Input(append([]byte(nil), data[:size]...))
	})

	// large message spanning multiple segments
	payload := make([]byte, 5000)
	for i := range payload {
		payload[i] = byte(i)
	}

	// manually pump A's output into B
	kcpA.Output = func(data []byte, size int) {
		kcpB.Input(append([]byte(nil), data[:size]...))
	}
	kcpA.SetMTU(1400)
	kcpB.SetMTU(1400)

	kcpA.Send(payload)

	now := uint32(1)
	for i := 0; i < 20; i++ {
		now += 10
		kcpA.Update(now)
		kcpB.Update(now)
	}

	got := kcpB.Recv()
	if len(got) != len(payload) {
		t.Fatalf("fragmented recv: got %d bytes, want %d", len(got), len(payload))
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("fragmented data mismatch at %d", i)
		}
	}
}

func TestKCPIncompleteFragmentChain(t *testing.T) {
	kcp := NewKCPConn(0x9ABC, func(data []byte, size int) {})
	now := uint32(100)

	// three-fragment message: frg=2, frg=1, frg=0
	build := func(sn uint32, frg byte, data []byte) []byte {
		seg := make([]byte, 24+len(data))
		binary.LittleEndian.PutUint32(seg[0:4], 0x9ABC)
		seg[4] = IKCP_CMD_PUSH
		seg[5] = frg
		binary.LittleEndian.PutUint16(seg[6:8], 512)
		binary.LittleEndian.PutUint32(seg[8:12], now)
		binary.LittleEndian.PutUint32(seg[12:16], sn)
		binary.LittleEndian.PutUint32(seg[16:20], 0) // una
		binary.LittleEndian.PutUint32(seg[20:24], uint32(len(data)))
		copy(seg[24:], data)
		return seg
	}

	// deliver only the first two fragments
	kcp.Input(build(0, 2, []byte("AAA")))
	kcp.Input(build(1, 1, []byte("BBB")))

	// an incomplete chain must not be delivered early
	if got := kcp.Recv(); got != nil {
		t.Fatalf("incomplete chain delivered early: %q", got)
	}

	// last fragment completes the message
	kcp.Input(build(2, 0, []byte("CCC")))
	got := kcp.Recv()
	if string(got) != "AAABBBCCC" {
		t.Fatalf("reassembled message: got %q, want %q", got, "AAABBBCCC")
	}
}

func TestKCPZeroLengthSegmentDoesNotWedge(t *testing.T) {
	kcp := NewKCPConn(0x9DEF, func(data []byte, size int) {})
	now := uint32(100)

	build := func(sn uint32, frg byte, data []byte) []byte {
		seg := make([]byte, 24+len(data))
		binary.LittleEndian.PutUint32(seg[0:4], 0x9DEF)
		seg[4] = IKCP_CMD_PUSH
		seg[5] = frg
		binary.LittleEndian.PutUint16(seg[6:8], 512)
		binary.LittleEndian.PutUint32(seg[8:12], now)
		binary.LittleEndian.PutUint32(seg[12:16], sn)
		binary.LittleEndian.PutUint32(seg[16:20], 0)
		binary.LittleEndian.PutUint32(seg[20:24], uint32(len(data)))
		copy(seg[24:], data)
		return seg
	}

	// an empty complete message at the queue head used to block Recv forever
	kcp.Input(build(0, 0, nil))

	if got := kcp.Recv(); got != nil {
		t.Fatalf("empty message returned data: %q", got)
	}

	// the following real message must still be delivered
	kcp.Input(build(1, 0, []byte("DATA")))
	if got := kcp.Recv(); string(got) != "DATA" {
		t.Fatalf("message after empty segment: got %q, want %q", got, "DATA")
	}
}
