package gwell

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/h264"
	"github.com/AlexxIT/go2rtc/pkg/h264/annexb"
)

func testToken(t *testing.T) *AccessToken {
	t.Helper()
	tokenBytes := make([]byte, 64)
	for i := range tokenBytes {
		tokenBytes[i] = byte(i * 5)
	}
	// extra token data for the token subscribe path
	extra := make([]byte, 80)
	for i := range extra {
		extra[i] = byte(i + 3)
	}
	token, err := ParseAccessToken("10593094227361022708", hex.EncodeToString(tokenBytes)+encodeBase64(extra))
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	return token
}

func testConfig(world *mockWorld, token *AccessToken) Config {
	return Config{
		Token:       token,
		ServerAddr:  world.marsAddr(),
		CameraLanIP: "127.0.0.1",
		DeviceMAC:   mockMAC,
	}
}

// TestSessionEndToEnd runs the full protocol flow against the mock world.
func TestSessionEndToEnd(t *testing.T) {
	token := testToken(t)
	world := startMockWorld(t, token)
	defer world.close()

	client := NewClient(testConfig(world, token))
	defer client.Close()

	if err := client.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	if client.targetDev.TID != mockCameraTID {
		t.Errorf("target TID: got 0x%016X, want 0x%016X", client.targetDev.TID, mockCameraTID)
	}
	if client.targetDev.Name != mockDeviceName {
		t.Errorf("target name: got %q", client.targetDev.Name)
	}
	if client.routingSessionID != world.routingID {
		t.Errorf("routing session: got 0x%016X, want 0x%016X", client.routingSessionID, world.routingID)
	}

	if err := client.Handshake(); err != nil {
		t.Fatalf("Handshake: %v", err)
	}

	// read frames: the multiplexed stream starts with audio sub-frames
	// packed ahead of the keyframe, then the keyframe (SPS+PPS+IDR)
	deadline := time.Now().Add(15 * time.Second)
	var keyframe []byte
	var audioFrames []*AudioFrame
	var pframes int
	for time.Now().Before(deadline) && (keyframe == nil || pframes < 3) {
		frame, err := client.ReadMedia()
		if err != nil {
			t.Fatalf("ReadMedia: %v", err)
		}
		switch frame.Kind {
		case MediaAudio:
			audioFrames = append(audioFrames, frame.Audio)
		case MediaVideo:
			if keyframe == nil {
				if len(frame.Video) < 5 || !bytes.HasPrefix(frame.Video, []byte{0, 0, 0, 1}) {
					continue
				}
				if avcc := annexb.EncodeToAVCC(frame.Video); len(avcc) >= 5 && h264.NALUType(avcc) == h264.NALUTypeSPS {
					keyframe = frame.Video
				}
			} else if bytes.Equal(frame.Video, testP) {
				pframes++
			}
		}
	}

	if keyframe == nil {
		t.Fatal("no keyframe received")
	}
	wantKeyframe := append(append(append([]byte{}, testSPS...), testPPS...), testIDR...)
	if !bytes.Equal(keyframe, wantKeyframe) {
		t.Errorf("keyframe mismatch: got %d bytes, want %d bytes\n  got  %x...\n  want %x...",
			len(keyframe), len(wantKeyframe), keyframe[:32], wantKeyframe[:32])
	}
	if pframes < 3 {
		t.Fatalf("expected 3 P-frames, got %d", pframes)
	}

	// audio sub-frames: 320 samples with 20ms PTS steps
	if len(audioFrames) < 3 {
		t.Fatalf("expected audio sub-frames, got %d", len(audioFrames))
	}
	for i, f := range audioFrames {
		if len(f.Data) != 320 {
			t.Errorf("audio frame %d: len=%d, want 320", i, len(f.Data))
			break
		}
		if f.Data[0] != 0x7E {
			t.Errorf("audio frame %d: first byte %#x, want 0x7E", i, f.Data[0])
			break
		}
	}
	for i := 1; i < len(audioFrames); i++ {
		if delta := audioFrames[i].PTS - audioFrames[i-1].PTS; delta != 20000 {
			t.Errorf("audio PTS step %d: got %d, want 20000", i, delta)
			break
		}
	}
}

// TestProducerEndToEnd validates the go2rtc producer integration: codec
// probing from the live stream and packet delivery to a receiver.
func TestProducerEndToEnd(t *testing.T) {
	token := testToken(t)
	world := startMockWorld(t, token)
	defer world.close()

	cfg := testConfig(world, token)

	prod, err := NewProducer(cfg, "wyze://127.0.0.1?mac="+mockMAC+"&proto=gwell")
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer prod.Stop()

	if len(prod.Medias) != 2 {
		t.Fatalf("medias: got %d, want 2 (video+audio)", len(prod.Medias))
	}
	codec := prod.Medias[0].Codecs[0]
	if codec.Name != core.CodecH264 {
		t.Errorf("video codec: got %s, want %s", codec.Name, core.CodecH264)
	}
	acodec := prod.Medias[1].Codecs[0]
	if acodec.Name != core.CodecPCMU {
		t.Errorf("audio codec: got %s, want %s", acodec.Name, core.CodecPCMU)
	}
	if acodec.ClockRate != 16000 {
		t.Errorf("audio clock: got %d, want 16000", acodec.ClockRate)
	}

	// attach receivers
	recv, err := prod.GetTrack(prod.Medias[0], codec)
	if err != nil {
		t.Fatalf("GetTrack: %v", err)
	}
	arecv, err := prod.GetTrack(prod.Medias[1], acodec)
	if err != nil {
		t.Fatalf("GetTrack(audio): %v", err)
	}

	var mu sync.Mutex
	var packets, apackets []*core.Packet
	recv.Input = func(packet *core.Packet) {
		mu.Lock()
		packets = append(packets, packet)
		mu.Unlock()
	}
	arecv.Input = func(packet *core.Packet) {
		mu.Lock()
		apackets = append(apackets, packet)
		mu.Unlock()
	}

	done := make(chan error, 1)
	go func() { done <- prod.Start() }()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count, acount := len(packets), len(apackets)
		mu.Unlock()
		if count >= 5 && acount >= 5 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Start exited early: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}

	mu.Lock()
	count, acount := len(packets), len(apackets)
	mu.Unlock()
	if count < 5 {
		t.Fatalf("received only %d video packets", count)
	}
	if acount < 5 {
		t.Fatalf("received only %d audio packets", acount)
	}

	first := packets[0]
	if len(first.Payload) < 5 {
		t.Fatalf("first packet too small: %d bytes", len(first.Payload))
	}
	// the keyframe captured during the codec probe is replayed first so
	// consumers can decode immediately
	if h264.NALUType(first.Payload) != h264.NALUTypeSPS {
		t.Errorf("first packet NALU type: got %d, want SPS(7)", h264.NALUType(first.Payload))
	}
	if first.Header.Version != 2 || !first.Header.Marker {
		t.Errorf("RTP header: version=%d marker=%v", first.Header.Version, first.Header.Marker)
	}
	// sequence numbers must increase (packets[0] is the replayed keyframe
	// with sequence 0, streamed frames continue from 1)
	for i := 1; i < count && i < len(packets); i++ {
		if packets[i].Header.SequenceNumber != packets[0].Header.SequenceNumber+uint16(i) {
			t.Errorf("sequence number gap at %d", i)
			break
		}
	}

	// audio packets: 320 µ-law samples, RTP timestamps at 16 kHz (320/20ms)
	for i, pkt := range apackets {
		if len(pkt.Payload) != 320 {
			t.Errorf("audio packet %d: len=%d, want 320", i, len(pkt.Payload))
			break
		}
		if pkt.Payload[0] != 0x7E {
			t.Errorf("audio packet %d: first byte %#x, want 0x7E", i, pkt.Payload[0])
			break
		}
	}
	for i := 1; i < len(apackets); i++ {
		if delta := apackets[i].Header.Timestamp - apackets[i-1].Header.Timestamp; delta != 320 {
			t.Errorf("audio RTP timestamp step %d: got %d, want 320", i, delta)
			break
		}
	}
}

// TestParseSourceURL checks the URL parsing used by the internal dialer.
func TestParseSourceURL(t *testing.T) {
	host, mac, err := ParseSourceURL("wyze://192.168.1.230?dtls=true&enr=xx&mac=80482C37D86F&model=HL_CAM4&uid=abc")
	if err != nil {
		t.Fatalf("ParseSourceURL: %v", err)
	}
	if host != "192.168.1.230" {
		t.Errorf("host: got %s", host)
	}
	if mac != "80482C37D86F" {
		t.Errorf("mac: got %s", mac)
	}

	// MAC with colons must be normalized
	_, mac, err = ParseSourceURL("wyze://1.2.3.4?mac=80:48:2C:37:D8:6F")
	if err != nil {
		t.Fatalf("ParseSourceURL: %v", err)
	}
	if mac != "80482C37D86F" {
		t.Errorf("mac: got %s", mac)
	}

	// GW_ identifiers must match by their MAC suffix
	_, mac, _ = ParseSourceURL("wyze://host?mac=GW_HL_CAM4_D03F2775AC2F")
	if mac != "D03F2775AC2F" {
		t.Errorf("GW_ mac not stripped: got %s", mac)
	}

	if _, _, err = ParseSourceURL("wyze://host"); err == nil {
		t.Error("expected error for missing mac")
	}
	if _, _, err = ParseSourceURL("not-a-url"); err == nil {
		t.Error("expected error for bad URL")
	}
}

// TestSelectTargetMACMatching verifies the device list matching.
func TestSelectTargetMACMatching(t *testing.T) {
	c := &Client{cfg: Config{DeviceMAC: "80482C37D86F"}}
	c.devices = []DeviceInfo{
		{TID: 1, Name: "GW_GC1_D03F2775AC2F"},
		{TID: 2, Name: "GW_HL_CAM4_80482C37D86F"},
	}
	if err := c.selectTarget(); err != nil {
		t.Fatalf("selectTarget: %v", err)
	}
	if c.targetDev.TID != 2 {
		t.Errorf("wrong device selected: %d", c.targetDev.TID)
	}

	c.cfg.DeviceMAC = "FFFFFFFFFFFF"
	if err := c.selectTarget(); err == nil {
		t.Error("expected error for unknown MAC")
	}
}

func TestHasMacSuffix(t *testing.T) {
	if !hasMacSuffix("GW_HL_CAM4_D03F2775AC2F", "D03F2775AC2F") {
		t.Error("suffix not detected")
	}
	if !hasMacSuffix("GW_HL_CAM4_d03f2775ac2f", "D03F2775AC2F") {
		t.Error("case-insensitive match failed")
	}
	if hasMacSuffix("GW_HL_CAM4_D03F2775AC2F", "D03F2775AC2E") {
		t.Error("false positive")
	}
	if hasMacSuffix("SHORT", "D03F2775AC2F") {
		t.Error("name shorter than mac must not match")
	}
}

// TestCallTimeoutSleepingCamera covers peek mode (wake=0): with no wakeup
// and a short CallTimeout, a silent camera fails the dial quickly instead
// of retrying for the full battery-camera window.
func TestCallTimeoutSleepingCamera(t *testing.T) {
	token := testToken(t)
	world := startMockWorld(t, token)
	defer world.close()

	// simulate a camera that stays asleep (e.g. no motion event)
	world.camMu.Lock()
	world.silentCamera = true
	world.camMu.Unlock()

	cfg := testConfig(world, token)
	cfg.CallTimeout = 500 * time.Millisecond

	client := NewClient(cfg)
	defer client.Close()

	start := time.Now()
	err := client.Dial()
	if err == nil {
		t.Fatal("dial succeeded against a silent camera")
	}
	if !strings.Contains(err.Error(), "not answering") {
		t.Errorf("error: got %q, want a not-answering error", err)
	}
	// the pre-call handshake has fixed costs; only the calling phase is
	// bounded by CallTimeout
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("dial with 500ms CallTimeout took %s, want a fast failure", elapsed)
	}
}

// TestPeekSleepCooldown covers peek mode (wake=0): after the camera ends
// its live view and goes to sleep, reconnects are refused until the sleep
// cooldown passes, so redial loops cannot keep the camera awake.
func TestPeekSleepCooldown(t *testing.T) {
	token := testToken(t)
	world := startMockWorld(t, token)
	defer world.close()

	peekCfg := testConfig(world, token)
	peekCfg.Peek = true
	peekCooldowns.Delete(peekCfg.DeviceMAC) // tests share the package-level table

	// run one peek session to completion: the mock camera streams for
	// ~5s and then goes quiet (battery save)
	client := NewClient(peekCfg)
	client.silentTimeout = 500 * time.Millisecond
	defer client.Close()
	if err := client.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := client.Handshake(); err != nil {
		t.Fatalf("Handshake: %v", err)
	}

	deadline := time.Now().Add(20 * time.Second)
	var silentErr error
	for silentErr == nil && time.Now().Before(deadline) {
		if _, err := client.ReadMedia(); err != nil {
			silentErr = err
		}
	}
	if !errors.Is(silentErr, ErrSilent) {
		t.Fatalf("session end: got %v, want ErrSilent", silentErr)
	}

	// a reconnect during the cooldown must be refused instantly, without
	// contacting the camera at all
	client2 := NewClient(peekCfg)
	defer client2.Close()
	start := time.Now()
	err := client2.Dial()
	if err == nil {
		t.Fatal("dial during peek cooldown unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "peek cooldown") {
		t.Errorf("cooldown error: got %q", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("cooldown refusal took %s, want an instant failure", elapsed)
	}

	// once the cooldown expires, peeks go through again
	peekCooldowns.Store(peekCfg.DeviceMAC, time.Now().Add(-time.Second))
	client3 := NewClient(peekCfg)
	defer client3.Close()
	if err := client3.Dial(); err != nil {
		t.Errorf("dial after cooldown expiry: %v", err)
	}

	// non-peek sessions ignore the cooldown entirely
	world.camMu.Lock()
	world.silentCamera = true
	world.camMu.Unlock()
	peekCooldowns.Store(peekCfg.DeviceMAC, time.Now().Add(time.Minute))
	normalCfg := testConfig(world, token)
	normalCfg.CallTimeout = 500 * time.Millisecond
	client4 := NewClient(normalCfg)
	defer client4.Close()
	if err := client4.Dial(); err == nil || !strings.Contains(err.Error(), "not answering") {
		t.Errorf("non-peek dial: got %v, want the silent-camera failure", err)
	}
}

// TestSleepCooldownConfigurable verifies a custom (short) cooldown via
// Config.SleepCooldown and its disable switch.
func TestSleepCooldownConfigurable(t *testing.T) {
	token := testToken(t)
	world := startMockWorld(t, token)
	defer world.close()

	peekCfg := testConfig(world, token)
	peekCfg.Peek = true
	peekCfg.SleepCooldown = 1200 * time.Millisecond
	peekCooldowns.Delete(peekCfg.DeviceMAC) // tests share the package-level table

	client := NewClient(peekCfg)
	client.silentTimeout = 500 * time.Millisecond
	defer client.Close()
	if err := client.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := client.Handshake(); err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := client.ReadMedia(); err != nil {
			if !errors.Is(err, ErrSilent) {
				t.Fatalf("session end: %v", err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream never went silent")
		}
	}

	// refused while the 1.2s cooldown is active
	client2 := NewClient(peekCfg)
	defer client2.Close()
	if err := client2.Dial(); err == nil || !strings.Contains(err.Error(), "peek cooldown") {
		t.Errorf("during cooldown: got %v, want refusal", err)
	}

	// allowed once it expires
	time.Sleep(1300 * time.Millisecond)
	client3 := NewClient(peekCfg)
	defer client3.Close()
	if err := client3.Dial(); err != nil {
		t.Errorf("after cooldown expiry: %v", err)
	}

	// a disabled cooldown records nothing at all
	disabled := &Client{cfg: Config{Peek: true, SleepCooldown: -1, DeviceMAC: "DISABLEDTEST"}}
	disabled.notePeekSleep()
	if _, ok := peekCooldowns.Load(disabled.deviceKey()); ok {
		t.Error("cooldown recorded despite SleepCooldown < 0")
	}

	// and the default applies when unset
	def := &Client{cfg: Config{Peek: true, DeviceMAC: "DEFAULTTEST"}}
	if got := def.sleepCooldown(); got != peekSleepCooldown {
		t.Errorf("default cooldown: got %s, want %s", got, peekSleepCooldown)
	}
}
