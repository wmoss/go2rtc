package gwell

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func buildAudioSub(pts uint32) []byte {
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

func buildVideoHead(ts uint32) []byte {
	head := make([]byte, headInfoLen)
	copy(head, []byte{0xFF, 0xFF, 0xFF, 0x88})
	binary.LittleEndian.PutUint32(head[4:8], videoMarker)
	binary.LittleEndian.PutUint32(head[8:12], ts)
	return head
}

// TestMuxAudioVideoInterleaved feeds the exact message pattern observed
// from the live doorbell: two audio sub-frames packed ahead of a video
// head+chunk, then bare video continuation chunks.
func TestMuxAudioVideoInterleaved(t *testing.T) {
	var video []byte
	var audio []*AudioFrame
	m := avMux{
		video: func(b []byte) { video = append(video, b...) },
		audio: func(f *AudioFrame) { audio = append(audio, f) },
	}

	h264 := []byte{0, 0, 0, 1, 0x41, 0xE5, 0xAA, 0xBB}

	// message 1: audio(350) + audio(350) + video head + first chunk
	msg1 := append([]byte{}, buildAudioSub(1000)...)
	msg1 = append(msg1, buildAudioSub(21000)...)
	msg1 = append(msg1, buildVideoHead(500)...)
	msg1 = append(msg1, h264...)
	m.Write(msg1)

	// message 2: bare video continuation
	m.Write([]byte{0xCC, 0xDD})

	if len(audio) != 2 {
		t.Fatalf("audio sub-frames: got %d, want 2", len(audio))
	}
	if audio[0].PTS != 1000 || audio[1].PTS != 21000 {
		t.Errorf("audio PTS: got %d,%d want 1000,21000", audio[0].PTS, audio[1].PTS)
	}
	for i, f := range audio {
		if len(f.Data) != 320 || f.Data[0] != 0x7E {
			t.Errorf("audio %d: len=%d first=%#x", i, len(f.Data), f.Data[0])
		}
	}

	wantVideo := append([]byte{}, h264...)
	wantVideo = append(wantVideo, 0xCC, 0xDD)
	if !bytes.Equal(video, wantVideo) {
		t.Errorf("video bytes:\n  got  %x\n  want %x", video, wantVideo)
	}
}

// TestMuxSplitAudioSubFrame verifies an audio sub-frame split across two
// KCP messages is reassembled via the carry buffer.
func TestMuxSplitAudioSubFrame(t *testing.T) {
	var audio []*AudioFrame
	m := avMux{video: func([]byte) {}, audio: func(f *AudioFrame) { audio = append(audio, f) }}

	sub := buildAudioSub(42000)
	m.Write(sub[:200])
	if len(audio) != 0 {
		t.Fatal("premature audio emission")
	}
	m.Write(sub[200:])
	if len(audio) != 1 {
		t.Fatalf("audio: got %d, want 1", len(audio))
	}
	if audio[0].PTS != 42000 || len(audio[0].Data) != 320 {
		t.Errorf("reassembled frame wrong: pts=%d len=%d", audio[0].PTS, len(audio[0].Data))
	}
}

// TestMuxFalsePositiveHead verifies that a head magic inside video data
// without a valid marker is passed through as video bytes.
func TestMuxFalsePositiveHead(t *testing.T) {
	var video []byte
	m := avMux{video: func(b []byte) { video = append(video, b...) }, audio: func(*AudioFrame) {}}

	chunk := []byte{0x11, 0x22, 0xFF, 0xFF, 0xFF, 0x88, 0x55, 0x66, 0x77}
	m.Write(chunk)

	if !bytes.Equal(video, chunk) {
		t.Errorf("video passthrough:\n  got  %x\n  want %x", video, chunk)
	}
}

// TestMuxSessionStartHead verifies the empty session-start head variant
// (marker 0x70010000) is consumed without corrupting the stream.
func TestMuxSessionStartHead(t *testing.T) {
	var video []byte
	m := avMux{video: func(b []byte) { video = append(video, b...) }, audio: func(*AudioFrame) {}}

	head := buildVideoHead(0)
	binary.LittleEndian.PutUint32(head[4:8], sessionMarker)

	h264 := []byte{0, 0, 0, 1, 0x67, 0x64}
	msg := append(append([]byte{}, head...), h264...)
	m.Write(msg)

	if !bytes.Equal(video, h264) {
		t.Errorf("video:\n  got  %x\n  want %x", video, h264)
	}
}

// TestAudioRTPClock verifies µ-law PTS conversion to RTP timestamps.
func TestAudioRTPClock(t *testing.T) {
	f := &AudioFrame{PTS: 1000000} // 1 second
	if ts := f.RTPClock(16000); ts != 16000 {
		t.Errorf("RTPClock(16000): got %d, want 16000", ts)
	}
	if ts := f.RTPClock(8000); ts != 8000 {
		t.Errorf("RTPClock(8000): got %d, want 8000", ts)
	}
}

// TestDrainUpdatesLastMedia verifies every frame emission path refreshes
// the media liveness clock: a healthy stream must never trip the battery
// silence timeout.
func TestDrainUpdatesLastMedia(t *testing.T) {
	// queued audio first
	c := &Client{audioQueue: []*AudioFrame{{PTS: 1, Data: []byte{0x7E}}}}
	if c.drainKCPRecv() == nil {
		t.Fatal("audio frame not drained")
	}
	if c.lastMedia.IsZero() {
		t.Error("lastMedia not set after audio drain")
	}

	// queued video AU
	c = &Client{auQueue: [][]byte{{0, 0, 0, 1, 0x41}}}
	if c.drainKCPRecv() == nil {
		t.Fatal("video frame not drained")
	}
	if c.lastMedia.IsZero() {
		t.Error("lastMedia not set after video drain")
	}

	// nothing queued: clock must not move
	c = &Client{}
	before := c.lastMedia
	if c.drainKCPRecv() != nil {
		t.Fatal("empty client produced a frame")
	}
	if c.lastMedia != before {
		t.Error("lastMedia advanced without media")
	}
}
