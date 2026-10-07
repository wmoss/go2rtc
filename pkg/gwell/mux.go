package gwell

import (
	"bytes"
	"encoding/binary"
)

// The camera's AV data arrives as a multiplexed byte stream inside RC5
// encrypted MTP TLV messages (type 0x04) on the KCP data channel:
//
//	audio sub-frame: [28-byte head_info][40 01][320 bytes G.711 µ-law]
//	  - head magic 0xFFFFFF88, marker (head[4:8] LE) 0x00010000
//	  - head[20:24] LE: PTS in microseconds since stream start
//	  - exactly 350 bytes, never split across messages
//	  - 320 samples per 20ms => 16 kHz µ-law
//
//	video access unit: [28-byte head_info][H.264 Annex B chunk]
//	  - marker 0x00000000 (0x70010000 for the empty session-start head)
//	  - the Annex B data continues in following messages as bare chunks
//	  - until the next head magic appears
//
// H.264 emulation prevention (00 00 01 never appears unescaped inside NALU
// data) makes it safe to scan for the head magic in video data: a random
// 0xFFFFFF88 in compressed video can never be followed by a valid marker.

const (
	audioMarker   = 0x00010000
	videoMarker   = 0x00000000
	sessionMarker = 0x70010000

	headInfoLen = 28
	audioSubLen = 350 // head + 2-byte prefix + 320 samples
)

var headMagicBytes = []byte{0xFF, 0xFF, 0xFF, 0x88}

// AudioFrame is one 20 ms G.711 µ-law sub-frame (16 kHz).
type AudioFrame struct {
	PTS  uint32 // microseconds since the camera's stream start
	Data []byte // µ-law samples
}

// RTPClock returns the RTP timestamp for the frame at the given clock rate.
func (f *AudioFrame) RTPClock(rate int) uint32 {
	return uint32(uint64(f.PTS) * uint64(rate) / 1000000)
}

// MediaKind discriminates MediaFrame.
type MediaKind byte

const (
	MediaVideo MediaKind = iota
	MediaAudio
)

// MediaFrame is one demultiplexed media unit from the camera.
type MediaFrame struct {
	Kind  MediaKind
	Video []byte      // Annex B access unit (MediaVideo)
	Audio *AudioFrame // µ-law sub-frame (MediaAudio)
}

// avMux demultiplexes the camera's interleaved audio/video byte stream.
// It is not safe for concurrent use; the client reads from a single
// goroutine.
type avMux struct {
	video func([]byte)      // receives video bytes (Annex B, heads stripped)
	audio func(*AudioFrame) // receives parsed audio sub-frames

	carry []byte // partial sub-frame bytes spanning KCP messages
}

// Write consumes one decrypted MTP TLV payload. Video bytes are passed
// through with all head_info headers removed; audio sub-frames are parsed
// and emitted individually.
func (m *avMux) Write(p []byte) {
	if len(m.carry) > 0 {
		p = append(m.carry, p...)
		m.carry = m.carry[:0]
	}

	off := 0
	for off < len(p) {
		idx := bytes.Index(p[off:], headMagicBytes)
		if idx < 0 {
			if rest := p[off:]; len(rest) > 0 {
				m.video(rest)
			}
			return
		}
		abs := off + idx

		// bytes before the head are video data
		if abs > off {
			m.video(p[off:abs])
		}

		if abs+headInfoLen > len(p) {
			// not enough bytes to validate a head: video data with a
			// look-alike magic near the message end. Pass it through; the
			// demuxer discards bytes outside start codes anyway.
			m.video(p[abs:])
			return
		}

		switch binary.LittleEndian.Uint32(p[abs+4 : abs+8]) {
		case audioMarker:
			end := abs + audioSubLen
			if end > len(p) {
				// partial audio sub-frame: carry until complete
				m.carry = append(m.carry, p[abs:]...)
				return
			}
			if f := parseAudioSubFrame(p[abs:end]); f != nil {
				m.audio(f)
			}
			off = end
		case videoMarker, sessionMarker:
			// video head: skip the 28 bytes, data follows (possibly none)
			off = abs + headInfoLen
		default:
			// false positive: a byte sequence in video data that looks
			// like a head but has no valid marker; treat it as video data
			m.video(p[abs : abs+1])
			off = abs + 1
		}
	}
}

// parseAudioSubFrame extracts PTS and samples from a 350-byte sub-frame.
func parseAudioSubFrame(sub []byte) *AudioFrame {
	if len(sub) < headInfoLen+2 {
		return nil
	}
	data := sub[headInfoLen:]
	// every observed sub-frame starts with a 40 01 prefix
	if data[0] == 0x40 && data[1] == 0x01 {
		data = data[2:]
	}
	if len(data) == 0 {
		return nil
	}
	return &AudioFrame{
		PTS:  binary.LittleEndian.Uint32(sub[20:24]),
		Data: data,
	}
}
