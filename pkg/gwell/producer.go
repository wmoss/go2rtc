package gwell

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/h264"
	"github.com/AlexxIT/go2rtc/pkg/h264/annexb"
	"github.com/pion/rtp"
)

// Gwell cameras send 16 kHz G.711 µ-law audio sub-frames interleaved with
// the H.264 video stream.
const audioClockRate = 16000

// Producer implements core.Producer for a Gwell camera session.
type Producer struct {
	core.Connection
	client   *Client
	keyframe []byte // SPS+PPS+IDR captured during the codec probe
}

// NewProducer dials the camera, probes the video codec (and audio presence)
// and returns a ready-to-start producer.
func NewProducer(cfg Config, source string) (*Producer, error) {
	client := NewClient(cfg)

	if err := client.Dial(); err != nil {
		_ = client.Close()
		return nil, err
	}
	if err := client.Handshake(); err != nil {
		_ = client.Close()
		return nil, err
	}

	vcodec, hasAudio, keyframe, err := probeMedia(client)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	debugf("gwell: probed codecs: video=%s audio=%v", vcodec.Name, hasAudio)

	medias := []*core.Media{{
		Kind:      core.KindVideo,
		Direction: core.DirectionRecvonly,
		Codecs:    []*core.Codec{vcodec},
	}}
	if hasAudio {
		medias = append(medias, &core.Media{
			Kind:      core.KindAudio,
			Direction: core.DirectionRecvonly,
			Codecs: []*core.Codec{{
				Name:      core.CodecPCMU,
				ClockRate: audioClockRate,
			}},
		})
	}

	prod := &Producer{
		Connection: core.Connection{
			ID:         core.NewID(),
			FormatName: "gwell",
			Protocol:   "p2p/kcp",
			RemoteAddr: cfg.CameraLanIP,
			Source:     source,
			Medias:     medias,
			Transport:  client,
		},
		client:   client,
		keyframe: keyframe,
	}

	return prod, nil
}

// Start streams video access units and audio sub-frames to the attached
// receivers until the session ends or the client is closed.
func (p *Producer) Start() error {
	var videoSeq, audioSeq uint16
	start := time.Now()

	// replay the keyframe captured during the codec probe first, so newly
	// attached receivers get decodable video immediately
	if len(p.keyframe) > 0 {
		pkt := &core.Packet{
			Header: rtp.Header{
				Version:        2,
				Marker:         true,
				SequenceNumber: 0,
				Timestamp:      0,
			},
			Payload: annexb.EncodeToAVCC(p.keyframe),
		}
		for _, recv := range p.Receivers {
			if recv.Codec.Name == core.CodecH264 {
				recv.WriteRTP(pkt)
			}
		}
	}

	for {
		frame, err := p.client.ReadMedia()
		if err != nil {
			return err
		}

		switch frame.Kind {
		case MediaVideo:
			payload := frame.Video
			if len(payload) < 5 {
				continue
			}

			videoSeq++

			if isAnnexB(payload) {
				payload = annexb.EncodeToAVCC(payload)
			}

			pkt := &core.Packet{
				Header: rtp.Header{
					Version:        2,
					Marker:         true,
					SequenceNumber: videoSeq,
					Timestamp:      msTo90kHz(time.Since(start)),
				},
				Payload: payload,
			}

			for _, recv := range p.Receivers {
				if recv.Codec.Name == core.CodecH264 {
					recv.WriteRTP(pkt)
					break
				}
			}

		case MediaAudio:
			audioSeq++
			pkt := &core.Packet{
				Header: rtp.Header{
					Version:        2,
					SequenceNumber: audioSeq,
					Timestamp:      frame.Audio.RTPClock(audioClockRate),
				},
				Payload: frame.Audio.Data,
			}

			for _, recv := range p.Receivers {
				if recv.Codec.Name == core.CodecPCMU {
					recv.WriteRTP(pkt)
					break
				}
			}
		}
	}
}

func isAnnexB(b []byte) bool {
	return bytes.HasPrefix(b, []byte{0, 0, 0, 1}) || bytes.HasPrefix(b, []byte{0, 0, 1})
}

func msTo90kHz(d time.Duration) uint32 {
	return uint32(d.Milliseconds() * 90)
}

// probeMedia waits for the first keyframe with SPS to build the video codec
// and, for a short grace window after it, watches for audio sub-frames.
// The consumed keyframe is returned so Start can hand it to receivers
// instead of making them wait a full GOP for the next IDR.
func probeMedia(client *Client) (*core.Codec, bool, []byte, error) {
	deadline := time.Now().Add(core.ProbeTimeout * 2)

	var vcodec *core.Codec
	var keyframe []byte
	var audioSeen bool
	graceEnd := time.Now().Add(core.ProbeTimeout * 2)

	for time.Now().Before(deadline) {
		frame, err := client.ReadMedia()
		if err != nil {
			return nil, false, nil, err
		}

		switch frame.Kind {
		case MediaAudio:
			audioSeen = true
		case MediaVideo:
			if vcodec == nil && len(frame.Video) >= 5 && isAnnexB(frame.Video) {
				avcc := annexb.EncodeToAVCC(frame.Video)
				if len(avcc) >= 5 && h264.NALUType(avcc) == h264.NALUTypeSPS {
					if codec := h264.AVCCToCodec(avcc); codec != nil {
						vcodec = codec
						keyframe = frame.Video
						// the camera interleaves audio with video; give it a
						// moment to show up before declaring video-only
						graceEnd = time.Now().Add(2 * time.Second)
						continue
					}
				}
			}
		}

		if vcodec != nil && (audioSeen || time.Now().After(graceEnd)) {
			return vcodec, audioSeen, keyframe, nil
		}
	}
	if vcodec == nil {
		return nil, false, nil, fmt.Errorf("gwell: probe timeout")
	}
	return vcodec, audioSeen, keyframe, nil
}

// ParseSourceURL extracts the camera host and MAC from a wyze:// URL.
func ParseSourceURL(rawURL string) (host string, mac string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("gwell: missing camera host in URL")
	}
	query := u.Query()

	mac = strings.ToUpper(query.Get("mac"))
	if mac == "" {
		return "", "", fmt.Errorf("gwell: missing mac parameter in URL")
	}
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")

	// GW_ device identifiers end with the bare MAC: use only that suffix
	if idx := strings.LastIndex(mac, "_"); idx >= 0 {
		suffix := mac[idx+1:]
		if len(suffix) == 12 {
			mac = suffix
		}
	}

	return u.Host, mac, nil
}
