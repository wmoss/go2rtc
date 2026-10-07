package gwell

// Live-camera integration harness.
//
// Skipped by default; runs against a real camera when env vars are set:
//
//	GWELL_LIVE_SOURCE   wyze:// source URL (required), e.g.
//	                    wyze://GW_BE1_7C78B2A2AFAA?mac=7C78B2A2AFAA&proto=gwell
//	GWELL_LIVE_SECRET   path to a go2rtc-style YAML with Wyze credentials:
//	                    wyze: {email: {api_id: ..., api_key: ..., password: ...}}
//	GWELL_LIVE_EMAIL    pick the account when the YAML holds several
//	GWELL_LIVE_SECONDS  stream duration (default 20s)
//	GWELL_TRACE         path to write raw frame dumps (hex), one per line
//	GWELL_DUMP_DIR      directory for video.264 / audio.bin media dumps
//	GWELL_AUDIO_PROBE   protocol experiments, "name@seconds,..." e.g.
//	                    "initreq1@5,start2@10" (see runAudioProbe)
//
// The harness logs per-second stats, validates that video frames arrive and
// writes everything needed to analyze the wire protocol offline.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/wyze"
	"gopkg.in/yaml.v3"
)

type liveAccount struct {
	APIKey   string `yaml:"api_key"`
	APIID    string `yaml:"api_id"`
	Password string `yaml:"password"`
}

func liveCredentials(t *testing.T) (email string, acc liveAccount) {
	secret := os.Getenv("GWELL_LIVE_SECRET")
	if secret == "" {
		t.Fatal("GWELL_LIVE_SOURCE set but GWELL_LIVE_SECRET missing")
	}
	raw, err := os.ReadFile(secret)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	var v struct {
		Cfg map[string]liveAccount `yaml:"wyze"`
	}
	if err := yaml.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse secret: %v", err)
	}
	if len(v.Cfg) == 0 {
		t.Fatal("no wyze account in secret file")
	}
	if pick := os.Getenv("GWELL_LIVE_EMAIL"); pick != "" {
		acc, ok := v.Cfg[pick]
		if !ok {
			t.Fatalf("account %q not in secret file", pick)
		}
		return pick, acc
	}
	for email, acc = range v.Cfg {
		return email, acc
	}
	return "", liveAccount{}
}

func TestLiveCamera(t *testing.T) {
	source := os.Getenv("GWELL_LIVE_SOURCE")
	if source == "" {
		t.Skip("GWELL_LIVE_SOURCE not set")
	}

	seconds := 20
	if s := os.Getenv("GWELL_LIVE_SECONDS"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			seconds = int(d.Seconds())
		} else if n, err := fmt.Sscanf(s, "%d", &seconds); n != 1 || err != nil {
			t.Fatalf("bad GWELL_LIVE_SECONDS: %v", err)
		}
	}

	email, acc := liveCredentials(t)

	// trace + debug into the log (and optionally a trace file)
	DebugLog = func(msg string) { t.Log(msg) }
	start := time.Now()
	if path := os.Getenv("GWELL_TRACE"); path != "" {
		f, err := os.Create(path)
		if err != nil {
			t.Fatalf("create trace: %v", err)
		}
		defer f.Close()
		w := bufio.NewWriter(f)
		defer w.Flush()
		TraceLog = func(msg string) {
			fmt.Fprintf(w, "%8.3f %s\n", time.Since(start).Seconds(), msg)
		}
		defer func() { TraceLog = nil }()
	} else {
		TraceLog = nil
	}
	defer func() { DebugLog = nil }()

	cloud := wyze.NewCloud(acc.APIKey, acc.APIID)
	if err := cloud.Login(email, acc.Password); err != nil {
		t.Fatalf("wyze login: %v", err)
	}

	host, mac, err := ParseSourceURL(source)
	if err != nil {
		t.Fatalf("source URL: %v", err)
	}

	creds, err := cloud.GetGwellCredentials(mac)
	if err != nil {
		t.Fatalf("gwell credentials: %v", err)
	}
	token, err := ParseAccessToken(creds.AccessID, creds.AccessToken)
	if err != nil {
		t.Fatalf("access token: %v", err)
	}

	wakeup := func() error {
		cam, err := cloud.GetCameraByMACSuffix(mac)
		if err != nil {
			return err
		}
		return cloud.WakeupDevice(cam.MAC, cam.ProductModel)
	}

	cfg := Config{
		Token:     token,
		DeviceMAC: mac,
		OnWakeup:  wakeup,
	}
	if ip := net.ParseIP(host); ip != nil {
		cfg.CameraLanIP = host
	}
	if tid := os.Getenv("GWELL_LIVE_TID"); tid != "" {
		var v uint64
		if _, err := fmt.Sscanf(tid, "0x%X", &v); err != nil {
			t.Fatalf("bad GWELL_LIVE_TID: %v", err)
		}
		cfg.DeviceTID = v
	}

	t.Logf("dialing %s (mac=%s)", host, mac)
	if err := wakeup(); err != nil {
		t.Logf("initial wakeup: %v", err)
	}

	client := NewClient(cfg)
	if err := client.Dial(); err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if err := client.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	t.Logf("session established: streamID=0x%08X", client.streamID)

	// watchdog: a silent camera must not hang the harness
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-time.After(time.Duration(seconds)*time.Second + 15*time.Second):
			t.Error("watchdog: stalled session, forcing close")
			_ = client.Close()
		case <-watchDone:
		}
	}()
	defer close(watchDone)

	// optional media dumps
	var videoDump, audioDump *os.File
	if dir := os.Getenv("GWELL_DUMP_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("dump dir: %v", err)
		}
		if videoDump, err = os.Create(filepath.Join(dir, "video.264")); err != nil {
			t.Fatalf("video dump: %v", err)
		}
		defer videoDump.Close()
		if audioDump, err = os.Create(filepath.Join(dir, "audio.bin")); err != nil {
			t.Fatalf("audio dump: %v", err)
		}
		defer audioDump.Close()
	}

	// scheduled protocol experiments
	type probe struct {
		at    time.Duration
		name  string
		fired bool
	}
	var probes []probe
	for _, spec := range strings.Split(os.Getenv("GWELL_AUDIO_PROBE"), ",") {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		name, _, ok := strings.Cut(spec, "@")
		var at time.Duration
		if ok {
			if d, err := time.ParseDuration(strings.SplitN(spec, "@", 2)[1]); err == nil {
				at = d
			}
		}
		probes = append(probes, probe{at: at, name: name})
		t.Logf("audio probe %q scheduled at %s", name, at)
	}

	// main capture loop
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	var frames, videoBytes, keyframes, audioFrames int
	var firstFrame, firstAudio time.Duration
	lastSecond := time.Now()

	for time.Now().Before(deadline) {
		for i := range probes {
			if !probes[i].fired && time.Since(start) >= probes[i].at {
				probes[i].fired = true
				t.Logf("firing audio probe %q", probes[i].name)
				runAudioProbe(client, probes[i].name)
			}
		}

		frame, err := client.ReadMedia()
		if err != nil {
			// battery doorbells end the live view themselves after ~20s:
			// count that as a clean end once media was received
			if frames > 0 && errors.Is(err, ErrSilent) {
				t.Logf("camera ended the session: %v", err)
				break
			}
			t.Fatalf("read frame: %v", err)
		}

		switch frame.Kind {
		case MediaVideo:
			if len(frame.Video) < 5 {
				continue
			}
			frames++
			videoBytes += len(frame.Video)
			if firstFrame == 0 {
				firstFrame = time.Since(start)
				t.Logf("first video AU after %s (%d bytes)", firstFrame, len(frame.Video))
			}
			if videoDump != nil {
				_, _ = videoDump.Write(frame.Video)
			}
			if isAnnexB(frame.Video) {
				if t := frameNALUType(frame.Video); t == 7 || t == 5 {
					keyframes++
				}
			}
		case MediaAudio:
			audioFrames++
			if firstAudio == 0 {
				firstAudio = time.Since(start)
				t.Logf("first audio sub-frame after %s (pts=%dµs, %d bytes)",
					firstAudio, frame.Audio.PTS, len(frame.Audio.Data))
			}
			if audioDump != nil {
				_, _ = audioDump.Write(frame.Audio.Data)
			}
		}

		if time.Since(lastSecond) >= 5*time.Second {
			lastSecond = time.Now()
			t.Logf("stats: video=%d keyframes=%d vbytes=%dKB audio=%d elapsed=%s",
				frames, keyframes, videoBytes/1024, audioFrames, time.Since(start).Round(time.Second))
		}
	}

	if frames == 0 {
		t.Fatalf("no video frames received in %ds", seconds)
	}
	if keyframes == 0 {
		t.Errorf("no keyframe observed among %d frames", frames)
	}
	if audioFrames == 0 {
		t.Errorf("no audio sub-frames received among %d video frames", frames)
	}
	t.Logf("done: video=%d keyframes=%d vbytes=%dKB audio=%d in %s",
		frames, keyframes, videoBytes/1024, audioFrames, time.Since(start).Round(time.Second))
}

// frameNALUType returns the first NALU type of an Annex B frame (0 if unknown).
func frameNALUType(frame []byte) byte {
	off := 0
	if len(frame) > 4 && frame[2] == 0 && frame[3] == 1 {
		off = 4
	} else if len(frame) > 3 && frame[2] == 1 {
		off = 3
	} else {
		return 0
	}
	if off < len(frame) {
		return frame[off] & 0x1F
	}
	return 0
}

// runAudioProbe sends one experimental audio-request message to the camera.
// The Gwell audio request mechanism is not publicly documented; each probe
// sends a plausible variant while the trace captures the camera's response.
//
// Probe names:
//
//	initreq[-udN][-rN][-cN]   AVSTREAMCTL INITREQ with PlayerUserData[0]=N
//	                          (ud, default 2), resource field [12:16]=N (r)
//	                          and channel field [62:64]=N (c); all hex
//	startplain                plain AVSTREAMCTL START re-send
//	start2/start100/start3    START with resource mask 2 / 0x100 / 3 (risky)
//	avinit1/avinit4           viewer init [04 01 20] / [04 04 20]
func runAudioProbe(c *Client, name string) {
	switch {
	case strings.HasPrefix(name, "initreq"):
		// fields: -udN PlayerUserData[0], -rN resource [12:16], -cN channel [62:64]
		userData := byte(2)
		resource := uint32(0)
		channel := uint16(0)
		for _, part := range strings.Split(name, "-") {
			switch {
			case strings.HasPrefix(part, "ud"):
				if v, err := strconv.ParseUint(part[2:], 16, 8); err == nil {
					userData = byte(v)
				}
			case strings.HasPrefix(part, "r") && len(part) > 1:
				if v, err := strconv.ParseUint(part[1:], 16, 32); err == nil {
					resource = uint32(v)
				}
			case strings.HasPrefix(part, "c") && len(part) > 1:
				if v, err := strconv.ParseUint(part[1:], 16, 16); err == nil {
					channel = uint16(v)
				}
			}
		}
		avKey := make([]byte, 32)
		avKey[0] = userData
		payload := BuildAVStreamCtlINITREQ(c.streamID, 1, 1, channel, avKey)
		binary.LittleEndian.PutUint32(payload[12:16], resource)
		tracef("probe.initreq", payload)
		// proper KCP send: raw push segments with a stale sn desync the
		// camera's ctrl channel
		c.ctrlKCP.Send(payload)
		c.ctrlKCP.Flush()
	case name == "startplain":
		payload := BuildAVStreamCtlSTART(c.streamID)
		tracef("probe.startplain", payload)
		c.dataKCP.Send(payload)
		c.dataKCP.Flush()
	case name == "start2", name == "start100", name == "start3":
		// AVSTREAMCTL START with a resource mask in [12:16]
		start := BuildAVStreamCtlSTART(c.streamID)
		var v uint32
		switch name {
		case "start2":
			v = 2
		case "start100":
			v = 0x0100
		case "start3":
			v = 3
		}
		binary.LittleEndian.PutUint32(start[12:16], v)
		tracef("probe."+name, start)
		c.dataKCP.Send(start)
		c.dataKCP.Flush()
	case name == "avinit1", name == "avinit4":
		// viewer init with a different sub-type
		avKeyInit := make([]byte, 32)
		avKeyInit[0] = 0x04
		if name == "avinit1" {
			avKeyInit[1] = 0x01
		} else {
			avKeyInit[1] = 0x04
		}
		binary.LittleEndian.PutUint16(avKeyInit[2:4], 0x0020)
		for i := 0; i < 3; i++ {
			off := 4 + i*8
			c.mtpRC5Ctx.EncryptBlock(avKeyInit[off : off+8])
		}
		tracef("probe."+name, avKeyInit)
		c.dataKCP.Send(avKeyInit)
		c.dataKCP.Flush()
	default:
		DebugLog("gwell: unknown audio probe " + name)
	}
}
