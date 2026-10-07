package gwell

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Config configures a client session.
type Config struct {
	Token       *AccessToken // Mars credentials (required)
	ServerAddr  string       // Mars server (auto-discovered when empty)
	CameraLanIP string       // camera LAN IP for the direct media path (optional)
	DeviceMAC   string       // camera MAC (12 hex chars), matched against device names
	DeviceTID   uint64       // select the device by TID (overrides DeviceMAC)
	Devices     []DeviceInfo // pre-populated device list (skips waiting for 0xA7)
	OnWakeup    func() error // optional: wake the device (called during CALLING)

	// CallTimeout bounds how long CALLING is retried while waiting for the
	// camera to answer. Zero selects the 75s default, which covers waking
	// a sleeping battery camera. Short values (e.g. 8s) make sense when
	// no wakeup is configured and the call should fail fast instead.
	CallTimeout time.Duration

	// Peek mode (wake=0): never wake the camera, connect only when it is
	// already awake. After the camera ends its live view and goes to
	// sleep, further dials are refused until the sleep cooldown passes so
	// that reconnect attempts cannot keep the camera awake.
	Peek bool

	// SleepCooldown overrides the peek sleep cooldown for this source
	// (URL parameter "cooldown"). Zero selects the 60s default; a negative
	// value disables the cooldown entirely.
	SleepCooldown time.Duration
}

// ErrSilent reports a battery camera that ended its live view on its own
// timer and stopped responding; peek sessions record a sleep cooldown
// when they observe it.
var ErrSilent = errors.New("gwell: camera went to sleep")

// peekSleepCooldown suppresses new peek dials after a battery camera ended
// its live view: the camera stays reachable for a short window after it
// stops streaming, and immediate reconnects would restart it before it
// can reach deep sleep.
const peekSleepCooldown = 60 * time.Second

// peekCooldowns maps device keys to the time until peek dials are allowed
// again (package level: reconnects create fresh clients).
var peekCooldowns sync.Map

// defaultCallTimeout retries CALLING long enough for a sleeping battery
// camera to be woken and connect.
const defaultCallTimeout = 75 * time.Second

// silentTimeout is how long without any media the session waits before
// reporting the camera as gone (battery doorbells stop streaming ~20s
// after the live view starts, without sending STOP/CLOSE).
const silentTimeout = 15 * time.Second

// noMediaTimeout bounds how long a freshly started session may wait for
// the very first media frame (cameras normally send it within a second of
// ACCEPT).
const noMediaTimeout = 60 * time.Second

// maxAudioQueue bounds queued audio sub-frames (~10s at 20ms frames)
// when only video is consumed.
const maxAudioQueue = 512

// Client manages the lifecycle of one camera streaming session.
type Client struct {
	cfg    Config
	pwdKey *RC5Key

	conn       net.Conn // connected UDP socket to the Mars server
	serverAddr *net.UDPAddr
	pc         *net.UDPConn // unconnected UDP socket for the media phase
	rbuf       []byte       // per-client receive scratch buffer

	certResult       *CertifyResult
	routingSessionID uint64
	sqnum            atomic.Uint32

	devices   []DeviceInfo
	targetDev DeviceInfo

	linkID      uint32
	mtpRC5Key   []byte
	mtpRC5Ctx   *RC5Key
	relayAddrs  []RelayAddr
	udpRelays   []udpRelayTarget
	tcpRelay    net.Conn
	lanMTPAddrs []*net.UDPAddr

	// mu guards the transport-selection state below: it is read by the
	// KCP output callback (driven by the ticker goroutine) while the
	// session goroutine updates it from the receive loops
	mu           sync.RWMutex
	bestLanAddr  *net.UDPAddr
	lastLanAlive time.Time

	meterRound         uint32
	dataKCP, ctrlKCP   *KCPConn
	convData, convCtrl uint32

	streamID uint32

	demuxer       annexbDemuxer
	auQueue       [][]byte
	remoteStopped bool
	echoedStarted bool
	mux           avMux
	audioQueue    []*AudioFrame
	lastMedia     time.Time
	silentTimeout time.Duration

	closed int32
	stop   chan struct{}
	once   sync.Once
}

// RelayAddr holds a relay server address from MTP_RES_RESPONSE.
type RelayAddr struct {
	IP        net.IP
	Port      uint16
	TCP       bool
	SessionID uint64
}

type udpRelayTarget struct {
	Addr      *net.UDPAddr
	SessionID uint64
}

// NewClient creates a session (does not connect yet).
func NewClient(cfg Config) *Client {
	c := &Client{
		cfg:    cfg,
		pwdKey: NewPasswordKey(),
		rbuf:   make([]byte, 8192),
		stop:   make(chan struct{}),
	}
	c.sqnum.Store(1)
	c.silentTimeout = silentTimeout
	// demultiplex the camera's interleaved audio/video stream
	c.mux.video = func(b []byte) {
		if aus := c.demuxer.Write(b); len(aus) > 0 {
			c.auQueue = append(c.auQueue, aus...)
		}
	}
	c.mux.audio = func(f *AudioFrame) {
		c.audioQueue = append(c.audioQueue, f)
		// bound the queue when only video is consumed
		if len(c.audioQueue) > maxAudioQueue {
			c.audioQueue = c.audioQueue[len(c.audioQueue)-maxAudioQueue:]
		}
	}
	return c
}

// TargetDevice returns the device selected after Dial.
func (c *Client) TargetDevice() DeviceInfo {
	return c.targetDev
}

// Close terminates the session.
func (c *Client) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}
	c.once.Do(func() { close(c.stop) })
	if c.pc != nil {
		_ = c.pc.Close()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
	if c.tcpRelay != nil {
		_ = c.tcpRelay.Close()
	}
	return nil
}

func (c *Client) isClosed() bool {
	return atomic.LoadInt32(&c.closed) != 0
}

func (c *Client) nextSqnum() uint32 {
	return c.sqnum.Add(1) - 1
}

// Dial performs the full session establishment: server discovery, certify,
// device list, network detect, subscribe, CALLING and transport negotiation.
// After Dial the caller must run Handshake and then ReadFrame in a loop.
func (c *Client) Dial() error {
	if c.cfg.Peek {
		if until, ok := peekCooldowns.Load(c.deviceKey()); ok {
			if until, ok := until.(time.Time); ok {
				if remain := time.Until(until); remain > 0 {
					return fmt.Errorf("gwell: peek cooldown for %s: camera went to sleep, waiting before the next attempt",
						remain.Round(time.Second))
				}
				peekCooldowns.Delete(c.deviceKey())
			}
		}
	}

	if err := c.connect(); err != nil {
		return fmt.Errorf("gwell: connect: %w", err)
	}
	if err := c.certify(); err != nil {
		return fmt.Errorf("gwell: certify: %w", err)
	}
	if err := c.initInfo(); err != nil {
		return fmt.Errorf("gwell: initInfo: %w", err)
	}
	c.networkDetect()
	c.subscribe()
	if err := c.calling(); err != nil {
		return fmt.Errorf("gwell: calling: %w", err)
	}
	return nil
}

// connect discovers and connects to a Mars P2P server.
func (c *Client) connect() error {
	if c.cfg.ServerAddr != "" {
		conn, err := net.DialTimeout("udp", c.cfg.ServerAddr, 5*time.Second)
		if err != nil {
			return err
		}
		c.conn = conn
		c.serverAddr, _ = net.ResolveUDPAddr("udp", c.cfg.ServerAddr)
		return nil
	}

	servers := DiscoverServers()
	for _, srv := range servers {
		addr := srv.Addr()
		conn, err := net.DialTimeout("udp", addr, 2*time.Second)
		if err != nil {
			continue
		}
		req := BuildDetectReq2()
		EncryptFrameFull(req, c.pwdKey)
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(req); err != nil {
			_ = conn.Close()
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err == nil && n >= FrameHeader {
			c.conn = conn
			c.serverAddr, _ = net.ResolveUDPAddr("udp", addr)
			return nil
		}
		_ = conn.Close()
	}
	return ErrNoServers
}

// certify performs the CertifyReq/CertifyResp handshake.
func (c *Client) certify() error {
	buf := make([]byte, 8192)

	certifyReq, randomKey := BuildCertifyReq(c.cfg.Token, c.nextSqnum())
	if err := c.writeConn(certifyReq); err != nil {
		return err
	}

	for attempt := 0; attempt < 3; attempt++ {
		n, err := c.readConn(buf, 5*time.Second)
		if err != nil {
			if attempt == 0 {
				// retry without the outer mode-1 encryption
				certifyReq2, randomKey2 := BuildCertifyReqRaw(c.cfg.Token, c.nextSqnum())
				randomKey = randomKey2
				if err := c.writeConn(certifyReq2); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("no CertifyResp after %d attempts: %w", attempt+1, err)
		}

		resp := make([]byte, n)
		copy(resp, buf[:n])

		if DecryptFrameFull(resp, c.pwdKey) {
			if resp[1] == SubTypeSessionInit || resp[1] == SubTypeSessionResp {
				orig := make([]byte, n)
				copy(orig, buf[:n])
				if result, err := ParseCertifyResp(orig, randomKey, c.pwdKey); err == nil {
					c.certResult = result
					debugf("gwell: certified, sessionID=0x%016X", result.SessionID)
					return nil
				}
			}
		}

		// fallback parse on a fresh copy
		resp2 := make([]byte, n)
		copy(resp2, buf[:n])
		DecryptID(resp2, c.pwdKey)
		DecryptFrame(resp2)
		if n >= 36 && (resp2[1] == SubTypeSessionInit || resp2[1] == SubTypeSessionResp) {
			errCode := binary.LittleEndian.Uint16(resp2[26:28])
			sessionID := binary.LittleEndian.Uint64(resp2[28:36])
			if errCode == 0 && sessionID != 0 {
				c.certResult = &CertifyResult{
					SessionID:  sessionID,
					SessionKey: NewRC5Key(randomKey[:]),
					RandomKey:  randomKey,
				}
				debugf("gwell: certified (fallback parse), sessionID=0x%016X", sessionID)
				return nil
			}
		}
	}
	return fmt.Errorf("no valid CertifyResp")
}

func (c *Client) writeConn(b []byte) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := c.conn.Write(b)
	return err
}

func (c *Client) readConn(buf []byte, timeout time.Duration) (int, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	return c.conn.Read(buf)
}

// initInfo requests the device list and selects the target camera.
func (c *Client) initInfo() error {
	if len(c.cfg.Devices) > 0 {
		c.devices = c.cfg.Devices
	}

	initMsg := BuildInitInfoMsg(c.cfg.Token, c.certResult.SessionID, c.nextSqnum(), c.certResult.SessionKey, c.pwdKey)
	if err := c.writeConn(initMsg); err != nil {
		return err
	}

	for i := 0; i < 10; i++ {
		n, err := c.readConn(c.rbuf, 3*time.Second)
		if err != nil {
			break
		}
		decrypted := TryDecrypt(c.rbuf[:n], c.certResult.SessionKey, c.pwdKey)
		if decrypted == nil {
			continue
		}

		// routing session ID from 0x0D
		if decrypted[1] == SubTypeSessionResp && n >= 36 && c.routingSessionID == 0 {
			c.routingSessionID = binary.LittleEndian.Uint64(decrypted[28:36])
		}

		// device list from 0xA7
		if decrypted[1] == SubTypeInitInfoResp && n > 24 {
			dumpLen := n - 24
			if dumpLen > 200 {
				dumpLen = 200
			}
			debugf("gwell: INIT_INFO_RESP payload (%d bytes): %x", n-24, decrypted[24:24+dumpLen])
			if devs := ParseInitInfoResp(decrypted[24:n]); len(devs) > 0 {
				c.devices = devs
			}
		}

		if c.routingSessionID != 0 && len(c.devices) > 0 {
			break
		}
	}

	if len(c.devices) == 0 {
		return fmt.Errorf("no devices from InitInfoResp")
	}

	debugf("gwell: initInfo: %d devices, routing sessionID=0x%016X", len(c.devices), c.routingSessionID)
	for _, d := range c.devices {
		debugf("gwell:   device: %q TID=0x%016X", d.Name, d.TID)
	}

	return c.selectTarget()
}

// selectTarget matches the configured MAC against device names
// (device names end with the bare MAC, e.g. GW_GC1_D03F2775AC2F).
func (c *Client) selectTarget() error {
	if c.cfg.DeviceTID != 0 {
		for _, d := range c.devices {
			if d.TID == c.cfg.DeviceTID {
				c.targetDev = d
				debugf("gwell: target device by TID=0x%016X name=%q", d.TID, d.Name)
				return nil
			}
		}
		return fmt.Errorf("device with TID 0x%016X not in device list", c.cfg.DeviceTID)
	}
	if c.cfg.DeviceMAC == "" {
		c.targetDev = c.devices[0]
		return nil
	}
	mac := c.cfg.DeviceMAC
	for _, d := range c.devices {
		if hasMacSuffix(d.Name, mac) {
			c.targetDev = d
			debugf("gwell: target device %q TID=0x%016X", d.Name, d.TID)
			return nil
		}
	}
	var names []string
	for _, d := range c.devices {
		names = append(names, d.Name)
	}
	return fmt.Errorf("device with MAC %s not in device list %v", mac, names)
}

func hasMacSuffix(name, mac string) bool {
	if len(name) < len(mac) {
		return false
	}
	tail := name[len(name)-len(mac):]
	for i := 0; i < len(mac); i++ {
		a := tail[i] | 0x20 // lowercase
		b := mac[i] | 0x20
		if a >= '0' && a <= '9' || a >= 'a' && a <= 'f' {
			if a != b {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

// networkDetect tells the camera (through Mars) about our LAN presence.
func (c *Client) networkDetect() {
	if c.cfg.CameraLanIP == "" {
		return
	}
	ourIP := GetOutboundIP(c.cfg.CameraLanIP)
	if ourIP == nil {
		return
	}
	probe := BuildNetworkDetectProbe(c.cfg.Token, c.routingSessionID, c.nextSqnum(),
		c.targetDev.TID, c.pwdKey, ourIP.String(), 5, 3000)
	_ = c.writeConn(probe)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, err := c.readConn(c.rbuf, 500*time.Millisecond)
		if err != nil {
			continue
		}
		_ = TryDecrypt(c.rbuf[:n], c.certResult.SessionKey, c.pwdKey)
	}
}

// subscribe sends the DevID and token subscribe messages.
func (c *Client) subscribe() {
	useRouting := c.routingSessionID != 0
	sessionKey := c.certResult.SessionKey

	subMsg := BuildSubscribeDevID(c.cfg.Token, c.routingSessionID, c.nextSqnum(),
		c.cfg.Token.AccessID, useRouting, sessionKey, c.pwdKey)
	_ = c.writeConn(subMsg)

	if len(c.cfg.Token.ExtraTokenData) > 0 {
		subTokenMsg := BuildSubscribeTokens(c.cfg.Token, c.routingSessionID, c.nextSqnum(),
			c.cfg.Token.ExtraTokenData, useRouting, sessionKey, c.pwdKey)
		_ = c.writeConn(subTokenMsg)
	}

	for i := 0; i < 5; i++ {
		n, err := c.readConn(c.rbuf, 2*time.Second)
		if err != nil {
			break
		}
		_ = TryDecrypt(c.rbuf[:n], sessionKey, c.pwdKey)
	}
}

// RelayAddr parsing + the CALLING exchange.
func (c *Client) calling() error {
	sessionKey := c.certResult.SessionKey

	c.linkID = mrand.Uint32()
	if c.linkID == 0 {
		c.linkID = 1
	}

	c.mtpRC5Key = make([]byte, 8)
	_, _ = rand.Read(c.mtpRC5Key)
	c.mtpRC5Ctx = NewRC5Key(c.mtpRC5Key)

	var ourLanIP net.IP
	var ourLanPort uint16
	if c.cfg.CameraLanIP != "" {
		ourLanIP = GetOutboundIP(c.cfg.CameraLanIP)
		if c.conn != nil {
			if local, ok := c.conn.LocalAddr().(*net.UDPAddr); ok {
				ourLanPort = uint16(local.Port)
			}
		}
	}

	callingMsg := BuildCallingMsg(c.cfg.Token, c.routingSessionID, c.nextSqnum(),
		c.linkID, c.targetDev.TID, sessionKey, c.pwdKey, ourLanIP, ourLanPort, c.mtpRC5Key)
	if err := c.writeConn(callingMsg); err != nil {
		return err
	}

	// relay-only variant: some cameras ignore calls that advertise a LAN
	// address they cannot reach, so fall back to a relay-only CALLING
	var relayCallingMsg []byte
	if ourLanIP != nil {
		relayCallingMsg = BuildCallingMsg(c.cfg.Token, c.routingSessionID, c.nextSqnum(),
			c.linkID, c.targetDev.TID, sessionKey, c.pwdKey, nil, 0, c.mtpRC5Key)
	}

	var callingPeerIP net.IP
	var callingPeerPort uint16
	var peerOuterPort, peerSessionPort, peerLanPort uint16
	var peerOuterIP, peerLanIP net.IP

	// The camera (especially a sleeping battery doorbell) may need tens of
	// seconds to answer the call: keep retransmitting CALLING while waiting
	// for the MTP_RES_RESPONSE (the SDK does the same).
	gotMTPRes := false
	lastWakeup := time.Time{}
	callStart := time.Now()
	usingLan := ourLanIP != nil
	callTimeout := c.cfg.CallTimeout
	if callTimeout <= 0 {
		callTimeout = defaultCallTimeout
	}
	deadline := callStart.Add(callTimeout)
	for time.Now().Before(deadline) {
		if c.cfg.OnWakeup != nil && time.Since(lastWakeup) > 20*time.Second {
			lastWakeup = time.Now()
			if err := c.cfg.OnWakeup(); err != nil {
				debugf("gwell: wakeup during call: %v", err)
			} else {
				debugf("gwell: wakeup re-sent during call")
			}
		}

		// no answer with the LAN address: retry relay-only
		if usingLan && relayCallingMsg != nil && time.Since(callStart) > 25*time.Second {
			usingLan = false
			callingMsg = relayCallingMsg
			debugf("gwell: no MTP_RES with LAN address, retrying relay-only CALLING")
			_ = c.writeConn(callingMsg)
		}

		readTimeout := time.Until(deadline)
		if readTimeout > 3*time.Second {
			readTimeout = 3 * time.Second
		} else if readTimeout < 10*time.Millisecond {
			readTimeout = 10 * time.Millisecond
		}
		n, err := c.readConn(c.rbuf, readTimeout)
		if err != nil {
			// retransmit CALLING on every timeout
			if err := c.writeConn(callingMsg); err != nil {
				return err
			}
			continue
		}
		if n > 0 && c.rbuf[0] == 0xC0 {
			continue // MTP frame during CALLING phase
		}
		decrypted := TryDecrypt(c.rbuf[:n], sessionKey, c.pwdKey)
		if decrypted == nil {
			continue
		}

		sub := decrypted[1]

		// CALLING ACK: peer address at [32:38]
		if sub == SubTypeCalling && n >= 38 {
			callingPeerIP = net.IPv4(decrypted[32], decrypted[33], decrypted[34], decrypted[35])
			callingPeerPort = binary.LittleEndian.Uint16(decrypted[36:38])
			debugf("gwell: CALLING ACK peer=%s:%d", callingPeerIP, callingPeerPort)
		}

		// MTP_RES_RESPONSE
		if sub == SubTypeMTPResResp && n >= 0x68 {
			peerOuterPort = binary.LittleEndian.Uint16(decrypted[0x58:0x5A])
			peerOuterIP = net.IPv4(decrypted[0x60], decrypted[0x61], decrypted[0x62], decrypted[0x63])
			peerLanIP = net.IPv4(decrypted[0x64], decrypted[0x65], decrypted[0x66], decrypted[0x67])
			peerSessionPort = binary.LittleEndian.Uint16(decrypted[0x5E:0x60])
			peerLanPort = binary.LittleEndian.Uint16(decrypted[0x5A:0x5C])
			c.parseRelayList(decrypted, n)
			gotMTPRes = true
			debugf("gwell: MTP_RES: outer=%s:%d lan=%s:%d session=%d relays=%d",
				peerOuterIP, peerOuterPort, peerLanIP, peerLanPort, peerSessionPort, len(c.relayAddrs))
			break
		}
	}

	// The camera's self-reported LAN IP is authoritative; use it for the
	// direct media path when it differs from the configured one.
	cameraLanIP := c.cfg.CameraLanIP
	if peerLanIP != nil && !peerLanIP.Equal(net.IPv4zero) && isCameraLanIP(peerLanIP) {
		cameraLanIP = peerLanIP.String()
		if c.cfg.CameraLanIP != "" && cameraLanIP != c.cfg.CameraLanIP {
			debugf("gwell: camera LAN IP from MTP_RES (%s) differs from configured %s",
				cameraLanIP, c.cfg.CameraLanIP)
		}
	}

	if callingPeerIP == nil && !gotMTPRes && len(c.relayAddrs) == 0 {
		return fmt.Errorf("gwell: camera not answering the call (sleeping or offline)")
	}

	// Reopen the socket as unconnected for multi-target media transport
	localPort := 0
	if local, ok := c.conn.LocalAddr().(*net.UDPAddr); ok {
		localPort = local.Port
	}
	_ = c.conn.Close()
	c.conn = nil

	pc, err := net.ListenUDP("udp4", &net.UDPAddr{Port: localPort})
	if err != nil {
		pc, err = net.ListenUDP("udp4", nil)
		if err != nil {
			return err
		}
	}
	c.pc = pc

	// Camera address list from the response ports
	if cameraLanIP != "" {
		if lanIP := net.ParseIP(cameraLanIP); lanIP != nil {
			seen := map[uint16]bool{}
			addPort := func(p uint16) {
				if p != 0 && !seen[p] {
					seen[p] = true
					c.lanMTPAddrs = append(c.lanMTPAddrs, &net.UDPAddr{IP: lanIP, Port: int(p)})
				}
			}
			addPort(peerLanPort)
			addPort(peerSessionPort)
			addPort(callingPeerPort)
			addPort(peerOuterPort)
			addPort(6789)
			addPort(32761)
			addPort(32100)
		}
	}

	// MTP_RES_REQUEST via the server
	mtpResReq := BuildMTPResRequest(c.cfg.Token, c.linkID, c.targetDev.TID, c.routingSessionID, sessionKey, c.pwdKey)
	_ = pc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = pc.WriteToUDP(mtpResReq, c.serverAddr)
	_ = pc.SetWriteDeadline(time.Time{})

	// unbuffered: an unconsumed result is closed by the dialer when the
	// session ends instead of leaking
	tcpRelayChan := make(chan net.Conn)
	c.startRelayActivation(tcpRelayChan)
	c.probeAndWait()

	// Transport priority: LAN direct, then TCP relay
	if len(c.lanMTPAddrs) == 0 {
		select {
		case conn := <-tcpRelayChan:
			if conn != nil {
				c.tcpRelay = conn
			}
		case <-time.After(5 * time.Second):
			// dialer keeps its conn and closes it when the session ends
		}
	}

	if len(c.lanMTPAddrs) > 0 {
		for _, a := range c.lanMTPAddrs {
			debugf("gwell: LAN MTP addr: %s", a)
		}
	} else {
		debugf("gwell: no LAN MTP addresses, relay-only mode")
	}

	for _, ra := range c.relayAddrs {
		seen := map[netip.AddrPort]bool{}
		addr, err := netip.ParseAddr(ra.IP.String())
		if err != nil {
			continue
		}
		ap := netip.AddrPortFrom(addr, ra.Port)
		if seen[ap] {
			continue
		}
		seen[ap] = true
		if raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ra.IP, ra.Port)); err == nil {
			c.udpRelays = append(c.udpRelays, udpRelayTarget{Addr: raddr, SessionID: ra.SessionID})
		}
	}

	return nil
}

func (c *Client) parseRelayList(decrypted []byte, n int) {
	if n < 0x7B {
		return
	}
	relayV4Count := int(decrypted[0x78])
	if relayV4Count > 32 {
		relayV4Count = 32
	}
	relayOff := 0x7A
	for ri := 0; ri < relayV4Count && relayOff+16 <= n; ri++ {
		rFlags := binary.LittleEndian.Uint16(decrypted[relayOff+8 : relayOff+10])
		rPort := binary.LittleEndian.Uint16(decrypted[relayOff+10 : relayOff+12])
		rIP := net.IPv4(decrypted[relayOff+12], decrypted[relayOff+13], decrypted[relayOff+14], decrypted[relayOff+15])
		isTCP := (rFlags>>2)&1 == 1
		relaySessID := binary.LittleEndian.Uint64(decrypted[relayOff : relayOff+8])
		c.relayAddrs = append(c.relayAddrs, RelayAddr{IP: rIP, Port: rPort, TCP: isTCP, SessionID: relaySessID})
		debugf("gwell:   relay: %s:%d tcp=%v", rIP, rPort, isTCP)
		relayOff += 16
	}
}

// startRelayActivation launches background relay registration attempts.
func (c *Client) startRelayActivation(tcpRelayChan chan net.Conn) {
	if len(c.relayAddrs) == 0 {
		// P2P server TCP fallback
		go func() {
			time.Sleep(500 * time.Millisecond)
			dialer := net.Dialer{Timeout: 5 * time.Second}
			conn, err := dialer.Dial("tcp", c.serverAddr.String())
			if err != nil {
				select {
				case tcpRelayChan <- nil:
				case <-c.stop:
				}
				return
			}
			reg := BuildTCPRelayRegister(c.linkID, c.cfg.Token.AccessID, c.targetDev.TID)
			_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			_, _ = conn.Write(reg)
			_ = conn.SetWriteDeadline(time.Time{})
			select {
			case tcpRelayChan <- conn:
			case <-c.stop:
				_ = conn.Close()
			}
		}()
		return
	}

	// Session socket activation to camera + server + relays
	go func() {
		var addrs []*net.UDPAddr
		_, lans := c.lanSnapshot()
		addrs = append(addrs, lans...)
		addrs = append(addrs, c.serverAddr)
		var relayPortList []uint16
		for i, ra := range c.relayAddrs {
			if raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ra.IP, ra.Port)); err == nil {
				addrs = append(addrs, raddr)
			}
			if i < 4 {
				relayPortList = append(relayPortList, ra.Port)
			}
		}
		for round := 0; round < 10 && !c.isClosed(); round++ {
			subType := byte(1)
			if round == 2 {
				subType = 2
			}
			ssFrame := BuildSessionSocket(c.cfg.Token, c.routingSessionID, c.sqnum.Load(),
				c.linkID, c.targetDev.TID, subType, relayPortList, c.pwdKey)
			for _, addr := range addrs {
				_, _ = c.pc.WriteToUDP(ssFrame, addr)
			}
			time.Sleep(400 * time.Millisecond)
		}
	}()

	// UDP relay pre-registration
	go func() {
		reg := BuildTCPRelayRegister(c.linkID, c.cfg.Token.AccessID, c.targetDev.TID)
		seen := map[netip.AddrPort]bool{}
		for _, ra := range c.relayAddrs {
			addr, err := netip.ParseAddr(ra.IP.String())
			if err != nil {
				continue
			}
			ap := netip.AddrPortFrom(addr, ra.Port)
			if seen[ap] {
				continue
			}
			seen[ap] = true
			raddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ra.IP, ra.Port))
			if raddr != nil {
				_, _ = c.pc.WriteToUDP(reg, raddr)
			}
		}
	}()

	// TCP relay dial race
	go func() {
		time.Sleep(200 * time.Millisecond)
		seen := map[netip.AddrPort]bool{}
		var addrs []string
		for _, ra := range c.relayAddrs {
			if !ra.TCP {
				continue
			}
			addr, err := netip.ParseAddr(ra.IP.String())
			if err != nil {
				continue
			}
			ap := netip.AddrPortFrom(addr, ra.Port)
			if seen[ap] {
				continue
			}
			seen[ap] = true
			addrs = append(addrs, fmt.Sprintf("%s:%d", ra.IP, ra.Port))
		}
		if ap, err := netip.ParseAddrPort(c.serverAddr.String()); err == nil {
			if !seen[ap] {
				addrs = append(addrs, c.serverAddr.String())
			}
		}

		var firstConn net.Conn
	dialLoop:
		for round := 0; round < 30 && firstConn == nil && !c.isClosed(); round++ {
			if round > 0 {
				time.Sleep(1 * time.Second)
			}
			winner := make(chan net.Conn, len(addrs))
			for _, tcpAddr := range addrs {
				go func(addr string) {
					dialer := net.Dialer{Timeout: 5 * time.Second}
					conn, err := dialer.Dial("tcp", addr)
					if err != nil {
						winner <- nil
						return
					}
					reg := BuildTCPRelayRegister(c.linkID, c.cfg.Token.AccessID, c.targetDev.TID)
					_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
					_, _ = conn.Write(reg)
					_ = conn.SetWriteDeadline(time.Time{})
					winner <- conn
				}(tcpAddr)
			}
			for range addrs {
				conn := <-winner
				if conn == nil {
					continue
				}
				if firstConn == nil {
					firstConn = conn
				} else {
					// losing relay sockets must not leak
					_ = conn.Close()
					if c.isClosed() {
						break dialLoop
					}
				}
			}
		}

		// deliver, or close when the session ended (nobody will receive)
		select {
		case tcpRelayChan <- firstConn:
		case <-c.stop:
			if firstConn != nil {
				_ = firstConn.Close()
			}
		}
	}()
}

// probeAndWait sends PortStatReq probes and waits for the camera to send
// its CREATE_KCP meter request.
func (c *Client) probeAndWait() {
	portStatReq := BuildPortStatReq(c.cfg.Token, c.routingSessionID, c.nextSqnum(), c.linkID, c.targetDev.TID, c.pwdKey)
	detectReq := BuildDetectReq2()
	EncryptFrameFull(detectReq, c.pwdKey)

	for _, addr := range c.lanMTPAddrs {
		_, _ = c.pc.WriteToUDP(portStatReq, addr)
		if c.cfg.CameraLanIP != "" && addr.IP.Equal(net.ParseIP(c.cfg.CameraLanIP)) {
			_, _ = c.pc.WriteToUDP(detectReq, addr)
		}
	}
	_, _ = c.pc.WriteToUDP(portStatReq, c.serverAddr)

	createKCPReceived := false
	firstCreateKCP := time.Time{}
	kcpSessionSent := false

	for i := 0; i < 30 && !c.isClosed(); i++ {
		if createKCPReceived && time.Since(firstCreateKCP) >= 3*time.Second {
			break
		}

		_ = c.pc.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, fromAddr, err := c.pc.ReadFromUDP(c.rbuf)
		if err != nil {
			if i%3 == 2 {
				portStatReq = BuildPortStatReq(c.cfg.Token, c.routingSessionID, c.nextSqnum(), c.linkID, c.targetDev.TID, c.pwdKey)
				for _, addr := range c.lanMTPAddrs {
					_, _ = c.pc.WriteToUDP(portStatReq, addr)
				}
				_, _ = c.pc.WriteToUDP(portStatReq, c.serverAddr)
				hb := BuildHeartbeat(c.cfg.Token, c.routingSessionID, c.nextSqnum(), c.certResult.SessionKey, c.pwdKey)
				_, _ = c.pc.WriteToUDP(hb, c.serverAddr)
			}
			if createKCPReceived && kcpSessionSent {
				earlyKCP := BuildCreateKCPSessionMsg(c.linkID, c.cfg.Token.AccessID, c.targetDev.TID)
				earlyFrame := BuildMTPFrame(earlyKCP, true)
				for _, addr := range c.lanMTPAddrs {
					_, _ = c.pc.WriteToUDP(earlyFrame, addr)
				}
			}
			continue
		}

		isFromServer := isSameAddr(fromAddr, c.serverAddr)

		if n > 0 && c.rbuf[0] == 0xC0 {
			if !isFromServer && fromAddr != nil {
				mtpFlags := c.rbuf[1]
				if (mtpFlags>>5)&3 == 0 {
					c.addLanMTPAddr(fromAddr)
				}
			}

			probePayOff := MTPPayloadOffset(c.rbuf[1])
			if !isFromServer && n >= probePayOff+8 && c.rbuf[probePayOff] == 0x00 && c.rbuf[probePayOff+1] == 0x01 {
				if !createKCPReceived {
					createKCPReceived = true
					firstCreateKCP = time.Now()
					debugf("gwell: CREATE_KCP received from %s", fromAddr)
				}
				respPayload := BuildMeterAckFromRequest(c.rbuf[probePayOff:minInt(n, probePayOff+68)])
				respFrame := BuildMTPFrame(respPayload, true)
				if fromAddr != nil {
					_, _ = c.pc.WriteToUDP(respFrame, fromAddr)
				}
				for _, addr := range c.lanMTPAddrs {
					_, _ = c.pc.WriteToUDP(respFrame, addr)
				}
				for _, ra := range c.relayAddrs {
					if raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ra.IP, ra.Port)); err == nil {
						extFrame := BuildExtendedMTPFrame(respPayload, c.targetDev.TID, true)
						_, _ = c.pc.WriteToUDP(extFrame, raddr)
					}
				}

				if !kcpSessionSent {
					kcpSessionSent = true
					earlyKCP := BuildCreateKCPSessionMsg(c.linkID, c.cfg.Token.AccessID, c.targetDev.TID)
					earlyFrame := BuildMTPFrame(earlyKCP, true)
					if fromAddr != nil {
						_, _ = c.pc.WriteToUDP(earlyFrame, fromAddr)
					}
					for _, addr := range c.lanMTPAddrs {
						_, _ = c.pc.WriteToUDP(earlyFrame, addr)
					}
					for _, ra := range c.relayAddrs {
						if raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ra.IP, ra.Port)); err == nil {
							extFrame := BuildExtendedMTPFrame(earlyKCP, c.targetDev.TID, true)
							_, _ = c.pc.WriteToUDP(extFrame, raddr)
						}
					}
				}
			}
		} else {
			decrypted := TryDecrypt(c.rbuf[:n], c.certResult.SessionKey, c.pwdKey)
			if decrypted == nil {
				continue
			}
			sub := decrypted[1]
			if sub == SubTypePortStatResp || sub == SubTypeDetectResp {
				debugf("gwell: %s from %s (server=%v)", subTypeName(sub), fromAddr, isFromServer)
				if !isFromServer && !createKCPReceived {
					c.addLanMTPAddr(fromAddr)
					createKCPReceived = true
					firstCreateKCP = time.Now()
					kcpSessionSent = true
					earlyKCP := BuildCreateKCPSessionMsg(c.linkID, c.cfg.Token.AccessID, c.targetDev.TID)
					earlyFrame := BuildMTPFrame(earlyKCP, true)
					for _, addr := range c.lanMTPAddrs {
						_, _ = c.pc.WriteToUDP(earlyFrame, addr)
					}
				}
			}
			if sub == SubTypePortStatReq && !isFromServer {
				resp := BuildPortStatResp(c.cfg.Token, c.routingSessionID, c.nextSqnum(), c.linkID, c.targetDev.TID, c.pwdKey)
				_, _ = c.pc.WriteToUDP(resp, fromAddr)
				c.addLanMTPAddr(fromAddr)
			}
		}
	}
}

// isCameraLanIP reports whether the IP is on a real LAN subnet (or loopback,
// which occurs with local port-forwards). 172.16.0.0/12 is excluded as it is
// commonly a container bridge that cannot reach the camera.
func isCameraLanIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4[0] == 127 {
		return true
	}
	if ip4[0] == 10 {
		return true
	}
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}
	return false
}

func (c *Client) addLanMTPAddr(addr *net.UDPAddr) {
	if addr == nil || !isCameraLanIP(addr.IP) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, a := range c.lanMTPAddrs {
		if a.IP.Equal(addr.IP) && a.Port == addr.Port {
			return
		}
	}
	c.lanMTPAddrs = append(c.lanMTPAddrs, &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port})
}

// lanPathFresh reports whether the locked LAN address is still confirmed
// alive by recent inbound traffic.
func (c *Client) lanPathFresh() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.bestLanAddr != nil && time.Since(c.lastLanAlive) < 30*time.Second
}

// lockLanPath adopts a discovered LAN address as the preferred direct path.
func (c *Client) lockLanPath(addr *net.UDPAddr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bestLanAddr == nil && isCameraLanIP(addr.IP) {
		c.bestLanAddr = &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port}
		c.lastLanAlive = time.Now()
	}
}

// noteLanAlive refreshes the liveness timestamp when traffic arrives from
// the locked LAN address.
func (c *Client) noteLanAlive(from *net.UDPAddr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bestLanAddr != nil && c.bestLanAddr.IP.Equal(from.IP) && c.bestLanAddr.Port == from.Port {
		c.lastLanAlive = time.Now()
	}
}

// lanSnapshot returns the current transport targets under the transport
// lock, for use by background senders (KCP output callback, relays).
func (c *Client) lanSnapshot() (best *net.UDPAddr, lans []*net.UDPAddr) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.bestLanAddr, c.lanMTPAddrs
}

// sendMTP sends an MTP frame to the camera via the best available path.
func (c *Client) sendMTP(data []byte) {
	if c.lanPathFresh() {
		if best, _ := c.lanSnapshot(); best != nil {
			_, _ = c.pc.WriteToUDP(data, best)
			return
		}
	}

	_, lans := c.lanSnapshot()
	for _, addr := range lans {
		_, _ = c.pc.WriteToUDP(data, addr)
	}

	if c.tcpRelay != nil {
		tcpData := make([]byte, len(data))
		copy(tcpData, data)
		if len(tcpData) > 1 {
			tcpData[1] &^= 0x10
		}
		_ = c.tcpRelay.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.tcpRelay.Write(tcpData)
	}

	if len(data) > 6 && data[0] == 0xC0 {
		payload := data[6:]
		urgent := data[1]&0x80 != 0
		for _, rt := range c.udpRelays {
			extFrame := BuildExtendedMTPFrame(payload, c.targetDev.TID, urgent)
			_, _ = c.pc.WriteToUDP(extFrame, rt.Addr)
		}
	}
}

// Handshake performs the AVSTREAMCTL exchange: INITREQ, waits for ACCEPT,
// sends START and the viewer AV_INIT. Must be called once after Dial.
func (c *Client) Handshake() error {
	sessionKey := c.certResult.SessionKey

	hb := BuildHeartbeat(c.cfg.Token, c.routingSessionID, c.nextSqnum(), sessionKey, c.pwdKey)
	_, _ = c.pc.WriteToUDP(hb, c.serverAddr)

	// PASSTHROUGH control to trigger KCP creation on the camera
	ptCtrl := BuildPassthroughControl(c.cfg.Token, c.routingSessionID, c.nextSqnum(),
		c.targetDev.TID, 0x01, c.linkID, sessionKey, c.pwdKey)
	_, _ = c.pc.WriteToUDP(ptCtrl, c.serverAddr)
	time.Sleep(200 * time.Millisecond)

	kcpCreateMsg := BuildCreateKCPSessionMsg(c.linkID, c.cfg.Token.AccessID, c.targetDev.TID)
	c.sendMTP(BuildMTPFrame(kcpCreateMsg, true))

	c.convData = c.linkID & 0x7FFFFFFF
	c.convCtrl = c.linkID | 0x80000000

	kcpOutputFn := func(data []byte, size int) {
		payload := data[:size]
		stdFrame := BuildMTPFrame(payload, false)
		best, lans := c.lanSnapshot()
		if c.lanPathFresh() && best != nil {
			_, _ = c.pc.WriteToUDP(stdFrame, best)
			return
		}
		for _, addr := range lans {
			_, _ = c.pc.WriteToUDP(stdFrame, addr)
		}
		for _, rt := range c.udpRelays {
			extFrame := BuildExtendedMTPFrame(payload, c.targetDev.TID, false)
			_, _ = c.pc.WriteToUDP(extFrame, rt.Addr)
		}
		if c.tcpRelay != nil {
			tcpData := make([]byte, len(stdFrame))
			copy(tcpData, stdFrame)
			if len(tcpData) > 1 {
				tcpData[1] &^= 0x10
			}
			_, _ = c.tcpRelay.Write(tcpData)
		}
	}

	c.dataKCP = NewKCPConn(c.convData, kcpOutputFn)
	c.ctrlKCP = NewKCPConn(c.convCtrl, kcpOutputFn)
	c.dataKCP.NoDelay(0, 5, 10, 1)
	c.ctrlKCP.NoDelay(0, 5, 10, 1)
	c.dataKCP.SetWndSize(64, 512)
	c.ctrlKCP.SetWndSize(64, 128)

	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-ticker.C:
				now := uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
				c.dataKCP.Update(now)
				c.ctrlKCP.Update(now)
			}
		}
	}()

	// INITREQ retry loop: a non-zero streamID and avKey=[2,0,...] are required
	c.streamID = mrand.Uint32()
	if c.streamID == 0 {
		c.streamID = 1
	}
	avKey := make([]byte, 32)
	avKey[0] = 0x02
	initreqPayload := BuildAVStreamCtlINITREQ(c.streamID, 1, 1, 0, avKey)

	acceptReceived := false
	kcpSN := uint32(0)
	initDeadline := time.Now().Add(90 * time.Second)

	for retry := 0; !acceptReceived && time.Now().Before(initDeadline) && !c.isClosed(); retry++ {
		ts := uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
		if kcpSN > 0 {
			retransmit := BuildKCPPushSegment(c.convCtrl, 0, ts, initreqPayload)
			c.sendMTP(BuildMTPFrame(retransmit, false))
		}
		kcpSegment := BuildKCPPushSegment(c.convCtrl, kcpSN, ts, initreqPayload)
		c.sendMTP(BuildMTPFrame(kcpSegment, false))
		kcpSN++

		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) && !acceptReceived {
			remaining := time.Until(deadline)
			if remaining < 10*time.Millisecond {
				remaining = 10 * time.Millisecond
			}
			_ = c.pc.SetReadDeadline(time.Now().Add(remaining))
			n, fromAddr, err := c.pc.ReadFromUDP(c.rbuf)
			if err != nil {
				break
			}

			isFromServer := isSameAddr(fromAddr, c.serverAddr)

			if n > 0 && c.rbuf[0] == 0xC0 {
				if !isFromServer && fromAddr != nil {
					mtpFlags := c.rbuf[1]
					if (mtpFlags>>5)&3 == 0 {
						c.addLanMTPAddr(fromAddr)
						c.lockLanPath(fromAddr)
					}
				}

				avCmd := ParseMTPForAVSTREAMCTL(c.rbuf, n, c.convCtrl, c.convData, nil)
				FeedMTPToKCP(c.rbuf, n, c.dataKCP, c.ctrlKCP, c.convData, c.convCtrl)

				if avCmd == AVActionACCEPT {
					acceptReceived = true
					debugf("gwell: AVSTREAMCTL ACCEPT received from %s", fromAddr)
					break
				}
				if avCmd == 0x10001 {
					payOff := MTPPayloadOffset(c.rbuf[1])
					resp := BuildMeterAckFromRequest(c.rbuf[payOff:minInt(n, payOff+68)])
					respFrame := BuildMTPFrame(resp, true)
					if fromAddr != nil {
						_, _ = c.pc.WriteToUDP(respFrame, fromAddr)
					}
					for _, addr := range c.lanMTPAddrs {
						_, _ = c.pc.WriteToUDP(respFrame, addr)
					}
				}
			} else {
				decrypted := TryDecrypt(c.rbuf[:n], c.certResult.SessionKey, c.pwdKey)
				if decrypted != nil && decrypted[1] == SubTypePortStatReq {
					resp := BuildPortStatResp(c.cfg.Token, c.routingSessionID, c.nextSqnum(), c.linkID, c.targetDev.TID, c.pwdKey)
					_, _ = c.pc.WriteToUDP(resp, fromAddr)
				}
			}
		}

		if retry%5 == 4 {
			hb := BuildHeartbeat(c.cfg.Token, c.routingSessionID, c.nextSqnum(), c.certResult.SessionKey, c.pwdKey)
			_, _ = c.pc.WriteToUDP(hb, c.serverAddr)
		}
		if retry%10 == 9 {
			debugf("gwell: INITREQ retry %d, still no ACCEPT", retry)
		}
	}

	if !acceptReceived {
		return fmt.Errorf("gwell: no AVSTREAMCTL ACCEPT after 90s")
	}

	// START via the DATA KCP channel
	startPayload := BuildAVStreamCtlSTART(c.streamID)
	c.dataKCP.Send(startPayload)
	c.dataKCP.Flush()

	// Viewer AV_INIT: 32-byte frame, RC5-encrypted with the MTP session key
	avKeyInit := make([]byte, 32)
	avKeyInit[0] = 0x04
	avKeyInit[1] = 0x02
	binary.LittleEndian.PutUint16(avKeyInit[2:4], 0x0020)
	for i := 0; i < 3; i++ {
		off := 4 + i*8
		c.mtpRC5Ctx.EncryptBlock(avKeyInit[off : off+8])
	}
	c.dataKCP.Send(avKeyInit)
	c.dataKCP.Flush()

	return nil
}

// ReadFrame returns the next video access unit (H.264 Annex B), discarding
// audio sub-frames. Prefer ReadMedia for full audio/video demultiplexing.
func (c *Client) ReadFrame() ([]byte, error) {
	for {
		frame, err := c.ReadMedia()
		if err != nil {
			return nil, err
		}
		if frame.Kind == MediaVideo {
			return frame.Video, nil
		}
	}
}

// ReadMedia returns the next demultiplexed media frame from the camera:
// an H.264 Annex B access unit or a G.711 µ-law audio sub-frame. It
// maintains the session keepalive timers while waiting.
func (c *Client) ReadMedia() (*MediaFrame, error) {
	if c.dataKCP == nil {
		return nil, fmt.Errorf("gwell: handshake not completed")
	}

	lastHeartbeat := time.Now()
	lastMeterProbe := time.Now()
	lastOnlineSocket := time.Now()

	// first frame deadline, only meaningful until media starts flowing
	mediaDeadline := time.Now().Add(noMediaTimeout)
	if !c.lastMedia.IsZero() {
		mediaDeadline = time.Time{}
	}

	for !c.isClosed() {
		if c.remoteStopped {
			c.notePeekSleep()
			return nil, fmt.Errorf("%w: camera stopped the session", ErrSilent)
		}
		if time.Since(lastHeartbeat) > 40*time.Second {
			hb := BuildHeartbeat(c.cfg.Token, c.routingSessionID, c.nextSqnum(), c.certResult.SessionKey, c.pwdKey)
			_, _ = c.pc.WriteToUDP(hb, c.serverAddr)
			lastHeartbeat = time.Now()
		}

		// meter probes keep the camera session alive (~119s timeout)
		if time.Since(lastMeterProbe) > 2*time.Second {
			c.meterRound++
			probe := BuildMeterProbe(c.linkID, c.cfg.Token.AccessID, c.targetDev.TID, c.meterRound)
			c.sendMTP(BuildMTPFrame(probe, true))
			lastMeterProbe = time.Now()
		}

		// online socket keepalive to the Mars server
		if time.Since(lastOnlineSocket) > 10*time.Second {
			keepalive := BuildSessionSocket(c.cfg.Token, c.routingSessionID, c.nextSqnum(),
				c.linkID, c.targetDev.TID, 3, nil, c.pwdKey)
			_, _ = c.pc.WriteToUDP(keepalive, c.serverAddr)
			lastOnlineSocket = time.Now()
		}

		if frame := c.drainKCPRecv(); frame != nil {
			return frame, nil
		}

		// battery cameras (e.g. doorbells) end the live view on their own
		// timer by going silent: surface that as an error so the consumer
		// can redial instead of blocking forever
		if !c.lastMedia.IsZero() && time.Since(c.lastMedia) > c.silentTimeout {
			c.notePeekSleep()
			return nil, fmt.Errorf("%w: battery save (no media for %s)", ErrSilent, c.silentTimeout)
		}

		// a freshly started session must produce media within a bounded
		// time, otherwise the stream hangs forever with no way to redial
		if c.lastMedia.IsZero() && time.Now().After(mediaDeadline) {
			return nil, fmt.Errorf("gwell: no media from camera")
		}

		_ = c.pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, fromAddr, err := c.pc.ReadFromUDP(c.rbuf)
		if err != nil {
			if frame := c.drainKCPRecv(); frame != nil {
				return frame, nil
			}
			continue
		}

		if fromAddr != nil {
			c.noteLanAlive(fromAddr)
		}
		isFromServer := isSameAddr(fromAddr, c.serverAddr)

		if n > 0 && c.rbuf[0] == 0xC0 {
			if !isFromServer && fromAddr != nil {
				mtpFlags := c.rbuf[1]
				if (mtpFlags>>5)&3 == 0 {
					c.addLanMTPAddr(fromAddr)
					c.lockLanPath(fromAddr)
				}
			}

			sessCmd := FeedMTPToKCP(c.rbuf, n, c.dataKCP, c.ctrlKCP, c.convData, c.convCtrl)
			c.ackKCPPushes(c.rbuf, n, fromAddr)

			if sessCmd == 0x10001 {
				payOff := MTPPayloadOffset(c.rbuf[1])
				resp := BuildMeterAckFromRequest(c.rbuf[payOff:minInt(n, payOff+68)])
				respFrame := BuildMTPFrame(resp, true)
				if fromAddr != nil {
					_, _ = c.pc.WriteToUDP(respFrame, fromAddr)
				}
				for _, addr := range c.lanMTPAddrs {
					_, _ = c.pc.WriteToUDP(respFrame, addr)
				}
			}

			if frame := c.drainKCPRecv(); frame != nil {
				return frame, nil
			}
		} else {
			decrypted := TryDecrypt(c.rbuf[:n], c.certResult.SessionKey, c.pwdKey)
			if decrypted == nil {
				continue
			}
			if decrypted[1] == SubTypePortStatReq {
				resp := BuildPortStatResp(c.cfg.Token, c.routingSessionID, c.nextSqnum(), c.linkID, c.targetDev.TID, c.pwdKey)
				_, _ = c.pc.WriteToUDP(resp, fromAddr)
			}
			// PASSTHROUGH DATA carrying MTP frames via the server
			if decrypted[1] == SubTypeNetworkDetect && n >= 52 {
				modeFlags := binary.LittleEndian.Uint32(decrypted[24:28])
				if modeFlags&1 == 0 {
					ptPayloadLen := binary.LittleEndian.Uint16(decrypted[48:50])
					if int(52+ptPayloadLen) <= n && ptPayloadLen > 0 {
						ptPayload := decrypted[52 : 52+ptPayloadLen]
						if ptPayload[0] == 0xC0 && ptPayloadLen >= 6 {
							copy(c.rbuf[:ptPayloadLen], ptPayload)
							FeedMTPToKCP(c.rbuf, int(ptPayloadLen), c.dataKCP, c.ctrlKCP, c.convData, c.convCtrl)
							if frame := c.drainKCPRecv(); frame != nil {
								return frame, nil
							}
						}
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("gwell: session closed")
}

// ackKCPPushes sends a direct KCP ACK for every PUSH segment in the frame.
func (c *Client) ackKCPPushes(buf []byte, n int, fromAddr *net.UDPAddr) {
	off := MTPPayloadOffset(buf[1])
	// skip a session control message prefix if present
	if n >= off+8 && buf[off] == 0x00 {
		mcmd := buf[off+1]
		if isMTPSessionCmd(mcmd) {
			msLen := binary.LittleEndian.Uint16(buf[off+2 : off+4])
			off += int(msLen)
		}
	}
	for off+24 <= n {
		kcpCmd := buf[off+4]
		if kcpCmd == 81 {
			kcpConv := binary.LittleEndian.Uint32(buf[off : off+4])
			kcpSN := binary.LittleEndian.Uint32(buf[off+12 : off+16])
			kcpTS := binary.LittleEndian.Uint32(buf[off+8 : off+12])
			ackSeg := BuildKCPAckSegment(kcpConv, kcpSN, kcpTS, c.dataKCP.RcvNxt())
			ackMTP := BuildMTPFrame(ackSeg, false)
			if fromAddr != nil {
				_, _ = c.pc.WriteToUDP(ackMTP, fromAddr)
			}
		}
		segLen := binary.LittleEndian.Uint32(buf[off+20 : off+24])
		off += 24 + int(segLen)
	}
}

// drainKCPRecv extracts the next media frame from both KCP receive queues.
// Audio sub-frames are returned first to keep audio latency low.
func (c *Client) drainKCPRecv() *MediaFrame {
	if frame := c.popMediaFrame(); frame != nil {
		c.lastMedia = time.Now()
		return frame
	}

	if c.dataKCP == nil || c.ctrlKCP == nil {
		return nil
	}

	for {
		data := c.dataKCP.Recv()
		if data == nil {
			break
		}
		// AVSTREAMCTL on the data channel: echo the camera's STARTED back once
		if len(data) >= 12 && data[0] == 0x03 {
			if action := binary.LittleEndian.Uint32(data[8:12]); action == AVActionSTART && !c.echoedStarted {
				c.echoedStarted = true
				c.dataKCP.Send(data)
				c.dataKCP.Flush()
			}
			continue
		}

		if payload := DecryptMTPPayload(data, c.mtpRC5Ctx); payload != nil {
			c.mux.Write(payload)
		}
	}

	for {
		data := c.ctrlKCP.Recv()
		if data == nil {
			break
		}
		tracef("kcp.ctrl", data)
		// Control channel carries AVSTREAMCTL (type=0x03) messages;
		// echo STARTED (cmd=6) frames back to the camera on the DATA channel.
		if len(data) >= 12 && data[0] == 0x03 {
			switch action := binary.LittleEndian.Uint32(data[8:12]); action {
			case AVActionSTART:
				c.dataKCP.Send(data)
				c.dataKCP.Flush()
			case AVActionSTOP, AVActionCLOSE:
				// the camera ended the live session (e.g. battery doorbell
				// going back to sleep)
				c.remoteStopped = true
			default:
				debugf("gwell: ctrl AVSTREAMCTL action=%d session=0x%X",
					action, binary.LittleEndian.Uint32(data[4:8]))
			}
		}
	}

	return c.popMediaFrame()
}

// popMediaFrame returns the next queued media frame, audio first, without
// updating the media liveness clock.
func (c *Client) popMediaFrame() *MediaFrame {
	if len(c.audioQueue) > 0 {
		f := c.audioQueue[0]
		c.audioQueue = c.audioQueue[1:]
		return &MediaFrame{Kind: MediaAudio, Audio: f}
	}
	if len(c.auQueue) > 0 {
		au := c.auQueue[0]
		c.auQueue = c.auQueue[1:]
		return &MediaFrame{Kind: MediaVideo, Video: au}
	}
	return nil
}

// deviceKey identifies the camera for the peek cooldown table.
func (c *Client) deviceKey() string {
	if c.cfg.DeviceMAC != "" {
		return c.cfg.DeviceMAC
	}
	return fmt.Sprintf("tid:%d", c.cfg.DeviceTID)
}

// sleepCooldown returns the effective peek sleep cooldown for this source.
func (c *Client) sleepCooldown() time.Duration {
	if c.cfg.SleepCooldown != 0 {
		return c.cfg.SleepCooldown
	}
	return peekSleepCooldown
}

// notePeekSleep records the sleep cooldown in peek mode: reconnects must
// not restart the camera before it reaches deep sleep. A negative
// SleepCooldown disables the cooldown entirely.
func (c *Client) notePeekSleep() {
	if !c.cfg.Peek || c.sleepCooldown() < 0 {
		return
	}
	peekCooldowns.Store(c.deviceKey(), time.Now().Add(c.sleepCooldown()))
}

// GetOutboundIP returns the local IP that routes to the given target.
func GetOutboundIP(targetIP string) net.IP {
	conn, err := net.Dial("udp4", targetIP+":1")
	if err != nil {
		return nil
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}

func isSameAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.IP.Equal(b.IP) && a.Port == b.Port
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
