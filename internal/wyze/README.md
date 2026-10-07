# Wyze

[`new in v1.9.14`](https://github.com/AlexxIT/go2rtc/releases/tag/v1.9.14) by [@seydx](https://github.com/AlexxIT/go2rtc)

This source allows you to stream from [Wyze](https://wyze.com/) cameras using native P2P protocol without the Wyze app or SDK.

**Important:**

1. **Requires Wyze account**. You need to login once via the WebUI to load your cameras.
2. **TUTK cameras require firmware with DTLS**. Only cameras with DTLS-enabled firmware are supported.
3. Internet access is only needed when loading cameras from your account. After that, all streaming is local P2P.
4. Connection to the camera is local only (direct P2P to camera IP).
5. **Gwell cameras** (Wyze Cam OG, Cam OG Telephoto, Cam Pan v4, and Gwell firmware revisions of other models) are supported natively: the stream falls back from TUTK to the Gwell/IoTVideo protocol automatically.

**Features:**

- H.264 and H.265 video codec support
- AAC, G.711, PCM, and Opus audio codec support (TUTK)
- Two-way audio (intercom) support (TUTK)
- Resolution switching (HD/SD)
- Gwell/IoTVideo P2P protocol with H.264 video and G.711 µ-law (16 kHz) audio

**Gwell notes:**

- Gwell cameras send audio and video automatically; no extra request is needed.
- Battery doorbells (e.g. Doorbell Pro) sleep and must be woken via the Wyze
  cloud API before each call (handled automatically), end the live view after
  ~20 seconds on their own timer, and go back to sleep. go2rtc reports the
  session end and reconnects on the next consumer request.
- Add `&wake=0` to a stream URL for a peek mode that never sends cloud
  wakeups: it connects only when the camera is already awake (e.g. from a
  motion event or another active stream) and fails fast with "camera not
  answering the call" while the camera sleeps. Combine it with a second
  stream entry to preview motion-triggered live view without ringing the
  doorbell awake on every click. After the camera ends its live view and
  goes to sleep, peek dials are refused for a short cooldown window so
  that automatic reconnects cannot keep the camera awake. The cooldown
  defaults to 60 seconds and can be tuned per stream with `&cooldown=`
  (Go duration like `90s`/`2m`, or plain seconds like `90`; `&cooldown=0`
  disables it).
- LAN-direct calls advertise the local IP in the CALLING frame; when the
  camera cannot reach it, the client falls back to relay-only calling
  automatically.

## Setup

1. Get your API Key from [Wyze Developer Portal](https://support.wyze.com/hc/en-us/articles/16129834216731)
2. Go to go2rtc WebUI > Add > Wyze
3. Enter your API ID, API Key, email, and password
4. Select cameras to add - stream URLs are generated automatically

**Example Config**

```yaml
wyze:
  user@email.com:
    api_id: "your-api-id"
    api_key: "your-api-key"
    password: "yourpassword"    # or MD5 triple-hash with "md5:" prefix

streams:
  wyze_cam: wyze://192.168.1.123?uid=WYZEUID1234567890AB&enr=xxx&mac=AABBCCDDEEFF&model=HL_CAM4&dtls=true
  gwell_cam: wyze://192.168.1.230?mac=AABBCCDDEEFF&model=HL_CAM4&proto=gwell
```

## Stream URL Format

The stream URL is automatically generated when you add cameras via the WebUI:

```
wyze://[IP]?uid=[P2P_ID]&enr=[ENR]&mac=[MAC]&model=[MODEL]&subtype=[hd|sd]&dtls=true
```

| Parameter | Description                                     |
|-----------|-------------------------------------------------|
| `IP`      | Camera's local IP address                       |
| `uid`     | P2P identifier (20 chars)                       |
| `enr`     | Encryption key for DTLS                         |
| `mac`     | Device MAC address                              |
| `model`   | Camera model (e.g., HL_CAM4)                    |
| `dtls`    | Enable DTLS encryption (default: true)          |
| `subtype` | Camera resolution: `hd` or `sd` (default: `hd`) |
| `proto`   | Force protocol: `tutk` or `gwell` (default: auto) |

Without a `proto` parameter the TUTK protocol is tried first and the source
falls back to Gwell when the TUTK handshake fails. Gwell cameras are also
matched by MAC when the cloud reports a `GW_` device identifier.

### Gwell cameras

Gwell (IoTVideo) cameras stream via Wyze's Mars P2P infrastructure:

1. go2rtc registers a Mars user for the camera with your Wyze account
   (credentials are cached for 7 days, like the vendor SDK).
2. The client certifies with a Mars server, looks up the camera in the
   account device list and initiates a CALLING.
3. The media path is negotiated directly to the camera on the LAN (UDP +
   KCP), with Mars relays as fallback.
4. Video is transported as RC5-encrypted H.264 over the KCP session.

Advanced: you can pass per-camera Mars credentials directly in the URL
(`&access_id=...&access_token=...`) to skip the account requirement, and
select a specific account with `&email=...`.

## Configuration

### Resolution

You can change the camera's resolution using the `subtype` parameter (TUTK cameras):

```yaml
streams:
  wyze_hd: wyze://...&subtype=hd
  wyze_sd: wyze://...&subtype=sd
```

### Two-Way Audio

Two-way audio (intercom) is supported automatically on TUTK cameras. When a consumer sends audio to the stream, it will be transmitted to the camera's speaker.

## Camera Compatibility

| Name                        | Model          | Firmware     | Protocol | Encryption | Codecs     |
|-----------------------------|----------------|--------------|----------|------------|------------|
| Wyze Cam v4                 | HL_CAM4        | 4.52.9.4188  | TUTK     | TransCode  | h264, aac  |
|                             |                | 4.52.9.5332  | TUTK     | HMAC-SHA1  | h264, aac  |
|                             |                | 5.x          | Gwell    | RC5        | h264       |
| Wyze Cam v3 Pro             |                |              | TUTK     |            |            |
| Wyze Cam v3                 | WYZE_CAKP2JFUS | 4.36.14.3497 | TUTK     | TransCode  | h264, pcm  |
| Wyze Cam v2                 | WYZEC1-JZ      | 4.9.9.3006   | TUTK     | TransCode  | h264, pcmu |
| Wyze Cam v1                 |                |              | TUTK     |            |            |
| Wyze Cam Pan v4             |                |              | Gwell    | RC5        | h264       |
| Wyze Cam Pan v3             |                |              | TUTK     |            |            |
| Wyze Cam Pan v2             |                |              | TUTK     |            |            |
| Wyze Cam Pan v1             |                |              | TUTK     |            |            |
| Wyze Cam OG                 | GW_GC1         |              | Gwell    | RC5        | h264       |
| Wyze Cam OG Telephoto       | GW_GC2         |              | Gwell    | RC5        | h264       |
| Wyze Cam OG (2025)          |                |              | Gwell    | RC5        | h264       |
| Wyze Cam Outdoor v2         |                |              | TUTK     |            |            |
| Wyze Cam Outdoor v1         |                |              | TUTK     |            |            |
| Wyze Cam Floodlight Pro     |                |              | ?        |            |            |
| Wyze Cam Floodlight v2      |                |              | TUTK     |            |            |
| Wyze Cam Floodlight         |                |              | TUTK     |            |            |
| Wyze Video Doorbell v2      | HL_DB2         | 4.51.3.4992  | TUTK     | TransCode  | h264, pcm  |
| Wyze Video Doorbell v1      |                |              | TUTK     |            |            |
| Wyze Video Doorbell Pro     | GW_BE1/GW_BE2  |              | Gwell    | RC5        | h264, pcmu |
| Wyze Battery Video Doorbell |                |              | ?        |            |            |
| Wyze Duo Cam Doorbell       | GW_DB2         |              | Gwell    | RC5        | h264       |
| Wyze Battery Cam Pro        |                |              | ?        |            |            |
| Wyze Solar Cam Pan          |                |              | ?        |            |            |
| Wyze Duo Cam Pan            |                |              | ?        |            |            |
| Wyze Window Cam             |                |              | ?        |            |            |
| Wyze Bulb Cam               |                |              | ?        |            |            |

## Live test harness

`pkg/gwell/live_test.go` is a real-camera integration harness for developing
against the Gwell protocol. It is skipped by default and runs against a real
camera when environment variables are set:

```bash
GWELL_LIVE_SOURCE="wyze://GW_BE1_XXXXXXXXXXXX?mac=XXXXXXXXXXXX&proto=gwell" \
GWELL_LIVE_SECRET=/path/to/go2rtc.yaml   # wyze: {email: {api_id, api_key, password}}
GWELL_LIVE_SECONDS=30 \
GWELL_TRACE=/tmp/trace.log              # raw frame dumps (hex, one per line)
GWELL_DUMP_DIR=/tmp/dump                # writes video.264 and audio.bin
go test ./pkg/gwell/ -run TestLiveCamera -v
```

`GWELL_AUDIO_PROBE=name@seconds,...` schedules experimental protocol probes
(useful for reverse-engineering; e.g. `initreq-ud3@5s,startplain@10s`).
