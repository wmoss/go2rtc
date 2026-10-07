package gwell

// The camera delivers the H.264 elementary stream as a continuous Annex B
// byte stream, chunked over multiple KCP messages (~1004 bytes each) with a
// 28-byte 0xffffff88 head_info prepended to each access unit. The demuxer
// buffers the stream and extracts complete access units.

const (
	annexbBufLimit = 4 << 20 // drop the buffer if no boundary is found
	auMagic        = 0xffffff88
)

// annexbDemuxer reassembles an Annex B byte stream into access units.
type annexbDemuxer struct {
	buf []byte
}

// Write appends stream bytes and returns the access units that became
// complete. The head_info magic is stripped when found.
func (d *annexbDemuxer) Write(p []byte) [][]byte {
	if len(p) == 0 {
		return nil
	}

	// strip a head_info magic at the start of a chunk (access unit header)
	if hasHeadInfo(p) {
		p = p[28:]
	}
	if len(p) == 0 {
		return nil
	}

	d.buf = append(d.buf, p...)

	if len(d.buf) > annexbBufLimit {
		// no Annex B boundary within 4 MiB: the stream is corrupt
		debugf("gwell: annexb demuxer buffer over limit, dropping %d bytes", len(d.buf))
		d.buf = nil
		return nil
	}

	return d.extract()
}

// extract walks the buffered stream and splits it into access units.
// An access unit boundary is a NAL unit of type SPS, AUD, IDR, or a slice
// with first_mb_in_slice == 0. Trailing bytes (possibly an incomplete unit)
// stay buffered.
func (d *annexbDemuxer) extract() [][]byte {
	var aus [][]byte

	for {
		au, ok := d.nextAU()
		if !ok {
			break
		}
		if len(au) > 0 {
			aus = append(aus, au)
		}
	}

	return aus
}

// nextAU finds the next access unit boundary and returns the bytes before it.
// A new access unit starts at a SPS or AUD NAL unit, or at a slice NAL unit
// with first_mb_in_slice == 0 when the current unit already has a slice
// (this keeps SPS+PPS+IDR together in one packet).
func (d *annexbDemuxer) nextAU() ([]byte, bool) {
	buf := d.buf

	if len(buf) == 0 {
		return nil, false
	}

	// the buffer must start with a start code (access unit boundary);
	// skip anything before the first one
	auStart, auHeader, ok := findStartCode(buf, 0)
	if !ok {
		return nil, false
	}
	if auStart > 0 {
		d.buf = buf[auStart:]
		buf = d.buf
		auHeader -= auStart
	}

	hasSlice := false
	if t := buf[auHeader] & 0x1F; t == 1 || t == 5 {
		hasSlice = true
	}

	pos := auHeader
	for {
		nextStart, nextHeader, ok := findStartCode(buf, pos)
		if !ok {
			// no complete boundary yet: wait for more data
			return nil, false
		}

		naluType := buf[nextHeader] & 0x1F

		boundary := false
		switch naluType {
		case 7, 9: // SPS, AUD
			boundary = true
		case 1, 5: // slice, IDR
			boundary = hasSlice && firstMbZero(buf, nextHeader)
		}

		if boundary && nextStart > auStart {
			au := buf[:nextStart]
			d.buf = buf[nextStart:]
			return au, true
		}
		if naluType == 1 || naluType == 5 {
			hasSlice = true
		}
		pos = nextHeader
	}
}

// firstMbZero checks the first_mb_in_slice ue(v) of a slice NAL unit:
// a set first bit means the value is 0 (start of a new picture).
// Non-slice types always return true.
func firstMbZero(buf []byte, header int) bool {
	naluType := buf[header] & 0x1F
	if naluType != 1 && naluType != 5 {
		return true
	}

	// first byte after the NAL header (emulation prevention in a slice
	// header is extremely unlikely to affect the first bit)
	if header+1 >= len(buf) {
		return false
	}
	return buf[header+1]&0x80 != 0
}

// findStartCode locates the next Annex B start code in buf from offset.
// Returns the offset of the start code and the offset of the NAL header.
func findStartCode(buf []byte, from int) (int, int, bool) {
	for i := from; i+3 < len(buf); i++ {
		if buf[i] == 0 && buf[i+1] == 0 {
			if buf[i+2] == 1 {
				return i, i + 3, true
			}
			if buf[i+2] == 0 && i+3 < len(buf) && buf[i+3] == 1 {
				return i, i + 4, true
			}
		}
	}
	return 0, 0, false
}

// hasHeadInfo reports whether p starts with the 0xffffff88 head_info magic.
func hasHeadInfo(p []byte) bool {
	return len(p) >= 28 &&
		p[0] == 0xFF && p[1] == 0xFF && p[2] == 0xFF && p[3] == 0x88
}
