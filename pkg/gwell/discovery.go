package gwell

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrNoServers is returned when no Mars P2P servers could be reached.
var ErrNoServers = errors.New("gwell: no P2P servers responded")

// P2PServer represents a Mars relay server. 36-byte binary format:
//
//	[0:4]   IPv4 (network order)
//	[4:20]  IPv6 (zeros if IPv4-only)
//	[20:22] ip_version
//	[22:24] server_id (LE)
//	[24:26] port (BE)
type P2PServer struct {
	IP       net.IP
	Port     uint16
	ServerID uint16
}

func (s P2PServer) Addr() string {
	return fmt.Sprintf("%s:%d", s.IP, s.Port)
}

// ListServers are the Mars list servers used for discovery (UDP 51701).
var ListServers = []string{
	"34.215.36.59:51701",
	"18.118.90.161:51701",
	"35.85.21.174:51701",
}

// KnownServers is the fallback list of Mars relay servers.
var KnownServers = []P2PServer{
	{IP: net.IPv4(3, 13, 212, 24), Port: 28800, ServerID: 49},
	{IP: net.IPv4(52, 201, 137, 206), Port: 28800, ServerID: 59},
	{IP: net.IPv4(35, 81, 136, 54), Port: 8000, ServerID: 38},
	{IP: net.IPv4(54, 208, 16, 245), Port: 443, ServerID: 58},
	{IP: net.IPv4(44, 238, 104, 252), Port: 443, ServerID: 18},
	{IP: net.IPv4(52, 40, 221, 253), Port: 51705, ServerID: 28},
	{IP: net.IPv4(3, 131, 23, 11), Port: 8443, ServerID: 48},
}

// DiscoverServers sends ListFrmRequest to the list servers and parses the
// response. Falls back to the hardcoded server list on failure.
func DiscoverServers() []P2PServer {
	for _, addr := range ListServers {
		if servers, err := sendListRequest(addr); err == nil && len(servers) > 0 {
			return servers
		}
	}
	return KnownServers
}

func sendListRequest(addr string) ([]P2PServer, error) {
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(BuildListFrmRequest()); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseListResp(buf[:n]), nil
}

// parseListResp searches the response for the count + 36-byte entries.
func parseListResp(data []byte) []P2PServer {
	for offset := 0; offset+40 <= len(data); offset += 4 {
		count := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		if count < 1 || count > 32 {
			continue
		}
		expectedLen := 4 + count*36
		if offset+expectedLen > len(data) {
			continue
		}
		var servers []P2PServer
		for i := 0; i < count; i++ {
			off := offset + 4 + i*36
			entry := data[off : off+36]
			ip := net.IPv4(entry[0], entry[1], entry[2], entry[3])
			if ip.Equal(net.IPv4zero) {
				continue
			}
			servers = append(servers, P2PServer{
				IP:       ip,
				ServerID: binary.LittleEndian.Uint16(entry[22:24]),
				Port:     binary.BigEndian.Uint16(entry[24:26]),
			})
		}
		if len(servers) > 0 {
			return servers
		}
	}
	return nil
}

// DetectServer sends an encrypted DetectReq2 to a server and waits for any
// response frame.
func DetectServer(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	frame := BuildDetectReq2()
	EncryptFrameFull(frame, NewPasswordKey())

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(frame); err != nil {
		return false
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	return err == nil && n >= FrameHeader
}
