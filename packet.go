package main

import "encoding/binary"

const stride = 64

type endpoint struct {
	ip   uint32
	port uint16
}

func sumBytes(b []byte) uint32 {
	var s uint32
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		s += uint32(b[0]) << 8
	}
	return s
}
func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	return ^uint16(s)
}

// buildProbe writes an IPv4 SYN with MSS, SACK-permitted, and MP_CAPABLE.
// IPv4 checksum and total length are also populated for packet-level testing.
func buildProbe(b []byte, src uint32, dst endpoint, sport uint16, seq uint32, version int, key uint64) int {
	n := 52
	if version == 0 {
		n = 60
	}
	clear(b[:stride])
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(n))
	b[6] = 0x40
	b[8] = 64
	b[9] = 6
	binary.BigEndian.PutUint32(b[12:], src)
	binary.BigEndian.PutUint32(b[16:], dst.ip)
	t := b[20:n]
	binary.BigEndian.PutUint16(t, sport)
	binary.BigEndian.PutUint16(t[2:], dst.port)
	binary.BigEndian.PutUint32(t[4:], seq)
	t[12] = byte(len(t)/4) << 4
	t[13] = 2
	binary.BigEndian.PutUint16(t[14:], 64240)
	copy(t[20:], []byte{2, 4, 5, 180, 4, 2, 1, 1, 30, 4, 1, 0x81})
	if version == 0 {
		t[29] = 12
		t[30] = 0
		binary.BigEndian.PutUint64(t[32:], key)
	}
	pseudo := (src >> 16) + (src & 65535) + (dst.ip >> 16) + (dst.ip & 65535) + 6 + uint32(len(t))
	binary.BigEndian.PutUint16(t[16:], fold(pseudo+sumBytes(t)))
	binary.BigEndian.PutUint16(b[10:], fold(sumBytes(b[:20])))
	return n
}

const (
	unknown uint32 = iota
	reset
	fallback
	malformed
	capable0
	capable1
)

var stateNames = []string{"no_response", "reset", "tcp_fallback", "invalid_mp_capable", "mptcp_v0", "mptcp_v1"}

type reply struct {
	remote    endpoint
	localPort uint16
	ack       uint32
	state     uint32
}

func parseReply(b []byte, src uint32) (r reply, ok bool) {
	if len(b) < 40 || b[0]>>4 != 4 || b[9] != 6 {
		return
	}
	ih := int(b[0]&15) * 4
	total := int(binary.BigEndian.Uint16(b[2:]))
	if ih < 20 || total > len(b) || total < ih+20 || binary.BigEndian.Uint16(b[6:])&0x3fff != 0 || binary.BigEndian.Uint32(b[16:]) != src {
		return
	}
	t := b[ih:total]
	th := int(t[12]>>4) * 4
	if th < 20 || th > len(t) || t[13]&0x10 == 0 {
		return
	}
	r.remote = endpoint{binary.BigEndian.Uint32(b[12:]), binary.BigEndian.Uint16(t)}
	r.localPort = binary.BigEndian.Uint16(t[2:])
	r.ack = binary.BigEndian.Uint32(t[8:])
	if t[13]&4 != 0 {
		r.state = reset
		return r, true
	}
	if t[13]&0x17 != 0x12 {
		return r, false
	}
	r.state = fallback
	found := false
	for p := 20; p < th; {
		kind := t[p]
		if kind == 0 {
			break
		}
		if kind == 1 {
			p++
			continue
		}
		if p+2 > th || t[p+1] < 2 || p+int(t[p+1]) > th {
			r.state = malformed
			return r, true
		}
		n := int(t[p+1])
		if kind == 30 {
			if n < 3 {
				r.state = malformed
				return r, true
			}
			if t[p+2]>>4 == 0 {
				if found || n != 12 || t[p+2]&15 > 1 || t[p+3]&0x40 != 0 || t[p+3]&0x1f != 1 {
					r.state = malformed
					return r, true
				}
				found = true
				r.state = capable0 + uint32(t[p+2]&15)
			}
		}
		p += n
	}
	return r, true
}
