package main

import (
	"encoding/binary"
	"testing"
)

func TestBuildProbe(t *testing.T) {
	for _, v := range []int{0, 1} {
		b := make([]byte, stride)
		n := buildProbe(b, 0xc0000201, endpoint{0xc6336402, 443}, 40000, 0xffffffff, v, 0x123456789abcdef0)
		want := 52
		if v == 0 {
			want = 60
		}
		if n != want || fold(sumBytes(b[:20])) != 0 {
			t.Fatalf("v%d invalid IPv4", v)
		}
		pseudo := sumBytes(b[12:20]) + 6 + uint32(n-20)
		if fold(pseudo+sumBytes(b[20:n])) != 0 {
			t.Fatalf("v%d TCP checksum invalid", v)
		}
		if b[49] != byte(4+8*(1-v)) || int(b[50]) != v || b[51] != 0x81 {
			t.Fatalf("bad MP_CAPABLE v%d: %x", v, b[48:n])
		}
		if v == 0 && binary.BigEndian.Uint64(b[52:60]) != 0x123456789abcdef0 {
			t.Fatal("v0 key missing")
		}
	}
}
func fixtureReply(v int) []byte {
	b := make([]byte, 52)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], 52)
	b[8] = 64
	b[9] = 6
	binary.BigEndian.PutUint32(b[12:], 0xc6336402)
	binary.BigEndian.PutUint32(b[16:], 0xc0000201)
	t := b[20:]
	binary.BigEndian.PutUint16(t, 443)
	binary.BigEndian.PutUint16(t[2:], 40000)
	binary.BigEndian.PutUint32(t[4:], 123)
	binary.BigEndian.PutUint32(t[8:], 456)
	t[12] = 0x80
	t[13] = 0x12
	copy(t[20:], []byte{30, 12, byte(v), 0x81, 1, 2, 3, 4, 5, 6, 7, 8})
	return b
}
func TestParseReply(t *testing.T) {
	for _, v := range []int{0, 1} {
		r, ok := parseReply(fixtureReply(v), 0xc0000201)
		if !ok || r.state != capable0+uint32(v) || r.ack != 456 || r.remote.port != 443 {
			t.Fatalf("v%d: %+v %v", v, r, ok)
		}
	}
	cases := []struct {
		name  string
		edit  func([]byte)
		valid bool
		state uint32
	}{
		{"plain", func(b []byte) { b[40] = 0 }, true, fallback},
		{"reset", func(b []byte) { b[33] = 0x14 }, true, reset},
		{"no_ack", func(b []byte) { b[33] = 2 }, false, 0},
		{"syn_fin", func(b []byte) { b[33] |= 1 }, false, 0},
		{"wrong_dest", func(b []byte) { b[19]++ }, false, 0},
		{"fragment", func(b []byte) { b[6] = 0x20 }, false, 0},
		{"bad_ihl", func(b []byte) { b[0] = 0x44 }, false, 0},
		{"bad_offset", func(b []byte) { b[32] = 0x40 }, false, 0},
		{"truncated", func(b []byte) { b[3] = 60 }, false, 0},
		{"short_option", func(b []byte) { b[41] = 3 }, true, malformed},
		{"long_option", func(b []byte) { b[41] = 40 }, true, malformed},
		{"zero_length", func(b []byte) { b[41] = 0 }, true, malformed},
		{"future_version", func(b []byte) { b[42] = 2 }, true, malformed},
		{"extension_flag", func(b []byte) { b[43] |= 0x40 }, true, malformed},
		{"wrong_crypto", func(b []byte) { b[43] = 0x82 }, true, malformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := fixtureReply(1)
			tc.edit(b)
			r, ok := parseReply(b, 0xc0000201)
			if ok != tc.valid || (ok && r.state != tc.state) {
				t.Fatalf("got %+v ok=%v", r, ok)
			}
		})
	}
	// Variable IPv4 header length, as used by both parser and kernel filter.
	b := fixtureReply(1)
	b = append(b[:20], append([]byte{1, 1, 1, 1}, b[20:]...)...)
	b[0] = 0x46
	b[3] = 56
	if r, ok := parseReply(b, 0xc0000201); !ok || r.state != capable1 {
		t.Fatal("IPv4 options")
	}
}
func FuzzParseReply(f *testing.F) {
	f.Add(fixtureReply(1))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { parseReply(b, 0xc0000201) })
}
func BenchmarkBuildProbe(b *testing.B) {
	var p [64]byte
	ep := endpoint{0xc6336402, 443}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buildProbe(p[:], 0xc0000201, ep, 40000, uint32(i), 1, 1)
	}
}
func BenchmarkParseReply(b *testing.B) {
	p := fixtureReply(1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		parseReply(p, 0xc0000201)
	}
}
