package main

import "testing"

func TestReplyCorrelation(t *testing.T) {
	ep := endpoint{0xc6336402, 443}
	ts := make([]target, 1)
	ts[0].e = ep
	ts[0].seq = [2]uint32{123, 0xffffffff}
	index := map[uint64]int{endpointKey(ep): 0}
	enabled := [2]bool{true, true}
	r := reply{remote: ep, localPort: 40001, ack: 0, state: capable1}
	if applyReply(r, ts, index, 40000, enabled) {
		t.Fatal("accepted unsent probe")
	}
	ts[0].armed[1].Store(true)
	bad := r
	bad.ack = 1
	if applyReply(bad, ts, index, 40000, enabled) {
		t.Fatal("wrong ACK")
	}
	bad = r
	bad.remote.port++
	if applyReply(bad, ts, index, 40000, enabled) {
		t.Fatal("wrong tuple")
	}
	bad = r
	bad.remote.ip++
	if applyReply(bad, ts, index, 40000, enabled) {
		t.Fatal("wrong IP")
	}
	bad = r
	bad.localPort++
	if applyReply(bad, ts, index, 40000, enabled) {
		t.Fatal("wrong source port")
	}
	if applyReply(r, ts, index, 40000, [2]bool{}) {
		t.Fatal("disabled version")
	}
	if !applyReply(r, ts, index, 40000, enabled) || ts[0].state[1].Load() != capable1 {
		t.Fatal("valid ACK wraparound")
	}
	if applyReply(r, ts, index, 40000, enabled) {
		t.Fatal("duplicate counted")
	}
	r.state = fallback
	if applyReply(r, ts, index, 40000, enabled) {
		t.Fatal("positive downgraded")
	}
	ts[0].armed[0].Store(true)
	r.localPort = 40000
	r.ack = 124
	r.state = capable1
	if !applyReply(r, ts, index, 40000, enabled) || ts[0].state[0].Load() != malformed {
		t.Fatal("accepted v1 on v0 probe")
	}
	r.state = capable0
	if !applyReply(r, ts, index, 40000, enabled) {
		t.Fatal("v0 positive should override malformed")
	}
}
