//go:build linux && cgo

package main

import (
	"context"
	"encoding/binary"
	"encoding/csv"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func integration(t *testing.T) {
	t.Helper()
	if os.Getenv("MPTCPSCAN_INTEGRATION") != "1" {
		t.Skip("set MPTCPSCAN_INTEGRATION=1 for loopback raw-socket tests")
	}
}
func testConfig(t *testing.T) config {
	return config{rate: 10000, batch: 64, buffer: 1 << 20, retries: 1, wait: 150 * time.Millisecond, max: 100, versions: "both", source: "127.0.0.1", output: filepath.Join(t.TempDir(), "results.csv")}
}
func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	rows, e := csv.NewReader(f).ReadAll()
	if e != nil {
		t.Fatal(e)
	}
	return rows
}
func TestLoopbackTCPAndReset(t *testing.T) {
	integration(t)
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c := testConfig(t)
	if e = run(context.Background(), c, []endpoint{{0x7f000001, port}}); e != nil {
		ln.Close()
		t.Fatal(e)
	}
	rows := readCSV(t, c.output)
	if len(rows) != 2 || rows[1][2] != "open_no_mptcp_observed" || rows[1][3] != "tcp_fallback" || rows[1][4] != "tcp_fallback" {
		ln.Close()
		t.Fatalf("%v", rows)
	}
	ln.Close()
	c = testConfig(t)
	if e = run(context.Background(), c, []endpoint{{0x7f000001, port}}); e != nil {
		t.Fatal(e)
	}
	rows = readCSV(t, c.output)
	if rows[1][2] != "reset_observed" {
		t.Fatalf("%v", rows)
	}
}

// Synthetic wire responder validates positive detection through the real raw
// transport; this is not a substitute for testing against an actual MPTCP stack.
func TestLoopbackSyntheticMPTCP(t *testing.T) {
	integration(t)
	ln, e := net.Listen("tcp4", "127.0.0.2:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	fd, e := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 6)
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.Close(fd)
	if e = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 100000}); e != nil {
		t.Fatal(e)
	}
	tx, _, e := openSocket(0x7f000002, port, false, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.Close(tx)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		in := make([]byte, 2048)
		out := make([]byte, 64)
		for ctx.Err() == nil {
			n, _, err := syscall.Recvfrom(fd, in, 0)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EINTR {
					continue
				}
				done <- err
				return
			}
			if n < 40 || binary.BigEndian.Uint32(in[16:]) != 0x7f000002 {
				continue
			}
			h := int(in[0]&15) * 4
			if h+20 > n {
				continue
			}
			tcp := in[h:n]
			if tcp[13]&0x12 != 2 || binary.BigEndian.Uint16(tcp[2:]) != port {
				continue
			}
			// Locate the scanner's MP_CAPABLE after the eight bytes of TCP options.
			if len(tcp) < 32 || tcp[28] != 30 {
				continue
			}
			v := int(tcp[30] & 15)
			if v > 1 {
				continue
			}
			remote := endpoint{binary.BigEndian.Uint32(in[12:]), binary.BigEndian.Uint16(tcp)}
			buildProbe(out, 0x7f000002, remote, port, 12345, 0, 42)
			binary.BigEndian.PutUint32(out[28:], binary.BigEndian.Uint32(tcp[4:])+1)
			out[33] = 0x12
			out[50] = byte(v)
			out[36] = 0
			out[37] = 0
			pseudo := sumBytes(out[12:20]) + 6 + 40
			binary.BigEndian.PutUint16(out[36:], fold(pseudo+sumBytes(out[20:60])))
			if _, err = sendBatch(tx, out, 1); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	c := testConfig(t)
	e = run(context.Background(), c, []endpoint{{0x7f000002, port}})
	cancel()
	fixtureErr := <-done
	if e != nil {
		t.Fatal(e)
	}
	if fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
	rows := readCSV(t, c.output)
	if rows[1][2] != "mptcp_advertised" || rows[1][3] != "mptcp_v1" || rows[1][4] != "mptcp_v0" {
		t.Fatalf("%v", rows)
	}
}
