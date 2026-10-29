package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

type target struct {
	e     endpoint
	seq   [2]uint32
	key   uint64
	state [2]atomic.Uint32
	sent  [2]atomic.Uint32
	armed [2]atomic.Bool
}

func applyReply(r reply, ts []target, index map[uint64]int, sport uint16, enabled [2]bool) bool {
	v := int(r.localPort) - int(sport)
	if v < 0 || v > 1 || !enabled[v] {
		return false
	}
	j, ok := index[endpointKey(r.remote)]
	if !ok {
		return false
	}
	t := &ts[j]
	if !t.armed[v].Load() || r.ack != t.seq[v]+1 {
		return false
	}
	state := r.state
	if state == capable1 && v == 0 {
		state = malformed
	}
	for {
		old := t.state[v].Load()
		if state <= old {
			return false
		}
		if t.state[v].CompareAndSwap(old, state) {
			return true
		}
	}
}

type config struct {
	rate, retries, batch, buffer, sport, max    int
	wait                                        time.Duration
	ports, ips, pairs, source, versions, output string
	positiveOnly                                bool
}

func reservePorts(src uint32, requested int) (uint16, []int, error) {
	for tries := 0; tries < 100; tries++ {
		var r [2]byte
		if _, e := rand.Read(r[:]); e != nil {
			return 0, nil, e
		}
		p := requested
		if p == 0 {
			p = 32768 + int(binary.BigEndian.Uint16(r[:]))%28000
		}
		var fds []int
		var err error
		for j := 0; j < 2; j++ {
			fd, e := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 6)
			if e != nil {
				err = e
				break
			}
			var a [4]byte
			binary.BigEndian.PutUint32(a[:], src)
			e = syscall.Bind(fd, &syscall.SockaddrInet4{Port: p + j, Addr: a})
			if e != nil {
				syscall.Close(fd)
				err = e
				break
			}
			fds = append(fds, fd)
		}
		if err == nil {
			return uint16(p), fds, nil
		}
		for _, fd := range fds {
			syscall.Close(fd)
		}
		if requested != 0 || !errors.Is(err, syscall.EADDRINUSE) {
			return 0, nil, fmt.Errorf("reserve source ports: %w", err)
		}
	}
	return 0, nil, fmt.Errorf("could not reserve source ports")
}
func localSource(explicit string, first endpoint) (uint32, error) {
	if explicit == "" {
		c, e := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(ipString(first.ip)), Port: int(first.port)})
		if e != nil {
			return 0, e
		}
		defer c.Close()
		explicit = c.LocalAddr().(*net.UDPAddr).IP.String()
	}
	ip, e := address(explicit)
	if e != nil {
		return 0, e
	}
	addrs, e := net.InterfaceAddrs()
	if e != nil {
		return 0, e
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.String() == explicit {
			return ip, nil
		}
	}
	return 0, fmt.Errorf("source IP %s is not a local interface address", explicit)
}

func run(ctx context.Context, c config, eps []endpoint) error {
	src, e := localSource(c.source, eps[0])
	if e != nil {
		return e
	}
	sport, reserved, e := reservePorts(src, c.sport)
	if e != nil {
		return e
	}
	defer func() {
		for _, fd := range reserved {
			syscall.Close(fd)
		}
	}()
	rx, rb, e := openSocket(src, sport, true, c.buffer)
	if e != nil {
		return e
	}
	defer syscall.Close(rx)
	tx, sb, e := openSocket(src, sport, false, c.buffer)
	if e != nil {
		return e
	}
	defer syscall.Close(tx)
	enabled := [2]bool{c.versions != "1", c.versions != "0"}
	ts := make([]target, len(eps))
	index := make(map[uint64]int, len(eps))
	var material [39]byte
	if _, e := rand.Read(material[:32]); e != nil {
		return e
	}
	for i, ep := range eps {
		binary.BigEndian.PutUint32(material[32:], ep.ip)
		binary.BigEndian.PutUint16(material[36:], ep.port)
		material[38] = 0
		h := sha256.Sum256(material[:])
		ts[i].e = ep
		ts[i].seq = [2]uint32{binary.BigEndian.Uint32(h[:4]), binary.BigEndian.Uint32(h[4:8])}
		ts[i].key = binary.BigEndian.Uint64(h[8:16])
		index[endpointKey(ep)] = i
	}
	fmt.Fprintf(os.Stderr, "targets=%d source=%s ports=%d,%d rate=%d probes/s versions=%s rcvbuf=%d sndbuf=%d\n", len(ts), ipString(src), sport, sport+1, c.rate, c.versions, rb, sb)
	if rb < c.buffer*2 {
		fmt.Fprintln(os.Stderr, "note: receive buffer capped by net.core.rmem_max; increase it if receive drops occur")
	}
	rxctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	var accepted, dropped atomic.Uint64
	go func() {
		data := make([]byte, 64*256)
		var lens [64]uint32
		var drops, previous uint32
		for rxctx.Err() == nil {
			n, err := receiveBatch(rx, data, &lens, &drops)
			if err != nil {
				done <- err
				return
			}
			dropped.Add(uint64(drops - previous))
			previous = drops
			for i := 0; i < n; i++ {
				r, ok := parseReply(data[i*256:i*256+int(lens[i])], src)
				if !ok {
					continue
				}
				if applyReply(r, ts, index, sport, enabled) {
					accepted.Add(1)
				}
			}
		}
		done <- nil
	}()
	var sent uint64
	start := time.Now()
	var sendErr error
	// Global pacing deadline. Lag is discarded: no catch-up bursts after stalls.
	next := time.Now()
	batch := make([]byte, 64*stride)
	count := 0
	var pending [64]struct {
		t *target
		v int
	}
	flush := func() error {
		if count == 0 {
			return nil
		}
		if err := pause(ctx, time.Until(next)); err != nil {
			return err
		}
		select {
		case err := <-done:
			if err == nil {
				err = fmt.Errorf("receiver stopped")
			}
			done <- err
			return err
		default:
		}
		n, err := sendBatch(tx, batch, count)
		sent += uint64(n)
		for j := 0; j < n; j++ {
			pending[j].t.sent[pending[j].v].Add(1)
		}
		if err != nil {
			return fmt.Errorf("send batch: %w", err)
		}
		if n != count {
			return fmt.Errorf("partial send: %d/%d probes; reduce rate or increase send buffer", n, count)
		}
		duration := time.Duration(float64(count) * float64(time.Second) / float64(c.rate))
		now := time.Now()
		if next.Before(now) {
			next = now
		}
		next = next.Add(duration)
		count = 0
		return nil
	}
	for round := 0; round <= c.retries && sendErr == nil; round++ {
		before := sent
		offset, step := traversal(len(ts))
		for i, j := 0, offset; i < len(ts); i, j = i+1, (j+step)%len(ts) {
			if ctx.Err() != nil {
				sendErr = ctx.Err()
				break
			}
			t := &ts[j]
			for v := 1; v >= 0; v-- {
				if !enabled[v] {
					continue
				}
				s := t.state[v].Load()
				// Retry fallback/invalid replies too: SYN cookies and middleboxes may omit options transiently.
				if s == capable0 || s == capable1 || s == reset {
					continue
				}
				t.armed[v].Store(true)
				pending[count].t = t
				pending[count].v = v
				buildProbe(batch[count*stride:], src, t.e, sport+uint16(v), t.seq[v], v, t.key)
				count++
				if count == c.batch {
					if sendErr = flush(); sendErr != nil {
						break
					}
				}
			}
			if sendErr != nil {
				break
			}
		}
		if sendErr == nil {
			sendErr = flush()
		}
		if sendErr == nil && sent > before {
			sendErr = pause(ctx, c.wait)
		}
		fmt.Fprintf(os.Stderr, "round=%d sent=%d evidence_updates=%d rx_drops=%d elapsed=%s\n", round+1, sent, accepted.Load(), dropped.Load(), time.Since(start).Round(time.Millisecond))
		if sent == before {
			break
		}
	}
	cancel()
	rxErr := <-done
	outputErr := writeResults(c, ts, enabled)
	fmt.Fprintf(os.Stderr, "finished probes=%d elapsed=%s rx_drops=%d (SO_RXQ_OVFL; last delivered counter)\n", sent, time.Since(start).Round(time.Millisecond), dropped.Load())
	if sendErr != nil {
		return sendErr
	}
	if rxErr != nil {
		return rxErr
	}
	if outputErr != nil {
		return outputErr
	}
	if dropped.Load() > 0 {
		return fmt.Errorf("receive queue dropped packets; results may be incomplete: rerun at lower rate / larger receive buffer")
	}
	return nil
}

// Random coprime stride spreads sequential input without a shuffled copy.
func traversal(n int) (int, int) {
	if n == 1 {
		return 0, 1
	}
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return 0, 1
	}
	offset := int(binary.BigEndian.Uint64(b[:8]) % uint64(n))
	step := int(binary.BigEndian.Uint64(b[8:]) % uint64(n))
	if step == 0 {
		step = 1
	}
	for {
		a, b := step, n
		for b != 0 {
			a, b = b, a%b
		}
		if a == 1 {
			return offset, step
		}
		step++
		if step == n {
			step = 1
		}
	}
}
func pause(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
func writeResults(c config, ts []target, enabled [2]bool) error {
	out := os.Stdout
	if c.output != "-" {
		f, e := os.Create(c.output)
		if e != nil {
			return e
		}
		out = f
		defer f.Close()
	}
	buf := bufio.NewWriterSize(out, 1<<20)
	w := csv.NewWriter(buf)
	if e := w.Write([]string{"ip", "port", "result", "probe_v1", "probe_v0", "sent_v1", "sent_v0"}); e != nil {
		return e
	}
	for i := range ts {
		t := &ts[i]
		s0, s1 := t.state[0].Load(), t.state[1].Load()
		result := "unknown"
		if s0 >= capable0 || s1 >= capable0 {
			result = "mptcp_advertised"
		} else if s0 == fallback || s1 == fallback {
			result = "open_no_mptcp_observed"
		} else if s0 == malformed || s1 == malformed {
			result = "invalid_response"
		} else if s0 == reset || s1 == reset {
			result = "reset_observed"
		}
		if c.positiveOnly && result != "mptcp_advertised" {
			continue
		}
		names := [2]string{stateNames[s0], stateNames[s1]}
		for v := 0; v < 2; v++ {
			if !enabled[v] {
				names[v] = "not_tested"
			}
		}
		if e := w.Write([]string{ipString(t.e.ip), strconv.Itoa(int(t.e.port)), result, names[1], names[0], strconv.FormatUint(uint64(t.sent[1].Load()), 10), strconv.FormatUint(uint64(t.sent[0].Load()), 10)}); e != nil {
			return e
		}
	}
	w.Flush()
	if e := w.Error(); e != nil {
		return e
	}
	return buf.Flush()
}
func main() {
	if e := cli(); e != nil {
		fmt.Fprintln(os.Stderr, "error:", e)
		os.Exit(1)
	}
}
func cli() error {
	var c config
	fs := flag.NewFlagSet("mptcpscan", flag.ContinueOnError)
	fs.StringVar(&c.ports, "p", "", "ports/ranges, e.g. 80,443,8000-8100")
	fs.StringVar(&c.ips, "i", "", "IP/CIDR file, one per line; - for stdin")
	fs.StringVar(&c.pairs, "f", "", "IPv4:port file, one per line; - for stdin")
	fs.StringVar(&c.source, "source-ip", "", "local IPv4 source; default route to first target")
	fs.StringVar(&c.versions, "versions", "both", "both, 1, or 0")
	fs.StringVar(&c.output, "o", "-", "CSV output file, default stdout")
	fs.IntVar(&c.rate, "rate", 10000, "maximum probe packets/second, including retries and versions")
	fs.IntVar(&c.retries, "retries", 2, "additional passes for unresolved/fallback probes")
	fs.IntVar(&c.batch, "batch", 64, "send batch size, 1..64")
	fs.IntVar(&c.buffer, "buffer", 16<<20, "requested socket buffer bytes")
	fs.IntVar(&c.sport, "source-port", 0, "first of two reserved source ports; default random")
	fs.IntVar(&c.max, "max-targets", 10000000, "maximum unique IP:port pairs loaded in memory")
	fs.DurationVar(&c.wait, "wait", 2*time.Second, "receive drain time after each pass")
	fs.BoolVar(&c.positiveOnly, "positive-only", false, "output only endpoints advertising MPTCP")
	help := fs.Bool("h", false, "show help")
	args, e := interspersed(fs, os.Args[1:])
	if e != nil {
		return e
	}
	if e = fs.Parse(args); e != nil {
		return e
	}
	if *help {
		fs.PrintDefaults()
		return nil
	}
	if c.rate < 1 || c.retries < 0 || c.batch < 1 || c.batch > 64 || c.buffer < 65536 || c.buffer > 1<<30 || c.sport < 0 || c.sport > 65534 || c.max < 1 || c.wait <= 0 {
		return fmt.Errorf("invalid rate, retries, batch, buffer, source-port, max-targets, or wait")
	}
	if c.versions != "both" && c.versions != "0" && c.versions != "1" {
		return fmt.Errorf("-versions must be both, 0, or 1")
	}
	ports, e := parsePorts(c.ports)
	if e != nil {
		return e
	}
	eps, e := loadTargets(fs.Args(), c.ips, c.pairs, ports, c.max)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, c, eps)
}
