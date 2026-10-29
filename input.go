package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

func parsePorts(s string) ([]uint16, error) {
	if s == "" {
		return nil, nil
	}
	var out []uint16
	seen := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		pair := strings.Split(strings.TrimSpace(part), "-")
		lo, e := strconv.Atoi(pair[0])
		if e != nil || lo < 1 || lo > 65535 || len(pair) > 2 {
			return nil, fmt.Errorf("invalid port/range %q", part)
		}
		hi := lo
		if len(pair) == 2 {
			hi, e = strconv.Atoi(pair[1])
			if e != nil || hi < lo || hi > 65535 {
				return nil, fmt.Errorf("invalid port/range %q", part)
			}
		}
		for p := lo; p <= hi; p++ {
			if !seen[p] {
				out = append(out, uint16(p))
				seen[p] = true
			}
		}
	}
	return out, nil
}
func address(s string) (uint32, error) {
	a, e := netip.ParseAddr(s)
	if e != nil || !a.Is4() {
		return 0, fmt.Errorf("expected IPv4 address, got %q", s)
	}
	b := a.As4()
	return binary.BigEndian.Uint32(b[:]), nil
}
func ipString(ip uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ip)
	return netip.AddrFrom4(b).String()
}
func endpointKey(e endpoint) uint64 { return uint64(e.ip)<<16 | uint64(e.port) }

func loadTargets(args []string, ipFile, pairFile string, ports []uint16, limit int) ([]endpoint, error) {
	out := make([]endpoint, 0)
	seen := make(map[uint64]bool)
	add := func(e endpoint) error {
		k := endpointKey(e)
		if seen[k] {
			return nil
		}
		if len(out) >= limit {
			return fmt.Errorf("target count exceeds -max-targets=%d", limit)
		}
		seen[k] = true
		out = append(out, e)
		return nil
	}
	addIP := func(s string) error {
		if len(ports) == 0 {
			return fmt.Errorf("-p is required with IP/CIDR targets")
		}
		if strings.Contains(s, "/") {
			prefix, e := netip.ParsePrefix(s)
			if e != nil || !prefix.Addr().Is4() {
				return fmt.Errorf("invalid IPv4 CIDR %q", s)
			}
			prefix = prefix.Masked()
			for a := prefix.Addr(); a.IsValid() && prefix.Contains(a); a = a.Next() {
				ip, _ := address(a.String())
				for _, p := range ports {
					if e := add(endpoint{ip, p}); e != nil {
						return e
					}
				}
			}
			return nil
		}
		ip, e := address(s)
		if e != nil {
			return e
		}
		for _, p := range ports {
			if e := add(endpoint{ip, p}); e != nil {
				return e
			}
		}
		return nil
	}
	for _, a := range args {
		for _, s := range strings.Split(a, ",") {
			if e := addIP(strings.TrimSpace(s)); e != nil {
				return nil, e
			}
		}
	}
	read := func(path string, pairs bool) error {
		if path == "" {
			return nil
		}
		var r io.Reader = os.Stdin
		if path != "-" {
			f, e := os.Open(path)
			if e != nil {
				return e
			}
			defer f.Close()
			r = f
		}
		sc := bufio.NewScanner(r)
		line := 0
		for sc.Scan() {
			line++
			s := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
			if s == "" {
				continue
			}
			var e error
			if pairs {
				var ap netip.AddrPort
				ap, e = netip.ParseAddrPort(s)
				if e == nil {
					if !ap.Addr().Is4() || ap.Port() == 0 {
						e = fmt.Errorf("expected IPv4:port")
					} else {
						ip, _ := address(ap.Addr().String())
						e = add(endpoint{ip, ap.Port()})
					}
				}
			} else {
				e = addIP(s)
			}
			if e != nil {
				return fmt.Errorf("%s:%d: %w", path, line, e)
			}
		}
		return sc.Err()
	}
	if ipFile == "-" && pairFile == "-" {
		return nil, fmt.Errorf("only one input may read stdin")
	}
	if e := read(ipFile, false); e != nil {
		return nil, e
	}
	if e := read(pairFile, true); e != nil {
		return nil, e
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets: use IP arguments with -p, -i IP-file, or -f IP:port-file")
	}
	return out, nil
}

// Standard flag stops at positional arguments; reorder to accept IPs -p ports too.
func interspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var opts, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			pos = append(pos, a)
			continue
		}
		name := strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-")
		f := fs.Lookup(name)
		if f == nil {
			return nil, fmt.Errorf("unknown flag %s", a)
		}
		opts = append(opts, a)
		_, hasValue := strings.CutPrefix(a, strings.SplitN(a, "=", 2)[0]+"=")
		boolean, ok := f.Value.(interface{ IsBoolFlag() bool })
		if !hasValue && !(ok && boolean.IsBoolFlag()) {
			if i+1 == len(args) {
				return nil, fmt.Errorf("missing value for %s", a)
			}
			i++
			opts = append(opts, args[i])
		}
	}
	return append(append(opts, "--"), pos...), nil
}
