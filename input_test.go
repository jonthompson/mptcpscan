package main

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestInput(t *testing.T) {
	ports, e := parsePorts("80,443,8000-8002,80")
	if e != nil || !reflect.DeepEqual(ports, []uint16{80, 443, 8000, 8001, 8002}) {
		t.Fatalf("%v %v", ports, e)
	}
	for _, s := range []string{"0", "65536", "5-4", "a", "80-", "1-2-3", ",80"} {
		if _, e := parsePorts(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "pairs")
	if e := os.WriteFile(f, []byte("# comment\n192.0.2.1:443\n192.0.2.2:80 # note\n"), 0600); e != nil {
		t.Fatal(e)
	}
	eps, e := loadTargets([]string{"192.0.2.0/30", "192.0.2.1"}, "", f, []uint16{443}, 10)
	if e != nil || len(eps) != 5 {
		t.Fatalf("%+v %v", eps, e)
	}
	if _, e = loadTargets([]string{"192.0.2.0/24"}, "", "", []uint16{80}, 5); e == nil {
		t.Fatal("limit not applied")
	}
	if _, e = loadTargets([]string{"::1"}, "", "", []uint16{80}, 5); e == nil {
		t.Fatal("accepted ipv6")
	}
	if _, e = loadTargets([]string{"192.0.2.1"}, "", "", nil, 5); e == nil {
		t.Fatal("missing ports accepted")
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	p := fs.String("p", "", "")
	yes := fs.Bool("positive-only", false, "")
	args, e := interspersed(fs, []string{"192.0.2.1", "-p", "80", "192.0.2.2", "--positive-only"})
	if e != nil {
		t.Fatal(e)
	}
	if e = fs.Parse(args); e != nil || *p != "80" || !*yes || len(fs.Args()) != 2 {
		t.Fatalf("%v %v", args, e)
	}
	for n := 1; n < 100; n++ {
		offset, step := traversal(n)
		seen := map[int]bool{}
		for i, j := 0, offset; i < n; i, j = i+1, (j+step)%n {
			if seen[j] {
				t.Fatalf("traversal n=%d", n)
			}
			seen[j] = true
		}
	}
}
