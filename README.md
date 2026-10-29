# mptcpscan

Linux IPv4 MPTCP SYN scanner, written in Go with a small cgo Linux socket backend.
No Go module dependencies, libpcap, or per-probe goroutines. Includes the source,
protocol tests, fuzz target, benchmarks, and optional local raw-socket tests.

## Build

Requires Linux, Go 1.22+, a C compiler, and Linux libc headers. For example,
on Debian/Ubuntu install `golang-go build-essential` (ensure Go is 1.22+), then:

```sh
CGO_ENABLED=1 go build -buildvcs=false -trimpath -o mptcpscan .
```

Run as root or with `CAP_NET_RAW`. Linux is required; a macOS host can build/run
this in a Linux VM. A container requires `NET_RAW` and suitable networking;
use a direct host or VM interface for high-rate measurements. A scanner compiled
against glibc needs a compatible runtime libc; build on your target distribution.

## Usage

Flags can appear before or after positional IP addresses. Scan only your own
systems or systems you have permission to test.

```sh
# IP arguments, with a port list/ranges
sudo ./mptcpscan 192.0.2.10 192.0.2.11 -p 80,443,8000-8010 -o results.csv

# Comma-separated IPs and CIDRs also work
sudo ./mptcpscan 192.0.2.10,192.0.2.11 198.51.100.0/24 -p 443

# One IPv4 address or CIDR per line
sudo ./mptcpscan -i ips.txt -p 80,443 -rate 100000 -o results.csv

# One IPv4:port per line; -p is unnecessary
sudo ./mptcpscan -f endpoints.txt -rate 100000 -o results.csv

# stdin; keep sudo from trying to read a password from a pipeline
sudo -v
cat endpoints.txt | sudo ./mptcpscan -f - -rate 100000

# Only current MPTCP v1, fewer probes
sudo ./mptcpscan -f endpoints.txt -versions 1 -positive-only

# Explicit local source address and a longer receive window
sudo ./mptcpscan -f endpoints.txt -source-ip 192.0.2.2 -wait 5s -retries 2
```

`endpoints.txt`:

```text
# Previously discovered exposed ports
192.0.2.10:443
192.0.2.11:80
192.0.2.11:8443  # comments and blank lines are allowed
```

Duplicate IP:port pairs are removed across all inputs. All addresses in a CIDR
are included, including its first and last addresses. IP/CIDR inputs expand
against `-p`. Pair-file inputs retain their specified ports. Inputs must be
literal IPv4 addresses; DNS names, IPv6, and masscan JSON are not accepted.

## What the results mean

CSV is written once scanning finishes, in deduplicated input order. On Ctrl-C,
the scanner stops, writes partial results, and exits nonzero. Progress and
errors go to stderr. Do not discard a nonzero exit status when processing CSV.

| result | Meaning |
| --- | --- |
| `mptcp_advertised` | A correlated SYN-ACK contained a well-formed v0 or v1 MP_CAPABLE with the expected crypto flags. |
| `open_no_mptcp_observed` | A correlated TCP SYN-ACK was received without MP_CAPABLE for at least one tested version, and no positive advertisement was seen. |
| `invalid_response` | A correlated SYN-ACK contained invalid options/MP_CAPABLE, and no stronger result was seen. |
| `reset_observed` | A correlated RST+ACK was observed, without SYN-ACK evidence. Usually a closed/rejected port; a middlebox may produce it. |
| `unknown` | No qualifying response. Timeout is not evidence of absent MPTCP support. |

Additional columns `probe_v1`, `probe_v0`, `sent_v1`, and `sent_v0` retain each
probe's strongest evidence and actual successfully submitted probe counts.
Disabled versions say `not_tested`. Each version's evidence uses the precedence
positive advertisement > invalid options > ordinary SYN-ACK > reset > silence.
If different replies disagree, this is an evidence summary, not a packet log.
An older version can be advertised in response to a v1 probe; its returned
version is reported. A v1 advertisement in response to a v0 probe is invalid.

This is capability advertisement detection, **not** a completed MPTCP handshake,
MP_JOIN/subflow test, application test, or vulnerability check. The scanner does
not send the final handshake ACK or application traffic. The local TCP stack
normally sends RST for unsolicited SYN-ACKs, including those to reserved bound
source ports. Do not block these RSTs; otherwise server half-open entries may
remain until timeout. Firewalls/NATs/SYN proxies and load balancers can strip
options or terminate TCP, so results describe the visible endpoint and path.
Kernel support alone does not make a conventional TCP listening socket MPTCP.

There is no absolute negative result: `open_no_mptcp_observed` may mean an
ordinary TCP listener, option stripping, SYN-cookie fallback, or an untested
backend behind a load balancer. Retries improve observation without proving
absence. Separate scan runs may sample other backends; within one run retries
reuse each probe's source port and sequence number.

## Rate and performance

`-rate` is **probe packets per second**, including both versions and retries,
not distinct IPs/sec. With both versions, one port per IP, and no retries:

| Desired first-pass IPs/sec | Required probes/sec |
| --- | --- |
| 10,000 | 20,000 |
| 50,000 | 100,000 |
| 100,000 | 200,000 |

With three ports per IP, multiply those packet rates by three. Retries add work;
the default is up to three total passes per version, plus a 2s drain per active
pass. Resets and positive version probes are not retried. Silence, fallback,
and invalid replies are retried. Both versions are sent initially even if an
earlier reply already identified the other version. `-retries 0` makes one pass.

The implementation is designed for this rate class using 64-packet `sendmmsg`
and `recvmmsg` batches, preallocated hot-path buffers, constant-time endpoint
lookup, no per-probe timers, and no per-probe goroutines. The kernel handles
routing, ARP, and link-layer encapsulation. A coprime random stride spreads
sequential target input; probes for the two versions still go together.

Pacing permits a batch-sized burst and never catches up after stalls. `-batch 1`
reduces burst size at the cost of syscalls. The configured rate is a ceiling,
not a throughput promise. **No end-to-end 10k–100k+ IP/sec performance claim is
made.** Measure successful probe transmission, response completeness, and drops
on your actual host/NIC/path. Packet builder/parser benchmarks do not establish
wire throughput. At high rates, kernel routing, conntrack, NIC queues, RX load,
or one sender/receiver core can become the bottleneck; AF_XDP or AF_PACKET TX/RX
rings would be a further backend if measurements justify them.

The scanner requests 16 MiB socket buffers by default, logs the actual values,
and reports `SO_RXQ_OVFL` receive-queue drops. Linux reports doubled socket
buffer sizes. Host `net.core.rmem_max`/`wmem_max` may cap requests. If necessary:

```sh
sudo sysctl -w net.core.rmem_max=33554432
sudo sysctl -w net.core.wmem_max=33554432
```

These are host-wide, temporary tuning changes. Buffer settings do not prevent
NIC/ring/network drops. The drop counter is attached to delivered messages and
cannot account for final drops without a later delivery; zero does not prove
lossless capture. Also inspect `ip -s link`, `ethtool -S INTERFACE`, and
`/proc/net/softnet_stat` if available. The scanner exits nonzero on observed
receive drops or send errors/partial sends and still emits partial CSV. It
does not silently continue after a transmission failure.

All endpoints and their states are loaded into RAM before scanning. The default
`-max-targets 10000000` bounds unique IP:port pairs, not IPs; RAM use can reach
multiple gigabytes near that limit. Split larger inputs into files. The source
address is either explicitly specified or selected from the route to the first
input target, and must be assigned locally. For multihomed hosts/different
egress source addresses, split targets by source/route and run separately. This
backend does not automatically choose a source address for every destination.

## Reliability details

* Independent v1 and legacy v0 probes: v1 SYN MP_CAPABLE length 4; v0 SYN length
  12 with an initiator key. Both expect SYN-ACK MP_CAPABLE length 12.
* A random per-run secret plus SHA-256 derives endpoint-specific sequence
  numbers and v0 keys. Two locally bound, non-listening TCP source ports keep
  v0/v1 tuples distinct and avoid collisions with other local TCP uses.
* The kernel BPF receive filter admits only the chosen local IPv4 and source
  port pair. The parser validates IPv4/TCP lengths, rejects fragments, requires
  SYN+ACK or RST+ACK, checks the exact remote IP/port against the target map, and
  checks ACK == that version's transmitted sequence + 1.
* Malformed options, duplicate MP_CAPABLE, unexpected versions, and unsupported
  crypto/extension flags do not become positive results. Retransmitted replies
  are deduplicated by endpoint/version state.
* No software TCP checksum rejection is performed on RX, to accommodate local
  checksum offload representations. Correlation and option validation remain
  mandatory. Capability advertisements are unauthenticated protocol evidence.
* ICMP errors are not classified. They remain unknown. IPv4 fragments are not
  accepted by the parser (the IP stack may reassemble before raw delivery).

Protocol references:
[RFC 8684 section 3.1](https://www.rfc-editor.org/rfc/rfc8684.html#section-3.1),
[RFC 6824 section 3.1](https://www.rfc-editor.org/rfc/rfc6824.html#section-3.1),
[Linux raw sockets](https://man7.org/linux/man-pages/man7/raw.7.html),
[sendmmsg](https://man7.org/linux/man-pages/man2/sendmmsg.2.html).

## Tests

```sh
go test ./...
go vet ./...
go test -race ./...
go test -run '^$' -bench . -benchmem
go test -run '^$' -fuzz FuzzParseReply -fuzztime 10s

# Requires raw-socket privilege, sends only to loopback addresses.
sudo env MPTCPSCAN_INTEGRATION=1 go test -race -v ./...
```

Loopback integration covers actual ordinary-TCP SYN-ACKs, resets, and a synthetic
raw v0/v1 MP_CAPABLE responder. The synthetic responder does not implement a full
MPTCP stack. Verify against a real MPTCP listening socket on your target Linux
kernel and optionally a legacy v0 stack before production use. Compare repeated
low-rate and high-rate results over the same known-good endpoints to assess loss.

Use `./mptcpscan -h` for all options.
