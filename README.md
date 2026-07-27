# netflow
 
A dependency-free C++ network flow analyzer. It reads a raw `.pcap` capture,
decodes the Ethernet / IPv4 / TCP / UDP stack byte-by-byte, groups packets into
bidirectional conversations, surfaces the top talkers by volume, and recovers the
hostnames behind DNS lookups — all from the standard library, with no libpcap and
no external dependencies.
 
The point of the project was to understand the network stack from the wire up:
every header is parsed by hand from raw bytes rather than handed over to a library.
 
## Features
 
- **Direct pcap parsing.** Reads the classic pcap container itself — global header,
  per-record headers, and captured frames — with no parsing library.
- **Endianness-aware.** Detects capture byte order from the magic number and swaps
  multi-byte fields as needed, so captures written on big- or little-endian machines
  both parse correctly.
- **Four-layer decode.** Walks Ethernet -> IPv4 -> TCP/UDP, handling the
  variable-length IPv4 header to compute where the transport layer begins rather than
  assuming a fixed offset.
- **Bidirectional flow aggregation.** Groups packets into flows keyed on a
  *canonical* five-tuple, so a request (A->B) and its replies (B->A) collapse into a
  single conversation instead of two half-flows.
- **Top-talker ranking.** Sorts conversations by byte volume and reports per-flow
  packet and byte totals.
- **DNS hostname recovery.** Decodes the length-prefixed label encoding in DNS query
  payloads, turning anonymous resolver traffic into the actual domains looked up.
- **Defensive by design.** Every field read is bounds-checked against the captured
  length and every parsing loop is capped, so truncated or malformed packets are
  skipped rather than crashing the tool or reading past the buffer. Non-Ethernet
  link types and pcapng files are detected and rejected with a clear message.
## Build
 
Requires a C++17 compiler. No dependencies.
 
```sh
g++ -O2 -std=c++17 -Wall -o netflow netflow.cpp
```
 
## Usage
 
```sh
./netflow capture.pcap
```
 
Input must be a **classic pcap** file with **Ethernet** framing.
 
Capture your own (tcpdump writes classic pcap, which this tool reads directly):
 
```sh
# capture on a specific interface — NOT `-i any`, which uses a non-Ethernet
# link type that this tool intentionally rejects
sudo tcpdump -i en0 -w capture.pcap -c 5000
```
 
## Example output
 
```
DNS: github.com.
DNS: api.stripe.com.
DNS: www.cloudflare.com.
Packets Amount:    5000
Bytes Amount:      4337835
ipv4Count Amount:  124
ipv6Count Amount:  4875
otherCount Amount: 1
Conversations (biggest to smallest): 13
  10.0.0.12:60031 <-> 51.105.71.137:443    protocol 6   packets=32 bytes=17822
  10.0.0.12:60023 <-> 146.75.125.140:443   protocol 6   packets=15 bytes=6685
  10.0.0.12:60034 <-> 216.150.1.193:443    protocol 6   packets=12 bytes=4287
  10.0.0.12:60028 <-> 17.253.7.139:80      protocol 6   packets=10 bytes=1283
  10.0.0.12:59488 <-> 239.255.255.250:1900 protocol 17  packets=3  bytes=639
  ...
```
 
*(Illustrative output. Protocol 6 = TCP, 17 = UDP. The 239.255.255.250:1900 flow is
SSDP multicast — real captures include broadcast and discovery traffic, which the
parser handles without special-casing.)*
 
## Benchmark
 
On a live 5,000-packet capture (~4.3 MB) the tool parses, aggregates, ranks, and
prints in ~14 ms end-to-end, with zero crashes across the truncated frames,
multicast, broadcast, and non-IPv4 traffic present in real-world data.
 
## How it works
 
**The file as a flat stream.** A pcap file is a 24-byte global header followed by
repeating `[16-byte record header][captured frame]` pairs. The parser reads each
record's capture length and uses it to step to the next record — the same
"read a length, jump forward by it" move it then reuses at every layer.
 
**Two byte-order regimes.** pcap *file-format* fields (magic number, timestamps,
capture lengths) use the capturing machine's byte order, detected once from the
magic number. Packet *contents* (Ethernet, IP, TCP/UDP headers) are always
big-endian network byte order. The tool uses a different reader for each, which is
why it parses captures from either machine architecture correctly.
 
**Computed, not assumed, offsets.** The IPv4 header is variable-length (its IHL
field gives its size in 32-bit words), so the transport header's position is
computed from it rather than hardcoded — the same reason the DNS name walk follows
length-prefixed labels instead of fixed slices.
 
**Canonical flow keys.** Before a packet is counted, its two endpoints (IP + port)
are ordered consistently, so a packet and its reply — which have opposite
source/destination — produce an identical key and merge into one flow. Flows live
in an `unordered_map` with a custom hash over the five-tuple.
 
## Scope and limitations
 
These are deliberate boundaries, not oversights:
 
- **IPv4 only.** IPv6 packets are counted but not decoded into flows. On modern
  networks IPv6 is frequently the majority of traffic (see the sample counts).
- **DNS over UDP only.** DNS over TCP uses a different framing (a 2-byte length
  prefix ahead of the message) and is out of scope.
- **DNS query names only.** Compression pointers, which appear in answer records but
  not query names, are detected and skipped rather than followed.
 
