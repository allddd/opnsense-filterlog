// Copyright (c) 2025, 2026 allddd <me@allddd.onl>
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package filter

import (
	"net/netip"
	"testing"
	"time"

	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
)

var (
	logEntryTCP4 = stream.LogEntry{
		Time:              time.Date(2009, 11, 10, 23, 0, 0, 0, time.UTC),
		Label:             "02f4bab031b57d1e30553ce08e0ec131",
		Action:            "block",
		Reason:            "match",
		Direction:         "in",
		Interface:         "eth0",
		IPVersion:         4,
		ProtocolName:      "tcp",
		ProtocolNum:       6,
		Source:            netip.MustParseAddr("192.168.1.20"),
		SourcePort:        new(uint16(51234)),
		Destination:       netip.MustParseAddr("192.168.1.10"),
		DestinationPort:   new(uint16(443)),
		Length:            52,
		DSCP:              "0x0",
		Flags:             "DF",
		ID:                new(uint16(12519)),
		Offset:            new(uint16(0)),
		TTL:               new(uint8(127)),
		DataLength:        new(uint16(0)),
		TCPAcknowledgment: new(uint32(3456789012)),
		TCPFlags:          "S",
		TCPOptions:        "mss;nop;wscale;nop;nop;sackOK",
		TCPSequence:       new(uint32(2055277259)),
		TCPWindow:         new(uint16(64480)),
	}
	logEntryICMP4 = stream.LogEntry{
		Time:         time.Date(2009, 11, 10, 23, 0, 0, 0, time.UTC),
		Label:        "02f4bab031b57d1e30553ce08e0ec131",
		Action:       "block",
		Reason:       "match",
		Direction:    "in",
		Interface:    "eth0",
		IPVersion:    4,
		ProtocolName: "icmp",
		ProtocolNum:  1,
		Source:       netip.MustParseAddr("192.168.1.20"),
		Destination:  netip.MustParseAddr("192.168.1.10"),
		Length:       52,
		DSCP:         "0x0",
		Flags:        "DF",
		ID:           new(uint16(12519)),
		Offset:       new(uint16(0)),
		TTL:          new(uint8(127)),
	}
	logEntryTCP6 = stream.LogEntry{
		Time:              time.Date(2009, 11, 10, 23, 0, 0, 0, time.UTC),
		Label:             "02f4bab031b57d1e30553ce08e0ec131",
		Action:            "block",
		Reason:            "match",
		Direction:         "in",
		Interface:         "eth0",
		IPVersion:         6,
		ProtocolName:      "tcp",
		ProtocolNum:       6,
		Source:            netip.MustParseAddr("fd11:4ad:f2ce:6b0e::a894"),
		SourcePort:        new(uint16(51234)),
		Destination:       netip.MustParseAddr("fdf1:4357:edd8:f527::414f"),
		DestinationPort:   new(uint16(443)),
		Length:            32,
		Class:             "0x00",
		Flow:              "0x00000",
		HopLimit:          new(uint8(64)),
		DataLength:        new(uint16(0)),
		TCPAcknowledgment: new(uint32(3456789012)),
		TCPFlags:          "S",
		TCPOptions:        "mss;nop;wscale;nop;nop;sackOK",
		TCPSequence:       new(uint32(2055277259)),
		TCPWindow:         new(uint16(64480)),
	}
)

type test struct {
	name        string
	filter      string
	entry       *stream.LogEntry
	expectMatch bool
	expectError bool
}

func runTests(t *testing.T, tests []test) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := &logEntryTCP4
			if tc.entry != nil {
				entry = tc.entry
			}
			node, err := Compile(tc.filter)
			if tc.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if match := node.Matches(entry); tc.expectMatch != match {
				t.Fatalf("expected %v, got %v", tc.expectMatch, match)
			}
		})
	}
}

func TestFieldFilter(t *testing.T) {
	tests := []test{
		// fields
		{
			name:        "match action",
			filter:      "action block",
			expectMatch: true,
		},
		{
			name:        "match destination",
			filter:      "destination 192.168.1.10",
			expectMatch: true,
		},
		{
			name:        "match destination range",
			filter:      "destination 192.168.1.0/24",
			expectMatch: true,
		},
		{
			name:        "match destination port",
			filter:      "dstport 443",
			expectMatch: true,
		},
		{
			name:        "match direction",
			filter:      "direction in",
			expectMatch: true,
		},
		{
			name:        "match source host",
			filter:      "host 192.168.1.20",
			expectMatch: true,
		},
		{
			name:        "match source host range",
			filter:      "host 192.168.1.16/29",
			expectMatch: true,
		},
		{
			name:        "match destination host",
			filter:      "host 192.168.1.10",
			expectMatch: true,
		},
		{
			name:        "match destination host range",
			filter:      "host 192.168.1.8/29",
			expectMatch: true,
		},
		{
			name:        "match ip version",
			filter:      "ipversion 4",
			expectMatch: true,
		},
		{
			name:        "match interface",
			filter:      "interface eth0",
			expectMatch: true,
		},
		{
			name:        "match label",
			filter:      "label 02f4bab031b57d1e30553ce08e0ec131",
			expectMatch: true,
		},
		{
			name:        "match port on source port",
			filter:      "port 51234",
			expectMatch: true,
		},
		{
			name:        "match port on destination port",
			filter:      "port 443",
			expectMatch: true,
		},
		{
			name:        "match protocol name",
			filter:      "protocol tcp",
			expectMatch: true,
		},
		{
			name:        "match protocol number",
			filter:      "protocolnum 6",
			expectMatch: true,
		},
		{
			name:        "match reason",
			filter:      "reason match",
			expectMatch: true,
		},
		{
			name:        "match source",
			filter:      "source 192.168.1.20",
			expectMatch: true,
		},
		{
			name:        "match source range",
			filter:      "source 192.168.1.0/24",
			expectMatch: true,
		},
		{
			name:        "match source port",
			filter:      "srcport 51234",
			expectMatch: true,
		},
		// aliases
		{
			name:        "match destination alias dest",
			filter:      "dest 192.168.1.10",
			expectMatch: true,
		},
		{
			name:        "match destination alias dst",
			filter:      "dst 192.168.1.10",
			expectMatch: true,
		},
		{
			name:        "match destination port alias dport",
			filter:      "dport 443",
			expectMatch: true,
		},
		{
			name:        "match direction alias dir",
			filter:      "dir in",
			expectMatch: true,
		},
		{
			name:        "match ip version alias ip",
			filter:      "ip 4",
			expectMatch: true,
		},
		{
			name:        "match ip version alias ipver",
			filter:      "ipver 4",
			expectMatch: true,
		},
		{
			name:        "match interface alias iface",
			filter:      "iface eth0",
			expectMatch: true,
		},
		{
			name:        "match protocol name alias proto",
			filter:      "proto tcp",
			expectMatch: true,
		},
		{
			name:        "match protocol number alias protonum",
			filter:      "protonum 6",
			expectMatch: true,
		},
		{
			name:        "match source alias src",
			filter:      "src 192.168.1.20",
			expectMatch: true,
		},
		{
			name:        "match source port alias sport",
			filter:      "sport 51234",
			expectMatch: true,
		},
		// partial
		{
			name:        "invalid partial destination",
			filter:      "destination 192.168",
			expectError: true,
		},
		{
			name:        "invalid partial host",
			filter:      "host 192.168",
			expectError: true,
		},
		{
			name:   "do not match label partial",
			filter: "label b031b57d",
		},
		{
			name:        "invalid partial source",
			filter:      "source 192.168",
			expectError: true,
		},
		// case sensitive
		{
			name:   "do not match interface case insensitive",
			filter: "interface Eth0",
		},
		{
			name:   "do not match protocol name case insensitive",
			filter: "protocol TCP",
		},
		// no match
		{
			name:   "do not match wrong action",
			filter: "action pass",
		},
		{
			name:   "do not match wrong destination",
			filter: "destination 10.0.0.1",
		},
		{
			name:   "do not match wrong destination range",
			filter: "destination 10.0.0.0/16",
		},
		{
			name:   "do not match wrong destination port",
			filter: "dstport 8080",
		},
		{
			name:   "do not match wrong direction",
			filter: "direction out",
		},
		{
			name:   "do not match wrong host",
			filter: "host 10.0.0.1",
		},
		{
			name:   "do not match wrong ip version",
			filter: "ipversion 6",
		},
		{
			name:   "do not match wrong interface",
			filter: "interface eth1",
		},
		{
			name:   "do not match wrong label",
			filter: "label ffffffffffffffffffffffffffffffff",
		},
		{
			name:   "do not match wrong port",
			filter: "port 9999",
		},
		{
			name:   "do not match wrong protocol name",
			filter: "protocol udp",
		},
		{
			name:   "do not match wrong protocol number",
			filter: "protocolnum 1",
		},
		{
			name:   "do not match wrong reason",
			filter: "reason nomatch",
		},
		{
			name:   "do not match wrong source",
			filter: "source 10.0.0.1",
		},
		{
			name:   "do not match wrong source range",
			filter: "source 10.0.0.0/16",
		},
		{
			name:   "do not match wrong source port",
			filter: "srcport 8080",
		},
		// entry without ports
		{
			name:   "do not match destination port on entry without ports",
			filter: "dstport 443",
			entry:  &logEntryICMP4,
		},
		{
			name:   "do not match port on entry without ports",
			filter: "port 443",
			entry:  &logEntryICMP4,
		},
		{
			name:   "do not match source port on entry without ports",
			filter: "srcport 51234",
			entry:  &logEntryICMP4,
		},
		// ipv6
		{
			name:        "match ip version 6",
			filter:      "ipversion 6",
			entry:       &logEntryTCP6,
			expectMatch: true,
		},
		{
			name:        "match source ipv6",
			filter:      "source fd11:4ad:f2ce:6b0e::a894",
			entry:       &logEntryTCP6,
			expectMatch: true,
		},
		{
			name:        "match source ipv6 range",
			filter:      "source fd11:4ad:f2ce:6b0e::/64",
			entry:       &logEntryTCP6,
			expectMatch: true,
		},
		{
			name:   "do not match ipv4 range on ipv6 entry",
			filter: "source 0.0.0.0/0",
			entry:  &logEntryTCP6,
		},
		{
			name:   "do not match ipv6 range on ipv4 entry",
			filter: "source ::/0",
		},
	}
	runTests(t, tests)
}

func TestTimeFilter(t *testing.T) {
	tests := []test{
		// since
		{
			name:        "match since before entry",
			filter:      "since 2009-11-10T22:59:59Z",
			expectMatch: true,
		},
		{
			name:        "match since equal entry",
			filter:      "since 2009-11-10T23:00:00Z",
			expectMatch: true,
		},
		// until
		{
			name:        "match until after entry",
			filter:      "until 2009-11-10T23:00:01Z",
			expectMatch: true,
		},
		{
			name:        "match until equal entry",
			filter:      "until 2009-11-10T23:00:00Z",
			expectMatch: true,
		},
		// no match
		{
			name:   "do not match since after entry",
			filter: "since 2009-11-10T23:00:01Z",
		},
		{
			name:   "do not match until before entry",
			filter: "until 2009-11-10T22:59:59Z",
		},
		// errors
		{
			name:        "missing value after since",
			filter:      "since",
			expectError: true,
		},
		{
			name:        "missing value after until",
			filter:      "until",
			expectError: true,
		},
		{
			name:        "invalid time after since",
			filter:      "since qwerty",
			expectError: true,
		},
		{
			name:        "invalid time after until",
			filter:      "until qwerty",
			expectError: true,
		},
	}
	runTests(t, tests)
}

func TestAndOperator(t *testing.T) {
	tests := []test{
		// basic
		{
			name:        "match both",
			filter:      "since 2009-11-10T22:59:59Z and proto tcp",
			expectMatch: true,
		},
		{
			name:        "match both with alias",
			filter:      "action block && direction in",
			expectMatch: true,
		},
		{
			name:   "left fails",
			filter: "source 10.0.0.1 and proto tcp",
		},
		{
			name:   "right fails",
			filter: "source 192.168.1.20 and proto udp",
		},
		{
			name:   "both fail",
			filter: "source 10.0.0.1 and protocol udp",
		},
		// multiple
		{
			name:        "match three conditions",
			filter:      "source 192.168.1.20 and proto tcp and dport 443",
			expectMatch: true,
		},
		{
			name:        "match three conditions with alias",
			filter:      "action block && direction in and interface eth0",
			expectMatch: true,
		},
		{
			name:   "first fails",
			filter: "source 10.0.0.1 and proto tcp and dport 443",
		},
		{
			name:   "middle fails",
			filter: "source 192.168.1.20 and proto udp and dport 443",
		},
		{
			name:   "last fails",
			filter: "source 192.168.1.20 and proto tcp and dport 80",
		},
		// errors
		{
			name:        "missing value after operator",
			filter:      "source 192.168.1.20 and",
			expectError: true,
		},
		{
			name:        "missing right operand",
			filter:      "src 192.168.1.20 and proto",
			expectError: true,
		},
	}
	runTests(t, tests)
}

func TestOrOperator(t *testing.T) {
	tests := []test{
		// basic
		{
			name:        "first matches",
			filter:      "source 192.168.1.20 or source 10.0.0.1",
			expectMatch: true,
		},
		{
			name:        "first matches with alias",
			filter:      "action block || action pass",
			expectMatch: true,
		},
		{
			name:        "second matches",
			filter:      "source 10.0.0.1 or source 192.168.1.20",
			expectMatch: true,
		},
		{
			name:        "both match",
			filter:      "since 2009-11-10T22:59:59Z or proto tcp",
			expectMatch: true,
		},
		{
			name:   "neither matches",
			filter: "source 10.0.0.1 || destination 10.0.0.5",
		},
		// multiple
		{
			name:        "match first of three",
			filter:      "source 192.168.1.20 or source 10.0.0.1 or source 172.16.0.1",
			expectMatch: true,
		},
		{
			name:        "match second of three",
			filter:      "source 10.0.0.1 or action block or source 172.16.0.1",
			expectMatch: true,
		},
		{
			name:        "match last of three",
			filter:      "source 10.0.0.1 or source 172.16.0.1 or proto tcp",
			expectMatch: true,
		},
		{
			name:        "match multiple with alias",
			filter:      "action pass || direction out or proto tcp",
			expectMatch: true,
		},
		{
			name:   "all fail",
			filter: "source 10.0.0.1 or source 172.16.0.1 or proto udp",
		},
		// errors
		{
			name:        "missing value after operator",
			filter:      "source 192.168.1.20 or",
			expectError: true,
		},
		{
			name:        "missing right operand",
			filter:      "source 192.168.1.20 or destination",
			expectError: true,
		},
	}
	runTests(t, tests)
}

func TestNotOperator(t *testing.T) {
	tests := []test{
		// basic
		{
			name:   "invert match",
			filter: "not action block",
		},
		{
			name:   "invert match with alias",
			filter: "! proto tcp",
		},
		{
			name:        "invert no match",
			filter:      "not since 2009-11-10T23:00:01Z",
			expectMatch: true,
		},
		{
			name:        "invert no match with alias",
			filter:      "! source 10.0.0.1",
			expectMatch: true,
		},
		// combined
		{
			name:        "not with and",
			filter:      "not source 10.0.0.1 and proto tcp",
			expectMatch: true,
		},
		{
			name:        "not with or",
			filter:      "! source 10.0.0.1 or proto udp",
			expectMatch: true,
		},
		// errors
		{
			name:        "missing operand",
			filter:      "not",
			expectError: true,
		},
	}
	runTests(t, tests)
}

func TestGrouping(t *testing.T) {
	tests := []test{
		// basic
		{
			name:        "simple group",
			filter:      "(action block)",
			expectMatch: true,
		},
		{
			name:        "group with or",
			filter:      "since 2009-11-10T22:59:59Z and (src 192.168.1.20 or dst 192.168.1.10)",
			expectMatch: true,
		},
		{
			name:   "group no match",
			filter: "(source 192.168.1.20 or source 10.0.0.1) and proto icmp",
		},
		// nested
		{
			name:        "nested groups",
			filter:      "((source 192.168.1.20 or source 10.0.0.1) and proto tcp) and dir in",
			expectMatch: true,
		},
		{
			name:        "multiple groups",
			filter:      "(action block or action pass) and (proto tcp or proto udp)",
			expectMatch: true,
		},
		// combined
		{
			name:        "not with group",
			filter:      "not (source 10.0.0.1 and proto tcp)",
			expectMatch: true,
		},
		{
			name:        "group with aliases",
			filter:      "(action block || direction in) && proto tcp",
			expectMatch: true,
		},
		// errors
		{
			name:        "missing right parenthesis",
			filter:      "(action block",
			expectError: true,
		},
		{
			name:        "empty parentheses",
			filter:      "()",
			expectError: true,
		},
		{
			name:        "nested missing parenthesis",
			filter:      "((action block)",
			expectError: true,
		},
	}
	runTests(t, tests)
}

func TestEdge(t *testing.T) {
	tests := []test{
		{
			name:        "empty filter",
			filter:      "",
			expectError: true,
		},
		{
			name:        "extra spaces between tokens",
			filter:      "source    192.168.1.20   and    proto   tcp",
			expectMatch: true,
		},
		{
			name:        "leading and trailing spaces",
			filter:      "  action block  ",
			expectMatch: true,
		},
		{
			name:        "extra spaces in parentheses",
			filter:      "(  action block  )",
			expectMatch: true,
		},
		{
			name:        "uppercase field and operator names",
			filter:      "SOURCE 192.168.1.20 AND Proto tcp",
			expectMatch: true,
		},
		{
			name:        "value without field",
			filter:      "192.168.1.20",
			expectError: true,
		},
	}
	runTests(t, tests)
}
