// Copyright (c) 2025 allddd <me@allddd.onl>
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
	"testing"

	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
)

type test struct {
	name        string
	filter      string
	entry       stream.LogEntry
	expectMatch bool
	expectError bool
}

func runTests(t *testing.T, tests []test) {
	t.Helper()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := Compile(tc.filter)

			if tc.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if filter != nil {
				if match := filter.Matches(&tc.entry); match != tc.expectMatch {
					t.Fatalf("expected %v, got %v", match, tc.expectMatch)
				}
			}
		})
	}
}

func TestCompile_AnyFilter(t *testing.T) {
	tests := []test{
		{
			name:        "match action field",
			filter:      "block",
			entry:       stream.LogEntry{Action: "block"},
			expectMatch: true,
		},
		{
			name:        "match direction field",
			filter:      "in",
			entry:       stream.LogEntry{Direction: "in"},
			expectMatch: true,
		},
		{
			name:        "match interface field",
			filter:      "eth0",
			entry:       stream.LogEntry{Interface: "eth0"},
			expectMatch: true,
		},
		{
			name:        "match reason field",
			filter:      "match",
			entry:       stream.LogEntry{Reason: "match"},
			expectMatch: true,
		},
		{
			name:        "match destination field",
			filter:      "10.0",
			entry:       stream.LogEntry{Dst: "10.0.0.1"},
			expectMatch: true,
		},
		{
			name:        "match protocol field",
			filter:      "tcp",
			entry:       stream.LogEntry{ProtoName: "tcp"},
			expectMatch: true,
		},
		{
			name:        "match source field",
			filter:      "192.168.1.1",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: true,
		},
		{
			name:        "do not match any field",
			filter:      "random",
			entry:       stream.LogEntry{Action: "block", Src: "192.168.1.1", Dst: "10.0.0.1"},
			expectMatch: false,
		},
	}

	runTests(t, tests)
}

func TestCompile_FieldFilter(t *testing.T) {
	tests := []test{
		{
			name:        "match source ip exact",
			filter:      "source 192.168.1.1",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: true,
		},
		{
			name:        "match source ip prefix",
			filter:      "src 192.168",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: true,
		},
		{
			name:        "do not match wrong source ip",
			filter:      "src 92.168.1.1",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: false,
		},
		{
			name:        "match destination ip exact",
			filter:      "destination 10.0.0.1",
			entry:       stream.LogEntry{Dst: "10.0.0.1"},
			expectMatch: true,
		},
		{
			name:        "match destination ip prefix",
			filter:      "dst 10.0.0",
			entry:       stream.LogEntry{Dst: "10.0.0.5"},
			expectMatch: true,
		},
		{
			name:        "do not match wrong destination ip",
			filter:      "dest 10.0.0.0",
			entry:       stream.LogEntry{Dst: "10.0.0.1"},
			expectMatch: false,
		},
		{
			name:        "match protocol",
			filter:      "protocol tcp",
			entry:       stream.LogEntry{ProtoName: "tcp"},
			expectMatch: true,
		},
		{
			name:        "match protocol case insensitive",
			filter:      "proto UDP",
			entry:       stream.LogEntry{ProtoName: "udp"},
			expectMatch: true,
		},
		{
			name:        "match action",
			filter:      "action block",
			entry:       stream.LogEntry{Action: "block"},
			expectMatch: true,
		},
		{
			name:        "do not match action",
			filter:      "action pass",
			entry:       stream.LogEntry{Action: "synproxy-drop"},
			expectMatch: false,
		},
		{
			name:        "match interface",
			filter:      "interface eth0",
			entry:       stream.LogEntry{Interface: "eth0"},
			expectMatch: true,
		},
		{
			name:        "match interface alias",
			filter:      "iface eth1",
			entry:       stream.LogEntry{Interface: "eth1"},
			expectMatch: true,
		},
		{
			name:        "match ip version",
			filter:      "ipversion 4",
			entry:       stream.LogEntry{IPVersion: 4},
			expectMatch: true,
		},
		{
			name:        "match ip version alias",
			filter:      "ipver 6",
			entry:       stream.LogEntry{IPVersion: 6},
			expectMatch: true,
		},
		{
			name:        "match ip version alias",
			filter:      "ip 4",
			entry:       stream.LogEntry{IPVersion: 4},
			expectMatch: true,
		},
		{
			name:        "do not match wrong ip version",
			filter:      "ipversion 6",
			entry:       stream.LogEntry{IPVersion: 4},
			expectMatch: false,
		},
		{
			name:        "match direction",
			filter:      "direction in",
			entry:       stream.LogEntry{Direction: "in"},
			expectMatch: true,
		},
		{
			name:        "match direction alias",
			filter:      "dir out",
			entry:       stream.LogEntry{Direction: "out"},
			expectMatch: true,
		},
		{
			name:        "match reason",
			filter:      "reason match",
			entry:       stream.LogEntry{Reason: "match"},
			expectMatch: true,
		},
		{
			name:        "match source port",
			filter:      "srcport 443",
			entry:       stream.LogEntry{SrcPort: 443},
			expectMatch: true,
		},
		{
			name:        "match source port alias",
			filter:      "sport 80",
			entry:       stream.LogEntry{SrcPort: 80},
			expectMatch: true,
		},
		{
			name:        "match destination port",
			filter:      "dstport 22",
			entry:       stream.LogEntry{DstPort: 22},
			expectMatch: true,
		},
		{
			name:        "match destination port alias",
			filter:      "dport 8080",
			entry:       stream.LogEntry{DstPort: 8080},
			expectMatch: true,
		},
		{
			name:        "match port on source",
			filter:      "port 443",
			entry:       stream.LogEntry{SrcPort: 443, DstPort: 8080},
			expectMatch: true,
		},
		{
			name:        "match port on destination",
			filter:      "port 8080",
			entry:       stream.LogEntry{SrcPort: 443, DstPort: 8080},
			expectMatch: true,
		},
		{
			name:        "do not match port",
			filter:      "port 22",
			entry:       stream.LogEntry{SrcPort: 2, DstPort: 222},
			expectMatch: false,
		},
	}

	runTests(t, tests)
}

func TestCompile_AndOperator(t *testing.T) {
	tests := []test{
		{
			name:        "match both conditions",
			filter:      "src 192.168 and proto tcp",
			entry:       stream.LogEntry{Src: "192.168.1.1", ProtoName: "tcp"},
			expectMatch: true,
		},
		{
			name:        "first condition fails",
			filter:      "source 10.0 && protocol tcp",
			entry:       stream.LogEntry{Src: "192.168.1.1", ProtoName: "tcp"},
			expectMatch: false,
		},
		{
			name:        "second condition fails",
			filter:      "src 192.168 and proto udp",
			entry:       stream.LogEntry{Src: "192.168.1.1", ProtoName: "tcp"},
			expectMatch: false,
		},
		{
			name:        "both conditions fail",
			filter:      "source 10.0 && protocol udp",
			entry:       stream.LogEntry{Src: "192.168.1.1", ProtoName: "tcp"},
			expectMatch: false,
		},
		{
			name:        "multiple and operators",
			filter:      "src 192.168 && proto tcp and dport 443",
			entry:       stream.LogEntry{Src: "192.168.1.1", ProtoName: "tcp", DstPort: 443},
			expectMatch: true,
		},
		{
			name:        "multiple and operators one fails",
			filter:      "source 192.168 && protocol tcp && dstport 80",
			entry:       stream.LogEntry{Src: "192.168.1.1", ProtoName: "tcp", DstPort: 443},
			expectMatch: false,
		},
		{
			name:        "missing value after operator",
			filter:      "src 192.168 and",
			expectError: true,
		},
		{
			name:        "missing right operand",
			filter:      "src 192.168 and proto",
			expectError: true,
		},
	}

	runTests(t, tests)
}

func TestCompile_OrOperator(t *testing.T) {
	tests := []test{
		{
			name:        "first condition matches",
			filter:      "src 192.168 or src 10.0",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: true,
		},
		{
			name:        "second condition matches",
			filter:      "source 10.0 || source 192.168",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: true,
		},
		{
			name:        "both conditions match",
			filter:      "src 192.168 || proto tcp",
			entry:       stream.LogEntry{Src: "192.168.1.1", ProtoName: "tcp"},
			expectMatch: true,
		},
		{
			name:        "neither condition matches",
			filter:      "source 10.0 || source 172.16",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: false,
		},
		{
			name:        "multiple operators",
			filter:      "src 10.0 or src 172.16 or src 192.168",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: true,
		},
		{
			name:        "multiple operators all fail",
			filter:      "source 10.0 || source 172.16 or source 8.8",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: false,
		},
		{
			name:        "missing value after or operator",
			filter:      "src 192.168 or",
			expectError: true,
		},
		{
			name:        "missing right operand",
			filter:      "src 192.168 or dst",
			expectError: true,
		},
	}

	runTests(t, tests)
}

func TestCompile_NotOperator(t *testing.T) {
	tests := []test{
		{
			name:        "invert match to no match",
			filter:      "not src 192.168",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: false,
		},
		{
			name:        "invert no match to match",
			filter:      "! source 10.0",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: true,
		},
		{
			name:        "not with protocol",
			filter:      "not protocol tcp",
			entry:       stream.LogEntry{ProtoName: "udp"},
			expectMatch: true,
		},
		{
			name:        "not with action",
			filter:      "! action block",
			entry:       stream.LogEntry{Action: "pass"},
			expectMatch: true,
		},
		{
			name:        "not with and operator",
			filter:      "not src 192.168 and proto tcp",
			entry:       stream.LogEntry{Src: "10.0.0.1", ProtoName: "tcp"},
			expectMatch: true,
		},
		{
			name:        "not with or operator",
			filter:      "! source 192.168 || protocol udp",
			entry:       stream.LogEntry{Src: "10.0.0.1", ProtoName: "udp"},
			expectMatch: true,
		},
		{
			name:        "missing operand",
			filter:      "not",
			expectError: true,
		},
		{
			name:        "missing value after operator",
			filter:      "not src",
			expectError: true,
		},
	}

	runTests(t, tests)
}

func TestCompile_Grouping(t *testing.T) {
	tests := []test{
		{
			name:        "simple grouping",
			filter:      "(src 192.168)",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: true,
		},
		{
			name:        "grouping with or and and",
			filter:      "(src 192.168 or src 10.0) and proto tcp",
			entry:       stream.LogEntry{Src: "192.168.1.1", ProtoName: "tcp"},
			expectMatch: true,
		},
		{
			name:        "grouping changes precedence",
			filter:      "src 192.168 and (proto tcp or proto udp)",
			entry:       stream.LogEntry{Src: "192.168.1.1", ProtoName: "udp"},
			expectMatch: true,
		},
		{
			name:        "nested grouping",
			filter:      "((src 192.168 or src 10.0) and proto tcp)",
			entry:       stream.LogEntry{Src: "10.0.0.1", ProtoName: "tcp"},
			expectMatch: true,
		},
		{
			name:        "not with grouping",
			filter:      "not (src 192.168 and proto tcp)",
			entry:       stream.LogEntry{Src: "192.168.1.1", ProtoName: "udp"},
			expectMatch: true,
		},
		{
			name:        "complex grouping",
			filter:      "(src 192.168 or src 10.0) and (proto tcp or proto udp)",
			entry:       stream.LogEntry{Src: "10.0.0.1", ProtoName: "udp"},
			expectMatch: true,
		},
		{
			name:        "grouping no match",
			filter:      "(src 192.168 or src 10.0) and proto icmp",
			entry:       stream.LogEntry{Src: "192.168.1.1", ProtoName: "tcp"},
			expectMatch: false,
		},
		{
			name:        "error missing left parenthesis",
			filter:      "(src 192.168",
			expectError: true,
		},
		{
			name:        "error empty parentheses",
			filter:      "()",
			expectError: true,
		},
		{
			name:        "error nested missing parenthesis",
			filter:      "((src 192.168)",
			expectError: true,
		},
	}

	runTests(t, tests)
}

func TestCompile_Edge(t *testing.T) {
	tests := []test{
		{
			name:        "empty filter string",
			filter:      "",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: false,
		},
		{
			name:        "extra spaces between tokens",
			filter:      "src    192.168   and    proto   tcp",
			entry:       stream.LogEntry{Src: "192.168.1.1", ProtoName: "tcp"},
			expectMatch: true,
		},
		{
			name:        "leading and trailing spaces",
			filter:      "  src 192.168  ",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: true,
		},
		{
			name:        "multiple spaces in parentheses",
			filter:      "(  src 192.168  )",
			entry:       stream.LogEntry{Src: "192.168.1.1"},
			expectMatch: true,
		},
	}

	runTests(t, tests)
}
