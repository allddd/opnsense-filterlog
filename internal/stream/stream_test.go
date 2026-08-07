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

package stream

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

var files = []struct {
	path string
	size int
}{
	{"testdata/filter_20260727.log", 46488},
	{"testdata/filter_20260728.log", 51243},
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name string
		csv  string
	}{
		{"empty string", ""},
		{"single field", "a"},
		{"all empty", ",,"},
		{"empty at boundaries", ",b,"},
		{"empty in the middle", "a,,c"},
		{"real v4", "9,,,02f4bab031b57d1e30553ce08e0ec131,eth0,match,block,in,4,0x14,,48,54642,0,DF,6,tcp,52,10.174.12.141,10.247.95.6,55666,12186,0,S,1925882663,,61690,,mss;nop;wscale;nop;nop;sackOK"},   //nolint:lll
		{"real v6", "71,,,6125cb207f65033775d1069fdf6d0ccf,eth0,match,pass,out,6,0x00,0x07d4c,64,udp,17,58,fd11:4ad:f2ce:6b0e::a894,fd3e:938c:962d:e767::a620,54857,53,58"},                                 //nolint:lll
		{"real err", `9,,,02f4bab031b57d1e30553ce08e0ec131,eth0,match,block,in,4,0x0,,117,63581,0,none,6,tcp,40,10.161.149.187,10.247.95.6,80,16677,-8,R,errormsg='[bad hdr length 28 - too long, > 20]',`}, //nolint:lll
		{"very large", strings.Repeat("field,", 99) + "last"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expected := strings.Split(tc.csv, ",")
			got := splitCSV(tc.csv)
			if len(expected) != len(got) {
				t.Fatalf("expected %d fields, got %d", len(expected), len(got))
			}
			for i := range expected {
				if expected[i] != got[i] {
					t.Fatalf("expected field %d to be %q, got %q", i, expected[i], got[i])
				}
			}
		})
	}
}

func TestIndexSeekParse(t *testing.T) {
	tests := []struct {
		lineNum  int
		expected LogEntry
	}{
		{
			// gre4
			lineNum: 26454,
			expected: LogEntry{
				Time:         time.Date(2026, 7, 27, 13, 29, 6, 0, time.UTC),
				Label:        "02f4bab031b57d1e30553ce08e0ec131",
				Action:       "block",
				Reason:       "match",
				Direction:    "in",
				Interface:    "eth0",
				IPVersion:    "4",
				ProtocolName: "gre",
				ProtocolNum:  "47",
				Source:       "10.164.203.218",
				Destination:  "10.247.95.6",
				Length:       "578",
				DSCP:         "0x0",
				Flags:        "DF",
				ID:           "29882",
				Offset:       "0",
				TTL:          "49",
			},
		},
		{
			// icmp4
			lineNum: 43965,
			expected: LogEntry{
				Time:         time.Date(2026, 7, 27, 22, 40, 19, 0, time.UTC),
				Label:        "02f4bab031b57d1e30553ce08e0ec131",
				Action:       "block",
				Reason:       "match",
				Direction:    "in",
				Interface:    "eth0",
				IPVersion:    "4",
				ProtocolName: "icmp",
				ProtocolNum:  "1",
				Source:       "10.34.135.90",
				Destination:  "10.247.95.6",
				Length:       "40",
				DSCP:         "0x0",
				Flags:        "none",
				ID:           "54321",
				Offset:       "0",
				TTL:          "233",
			},
		},
		{
			// tcp4
			lineNum: 61,
			expected: LogEntry{
				Time:            time.Date(2026, 7, 27, 0, 0, 40, 0, time.UTC),
				Label:           "02f4bab031b57d1e30553ce08e0ec131",
				Action:          "block",
				Reason:          "match",
				Direction:       "in",
				Interface:       "eth0",
				IPVersion:       "4",
				ProtocolName:    "tcp",
				ProtocolNum:     "6",
				Source:          "10.61.225.162",
				SourcePort:      "41821",
				Destination:     "10.247.95.6",
				DestinationPort: "25048",
				Length:          "40",
				DSCP:            "0x0",
				Flags:           "none",
				ID:              "43049",
				Offset:          "0",
				TTL:             "244",
				DataLength:      "0",
				TCPFlags:        "S",
				TCPSequence:     "1042808185",
				TCPWindow:       "1024",
			},
		},
		{
			// udp4
			lineNum: 57,
			expected: LogEntry{
				Time:            time.Date(2026, 7, 27, 0, 0, 29, 0, time.UTC),
				Label:           "d732bf074e5af1431615bc5c20ab4d3c",
				Action:          "pass",
				Reason:          "match",
				Direction:       "out",
				Interface:       "eth0",
				IPVersion:       "4",
				ProtocolName:    "udp",
				ProtocolNum:     "17",
				Source:          "10.247.95.6",
				SourcePort:      "59066",
				Destination:     "10.80.8.109",
				DestinationPort: "53",
				Length:          "70",
				DSCP:            "0x0",
				Flags:           "DF",
				ID:              "0",
				Offset:          "0",
				TTL:             "64",
				DataLength:      "50",
			},
		},
		{
			// icmp6
			lineNum: 44067,
			expected: LogEntry{
				Time:         time.Date(2026, 7, 27, 22, 43, 34, 0, time.UTC),
				Label:        "80f90f0d4c5aba0c28d1c539e1e35766",
				Action:       "pass",
				Reason:       "match",
				Direction:    "out",
				Interface:    "eth0",
				IPVersion:    "6",
				ProtocolName: "ipv6-icmp",
				ProtocolNum:  "58",
				Source:       "fe80::cfbf:d893:e80d:17ff",
				Destination:  "fe80::bad8",
				Length:       "32",
				Class:        "0x00",
				Flow:         "0x00000",
				HopLimit:     "255",
			},
		},
		{
			// tcp6
			lineNum: 15727,
			expected: LogEntry{
				Time:            time.Date(2026, 7, 27, 7, 48, 1, 0, time.UTC),
				Label:           "6125cb207f65033775d1069fdf6d0ccf",
				Action:          "pass",
				Reason:          "match",
				Direction:       "out",
				Interface:       "eth0",
				IPVersion:       "6",
				ProtocolName:    "tcp",
				ProtocolNum:     "6",
				Source:          "fd11:4ad:f2ce:6b0e::a894",
				SourcePort:      "25408",
				Destination:     "fdf1:4357:edd8:f527::414f",
				DestinationPort: "443",
				Length:          "40",
				Class:           "0x00",
				Flow:            "0x32046",
				HopLimit:        "64",
				DataLength:      "0",
				TCPFlags:        "S",
				TCPOptions:      "mss;nop;wscale;sackOK;TS",
				TCPSequence:     "2820870139",
				TCPWindow:       "65228",
			},
		},
		{
			// udp6
			lineNum: 45808,
			expected: LogEntry{
				Time:            time.Date(2026, 7, 27, 23, 38, 2, 0, time.UTC),
				Label:           "6125cb207f65033775d1069fdf6d0ccf",
				Action:          "pass",
				Reason:          "match",
				Direction:       "out",
				Interface:       "eth0",
				IPVersion:       "6",
				ProtocolName:    "udp",
				ProtocolNum:     "17",
				Source:          "fd11:4ad:f2ce:6b0e::a894",
				SourcePort:      "123",
				Destination:     "fd25:380e:4b5f:1e3a::683",
				DestinationPort: "123",
				Length:          "56",
				Class:           "0xb8",
				Flow:            "0x00000",
				HopLimit:        "64",
				DataLength:      "56",
			},
		},
		{
			// ipv6 encapsulation
			lineNum: 8367,
			expected: LogEntry{
				Time:         time.Date(2026, 7, 27, 4, 5, 36, 0, time.UTC),
				Label:        "02f4bab031b57d1e30553ce08e0ec131",
				Action:       "block",
				Reason:       "match",
				Direction:    "in",
				Interface:    "eth0",
				IPVersion:    "4",
				ProtocolName: "ipv6",
				ProtocolNum:  "41",
				Source:       "10.119.149.16",
				Destination:  "10.247.95.6",
				Length:       "68",
				DSCP:         "0x0",
				Flags:        "none",
				ID:           "54321",
				Offset:       "0",
				TTL:          "241",
			},
		},
	}
	s, err := NewStream([]string{files[0].path})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.BuildIndex(); err != nil {
		t.Fatal(err)
	}
	if got := s.TotalLines(); files[0].size != got {
		t.Fatalf("expected %d indexed lines, got %d", files[0].size, got)
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("line_%d", tc.lineNum), func(t *testing.T) {
			if err := s.SeekToLine(tc.lineNum - 1); err != nil {
				t.Error(err)
			}
			got, err := s.Next()
			if err != nil {
				t.Error(err)
			}
			if got == nil {
				t.Error("expected entry, got nil")
			}
			if diff := cmp.Diff(tc.expected, *got); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestMultiFileSort(t *testing.T) {
	s, err := NewStream([]string{files[1].path, files[0].path})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.BuildIndex(); err != nil {
		t.Fatal(err)
	}
	if got := s.TotalLines(); files[0].size+files[1].size != got {
		t.Fatalf("expected %d indexed lines, got %d", files[0].size+files[1].size, got)
	}
	if err := s.SeekToLine(0); err != nil {
		t.Fatal(err)
	}
	for range files[0].size {
		got, err := s.Next()
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatal("expected entry, got nil")
		}
		if expected := 27; expected != got.Time.Day() {
			t.Fatalf("expected day to be %d, got %d", expected, got.Time.Day())
		}
	}
	for range files[1].size {
		got, err := s.Next()
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatal("expected entry, got nil")
		}
		if expected := 28; expected != got.Time.Day() {
			t.Fatalf("expected day to be %d, got %d", expected, got.Time.Day())
		}
	}
}

func BenchmarkParse(b *testing.B) {
	s := &Stream{}
	const line = `<134>1 2026-07-27T16:11:13+00:00 opnsense.filter.log filterlog 42443 - [meta sequenceId="321"] 10,,,02f4bab031b57d1e30553ce08e0ec131,eth0,match,block,in,6,0x00,0x00000,52,tcp,6,32,fd2a:697e:b72f:7075::61e4,fd16:b3e4:682e:47bc:f2b2:3ddd:e426:1181,46433,80,0,S,3158346414,,65535,,mss;nop;wscale;nop;nop;sackOK` //nolint:lll
	for b.Loop() {
		_ = s.parse(line, "")
	}
}
