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
	"strings"
	"testing"
	"time"
)

func TestSplit(t *testing.T) {
	tests := []struct {
		name string
		csv  string
	}{
		{"empty string", ""},
		{"single field", "a"},
		{"empty in the middle", "a,,c"},
		{"empty at boundaries", ",b,"},
		{"all empty", ",,"},
		{"real ipv4", "68,,,4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a,eth1,match,pass,out,4,0x0,,127,17785,0,DF,6,tcp,52,192.168.1.100,10.0.0.5,46376,80,0,S,1356197145,,64480,,mss;nop;wscale;nop;nop;sackOK"},     //nolint:lll
		{"real ipv6", "61,,,3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f,eth0,match,pass,in,6,0x00,0xd3e97,128,udp,17,60,fd00:abcd:ef01:2345:6789:abcd:ef01:2345,fd00:1111:2222:3333:4444:5555:6666:7777,51091,53,60"}, //nolint:lll
		{"very large", strings.Repeat("field,", 50) + "last"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := splitCSV(tc.csv)
			expected := strings.Split(tc.csv, ",")
			if len(got) != len(expected) {
				t.Fatalf("expected %d fields, got %d", len(expected), len(got))
			}
			for i := range expected {
				if got[i] != expected[i] {
					t.Fatalf("field %d: expected %q, got %q", i, expected[i], got[i])
				}
			}
		})
	}
}

func TestValidLog(t *testing.T) {
	s, err := NewStream([]string{"testdata/valid.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	valid := 0
	for {
		entry, err := s.Next()
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil {
			break
		}
		valid++
	}
	if valid != 20 {
		t.Fatalf("expected 20 valid entries, got %d", valid)
	}
	errors := len(s.GetErrors())
	if errors != 0 {
		t.Fatalf("expected 0 errors, got %d", errors)
	}
}

func TestMixedLog(t *testing.T) {
	s, err := NewStream([]string{"testdata/mixed.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	valid := 0
	for {
		entry, err := s.Next()
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil {
			break
		}
		valid++
	}
	if valid != 20 {
		t.Fatalf("expected 20 valid entries, got %d", valid)
	}
	errors := len(s.GetErrors())
	if errors != 30 {
		t.Fatalf("expected 30 errors, got %d", errors)
	}
}

func TestCorruptLog(t *testing.T) {
	s, err := NewStream([]string{"testdata/corrupt.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	valid := 0
	for {
		entry, err := s.Next()
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil {
			break
		}
		valid++
	}
	if valid != 1 {
		t.Fatalf("expected 1 valid entry, got %d", valid)
	}
	errors := len(s.GetErrors())
	if errors != 8 {
		t.Fatalf("expected 8 errors, got %d", errors)
	}
}

func TestBuildIndex(t *testing.T) {
	s, err := NewStream([]string{"testdata/valid.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.BuildIndex(); err != nil {
		t.Fatal(err)
	}
	total := s.TotalLines()
	if total != 20 {
		t.Fatalf("expected 20 indexed lines, got %d", total)
	}
}

func TestSeekToLine(t *testing.T) {
	s, err := NewStream([]string{"testdata/valid.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// seek before indexing
	if err := s.SeekToLine(5); err == nil {
		t.Fatal("expected error seeking without index")
	}
	if err := s.BuildIndex(); err != nil {
		t.Fatal(err)
	}
	// seek to top
	if err := s.SeekToLine(0); err != nil {
		t.Fatal(err)
	}
	entry, err := s.Next()
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected entry at line 0, got nil")
	}
	if entry.IPVersion != "6" {
		t.Fatalf("expected ipv6 at line 0, got ipv%s", entry.IPVersion)
	}
	// seek to middle
	if err := s.SeekToLine(10); err != nil {
		t.Fatal(err)
	}
	entry, err = s.Next()
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected entry at line 10, got nil")
	}
	// seek to bottom
	if err := s.SeekToLine(19); err != nil {
		t.Fatal(err)
	}
	entry, err = s.Next()
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected entry at line 19, got nil")
	}
	// seek out of bounds
	if err := s.SeekToLine(-1); err == nil {
		t.Fatal("expected error seeking to negative line")
	}
	if err := s.SeekToLine(1000); err == nil {
		t.Fatal("expected error seeking beyond end")
	}
}

func TestParsedValues(t *testing.T) {
	s, err := NewStream([]string{"testdata/valid.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// 1st entry
	entry, err := s.Next()
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected entry 1, got nil")
	}
	if entry.IPVersion != "6" {
		t.Fatalf("entry 1: expected ipv6, got ipv%s", entry.IPVersion)
	}
	if entry.ProtocolName != "udp" {
		t.Fatalf("entry 1: expected udp, got %s", entry.ProtocolName)
	}
	if entry.Action != "pass" {
		t.Fatalf("entry 1: expected pass, got %s", entry.Action)
	}
	if entry.Direction != "in" {
		t.Fatalf("entry 1: expected in, got %s", entry.Direction)
	}
	if entry.SourcePort != "63511" || entry.DestinationPort != "53" {
		t.Fatalf("entry 1: expected ports 63511:53, got %s:%s", entry.SourcePort, entry.DestinationPort)
	}
	expectedTime := time.Date(2025, 10, 11, 0, 0, 0, 0, time.FixedZone("", 2*60*60))
	if !entry.Time.Equal(expectedTime) {
		t.Fatalf("entry 1: expected time %v, got %v", expectedTime, entry.Time)
	}
	if entry.Class != "0x00" {
		t.Fatalf("entry 1: expected class 0x00, got %s", entry.Class)
	}
	if entry.Flow != "0xfd492" {
		t.Fatalf("entry 1: expected flow 0xfd492, got %s", entry.Flow)
	}
	if entry.HopLimit != "128" {
		t.Fatalf("entry 1: expected hoplimit 128, got %s", entry.HopLimit)
	}
	if entry.Length != "60" {
		t.Fatalf("entry 1: expected length 60, got %s", entry.Length)
	}
	if entry.Label != "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d" {
		t.Fatalf("entry 1: expected label 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d, got %s", entry.Label)
	}
	if entry.DataLength != "60" {
		t.Fatalf("entry 1: expected datalen 60, got %s", entry.DataLength)
	}
	// 2nd entry
	entry, err = s.Next()
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected entry 2, got nil")
	}
	if entry.IPVersion != "4" {
		t.Fatalf("entry 2: expected ipv4, got ipv%s", entry.IPVersion)
	}
	if entry.ProtocolName != "udp" {
		t.Fatalf("entry 2: expected udp, got %s", entry.ProtocolName)
	}
	if entry.Source != "192.168.1.100" || entry.Destination != "192.168.1.1" {
		t.Fatalf("entry 2: expected src/dst 192.168.1.100/192.168.1.1, got %s/%s", entry.Source, entry.Destination)
	}
	if entry.DSCP != "0x0" {
		t.Fatalf("entry 2: expected dscp 0x0, got %s", entry.DSCP)
	}
	if entry.TTL != "64" {
		t.Fatalf("entry 2: expected ttl 64, got %s", entry.TTL)
	}
	if entry.ID != "0" {
		t.Fatalf("entry 2: expected id 0, got %s", entry.ID)
	}
	if entry.Offset != "0" {
		t.Fatalf("entry 2: expected offset 0, got %s", entry.Offset)
	}
	if entry.Flags != "DF" {
		t.Fatalf("entry 2: expected flags DF, got %s", entry.Flags)
	}
	if entry.Length != "80" {
		t.Fatalf("entry 2: expected length 80, got %s", entry.Length)
	}
	if entry.ECN != "" {
		t.Fatalf("entry 2: expected ecn empty, got %s", entry.ECN)
	}
	if entry.DataLength != "60" {
		t.Fatalf("entry 2: expected datalen 60, got %s", entry.DataLength)
	}
	// 4th entry
	// skip 3rd entry
	if _, err = s.Next(); err != nil {
		t.Fatal(err)
	}
	entry, err = s.Next()
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected entry 4, got nil")
	}
	if entry.IPVersion != "4" {
		t.Fatalf("entry 4: expected ipv4, got ipv%s", entry.IPVersion)
	}
	if entry.ProtocolName != "tcp" {
		t.Fatalf("entry 4: expected tcp, got %s", entry.ProtocolName)
	}
	if entry.SourcePort != "46376" || entry.DestinationPort != "80" {
		t.Fatalf("entry 4: expected ports 46376:80, got %s:%s", entry.SourcePort, entry.DestinationPort)
	}
	if entry.DataLength != "0" {
		t.Fatalf("entry 4: expected datalen 0, got %s", entry.DataLength)
	}
	if entry.TCPFlags != "S" {
		t.Fatalf("entry 4: expected tcpflags S, got %s", entry.TCPFlags)
	}
	if entry.TCPSequence != "1356197145" {
		t.Fatalf("entry 4: expected tcpseq 1356197145, got %s", entry.TCPSequence)
	}
	if entry.TCPAcknowledgment != "" {
		t.Fatalf("entry 4: expected tcpack empty, got %s", entry.TCPAcknowledgment)
	}
	if entry.TCPWindow != "64480" {
		t.Fatalf("entry 4: expected tcpwindow 64480, got %s", entry.TCPWindow)
	}
	if entry.TCPUrgentPointer != "" {
		t.Fatalf("entry 4: expected tcpurg empty, got %s", entry.TCPUrgentPointer)
	}
	if entry.TCPOptions != "mss;nop;wscale;nop;nop;sackOK" {
		t.Fatalf("entry 4: expected tcpoptions mss;nop;wscale;nop;nop;sackOK, got %s", entry.TCPOptions)
	}
	if entry.DSCP != "0x0" {
		t.Fatalf("entry 4: expected dscp 0x0, got %s", entry.DSCP)
	}
	if entry.TTL != "127" {
		t.Fatalf("entry 4: expected ttl 127, got %s", entry.TTL)
	}
	if entry.Length != "52" {
		t.Fatalf("entry 4: expected length 52, got %s", entry.Length)
	}

}

func TestTotalLines(t *testing.T) {
	s, err := NewStream([]string{"testdata/valid.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// without index
	if total := s.TotalLines(); total != -1 {
		t.Fatalf("expected -1 without index, got %d", total)
	}
	// with index
	if err := s.BuildIndex(); err != nil {
		t.Fatal(err)
	}
	if total := s.TotalLines(); total != 20 {
		t.Fatalf("expected 20 with index, got %d", total)
	}
}

func TestMultiFile(t *testing.T) {
	s, err := NewStream([]string{"testdata/valid.log", "testdata/mixed.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	valid := 0
	for {
		entry, err := s.Next()
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil {
			break
		}
		valid++
	}
	if valid != 40 {
		t.Fatalf("expected 40 valid entries, got %d", valid)
	}
	errors := len(s.GetErrors())
	if errors != 30 {
		t.Fatalf("expected 30 errors, got %d", errors)
	}
}

func TestMultiFileSort(t *testing.T) {
	s, err := NewStream([]string{"testdata/valid.log", "testdata/mixed.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	entry, err := s.Next()
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected entry, got nil")
	}
	if entry.IPVersion != "4" {
		t.Fatalf("expected ipv4, got ipv%s", entry.IPVersion)
	}
}

func TestMultiFileBuildIndex(t *testing.T) {
	s, err := NewStream([]string{"testdata/valid.log", "testdata/mixed.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.BuildIndex(); err != nil {
		t.Fatal(err)
	}
	total := s.TotalLines()
	if total != 40 {
		t.Fatalf("expected 40 indexed lines, got %d", total)
	}
}

func TestMultiFileSeekToLine(t *testing.T) {
	s, err := NewStream([]string{"testdata/valid.log", "testdata/mixed.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.BuildIndex(); err != nil {
		t.Fatal(err)
	}
	// seek to first entry in second file (line 20)
	if err := s.SeekToLine(20); err != nil {
		t.Fatal(err)
	}
	entry, err := s.Next()
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected entry at line 20, got nil")
	}
	if entry.IPVersion != "6" {
		t.Fatalf("expected ipv6 at line 20, got ipv%s", entry.IPVersion)
	}
}

func TestMultiFileGetPaths(t *testing.T) {
	s, err := NewStream([]string{"testdata/valid.log", "testdata/mixed.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	paths := s.GetPaths()
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
}

func TestNewStreamEmpty(t *testing.T) {
	_, err := NewStream([]string{})
	if err == nil {
		t.Fatal("expected error for empty paths")
	}
}

func BenchmarkParse(b *testing.B) {
	s := &Stream{}
	line := `<134>1 2025-10-10T00:00:00+02:00 opnsense.filter.log filterlog 86605 - [meta sequenceId="4"] 68,,,4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a,eth1,match,pass,out,4,0x0,,127,17785,0,DF,6,tcp,52,192.168.1.100,10.0.0.5,46376,80,0,S,1356197145,,64480,,mss;nop;wscale;nop;nop;sackOK` //nolint:lll
	for b.Loop() {
		s.parse(line, "")
	}
}
