package stream

import (
	"testing"
	"time"
)

func TestExtractCSVField(t *testing.T) {
	tests := []struct {
		name        string
		csv         string
		field       int
		expectOk    bool
		expectValue string
	}{
		{
			name:        "first field",
			csv:         "a,b,c",
			field:       0,
			expectOk:    true,
			expectValue: "a",
		},
		{
			name:        "middle field",
			csv:         "a,b,c",
			field:       1,
			expectOk:    true,
			expectValue: "b",
		},
		{
			name:        "last field",
			csv:         "a,b,c",
			field:       2,
			expectOk:    true,
			expectValue: "c",
		},
		{
			name:        "field out of range",
			csv:         "a,b,c",
			field:       3,
			expectOk:    false,
			expectValue: "",
		},
		{
			name:        "empty field",
			csv:         "a,,c",
			field:       1,
			expectOk:    true,
			expectValue: "",
		},
		{
			name:        "single field",
			csv:         "a",
			field:       0,
			expectOk:    true,
			expectValue: "a",
		},
		{
			name:        "empty string",
			csv:         "",
			field:       0,
			expectOk:    true,
			expectValue: "",
		},
		{
			name:        "long csv",
			csv:         "a,b,c,d,e,f,g,h,i,j,k,l,m,n",
			field:       11,
			expectOk:    true,
			expectValue: "l",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			value, ok := extractCSVField(tc.csv, tc.field)
			if ok != tc.expectOk {
				t.Fatalf("expected ok=%v, got %v", tc.expectOk, ok)
			}
			if value != tc.expectValue {
				t.Fatalf("expected %q, got %q", tc.expectValue, value)
			}
		})
	}
}

func TestValidLog(t *testing.T) {
	s, err := NewStream("../../tests/filter_valid.log")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	valid := 0
	for entry := s.Next(); entry != nil; entry = s.Next() {
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
	s, err := NewStream("../../tests/filter_mixed.log")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	valid := 0
	for entry := s.Next(); entry != nil; entry = s.Next() {
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
	s, err := NewStream("../../tests/filter_corrupt.log")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	valid := 0
	for entry := s.Next(); entry != nil; entry = s.Next() {
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
	s, err := NewStream("../../tests/filter_valid.log")
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
	s, err := NewStream("../../tests/filter_valid.log")
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
	entry := s.Next()
	if entry == nil {
		t.Fatal("expected entry at line 0, got nil")
	}
	if entry.IPVersion != ipVersion6 {
		t.Fatalf("expected ipv%d at line 0, got ipv%d", ipVersion6, entry.IPVersion)
	}
	// seek to middle
	if err := s.SeekToLine(10); err != nil {
		t.Fatal(err)
	}
	entry = s.Next()
	if entry == nil {
		t.Fatal("expected entry at line 10, got nil")
	}
	// seek to bottom
	if err := s.SeekToLine(19); err != nil {
		t.Fatal(err)
	}
	entry = s.Next()
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
	s, err := NewStream("../../tests/filter_valid.log")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// 1st entry
	entry := s.Next()
	if entry == nil {
		t.Fatal("expected entry 1, got nil")
	}
	if entry.IPVersion != ipVersion6 {
		t.Fatalf("entry 1: expected ipv%d, got ipv%d", ipVersion6, entry.IPVersion)
	}
	if entry.ProtoName != protoUDP {
		t.Fatalf("entry 1: expected %s, got %s", protoUDP, entry.ProtoName)
	}
	if entry.Action != ActionPass {
		t.Fatalf("entry 1: expected %s, got %s", ActionPass, entry.Action)
	}
	if entry.Direction != directionIn {
		t.Fatalf("entry 1: expected %s, got %s", directionIn, entry.Direction)
	}
	if entry.SrcPort != 63511 || entry.DstPort != 53 {
		t.Fatalf("entry 1: expected ports 63511:53, got %d:%d", entry.SrcPort, entry.DstPort)
	}
	expectedTime := time.Date(2025, 10, 10, 0, 0, 0, 0, time.FixedZone("", 2*60*60))
	if !entry.Time.Equal(expectedTime) {
		t.Fatalf("entry 1: expected time %v, got %v", expectedTime, entry.Time)
	}
	// 2nd entry
	entry = s.Next()
	if entry == nil {
		t.Fatal("expected entry 2, got nil")
	}
	if entry.IPVersion != ipVersion4 {
		t.Fatalf("entry 2: expected ipv%d, got ipv%d", ipVersion4, entry.IPVersion)
	}
	if entry.ProtoName != protoUDP {
		t.Fatalf("entry 2: expected %s, got %s", protoUDP, entry.ProtoName)
	}
	if entry.Src != "192.168.1.100" || entry.Dst != "192.168.1.1" {
		t.Fatalf("entry 2: expected src/dst 192.168.1.100/192.168.1.1, got %s/%s", entry.Src, entry.Dst)
	}
	// 7th entry
	for range 4 {
		s.Next()
	}
	entry = s.Next()
	if entry == nil {
		t.Fatal("expected entry 7, got nil")
	}
	if entry.Action != ActionBlock {
		t.Fatalf("entry 7: expected %s, got %s", ActionBlock, entry.Action)
	}
	if entry.ProtoName != protoTCP {
		t.Fatalf("entry 7: expected %s, got %s", protoTCP, entry.ProtoName)
	}
}

func TestTotalLines(t *testing.T) {
	s, err := NewStream("../../tests/filter_valid.log")
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
