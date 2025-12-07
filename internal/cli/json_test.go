package cli

import (
	"encoding/json"
	"io"
	"os"
	"testing"

	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
)

func captureOutput(fn func() error) (stdout, stderr []byte, err error) {
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = wOut, wErr
	err = fn()
	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	stdout, _ = io.ReadAll(rOut)
	stderr, _ = io.ReadAll(rErr)
	return
}

func TestValidLog(t *testing.T) {
	s, err := stream.NewStream("../../tests/filter_valid.log")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	stdout, _, err := captureOutput(func() error {
		return displayJSON(s, "")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// parse json
	var obj jsonObj
	if err := json.Unmarshal(stdout, &obj); err != nil {
		t.Fatalf("could not parse json: %v", err)
	}
	// check entries
	if len(obj.Entries) != 20 {
		t.Fatalf("expected 20 entries in array, got %d", len(obj.Entries))
	}
	// check meta
	if obj.Meta.Entries != 20 {
		t.Fatalf("expected 20 entries in meta, got %d", obj.Meta.Entries)
	}
	if obj.Meta.Errors != 0 {
		t.Fatalf("expected 0 errors in meta, got %d", obj.Meta.Errors)
	}
	if obj.Meta.Filter != "" {
		t.Fatalf("expected empty filter in meta, got %q", obj.Meta.Filter)
	}
	if obj.Meta.Source == "" {
		t.Fatal("expected non-empty source in meta")
	}
}

func TestMixedLog(t *testing.T) {
	s, err := stream.NewStream("../../tests/filter_mixed.log")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	stdout, stderr, err := captureOutput(func() error {
		return displayJSON(s, "")
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// parse json
	var obj jsonObj
	if err := json.Unmarshal(stdout, &obj); err != nil {
		t.Fatalf("could not parse json: %v", err)
	}
	// check entries
	if len(obj.Entries) != 20 {
		t.Fatalf("expected 20 entries in array, got %d", len(obj.Entries))
	}
	// check meta
	if obj.Meta.Entries != 20 {
		t.Fatalf("expected 20 valid entries in meta, got %d", obj.Meta.Entries)
	}
	if obj.Meta.Errors != 30 {
		t.Fatalf("expected 30 errors in meta, got %d", obj.Meta.Errors)
	}
	// check stderr
	if len(stderr) == 0 {
		t.Fatal("expected errors to be written to stderr")
	}
}

func TestCorruptLog(t *testing.T) {
	s, err := stream.NewStream("../../tests/filter_corrupt.log")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	stdout, _, err := captureOutput(func() error {
		return displayJSON(s, "")
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// parse json
	var obj jsonObj
	if err := json.Unmarshal(stdout, &obj); err != nil {
		t.Fatalf("could not parse json: %v", err)
	}
	// check entries
	if len(obj.Entries) != 1 {
		t.Fatalf("expected 1 entry in array, got %d", len(obj.Entries))
	}
	// check meta
	if obj.Meta.Entries != 1 {
		t.Fatalf("expected 1 valid entry in meta, got %d", obj.Meta.Entries)
	}
	if obj.Meta.Errors != 8 {
		t.Fatalf("expected 8 errors in meta, got %d", obj.Meta.Errors)
	}
}

func TestWithFilter(t *testing.T) {
	tests := []struct {
		name        string
		filter      string
		expectCount int
		expectError bool
	}{
		{
			name:        "valid filter",
			filter:      "proto udp and action pass",
			expectCount: 8,
			expectError: false,
		},
		{
			name:        "valid filter with no matches",
			filter:      "src 1.2.3.4",
			expectCount: 0,
			expectError: false,
		},
		{
			name:        "invalid filter",
			filter:      "src and",
			expectCount: 0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := stream.NewStream("../../tests/filter_valid.log")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			stdout, _, err := captureOutput(func() error {
				return displayJSON(s, tc.filter)
			})
			if tc.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// parse json
			var obj jsonObj
			if err := json.Unmarshal(stdout, &obj); err != nil {
				t.Fatalf("could not parse json: %v", err)
			}
			// check entries
			if len(obj.Entries) != tc.expectCount {
				t.Fatalf("expected %d entries, got %d", tc.expectCount, len(obj.Entries))
			}
			// check meta
			if obj.Meta.Entries != tc.expectCount {
				t.Fatalf("expected %d entries in meta, got %d", tc.expectCount, obj.Meta.Entries)
			}
			if obj.Meta.Filter != tc.filter {
				t.Fatalf("expected filter %q in meta, got %q", tc.filter, obj.Meta.Filter)
			}
		})
	}
}

func TestEmpty(t *testing.T) {
	s, err := stream.NewStream("../../tests/filter_valid.log")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	stdout, _, err := captureOutput(func() error {
		return displayJSON(s, "src 1.2.3.4") // use filter that matches nothing
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// parse json
	var obj jsonObj
	if err := json.Unmarshal(stdout, &obj); err != nil {
		t.Fatalf("could not parse json: %v", err)
	}
	// check entries
	if len(obj.Entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(obj.Entries))
	}
	// check meta
	if obj.Meta.Entries != 0 {
		t.Fatalf("expected 0 entries in meta, got %d", obj.Meta.Entries)
	}
}

func TestStructure(t *testing.T) {
	s, err := stream.NewStream("../../tests/filter_valid.log")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	stdout, _, err := captureOutput(func() error {
		return displayJSON(s, "")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// parse json
	var raw map[string]any
	if err := json.Unmarshal(stdout, &raw); err != nil {
		t.Fatalf("could not parse json: %v", err)
	}
	// check top level structure
	if _, ok := raw["entries"]; !ok {
		t.Fatal("missing 'entries' key in json output")
	}
	if _, ok := raw["meta"]; !ok {
		t.Fatal("missing 'meta' key in json output")
	}
	// check entries is an array and it isn't empty
	entries, ok := raw["entries"].([]any)
	if !ok {
		t.Fatal("'entries' is not an array")
	}
	if len(entries) == 0 {
		t.Fatal("'entries' array is empty")
	}
	// check meta is an object
	meta, ok := raw["meta"].(map[string]any)
	if !ok {
		t.Fatal("'meta' is not an object")
	}
	// check meta fields
	if _, ok := meta["entries"]; !ok {
		t.Fatal("missing 'entries' in meta")
	}
	if _, ok := meta["source"]; !ok {
		t.Fatal("missing 'source' in meta")
	}
	// check all entries can be unmarshaled to LogEntry
	for i, e := range entries {
		var entry stream.LogEntry
		entryJSON, _ := json.Marshal(e)
		if err := json.Unmarshal(entryJSON, &entry); err != nil {
			t.Fatalf("could not unmarshal entry %d: %v", i, err)
		}
	}
}
