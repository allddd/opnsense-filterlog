// Copyright (c) 2026 allddd <me@allddd.onl>
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

package cli

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"gitlab.com/allddd/opnsense-filterlog/internal/meta"
)

var files = []struct {
	path string
	size int
}{
	{"testdata/filter_20260727.log", 46488},
	{"testdata/filter_20260728.log", 51243},
}

func TestFlags(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectError    bool
		expectedOutput string
	}{
		{
			name:           "help",
			args:           []string{"-h"},
			expectError:    false,
			expectedOutput: "Usage:",
		},
		{
			name:        "version",
			args:        []string{"-V"},
			expectError: false,
		},
		{
			name:           "filter no json",
			args:           []string{"-f", "proto tcp", files[0].path},
			expectError:    true,
			expectedOutput: "requires",
		},
		{
			name:           "exclusive help json",
			args:           []string{"-h", "-j", files[0].path},
			expectError:    true,
			expectedOutput: "mutually exclusive",
		},
		{
			name:           "exclusive help version",
			args:           []string{"-h", "-V"},
			expectError:    true,
			expectedOutput: "mutually exclusive",
		},
		{
			name:           "exclusive json version",
			args:           []string{"-j", "-V", files[0].path},
			expectError:    true,
			expectedOutput: "mutually exclusive",
		},
		{
			name:           "exclusive all",
			args:           []string{"-h", "-j", "-V", files[0].path},
			expectError:    true,
			expectedOutput: "mutually exclusive",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(context.Background(), "../../"+meta.Name, tc.args...)
			got, err := cmd.CombinedOutput()
			if tc.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
			if tc.expectedOutput != "" {
				if !strings.Contains(string(got), tc.expectedOutput) {
					t.Fatal("output mismatch")
				}
			}
		})
	}
}

func TestStdin(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		stdin          string
		expectError    bool
		expectedOutput string
		expectedCount  int
	}{
		{
			name:          "pipe",
			args:          []string{"-j"},
			stdin:         files[0].path,
			expectedCount: files[0].size,
		},
		{
			name:          "pipe dash",
			args:          []string{"-j", "-"},
			stdin:         files[0].path,
			expectedCount: files[0].size,
		},
		{
			name:           "no pipe",
			args:           []string{"-j", "-"},
			expectError:    true,
			expectedOutput: "no stdin data",
		},
		{
			name:           "dash duplicate",
			args:           []string{"-j", "-", "-"},
			stdin:          files[0].path,
			expectError:    true,
			expectedOutput: "duplicate stdin arg",
		},
		{
			name:          "file dash",
			args:          []string{"-j", files[1].path, "-"},
			stdin:         files[0].path,
			expectedCount: files[0].size + files[1].size,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(context.Background(), "../../"+meta.Name, tc.args...)
			if tc.stdin != "" {
				f, err := os.Open(tc.stdin)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				cmd.Stdin = f
			}
			got, err := cmd.CombinedOutput()
			if tc.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
			if tc.expectedOutput != "" {
				if !strings.Contains(string(got), tc.expectedOutput) {
					t.Fatal("output mismatch")
				}
			}
			if tc.expectedCount > 0 {
				var result jsonObj
				if err := json.Unmarshal(got, &result); err != nil {
					t.Fatal(err)
				}
				if result.Meta.Entries != tc.expectedCount {
					t.Fatalf("expected %d entries, got %d", tc.expectedCount, result.Meta.Entries)
				}
			}
		})
	}
}
