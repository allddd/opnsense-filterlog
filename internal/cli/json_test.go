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

package cli

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"testing"
)

var update = flag.Bool("update", false, "update .golden files")

func TestJSON(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectError    bool
		expectedOutput string
	}{
		{
			name:           "empty",
			args:           []string{"-j", "/dev/null"},
			expectedOutput: "testdata/empty.golden",
		},
		{
			name:           "full",
			args:           []string{"-j", files[2].path},
			expectedOutput: "testdata/full.golden",
		},
		{
			name:           "filter",
			args:           []string{"-j", "-f", "proto gre", files[1].path, files[2].path},
			expectedOutput: "testdata/filter.golden",
		},
		{
			name:        "filter invalid",
			args:        []string{"-j", "-f", "proto udp and", files[0].path},
			expectError: true,
		},
		{
			name:           "parse errors",
			args:           []string{"-j", "-f", "proto gre", files[0].path},
			expectError:    true,
			expectedOutput: "testdata/errors.golden",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), binary, tc.args...)
			got, err := cmd.CombinedOutput()
			if tc.expectError && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.expectedOutput != "" {
				if *update {
					if err := os.WriteFile(tc.expectedOutput, got, 0644); err != nil {
						t.Fatalf("could not update .golden files: %v", err)
					}
					return
				}
				expected, err := os.ReadFile(tc.expectedOutput)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(expected, got) {
					i := 0
					for i < len(expected) && i < len(got) && expected[i] == got[i] {
						i++
					}
					start := max(0, i-50) // 50 bytes before and after the first difference
					t.Fatalf("output mismatch at byte %d: expected %q, got %q",
						i, expected[start:min(i+50, len(expected))], got[start:min(i+50, len(got))])
				}
			}
		})
	}
}
