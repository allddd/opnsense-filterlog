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
	"context"
	"os"
	"os/exec"
	"testing"

	"gitlab.com/allddd/opnsense-filterlog/internal/meta"
)

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
			expectError:    false,
			expectedOutput: "testdata/empty.json",
		},
		{
			name:           "full",
			args:           []string{"-j", "testdata/filter_20260728.log"},
			expectError:    false,
			expectedOutput: "testdata/full.json",
		},
		{
			name:           "filter",
			args:           []string{"-j", "-f", "proto gre", "testdata/filter_20260727.log", "testdata/filter_20260728.log"},
			expectError:    false,
			expectedOutput: "testdata/filter.json",
		},
		{
			name:        "filter invalid",
			args:        []string{"-j", "-f", "proto udp and", "testdata/filter_20260726.log"},
			expectError: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(context.Background(), "../../"+meta.Name, tc.args...)
			got, err := cmd.Output()
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
				expected, err := os.ReadFile(tc.expectedOutput)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(expected, got) {
					t.Fatal("output mismatch")
				}
			}
		})
	}
}
