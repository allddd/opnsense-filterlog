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
	"bytes"
	"encoding/json"
	"os/exec"
	"testing"

	"gitlab.com/allddd/opnsense-filterlog/internal/meta"
)

func TestArgs(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectError    bool
		expectedSource string
	}{
		{
			name:           "one arg",
			args:           []string{"-j", "testdata/valid.log"},
			expectError:    false,
			expectedSource: "testdata/valid.log",
		},
		{
			name:        "multiple args",
			args:        []string{"-j", "testdata/valid.log", "testdata/invalid.log"},
			expectError: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("../../"+meta.Name, tc.args...)
			output, err := cmd.Output()
			if tc.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if tc.expectedSource != "" {
					var result jsonObj
					if err := json.Unmarshal(output, &result); err != nil {
						t.Fatal(err)
					}
					if result.Meta.Source != tc.expectedSource {
						t.Fatalf("expected source %q, got %q", tc.expectedSource, result.Meta.Source)
					}
				}
			}
		})
	}
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
			name:           "mutually exclusive help and json",
			args:           []string{"-h", "-j", "testdata/valid.log"},
			expectError:    true,
			expectedOutput: "mutually exclusive",
		},
		{
			name:           "mutually exclusive help and version",
			args:           []string{"-h", "-V"},
			expectError:    true,
			expectedOutput: "mutually exclusive",
		},
		{
			name:           "mutually exclusive json and version",
			args:           []string{"-j", "-V", "testdata/valid.log"},
			expectError:    true,
			expectedOutput: "mutually exclusive",
		},
		{
			name:           "mutually exclusive all",
			args:           []string{"-h", "-j", "-V", "testdata/valid.log"},
			expectError:    true,
			expectedOutput: "mutually exclusive",
		},
		{
			name:           "filter requires json",
			args:           []string{"-f", "proto tcp", "testdata/valid.log"},
			expectError:    true,
			expectedOutput: "requires",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("../../"+meta.Name, tc.args...)
			output, err := cmd.CombinedOutput()
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
				if !bytes.Contains(output, []byte(tc.expectedOutput)) {
					t.Fatalf("missing %q in output", tc.expectedOutput)
				}
			}
		})
	}
}
