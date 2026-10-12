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
	"bufio"
	"encoding/json/v2"
	"fmt"
	"os"

	"gitlab.com/allddd/opnsense-filterlog/internal/filter"
	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
)

type jsonObjMeta struct {
	Entries int      `json:"entries"`         // count of entries in entries array
	Errors  int      `json:"errors,omitzero"` // number of parse errors (at most stream.MaxErrorsInMemory)
	Filter  string   `json:"filter,omitzero"` // filter expression
	Sources []string `json:"sources"`         // file path(s)
}

// jsonObj represents the complete JSON output structure (used only for tests and docs).
type jsonObj struct {
	Entries []*stream.LogEntry `json:"entries"` // array of log entries
	Meta    jsonObjMeta        `json:"meta"`    // meta object
}

// displayJSON writes the jsonObj to stdout.
func displayJSON(s *stream.Stream, filterValue string) error {
	// compile filter expression (if any)
	var compiled filter.Node
	if filterValue != "" {
		var err error
		compiled, err = filter.Compile(filterValue)
		if err != nil {
			return err
		}
	}
	w := bufio.NewWriter(os.Stdout)
	defer func() { _ = w.Flush() }()
	// open object and entries array
	_, _ = w.WriteString(`{"entries":[`)
	// stream entries and count
	entries := 0
	for {
		entry, err := s.Next()
		if err != nil {
			return err
		}
		if entry == nil {
			break
		}
		// skip entries that don't match filter
		if compiled != nil && !compiled.Matches(entry) {
			continue
		}
		jsonEntry, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("error(json): could not encode entry: %w", err)
		}
		if entries > 0 {
			_ = w.WriteByte(',')
		}
		_, _ = w.Write(jsonEntry)
		entries++
	}
	// close entries and write meta object
	parseErrors := s.Errors()
	jsonMeta, err := json.Marshal(jsonObjMeta{
		Entries: entries,
		Errors:  len(parseErrors),
		Filter:  filterValue,
		Sources: s.Paths(),
	})
	if err != nil {
		return fmt.Errorf("error(json): could not encode meta: %w", err)
	}
	_, _ = w.WriteString(`],"meta":`)
	_, _ = w.Write(jsonMeta)
	_, _ = w.WriteString("}\n")
	if err := w.Flush(); err != nil {
		return fmt.Errorf("error(json): could not write output: %w", err)
	}
	// print parse errors to stderr (if any)
	if len(parseErrors) > 0 {
		for _, msg := range parseErrors {
			fmt.Fprintln(os.Stderr, msg)
		}
		return fmt.Errorf("error(json): could not process all entries: %d parse errors", len(parseErrors))
	}
	return nil
}
