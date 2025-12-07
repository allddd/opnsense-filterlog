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

package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"gitlab.com/allddd/opnsense-filterlog/internal/filter"
	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
)

type jsonObjMeta struct {
	Entries int    `json:"entries"`          // count of entries in entries array
	Errors  int    `json:"errors,omitempty"` // number of parse errors
	Filter  string `json:"filter,omitempty"` // filter expression
	Source  string `json:"source"`           // file path (absolute if possible)
}

// jsonObj represents the complete JSON output structure (used only for tests and docs)
type jsonObj struct {
	Entries []*stream.LogEntry `json:"entries"` // array of log entries
	Meta    jsonObjMeta        `json:"meta"`    // meta object
}

// displayJSON writes the jsonObj to stdout
func displayJSON(s *stream.Stream, filterValue string) error {
	// compile filter expression (if any)
	var compiled filter.FilterNode
	if filterValue != "" {
		var err error
		compiled, err = filter.Compile(filterValue)
		if err != nil {
			return err
		}
	}
	// open object and entries array
	fmt.Fprint(os.Stdout, `{"entries":[`)
	// stream entries and count
	entries := 0
	for entry := s.Next(); entry != nil; entry = s.Next() {
		// skip entries that don't match filter
		if compiled != nil && !compiled.Matches(entry) {
			continue
		}
		jsonEntry, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("error(json): could not encode entry: %w", err)
		}
		if entries > 0 {
			fmt.Fprint(os.Stdout, ",")
		}
		fmt.Fprint(os.Stdout, string(jsonEntry))
		entries++
	}
	// close entries and open meta
	fmt.Fprint(os.Stdout, `],"meta":`)
	// build and write meta object
	errors := s.GetErrors()
	source, err := s.GetPathAbs()
	if err != nil {
		source = s.GetPathRel()
	}
	meta := jsonObjMeta{
		Entries: entries,
		Errors:  len(errors),
		Filter:  filterValue,
		Source:  source,
	}
	jsonMeta, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("error(json): could not encode meta: %w", err)
	}
	fmt.Fprintln(os.Stdout, string(jsonMeta)+"}")
	// print errors to stderr (if any)
	if len(errors) > 0 {
		for _, err := range errors {
			fmt.Fprintln(os.Stderr, err)
		}
		return fmt.Errorf("error(json): could not process all entries: %d parse errors", len(errors))
	}
	return nil
}
