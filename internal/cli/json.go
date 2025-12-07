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
