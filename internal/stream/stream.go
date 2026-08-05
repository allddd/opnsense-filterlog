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
	"bufio"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

const (
	MaxErrorsInMemory = 1000
)

// LogEntry represents a parsed filter log entry.
type LogEntry struct {
	// common
	Time            time.Time `json:"time"`
	Label           string    `json:"label"`
	Action          string    `json:"action"`
	Reason          string    `json:"reason"`
	Direction       string    `json:"dir"`
	Interface       string    `json:"iface"`
	IPVersion       string    `json:"ipver"`
	ProtocolName    string    `json:"proto"`
	Source          string    `json:"src"`
	SourcePort      string    `json:"sport,omitempty"`
	Destination     string    `json:"dst"`
	DestinationPort string    `json:"dport,omitempty"`
	// ip
	Length string `json:"length,omitempty"`
	// ipv4
	DSCP   string `json:"dscp,omitempty"`
	ECN    string `json:"ecn,omitempty"`
	Flags  string `json:"flags,omitempty"`
	ID     string `json:"id,omitempty"`
	Offset string `json:"offset,omitempty"`
	TTL    string `json:"ttl,omitempty"`
	// ipv6
	Class    string `json:"class,omitempty"`
	Flow     string `json:"flow,omitempty"`
	HopLimit string `json:"hoplimit,omitempty"`
	// carp
	CARPAdvBase string `json:"carpabase,omitempty"`
	CARPAdvSkew string `json:"carpaskew,omitempty"`
	CARPTTL     string `json:"carpttl,omitempty"`
	CARPType    string `json:"carptype,omitempty"`
	CARPVHID    string `json:"carpvhid,omitempty"`
	CARPVersion string `json:"carpver,omitempty"`
	// tcp/udp
	DataLength string `json:"datalen,omitempty"`
	// tcp
	TCPAcknowledgment string `json:"tcpack,omitempty"`
	TCPFlags          string `json:"tcpflags,omitempty"`
	TCPOptions        string `json:"tcpopts,omitempty"`
	TCPSequence       string `json:"tcpseq,omitempty"`
	TCPUrgentPointer  string `json:"tcpurg,omitempty"`
	TCPWindow         string `json:"tcpwin,omitempty"`
}

// indexEntry represents an entry in the index.
type indexEntry struct {
	fileNum    int   // index of file entry is in
	lineOffset int64 // byte offset of entry
}

// Stream represents a streaming log parser.
type Stream struct {
	errors  []string       // parsing errors
	file    *os.File       // file handle
	fileNum int            // index of current file
	index   []indexEntry   // index of line positions
	lineNum int            // current line number
	paths   []string       // file paths (sorted by first entry)
	scanner *bufio.Scanner // file scanner
}

// parsing

// addError adds a parsing error to the errors slice.
func (s *Stream) addError(msg string) {
	if len(s.errors) < MaxErrorsInMemory {
		s.errors = append(s.errors, msg)
	}
}

// splitCSV splits a csv string into fields
// This is similar to strings.Split but optimized for this use case (almost 2x faster).
func splitCSV(csv string) []string {
	fields := make([]string, 0, 29) // preallocate for worst case (tcp4)
	start := 0
	for i := range len(csv) {
		if csv[i] == ',' {
			fields = append(fields, csv[start:i])
			start = i + 1 // +1 for comma
		}
	}
	fields = append(fields, csv[start:]) // add last field
	return fields
}

// parse parses a single line and returns a LogEntry.
func (s *Stream) parse(line string, path string) *LogEntry {
	var err error
	entry := LogEntry{}

	// extract the timestamp (between 1st and 2nd space)
	timeStart := strings.IndexByte(line, ' ') + 1 // +1 for 1st space
	timeEnd := strings.IndexByte(line[timeStart:], ' ')
	if timeStart <= 0 || timeEnd == -1 {
		s.addError(fmt.Sprintf("%s: invalid timestamp in %#q", path, line))
		return nil
	}
	timeEnd += timeStart // make relative index absolute
	entry.Time, err = time.Parse(time.RFC3339, line[timeStart:timeEnd])
	if err != nil {
		s.addError(fmt.Sprintf("%s: invalid timestamp in %#q: %v", path, line, err))
		return nil
	}

	// extract the csv string (after "] ") and split it into fields
	_, csv, ok := strings.Cut(line, "] ")
	if !ok {
		s.addError(fmt.Sprintf("%s: invalid csv in %#q", path, line))
		return nil
	}
	fields := splitCSV(csv)

	// 3: label, 4: interface, 5: reason, 6: action, 7: direction, 8: ipversion
	if len(fields) < 9 {
		s.addError(fmt.Sprintf("%s: invalid packetfilter section in %#q", path, line))
		return nil
	}

	entry.Label = fields[3]
	entry.Interface = fields[4]
	entry.Reason = fields[5]
	entry.Action = fields[6]
	entry.Direction = fields[7]
	entry.IPVersion = fields[8]

	switch entry.IPVersion {
	// ipv4
	case "4":
		// 9:dscp/tos, 10:ecn, 11:ttl, 12:id, 13:offset, 14:flags, 15:protonum, 16:protoname, 17:length, 18:src, 19:dst
		if len(fields) < 20 {
			s.addError(fmt.Sprintf("%s: invalid ipv4 section in %#q", path, line))
			return nil
		}

		entry.DSCP = fields[9]
		entry.ECN = fields[10]
		entry.TTL = fields[11]
		entry.ID = fields[12]
		entry.Offset = fields[13]
		entry.Flags = fields[14]
		entry.ProtocolName = fields[16]
		entry.Length = fields[17]
		entry.Source = fields[18]
		entry.Destination = fields[19]

		switch entry.ProtocolName { //nolint:dupl
		// udp4
		case "udp":
			// 20: srcport, 21: dstport, 22: datalen
			if len(fields) < 23 {
				s.addError(fmt.Sprintf("%s: invalid udp4 section in %#q", path, line))
				return nil
			}
			entry.SourcePort = fields[20]
			entry.DestinationPort = fields[21]
			entry.DataLength = fields[22]

		// tcp4
		case "tcp":
			// 20: srcport, 21: dstport, 22: datalen, 23: flags, 24: seq, 25: ack, 26: window, 27: urg, 28: options
			if len(fields) < 29 {
				s.addError(fmt.Sprintf("%s: invalid tcp4 section in %#q", path, line))
				return nil
			}
			entry.SourcePort = fields[20]
			entry.DestinationPort = fields[21]
			entry.DataLength = fields[22]
			entry.TCPFlags = fields[23]
			entry.TCPSequence = fields[24]
			entry.TCPAcknowledgment = fields[25]
			entry.TCPWindow = fields[26]
			entry.TCPUrgentPointer = fields[27]
			entry.TCPOptions = fields[28]

		// carp4
		case "carp":
			// 20: type, 21: ttl, 22: vhid, 23: version, 24: advskew, 25: advbase
			if len(fields) < 26 {
				s.addError(fmt.Sprintf("%s: invalid carp4 section in %#q", path, line))
				return nil
			}
			entry.CARPType = fields[20]
			entry.CARPTTL = fields[21]
			entry.CARPVHID = fields[22]
			entry.CARPVersion = fields[23]
			entry.CARPAdvSkew = fields[24]
			entry.CARPAdvBase = fields[25]

		// skip for any other protocol
		default:
		}

	// ipv6
	case "6":
		// 9:class, 10:flow, 11:hoplimit, 12:protoname, 13:protonum, 14:length, 15:src, 16:dst
		if len(fields) < 17 {
			s.addError(fmt.Sprintf("%s: invalid ipv6 section in %#q", path, line))
			return nil
		}

		entry.Class = fields[9]
		entry.Flow = fields[10]
		entry.HopLimit = fields[11]
		entry.ProtocolName = fields[12]
		entry.Length = fields[14]
		entry.Source = fields[15]
		entry.Destination = fields[16]

		switch entry.ProtocolName { //nolint:dupl
		// udp6
		case "udp":
			// 17: srcport, 18: dstport, 19: datalen
			if len(fields) < 20 {
				s.addError(fmt.Sprintf("%s: invalid udp6 section in %#q", path, line))
				return nil
			}
			entry.SourcePort = fields[17]
			entry.DestinationPort = fields[18]
			entry.DataLength = fields[19]

		// tcp6
		case "tcp":
			// 17: srcport, 18: dstport, 19: datalen, 20: flags, 21: seq, 22: ack, 23: window, 24: urg, 25: options
			if len(fields) < 26 {
				s.addError(fmt.Sprintf("%s: invalid tcp6 section in %#q", path, line))
				return nil
			}
			entry.SourcePort = fields[17]
			entry.DestinationPort = fields[18]
			entry.DataLength = fields[19]
			entry.TCPFlags = fields[20]
			entry.TCPSequence = fields[21]
			entry.TCPAcknowledgment = fields[22]
			entry.TCPWindow = fields[23]
			entry.TCPUrgentPointer = fields[24]
			entry.TCPOptions = fields[25]

		// carp6
		case "carp":
			// 17: type, 18: ttl, 19: vhid, 20: version, 21: advskew, 22: advbase
			if len(fields) < 23 {
				s.addError(fmt.Sprintf("%s: invalid carp6 section in %#q", path, line))
				return nil
			}
			entry.CARPType = fields[17]
			entry.CARPTTL = fields[18]
			entry.CARPVHID = fields[19]
			entry.CARPVersion = fields[20]
			entry.CARPAdvSkew = fields[21]
			entry.CARPAdvBase = fields[22]

		// skip for any other protocol
		default:
		}

	default:
		s.addError(fmt.Sprintf("%s: invalid ip version in %#q", path, line))
		return nil
	}

	return &entry
}

// stream

// reset repositions the stream to the start of the first file.
func (s *Stream) reset() error {
	if s.file != nil {
		if err := s.file.Close(); err != nil {
			return fmt.Errorf("error(stream): could not close file: %w", err)
		}
	}
	file, err := os.Open(s.paths[0])
	if err != nil {
		return fmt.Errorf("error(stream): could not open file: %w", err)
	}
	s.file = file
	s.fileNum = 0
	s.scanner = bufio.NewScanner(file)
	s.lineNum = 0
	return nil
}

// public

// BuildIndex builds an index of line positions across all files.
func (s *Stream) BuildIndex() error {
	s.index = make([]indexEntry, 0)
	for fileNum, path := range s.paths {
		if s.file != nil {
			if err := s.file.Close(); err != nil {
				return fmt.Errorf("error(stream): could not close file: %w", err)
			}
		}
		file, err := os.Open(path) //nolint:gosec
		if err != nil {
			return fmt.Errorf("error(stream): could not open file: %w", err)
		}
		s.file = file
		s.fileNum = fileNum
		s.scanner = bufio.NewScanner(file)
		lineOffset := int64(0)
		for s.scanner.Scan() {
			if entry := s.parse(s.scanner.Text(), path); entry != nil {
				s.index = append(s.index, indexEntry{
					fileNum:    fileNum,
					lineOffset: lineOffset,
				})
			}
			lineOffset += int64(len(s.scanner.Bytes()) + 1) // +1 for newline
		}
		if err := s.scanner.Err(); err != nil {
			return fmt.Errorf("error(stream): could not build index: %w", err)
		}
	}
	return s.reset()
}

// Close closes the log file.
func (s *Stream) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// GetPaths returns the file paths of the log files.
func (s Stream) GetPaths() []string {
	return s.paths
}

// GetErrors returns all parsing errors encountered during parsing.
func (s Stream) GetErrors() []string {
	return s.errors
}

// NewStream creates a new streaming parser for the given log files.
func NewStream(paths []string) (*Stream, error) {
	if len(paths) == 0 {
		return nil, errors.New("error(stream): no path provided")
	}
	// sort paths by first entry timestamp
	if len(paths) > 1 {
		order := make(map[string]time.Time, len(paths))
		tmp := &Stream{}
		for _, path := range paths {
			file, err := os.Open(path) //nolint:gosec
			if err != nil {
				return nil, fmt.Errorf("error(stream): could not open file: %w", err)
			}
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				if entry := tmp.parse(scanner.Text(), path); entry != nil {
					order[path] = entry.Time
					break
				}
			}
			if err := file.Close(); err != nil {
				return nil, fmt.Errorf("error(stream): could not close file: %w", err)
			}
		}
		slices.SortFunc(paths, func(a, b string) int {
			if c := order[a].Compare(order[b]); c != 0 {
				return c
			}
			return strings.Compare(a, b)
		})
	}
	file, err := os.Open(paths[0])
	if err != nil {
		return nil, fmt.Errorf("error(stream): could not open file: %w", err)
	}
	return &Stream{
		errors:  make([]string, 0),
		file:    file,
		fileNum: 0,
		index:   nil,
		lineNum: 0,
		paths:   paths,
		scanner: bufio.NewScanner(file),
	}, nil
}

// Next reads and parses the next log entry across all files.
func (s *Stream) Next() (*LogEntry, error) {
	for {
		for s.scanner.Scan() {
			s.lineNum++
			if entry := s.parse(s.scanner.Text(), s.paths[s.fileNum]); entry != nil {
				return entry, nil
			}
			// if nil, continue to the next line
		}
		s.fileNum++
		if s.fileNum >= len(s.paths) {
			return nil, nil
		}
		if s.file != nil {
			if err := s.file.Close(); err != nil {
				return nil, fmt.Errorf("error(stream): could not close file: %w", err)
			}
		}
		file, err := os.Open(s.paths[s.fileNum])
		if err != nil {
			return nil, fmt.Errorf("error(stream): could not open file: %w", err)
		}
		s.file = file
		s.scanner = bufio.NewScanner(file)
	}
}

// SeekToLine seeks to a specific line number using the index.
func (s *Stream) SeekToLine(lineNum int) error {
	if len(s.index) == 0 {
		return errors.New("error(stream): could not seek: missing index")
	}
	if lineNum < 0 || lineNum >= len(s.index) {
		return fmt.Errorf("error(stream): could not seek: line %d out of range [0, %d)", lineNum, len(s.index))
	}
	entry := s.index[lineNum]
	if s.file != nil {
		if err := s.file.Close(); err != nil {
			return fmt.Errorf("error(stream): could not close file: %w", err)
		}
	}
	file, err := os.Open(s.paths[entry.fileNum])
	if err != nil {
		return fmt.Errorf("error(stream): could not seek to line %d: %w", lineNum, err)
	}
	_, err = file.Seek(entry.lineOffset, 0)
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("error(stream): could not seek to line %d: %w", lineNum, err)
	}
	s.file = file
	s.fileNum = entry.fileNum
	s.scanner = bufio.NewScanner(file)
	s.lineNum = lineNum
	return nil
}

// TotalLines returns the total number of valid lines (if indexed).
func (s Stream) TotalLines() int {
	if i := len(s.index); i > 0 {
		return i
	}
	return -1
}
