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
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"gitlab.com/allddd/opnsense-filterlog/internal/parse"
)

const (
	// MaxErrorsInMemory is the maximum number of parsing errors kept in memory.
	MaxErrorsInMemory = 1000
)

// LogEntry represents a parsed filter log entry.
type LogEntry struct {
	// common
	Time            time.Time  `json:"time"`
	Label           string     `json:"label"`
	Action          string     `json:"action"`
	Reason          string     `json:"reason"`
	Direction       string     `json:"dir"`
	Interface       string     `json:"iface"`
	IPVersion       uint8      `json:"ipver"`
	ProtocolName    string     `json:"proto"`
	ProtocolNum     uint8      `json:"protonum"`
	Source          netip.Addr `json:"src"`
	SourcePort      *uint16    `json:"sport,omitzero"`
	Destination     netip.Addr `json:"dst"`
	DestinationPort *uint16    `json:"dport,omitzero"`
	// ip
	Length uint16 `json:"length"`
	// ipv4
	DSCP   string  `json:"dscp,omitzero"`
	ECN    string  `json:"ecn,omitzero"`
	Flags  string  `json:"flags,omitzero"`
	ID     *uint16 `json:"id,omitzero"`
	Offset *uint16 `json:"offset,omitzero"`
	TTL    *uint8  `json:"ttl,omitzero"`
	// ipv6
	Class    string `json:"class,omitzero"`
	Flow     string `json:"flow,omitzero"`
	HopLimit *uint8 `json:"hoplimit,omitzero"`
	// carp
	CARPAdvBase *uint8 `json:"carpabase,omitzero"`
	CARPAdvSkew *uint8 `json:"carpaskew,omitzero"`
	CARPTTL     *uint8 `json:"carpttl,omitzero"`
	CARPType    string `json:"carptype,omitzero"`
	CARPVHID    *uint8 `json:"carpvhid,omitzero"`
	CARPVersion *uint8 `json:"carpver,omitzero"`
	// tcp/udp
	DataLength *uint16 `json:"datalen,omitzero"`
	// tcp
	TCPAcknowledgment *uint32 `json:"tcpack,omitzero"`
	TCPFlags          string  `json:"tcpflags,omitzero"`
	TCPOptions        string  `json:"tcpopts,omitzero"`
	TCPSequence       *uint32 `json:"tcpseq,omitzero"`
	TCPUrgentPointer  *uint16 `json:"tcpurg,omitzero"`
	TCPWindow         *uint16 `json:"tcpwin,omitzero"`
	// common
	ErrMsg string `json:"errmsg,omitzero"`
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
	paths   []string       // file paths (sorted by first entry)
	scanner *bufio.Scanner // file scanner
}

// parsing

// addError adds a parsing error to the errors slice.
func (s *Stream) addError(line string, path string, what string, err error) {
	if len(s.errors) < MaxErrorsInMemory {
		msg := fmt.Sprintf("%s: invalid %s in %#q", path, what, line)
		if err != nil {
			msg += ": " + err.Error()
		}
		s.errors = append(s.errors, msg)
	}
}

// splitCSV splits a csv string into fields.
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
	var missingProtocolData bool
	var remainingFields []string
	entry := LogEntry{}

	// extract the timestamp (between 1st and 2nd space)
	_, after, _ := strings.Cut(line, " ")
	timestamp, _, ok := strings.Cut(after, " ")
	if !ok {
		s.addError(line, path, "timestamp", nil)
		return nil
	}
	entry.Time, err = time.Parse(time.RFC3339, timestamp)
	if err != nil {
		s.addError(line, path, "timestamp", err)
		return nil
	}

	// extract the csv string (after "] ") and split it into fields
	_, csv, ok := strings.Cut(line, "] ")
	if !ok {
		s.addError(line, path, "csv", nil)
		return nil
	}
	fields := splitCSV(csv)

	// 3:label, 4:interface, 5:reason, 6:action, 7:direction, 8:ipversion
	if len(fields) < 9 {
		s.addError(line, path, "packetfilter section", nil)
		return nil
	}

	entry.Label = fields[3]
	entry.Interface = fields[4]
	entry.Reason = fields[5]
	entry.Action = fields[6]
	entry.Direction = fields[7]

	switch fields[8] {
	// ipv4
	case "4":
		// 9:dscp/tos, 10:ecn, 11:ttl, 12:id, 13:offset, 14:flags, 15:protonum, 16:protoname, 17:length, 18:src, 19:dst
		if len(fields) < 20 {
			s.addError(line, path, "ipv4 section", nil)
			return nil
		}

		entry.IPVersion = 4
		entry.DSCP = fields[9]
		entry.ECN = fields[10]
		entry.TTL, err = parse.UintPointer[uint8](fields[11])
		if err != nil {
			s.addError(line, path, "ttl", err)
			return nil
		}
		entry.ID, err = parse.UintPointer[uint16](fields[12])
		if err != nil {
			s.addError(line, path, "id", err)
			return nil
		}
		entry.Offset, err = parse.UintPointer[uint16](fields[13])
		if err != nil {
			s.addError(line, path, "offset", err)
			return nil
		}
		entry.Flags = fields[14]
		entry.ProtocolNum, err = parse.Uint[uint8](fields[15])
		if err != nil {
			s.addError(line, path, "protocol number", err)
			return nil
		}
		entry.ProtocolName = fields[16]

		remainingFields = fields[17:]

	// ipv6
	case "6":
		// 9:class, 10:flow, 11:hoplimit, 12:protoname, 13:protonum, 14:length, 15:src, 16:dst
		if len(fields) < 17 {
			s.addError(line, path, "ipv6 section", nil)
			return nil
		}

		entry.IPVersion = 6
		entry.Class = fields[9]
		entry.Flow = fields[10]
		entry.HopLimit, err = parse.UintPointer[uint8](fields[11])
		if err != nil {
			s.addError(line, path, "hop limit", err)
			return nil
		}
		entry.ProtocolName = fields[12]
		entry.ProtocolNum, err = parse.Uint[uint8](fields[13])
		if err != nil {
			s.addError(line, path, "protocol number", err)
			return nil
		}

		remainingFields = fields[14:]

	default:
		s.addError(line, path, "ip version", nil)
		return nil
	}

	// 0:length, 1:src, 2:dst
	entry.Length, err = parse.Uint[uint16](remainingFields[0])
	if err != nil {
		s.addError(line, path, "length", err)
		return nil
	}
	entry.Source, err = netip.ParseAddr(remainingFields[1])
	if err != nil {
		s.addError(line, path, "source ip", err)
		return nil
	}
	entry.Destination, err = netip.ParseAddr(remainingFields[2])
	if err != nil {
		s.addError(line, path, "destination ip", err)
		return nil
	}
	remainingFields = remainingFields[3:]

	switch entry.ProtocolName {
	// udp
	case "udp":
		// 0:srcport, 1:dstport, 2:datalen
		if len(remainingFields) < 3 {
			missingProtocolData = true
			break
		}
		entry.SourcePort, err = parse.UintPointer[uint16](remainingFields[0])
		if err != nil {
			s.addError(line, path, "source port", err)
			return nil
		}
		entry.DestinationPort, err = parse.UintPointer[uint16](remainingFields[1])
		if err != nil {
			s.addError(line, path, "destination port", err)
			return nil
		}
		entry.DataLength, err = parse.UintPointer[uint16](remainingFields[2])
		if err != nil {
			s.addError(line, path, "data length", err)
			return nil
		}

	// tcp
	case "tcp":
		// 0:srcport, 1:dstport, 2:datalen, 3:flags, 4:seq, 5:ack, 6:window, 7:urg, 8:options
		if len(remainingFields) < 9 {
			missingProtocolData = true
			break
		}
		entry.SourcePort, err = parse.UintPointer[uint16](remainingFields[0])
		if err != nil {
			s.addError(line, path, "source port", err)
			return nil
		}
		entry.DestinationPort, err = parse.UintPointer[uint16](remainingFields[1])
		if err != nil {
			s.addError(line, path, "destination port", err)
			return nil
		}
		entry.DataLength, err = parse.UintPointer[uint16](remainingFields[2])
		if err != nil {
			s.addError(line, path, "data length", err)
			return nil
		}
		entry.TCPFlags = remainingFields[3]
		// empty if there is no data and no syn/fin/rst flag
		if remainingFields[4] != "" {
			// only start is kept since end is always start + datalen
			start, _, _ := strings.Cut(remainingFields[4], ":")
			entry.TCPSequence, err = parse.UintPointer[uint32](start)
			if err != nil {
				s.addError(line, path, "tcp sequence", err)
				return nil
			}
		}
		// empty if ack flag is not set
		if remainingFields[5] != "" {
			entry.TCPAcknowledgment, err = parse.UintPointer[uint32](remainingFields[5])
			if err != nil {
				s.addError(line, path, "tcp acknowledgment", err)
				return nil
			}
		}
		entry.TCPWindow, err = parse.UintPointer[uint16](remainingFields[6])
		if err != nil {
			s.addError(line, path, "tcp window", err)
			return nil
		}
		// empty if urg flag is not set
		if remainingFields[7] != "" {
			entry.TCPUrgentPointer, err = parse.UintPointer[uint16](remainingFields[7])
			if err != nil {
				s.addError(line, path, "tcp urgent pointer", err)
				return nil
			}
		}
		entry.TCPOptions = remainingFields[8]

	// carp
	case "carp":
		// 0:type, 1:ttl, 2:vhid, 3:version, 4:advskew, 5:advbase
		if len(remainingFields) < 6 {
			missingProtocolData = true
			break
		}
		entry.CARPType = remainingFields[0]
		entry.CARPTTL, err = parse.UintPointer[uint8](remainingFields[1])
		if err != nil {
			s.addError(line, path, "carp ttl", err)
			return nil
		}
		entry.CARPVHID, err = parse.UintPointer[uint8](remainingFields[2])
		if err != nil {
			s.addError(line, path, "carp vhid", err)
			return nil
		}
		entry.CARPVersion, err = parse.UintPointer[uint8](remainingFields[3])
		if err != nil {
			s.addError(line, path, "carp version", err)
			return nil
		}
		entry.CARPAdvSkew, err = parse.UintPointer[uint8](remainingFields[4])
		if err != nil {
			s.addError(line, path, "carp advskew", err)
			return nil
		}
		entry.CARPAdvBase, err = parse.UintPointer[uint8](remainingFields[5])
		if err != nil {
			s.addError(line, path, "carp advbase", err)
			return nil
		}

	// skip for any other protocol
	default:
	}

	if missingProtocolData {
		entry.ErrMsg = "malformed entry; error message not found"
		if _, after, ok := strings.Cut(line, "errormsg='"); ok {
			if msg, _, ok := strings.Cut(after, "'"); ok {
				entry.ErrMsg = msg
			}
		}
	}

	return &entry
}

// stream

// open closes the current file and opens the file with the given index.
func (s *Stream) open(fileNum int) error {
	if err := s.Close(); err != nil {
		return err
	}
	file, err := os.Open(s.paths[fileNum])
	if err != nil {
		return fmt.Errorf("error(stream): could not open file: %w", err)
	}
	s.file = file
	s.fileNum = fileNum
	s.scanner = bufio.NewScanner(file)
	return nil
}

// public

// BuildIndex builds an index of line positions across all files.
func (s *Stream) BuildIndex() error {
	s.index = make([]indexEntry, 0)
	for fileNum, path := range s.paths {
		if err := s.open(fileNum); err != nil {
			return err
		}
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
			return fmt.Errorf("error(stream): could not scan file: %w", err)
		}
	}
	return s.open(0)
}

// Close closes the log file.
func (s *Stream) Close() error {
	if s.file != nil {
		err := s.file.Close()
		s.file = nil
		if err != nil {
			return fmt.Errorf("error(stream): could not close file: %w", err)
		}
	}
	return nil
}

// Errors returns parsing errors encountered during parsing (at most MaxErrorsInMemory).
func (s Stream) Errors() []string {
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
		tmp := &Stream{paths: paths}
		for fileNum, path := range paths {
			if err := tmp.open(fileNum); err != nil {
				return nil, err
			}
			for tmp.scanner.Scan() {
				if entry := tmp.parse(tmp.scanner.Text(), path); entry != nil {
					order[path] = entry.Time
					break
				}
			}
			if err := tmp.scanner.Err(); err != nil {
				return nil, fmt.Errorf("error(stream): could not scan file: %w", err)
			}
		}
		if err := tmp.Close(); err != nil {
			return nil, err
		}
		slices.SortFunc(paths, func(a, b string) int {
			if c := order[a].Compare(order[b]); c != 0 {
				return c
			}
			return strings.Compare(a, b)
		})
	}
	s := &Stream{
		errors: make([]string, 0),
		index:  nil,
		paths:  paths,
	}
	if err := s.open(0); err != nil {
		return nil, err
	}
	return s, nil
}

// Next reads and parses the next log entry across all files.
func (s *Stream) Next() (*LogEntry, error) {
	for {
		for s.scanner.Scan() {
			if entry := s.parse(s.scanner.Text(), s.paths[s.fileNum]); entry != nil {
				return entry, nil
			}
			// if nil, continue to the next line
		}
		if err := s.scanner.Err(); err != nil {
			return nil, fmt.Errorf("error(stream): could not scan file: %w", err)
		}
		s.fileNum++
		if s.fileNum >= len(s.paths) {
			return nil, nil
		}
		if err := s.open(s.fileNum); err != nil {
			return nil, err
		}
	}
}

// Paths returns the file paths of the log files.
func (s Stream) Paths() []string {
	return s.paths
}

// SeekToLine seeks to a specific line number using the index.
func (s *Stream) SeekToLine(lineNum int) error {
	if len(s.index) == 0 {
		return errors.New("error(stream): could not seek: missing index")
	}
	if lineNum < 0 || lineNum >= len(s.index) {
		return fmt.Errorf("error(stream): could not seek: line %d out of range [0, %d)", lineNum, len(s.index))
	}
	pos := s.index[lineNum]
	if err := s.open(pos.fileNum); err != nil {
		return err
	}
	if _, err := s.file.Seek(pos.lineOffset, io.SeekStart); err != nil {
		return fmt.Errorf("error(stream): could not seek to line %d: %w", lineNum, err)
	}
	return nil
}

// TotalLines returns the total number of valid lines (if indexed).
func (s Stream) TotalLines() int {
	if i := len(s.index); i > 0 {
		return i
	}
	return -1
}
