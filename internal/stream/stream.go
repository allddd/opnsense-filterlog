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

package stream

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	MaxErrorsInMemory = 1000

	// actions
	actionBinat        = "binat"
	ActionBlock        = "block"
	actionNat          = "nat"
	ActionPass         = "pass"
	actionRdr          = "rdr"
	actionScrub        = "scrub"
	actionSynproxyDrop = "synproxy-drop"

	// directions
	DirectionIn    = "in"
	DirectionInOut = "in/out"
	DirectionOut   = "out"

	// ip
	ipVersion4 = 4
	ipVersion6 = 6

	// protocols
	protocolICMP   = "icmp"
	protocolICMPv6 = "ipv6-icmp"
	protocolTCP    = "tcp"
	protocolUDP    = "udp"

	// reasons
	reasonBadOffset     = "bad-offset"
	reasonBadTimestamp  = "bad-timestamp"
	reasonCongestion    = "congestion"
	reasonFragment      = "fragment"
	reasonIpOption      = "ip-option"
	reasonMatch         = "match"
	reasonMemory        = "memory"
	reasonNormalize     = "normalize"
	reasonProtoChecksum = "proto-cksum"
	reasonShort         = "short"
	reasonSrcLimit      = "src-limit"
	reasonStateInsert   = "state-insert"
	reasonStateLimit    = "state-limit"
	reasonStateMismatch = "state-mismatch"
	reasonSynproxy      = "synproxy"
)

// LogEntry represents a parsed filter log entry
type LogEntry struct {
	// common
	Action    string    `json:"action"`
	Direction string    `json:"dir"`
	Interface string    `json:"iface"`
	Reason    string    `json:"reason"`
	Time      time.Time `json:"time"`

	// ip
	Destination  string `json:"dst"`
	IPVersion    uint8  `json:"ipver"`
	ProtocolName string `json:"proto"`
	Source       string `json:"src"`

	// protocol
	DestinationPort uint16 `json:"dport,omitempty"`
	SourcePort      uint16 `json:"sport,omitempty"`
}

// indexEntry represents an entry in the index
type indexEntry struct {
	lineNum    int   // line number
	lineOffset int64 // byte offset
}

// Stream represents a streaming log parser
type Stream struct {
	errors  []string       // parsing errors
	file    *os.File       // file handle
	index   []indexEntry   // index of line positions
	lineNum int            // current line number
	path    string         // file path
	scanner *bufio.Scanner // file scanner
}

// parsing

// addError adds a parsing error to the errors slice
func (s *Stream) addError(msg string) {
	if len(s.errors) < MaxErrorsInMemory {
		s.errors = append(s.errors, msg)
	}
}

// convPort converts a port string to uint16
func convPort(portStr string) (uint16, error) {
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(port), nil
}

// splitCSV splits a csv string into fields
// this is similar to strings.Split but optimized for this use case (almost 2x faster)
func splitCSV(csv string) []string {
	fields := make([]string, 0, 30) // preallocate for worst case
	start := 0
	for i := 0; i < len(csv); i++ {
		if csv[i] == ',' {
			fields = append(fields, csv[start:i])
			start = i + 1 // +1 for comma
		}
	}
	fields = append(fields, csv[start:]) // add last field
	return fields
}

// parse parses a single line and returns a LogEntry
func (s *Stream) parse(line string, lineNum int) *LogEntry {
	var err error
	entry := LogEntry{}

	// extract the timestamp (between 1st and 2nd space)
	timeStart := strings.IndexByte(line, ' ') + 1 // +1 for 1st space
	timeEnd := strings.IndexByte(line[timeStart:], ' ')
	if timeStart <= 0 || timeEnd == -1 {
		s.addError(fmt.Sprintf("invalid timestamp on line %d", lineNum))
		return nil
	}
	timeEnd += timeStart // make relative index absolute
	entry.Time, err = time.Parse(time.RFC3339, line[timeStart:timeEnd])
	if err != nil {
		s.addError(fmt.Sprintf("invalid timestamp on line %d: %v", lineNum, err))
		return nil
	}

	// extract the csv string (after "] ") and split it into fields
	_, csv, ok := strings.Cut(line, "] ")
	if !ok {
		s.addError(fmt.Sprintf("invalid csv on line %d", lineNum))
		return nil
	}
	fields := splitCSV(csv)

	// 3: label, 4: interface, 5: reason, 6: action, 7: direction, 8: ipversion
	if len(fields) < 9 {
		s.addError(fmt.Sprintf("invalid packetfilter section on line %d", lineNum))
		return nil
	}

	entry.Interface = fields[4]

	switch fields[5] {
	case reasonMatch:
		entry.Reason = reasonMatch
	case reasonBadOffset:
		entry.Reason = reasonBadOffset
	case reasonBadTimestamp:
		entry.Reason = reasonBadTimestamp
	case reasonCongestion:
		entry.Reason = reasonCongestion
	case reasonFragment:
		entry.Reason = reasonFragment
	case reasonIpOption:
		entry.Reason = reasonIpOption
	case reasonMemory:
		entry.Reason = reasonMemory
	case reasonNormalize:
		entry.Reason = reasonNormalize
	case reasonProtoChecksum:
		entry.Reason = reasonProtoChecksum
	case reasonShort:
		entry.Reason = reasonShort
	case reasonSrcLimit:
		entry.Reason = reasonSrcLimit
	case reasonStateInsert:
		entry.Reason = reasonStateInsert
	case reasonStateLimit:
		entry.Reason = reasonStateLimit
	case reasonStateMismatch:
		entry.Reason = reasonStateMismatch
	case reasonSynproxy:
		entry.Reason = reasonSynproxy
	default:
		entry.Reason = fields[5]
	}

	switch fields[6] {
	case ActionPass:
		entry.Action = ActionPass
	case ActionBlock:
		entry.Action = ActionBlock
	case actionBinat:
		entry.Action = actionBinat
	case actionNat:
		entry.Action = actionNat
	case actionRdr:
		entry.Action = actionRdr
	case actionScrub:
		entry.Action = actionScrub
	case actionSynproxyDrop:
		entry.Action = actionSynproxyDrop
	default:
		entry.Action = fields[6]
	}

	switch fields[7] {
	case DirectionIn:
		entry.Direction = DirectionIn
	case DirectionOut:
		entry.Direction = DirectionOut
	case DirectionInOut:
		entry.Direction = DirectionInOut
	default:
		entry.Direction = fields[7]
	}

	switch fields[8] {
	case "4":
		entry.IPVersion = ipVersion4
	case "6":
		entry.IPVersion = ipVersion6
	default:
		s.addError(fmt.Sprintf("invalid ip version on line %d", lineNum))
		return nil
	}

	switch entry.IPVersion {
	// ipv4
	case ipVersion4:
		// 9:tos, 10:ecn, 11:ttl, 12:id, 13:offset, 14:flags, 15:protonum, 16:protoname, 17:length, 18:src, 19:dst
		if len(fields) < 20 {
			s.addError(fmt.Sprintf("invalid ipv4 section on line %d", lineNum))
			return nil
		}

		switch fields[16] {
		case protocolTCP:
			entry.ProtocolName = protocolTCP
		case protocolUDP:
			entry.ProtocolName = protocolUDP
		case protocolICMP:
			entry.ProtocolName = protocolICMP
		default:
			entry.ProtocolName = fields[16]
		}

		entry.Source = fields[18]
		entry.Destination = fields[19]

		switch entry.ProtocolName {
		// udp4
		case protocolUDP:
			// 20: srcport, 21: dstport, 22: datalen
			if len(fields) < 22 {
				s.addError(fmt.Sprintf("invalid udp4 section on line %d", lineNum))
				return nil
			}

			entry.SourcePort, err = convPort(fields[20])
			if err != nil {
				s.addError(fmt.Sprintf("invalid source port on line %d: %v", lineNum, err))
				return nil
			}

			entry.DestinationPort, err = convPort(fields[21])
			if err != nil {
				s.addError(fmt.Sprintf("invalid destination port on line %d: %v", lineNum, err))
				return nil
			}

		// tcp4
		case protocolTCP:
			// 20: srcport, 21: dstport, 22: datalen, 23: flags, 24: seq, 25: ack, 26: window, 27: urg, 28: options
			if len(fields) < 22 {
				s.addError(fmt.Sprintf("invalid tcp4 section on line %d", lineNum))
				return nil
			}

			entry.SourcePort, err = convPort(fields[20])
			if err != nil {
				s.addError(fmt.Sprintf("invalid source port on line %d: %v", lineNum, err))
				return nil
			}

			entry.DestinationPort, err = convPort(fields[21])
			if err != nil {
				s.addError(fmt.Sprintf("invalid destination port on line %d: %v", lineNum, err))
				return nil
			}

		// skip for any other protocol
		default:
		}

	// ipv6
	case ipVersion6:
		// 9:class, 10:flow, 11:hoplimit, 12:protoname, 13:protonum, 14:length, 15:src, 16:dst
		if len(fields) < 17 {
			s.addError(fmt.Sprintf("invalid ipv6 section on line %d", lineNum))
			return nil
		}

		switch fields[12] {
		case protocolTCP:
			entry.ProtocolName = protocolTCP
		case protocolUDP:
			entry.ProtocolName = protocolUDP
		case protocolICMPv6:
			entry.ProtocolName = protocolICMPv6
		default:
			entry.ProtocolName = fields[12]
		}

		entry.Source = fields[15]
		entry.Destination = fields[16]

		switch entry.ProtocolName {
		// udp6
		case protocolUDP:
			// 17: srcport, 18: dstport, 19: datalen
			if len(fields) < 19 {
				s.addError(fmt.Sprintf("invalid udp6 section on line %d", lineNum))
				return nil
			}

			entry.SourcePort, err = convPort(fields[17])
			if err != nil {
				s.addError(fmt.Sprintf("invalid source port on line %d: %v", lineNum, err))
				return nil
			}

			entry.DestinationPort, err = convPort(fields[18])
			if err != nil {
				s.addError(fmt.Sprintf("invalid destination port on line %d: %v", lineNum, err))
				return nil
			}

		// tcp6
		case protocolTCP:
			// 17: srcport, 18: dstport, 19: datalen, 20: flags, 21: seq, 22: ack, 23: window, 24: urg, 25: options
			if len(fields) < 19 {
				s.addError(fmt.Sprintf("invalid tcp6 section on line %d", lineNum))
				return nil
			}

			entry.SourcePort, err = convPort(fields[17])
			if err != nil {
				s.addError(fmt.Sprintf("invalid source port on line %d: %v", lineNum, err))
				return nil
			}

			entry.DestinationPort, err = convPort(fields[18])
			if err != nil {
				s.addError(fmt.Sprintf("invalid destination port on line %d: %v", lineNum, err))
				return nil
			}

		// skip for any other protocol
		default:
		}
	}

	return &entry
}

// stream

// reset repositions the stream to the start of the file
func (s *Stream) reset() error {
	if s.file != nil {
		s.file.Close()
	}
	file, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("error(stream): %w", err)
	}
	s.file = file
	s.scanner = bufio.NewScanner(file)
	s.lineNum = 0
	return nil
}

// public

// BuildIndex builds an index of line positions in the file
func (s *Stream) BuildIndex() error {
	if err := s.reset(); err != nil {
		return err
	}
	lineIndexed := 0
	lineNum := 0
	lineOffset := int64(0)
	s.index = make([]indexEntry, 0)
	// parse the file and add positions of valid entries to the index
	scanner := bufio.NewScanner(s.file)
	for scanner.Scan() {
		if entry := s.parse(scanner.Text(), lineNum); entry != nil {
			// it's valid, add to index
			s.index = append(s.index, indexEntry{
				lineNum:    lineIndexed,
				lineOffset: lineOffset,
			})
			lineIndexed++
		}
		lineOffset += int64(len(scanner.Bytes()) + 1) // +1 for newline
		lineNum++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error(stream): could not build index due to scanner error: %w", err)
	}
	return s.reset()
}

// Close closes the log file
func (s *Stream) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// GetPathAbs returns the absolute path of the log file
func (s Stream) GetPathAbs() (string, error) {
	return filepath.Abs(s.path)
}

// GetPathRel returns the relative path of the log file
func (s Stream) GetPathRel() string {
	return s.path
}

// GetErrors returns all parsing errors encountered during parsing
func (s Stream) GetErrors() []string {
	return s.errors
}

// NewStream creates a new streaming parser for the given log file
func NewStream(path string) (*Stream, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error(stream): %w", err)
	}
	return &Stream{
		errors:  make([]string, 0),
		file:    file,
		index:   nil,
		lineNum: 0,
		path:    path,
		scanner: bufio.NewScanner(file),
	}, nil
}

// Next reads and parses the next log entry (returns nil when EOF is reached)
func (s *Stream) Next() *LogEntry {
	for s.scanner.Scan() {
		s.lineNum++
		if entry := s.parse(s.scanner.Text(), s.lineNum); entry != nil {
			return entry
		}
		// if nil, continue to the next line
	}
	return nil
}

// SeekToLine seeks to a specific line number using the index
func (s *Stream) SeekToLine(lineNum int) error {
	if len(s.index) <= 0 {
		return fmt.Errorf("error(stream): could not seek: missing index")
	}
	if lineNum < 0 || lineNum >= len(s.index) {
		return fmt.Errorf("error(stream): could not seek: line %d out of range [0, %d)", lineNum, len(s.index))
	}
	if s.file != nil {
		s.file.Close()
	}
	file, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("error(stream): could not seek to line %d: %w", lineNum, err)
	}
	_, err = file.Seek(s.index[lineNum].lineOffset, 0)
	if err != nil {
		file.Close()
		return fmt.Errorf("error(stream): could not seek to line %d: %w", lineNum, err)
	}
	s.file = file
	s.scanner = bufio.NewScanner(file)
	s.lineNum = lineNum
	return nil
}

// TotalLines returns the total number of valid lines (if indexed)
func (s Stream) TotalLines() int {
	if i := len(s.index); i > 0 {
		return i
	}
	return -1
}
