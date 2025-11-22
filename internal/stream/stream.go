package stream

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	MaxErrorsInMemory = 1000

	actionBinat        = "binat"
	ActionBlock        = "block"
	actionNat          = "nat"
	ActionPass         = "pass"
	actionRdr          = "rdr"
	actionScrub        = "scrub"
	actionSynproxyDrop = "synproxy-drop"

	directionIn    = "in"
	directionInOut = "in/out"
	directionOut   = "out"

	protoICMP   = "icmp"
	protoICMPv6 = "ipv6-icmp"
	protoTCP    = "tcp"
	protoUDP    = "udp"

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

type LogEntry struct {
	// common
	Action    string
	Direction string
	Interface string
	Label     string
	Reason    string
	Time      time.Time

	// ip
	Dst       string
	IPVersion uint8
	ProtoName string
	Src       string

	// protocol
	DstPort uint16
	SrcPort uint16
}

// fileOffset represents a line's position in a file
type fileOffset struct {
	line   int
	offset int64
}

// Stream represents a streaming log parser
type Stream struct {
	errors     []string // collection of parsing errors
	file       *os.File
	index      []fileOffset // index of line positions
	lineNum    int
	path       string
	scanner    *bufio.Scanner
	validLines int // number of valid lines/entries
}

// index

// reset repositions the stream to the start of the file
func (s *Stream) reset() error {
	if s.file != nil {
		s.file.Close()
	}

	file, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	s.file = file
	s.scanner = bufio.NewScanner(file)
	s.lineNum = 0
	return nil
}

// BuildIndex builds an index of line positions in the file
func (s *Stream) BuildIndex() error {
	if err := s.reset(); err != nil {
		return err
	}

	lineNum := 0
	offset := int64(0)
	s.index = make([]fileOffset, 0)
	validLines := 0

	// parse the file and record positions of valid entries
	scanner := bufio.NewScanner(s.file)
	for scanner.Scan() {
		line := scanner.Text()

		entry := s.parseLine(line, lineNum)
		if entry != nil {
			// it's valid, add to index
			s.index = append(s.index, fileOffset{
				line:   validLines,
				offset: offset,
			})
			validLines++
		}

		offset += int64(len(scanner.Bytes()) + 1) // +1 for newline
		lineNum++
	}

	s.validLines = validLines

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error: could not build index due to scanner error: %w", err)
	}

	return s.reset()
}

// hasIndex returns true if index exists
func (s *Stream) hasIndex() bool {
	return len(s.index) > 0
}

// TotalLines returns the total number of valid lines (if indexed), -1 otherwise
func (s *Stream) TotalLines() int {
	if !s.hasIndex() {
		return -1
	}
	return s.validLines
}

// parsing

// addError adds a parsing error to the collection
func (s *Stream) addError(msg string) {
	if len(s.errors) < MaxErrorsInMemory {
		s.errors = append(s.errors, msg)
	}
}

// extractCSVField extracts a cvs field and returns a copy & true if succesful
func extractCSVField(csv string, field int) (string, bool) {
	start := 0

	// check if the field exists and get its start index
	for range field {
		idx := strings.IndexByte(csv[start:], ',')
		if idx == -1 {
			// field does not exist
			return "", false
		}
		start += idx + 1 // +1 for comma
	}

	// find end of field
	end := strings.IndexByte(csv[start:], ',')
	if end == -1 {
		// last field
		return strings.Clone(csv[start:]), true
	}
	return strings.Clone(csv[start : start+end]), true
}

// parseLine parses a single line and returns a LogEntry if seccesful, nil otherwise
func (s *Stream) parseLine(line string, lineNum int) *LogEntry {
	// extract the timestamp (between 1st and 2nd space)
	tsStartIdx := strings.IndexByte(line, ' ')
	tsEndIdx := strings.IndexByte(line[tsStartIdx+1:], ' ')
	if tsStartIdx == -1 || tsEndIdx == -1 {
		s.addError(fmt.Sprintf("invalid timestamp on line %d", lineNum))
		return nil
	}
	tsEndIdx += tsStartIdx + 1
	timestamp, err := time.Parse(time.RFC3339, line[tsStartIdx+1:tsEndIdx])
	if err != nil {
		s.addError(fmt.Sprintf("invalid timestamp on line %d: %v", lineNum, err))
		return nil
	}

	// extract the CSV data (after "] ")
	csvStart := strings.Index(line, "] ")
	if csvStart == -1 {
		s.addError(fmt.Sprintf("invalid csv on line %d", lineNum))
		return nil
	}
	csv := line[csvStart+2:]

	// extract CSV fields
	// 3: label, 4: interface, 5: reason, 6: action, 7: direction, 8: ipversion
	label, ok := extractCSVField(csv, 3)
	if !ok {
		s.addError(fmt.Sprintf("invalid label on line %d", lineNum))
		return nil
	}

	iface, ok := extractCSVField(csv, 4)
	if !ok {
		s.addError(fmt.Sprintf("invalid iface on line %d", lineNum))
		return nil
	}

	reason, ok := extractCSVField(csv, 5)
	if !ok {
		s.addError(fmt.Sprintf("invalid reason on line %d", lineNum))
		return nil
	}

	action, ok := extractCSVField(csv, 6)
	if !ok {
		s.addError(fmt.Sprintf("invalid action on line %d", lineNum))
		return nil
	}

	direction, ok := extractCSVField(csv, 7)
	if !ok {
		s.addError(fmt.Sprintf("invalid direction on line %d", lineNum))
		return nil
	}

	ipVersionStr, ok := extractCSVField(csv, 8)
	if !ok {
		s.addError(fmt.Sprintf("invalid ipVersionStr on line %d", lineNum))
		return nil
	}
	ipVersion, err := strconv.ParseUint(ipVersionStr, 10, 8)
	if err != nil {
		s.addError(fmt.Sprintf("invalid ipVersion on line %d", lineNum))
		return nil
	}

	entry := LogEntry{
		Time:      timestamp,
		Label:     label,
		Interface: iface,
		IPVersion: uint8(ipVersion),
	}

	switch reason {
	case "match":
		entry.Reason = reasonMatch
	case "bad-offset":
		entry.Reason = reasonBadOffset
	case "fragment":
		entry.Reason = reasonFragment
	case "short":
		entry.Reason = reasonShort
	case "normalize":
		entry.Reason = reasonNormalize
	case "memory":
		entry.Reason = reasonMemory
	case "bad-timestamp":
		entry.Reason = reasonBadTimestamp
	case "congestion":
		entry.Reason = reasonCongestion
	case "ip-option":
		entry.Reason = reasonIpOption
	case "proto-cksum":
		entry.Reason = reasonProtoChecksum
	case "state-mismatch":
		entry.Reason = reasonStateMismatch
	case "state-insert":
		entry.Reason = reasonStateInsert
	case "state-limit":
		entry.Reason = reasonStateLimit
	case "src-limit":
		entry.Reason = reasonSrcLimit
	case "synproxy":
		entry.Reason = reasonSynproxy
	default:
		entry.Reason = reason
	}

	switch action {
	case "pass":
		entry.Action = ActionPass
	case "block":
		entry.Action = ActionBlock
	case "scrub":
		entry.Action = actionScrub
	case "nat":
		entry.Action = actionNat
	case "binat":
		entry.Action = actionBinat
	case "rdr":
		entry.Action = actionRdr
	case "synproxy-drop":
		entry.Action = actionSynproxyDrop
	default:
		entry.Action = action
	}

	switch direction {
	case "in":
		entry.Direction = directionIn
	case "out":
		entry.Direction = directionOut
	case "in/out":
		entry.Direction = directionInOut
	default:
		entry.Direction = direction
	}

	switch entry.IPVersion {
	// ipv4
	case 4:
		// 9:tos, 10:ecn, 11:ttl, 12:id, 13:offset, 14:flags, 15:protonum, 16:protoname, 17:length, 18:src, 19:dst
		protoName, ok := extractCSVField(csv, 16)
		if !ok {
			s.addError(fmt.Sprintf("invalid v4/protoName on line %d", lineNum))
			return nil
		}

		src, ok := extractCSVField(csv, 18)
		if !ok {
			s.addError(fmt.Sprintf("invalid v4/src on line %d", lineNum))
			return nil
		}
		entry.Src = src

		dst, ok := extractCSVField(csv, 19)
		if !ok {
			s.addError(fmt.Sprintf("invalid v4/dst on line %d", lineNum))
			return nil
		}
		entry.Dst = dst

		switch protoName {
		case "tcp":
			entry.ProtoName = protoTCP
		case "udp":
			entry.ProtoName = protoUDP
		case "icmp":
			entry.ProtoName = protoICMP
		default:
			entry.ProtoName = protoName
		}

		switch entry.ProtoName {
		// udp4
		case protoUDP:
			// 20: srcport, 21: dstport, 22: datalen
			srcPortStr, ok := extractCSVField(csv, 20)
			if !ok {
				s.addError(fmt.Sprintf("invalid udp4/srcPortStr on line %d", lineNum))
				return nil
			}
			srcPort, err := strconv.ParseUint(srcPortStr, 10, 16)
			if err != nil {
				s.addError(fmt.Sprintf("invalid udp4/srcPort on line %d", lineNum))
				return nil
			}

			dstPortStr, ok := extractCSVField(csv, 21)
			if !ok {
				s.addError(fmt.Sprintf("invalid udp4/dstPortStr on line %d", lineNum))
				return nil
			}
			dstPort, err := strconv.ParseUint(dstPortStr, 10, 16)
			if err != nil {
				s.addError(fmt.Sprintf("invalid udp4/dstPort on line %d", lineNum))
				return nil
			}

			entry.SrcPort = uint16(srcPort)
			entry.DstPort = uint16(dstPort)

		// tcp4
		case protoTCP:
			// 20: srcport, 21: dstport, 22: datalen, 23: flags, 24: seq, 25: ack, 26: window, 27: urg, 28: options
			srcPortStr, ok := extractCSVField(csv, 20)
			if !ok {
				s.addError(fmt.Sprintf("invalid tcp4/srcPortStr on line %d", lineNum))
				return nil
			}
			srcPort, err := strconv.ParseUint(srcPortStr, 10, 16)
			if err != nil {
				s.addError(fmt.Sprintf("invalid tcp4/srcPort on line %d", lineNum))
				return nil
			}

			dstPortStr, ok := extractCSVField(csv, 21)
			if !ok {
				s.addError(fmt.Sprintf("invalid tcp4/dstPortStr on line %d", lineNum))
				return nil
			}
			dstPort, err := strconv.ParseUint(dstPortStr, 10, 16)
			if err != nil {
				s.addError(fmt.Sprintf("invalid tcp4/dstPort on line %d", lineNum))
				return nil
			}

			entry.SrcPort = uint16(srcPort)
			entry.DstPort = uint16(dstPort)

		// skip for any other protocol
		default:
		}

	// ipv6
	case 6:
		// 9:class, 10:flow, 11:hoplimit, 12:protoname, 13:protonum, 14:length, 15:src, 16:dst
		protoName, ok := extractCSVField(csv, 12)
		if !ok {
			s.addError(fmt.Sprintf("invalid v6/protoName on line %d", lineNum))
			return nil
		}

		src, ok := extractCSVField(csv, 15)
		if !ok {
			s.addError(fmt.Sprintf("invalid v6/src on line %d", lineNum))
			return nil
		}
		entry.Src = src

		dst, ok := extractCSVField(csv, 16)
		if !ok {
			s.addError(fmt.Sprintf("invalid v6/dst on line %d", lineNum))
			return nil
		}
		entry.Dst = dst

		switch protoName {
		case "tcp":
			entry.ProtoName = protoTCP
		case "udp":
			entry.ProtoName = protoUDP
		case "ipv6-icmp":
			entry.ProtoName = protoICMPv6
		default:
			entry.ProtoName = protoName
		}

		switch entry.ProtoName {

		// udp6
		case protoUDP:
			// 17: srcport, 18: dstport, 19: datalen
			srcPortStr, ok := extractCSVField(csv, 17)
			if !ok {
				s.addError(fmt.Sprintf("invalid udp6/srcPortStr on line %d", lineNum))
				return nil
			}
			srcPort, err := strconv.ParseUint(srcPortStr, 10, 16)
			if err != nil {
				s.addError(fmt.Sprintf("invalid udp6/srcPort on line %d", lineNum))
				return nil
			}

			dstPortStr, ok := extractCSVField(csv, 18)
			if !ok {
				s.addError(fmt.Sprintf("invalid udp6/dstPortStr on line %d", lineNum))
				return nil
			}
			dstPort, err := strconv.ParseUint(dstPortStr, 10, 16)
			if err != nil {
				s.addError(fmt.Sprintf("invalid udp6/dstPort on line %d", lineNum))
				return nil
			}

			entry.SrcPort = uint16(srcPort)
			entry.DstPort = uint16(dstPort)

		// tcp6
		case protoTCP:
			// 17: srcport, 18: dstport, 19: datalen, 20: flags, 21: seq, 22: ack, 23: window, 24: urg, 25: options
			srcPortStr, ok := extractCSVField(csv, 17)
			if !ok {
				s.addError(fmt.Sprintf("invalid tcp6/srcPortStr on line %d", lineNum))
				return nil
			}
			srcPort, err := strconv.ParseUint(srcPortStr, 10, 16)
			if err != nil {
				s.addError(fmt.Sprintf("invalid tcp6/srcPort on line %d", lineNum))
				return nil
			}

			dstPortStr, ok := extractCSVField(csv, 18)
			if !ok {
				s.addError(fmt.Sprintf("invalid tcp6/dstPortStr on line %d", lineNum))
				return nil
			}
			dstPort, err := strconv.ParseUint(dstPortStr, 10, 16)
			if err != nil {
				s.addError(fmt.Sprintf("invalid tcp6/dstPort on line %d", lineNum))
				return nil
			}

			entry.SrcPort = uint16(srcPort)
			entry.DstPort = uint16(dstPort)

		// skip for any other protocol
		default:
		}

	default:
		s.addError(fmt.Sprintf("invalid IPVersion '%d' on line %d", entry.IPVersion, lineNum))
		return nil
	}

	return &entry
}

// public

// GetErrors returns all parsing errors
func (s *Stream) GetErrors() []string {
	return s.errors
}

// Close closes the log file
func (s *Stream) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// NewStream creates a new streaming parser for the given log file
func NewStream(path string) (*Stream, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	return &Stream{
		errors:     make([]string, 0),
		file:       file,
		index:      nil,
		lineNum:    0,
		path:       path,
		scanner:    bufio.NewScanner(file),
		validLines: 0,
	}, nil
}

// Next reads and parses the next log entry, returns nil when EOF is reached
func (s *Stream) Next() *LogEntry {
	for s.scanner.Scan() {
		s.lineNum++
		line := s.scanner.Text()

		entry := s.parseLine(line, s.lineNum)
		if entry != nil {
			return entry
		}
		// if nil, continue to the next line
	}

	return nil
}

// SeekToLine seeks to a specific line number using the index
func (s *Stream) SeekToLine(lineNum int) error {
	if !s.hasIndex() {
		return fmt.Errorf("error: missing index")
	}

	if lineNum < 0 || lineNum >= len(s.index) {
		return fmt.Errorf("error: line %d out of range [0, %d)", lineNum, len(s.index))
	}

	if s.file != nil {
		s.file.Close()
	}
	file, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("error: could not seek to line %d: %w", lineNum, err)
	}

	_, err = file.Seek(s.index[lineNum].offset, 0)
	if err != nil {
		file.Close()
		return fmt.Errorf("error: could not seek to line %d: %w", lineNum, err)
	}

	s.file = file
	s.scanner = bufio.NewScanner(file)
	s.lineNum = lineNum
	return nil
}
