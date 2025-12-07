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
	directionIn    = "in"
	directionInOut = "in/out"
	directionOut   = "out"

	// ip
	ipVersion4 = 4
	ipVersion6 = 6

	// protocols
	protoICMP   = "icmp"
	protoICMPv6 = "ipv6-icmp"
	protoTCP    = "tcp"
	protoUDP    = "udp"

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
	Action    string    // action taken
	Direction string    // traffic direction
	Interface string    // network interface
	Reason    string    // reason for action
	Time      time.Time // timestamp

	// ip
	Dst       string // destination ip address
	IPVersion uint8  // ip protocol version
	ProtoName string // protocol name
	Src       string // source ip address

	// protocol
	DstPort uint16 // destination port
	SrcPort uint16 // source port
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

// extractCSVField extracts a csv field and returns a copy
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

// parse parses a single line and returns a LogEntry
func (s *Stream) parse(line string, lineNum int) *LogEntry {
	// extract the timestamp (between 1st and 2nd space)
	timestampStart := strings.IndexByte(line, ' ') + 1 // +1 for 1st space
	timestampEnd := strings.IndexByte(line[timestampStart:], ' ')
	if timestampStart <= 0 || timestampEnd == -1 {
		s.addError(fmt.Sprintf("invalid timestamp on line %d", lineNum))
		return nil
	}
	timestampEnd += timestampStart // make relative index absolute
	timestamp, err := time.Parse(time.RFC3339, line[timestampStart:timestampEnd])
	if err != nil {
		s.addError(fmt.Sprintf("invalid timestamp on line %d: %v", lineNum, err))
		// TODO: maybe we should just show a random timestamp instead of failing?
		return nil
	}

	// extract the csv data (after "] ")
	csvStart := strings.Index(line, "] ")
	if csvStart == -1 {
		s.addError(fmt.Sprintf("invalid csv on line %d", lineNum))
		return nil
	}
	csv := line[csvStart+2:] // +2 for "] "

	// extract CSV fields
	// 3: label, 4: interface, 5: reason, 6: action, 7: direction, 8: ipversion
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

	ipVersion, ok := extractCSVField(csv, 8)
	if !ok {
		s.addError(fmt.Sprintf("invalid ipVersion on line %d", lineNum))
		return nil
	}

	entry := LogEntry{
		Time:      timestamp,
		Interface: iface,
	}

	switch reason {
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
		entry.Reason = reason
	}

	switch action {
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
		entry.Action = action
	}

	switch direction {
	case directionIn:
		entry.Direction = directionIn
	case directionOut:
		entry.Direction = directionOut
	case directionInOut:
		entry.Direction = directionInOut
	default:
		entry.Direction = direction
	}

	switch ipVersion {
	case "4":
		entry.IPVersion = ipVersion4
	case "6":
		entry.IPVersion = ipVersion6
	default:
		ipVersion, err := strconv.ParseUint(ipVersion, 10, 8)
		if err != nil {
			s.addError(fmt.Sprintf("invalid ipVersion on line %d", lineNum))
			return nil
		}
		entry.IPVersion = uint8(ipVersion)
	}

	switch entry.IPVersion {
	// ipv4
	case ipVersion4:
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
		case protoTCP:
			entry.ProtoName = protoTCP
		case protoUDP:
			entry.ProtoName = protoUDP
		case protoICMP:
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
	case ipVersion6:
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
		case protoTCP:
			entry.ProtoName = protoTCP
		case protoUDP:
			entry.ProtoName = protoUDP
		case protoICMPv6:
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
		s.addError(fmt.Sprintf("invalid ipVersion '%d' on line %d", entry.IPVersion, lineNum))
		return nil
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
		return fmt.Errorf("error: %w", err)
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
		return fmt.Errorf("error: could not build index due to scanner error: %w", err)
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
		return nil, fmt.Errorf("error: %w", err)
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
		return fmt.Errorf("error: could not seek: missing index")
	}
	if lineNum < 0 || lineNum >= len(s.index) {
		return fmt.Errorf("error: could not seek: line %d out of range [0, %d)", lineNum, len(s.index))
	}
	if s.file != nil {
		s.file.Close()
	}
	file, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("error: could not seek to line %d: %w", lineNum, err)
	}
	_, err = file.Seek(s.index[lineNum].lineOffset, 0)
	if err != nil {
		file.Close()
		return fmt.Errorf("error: could not seek to line %d: %w", lineNum, err)
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
