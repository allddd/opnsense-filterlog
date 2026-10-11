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

package filter

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	stime "gitlab.com/allddd/go-systemd-time"
	"gitlab.com/allddd/opnsense-filterlog/internal/parse"
	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
)

const (
	tokenAnd tokenType = iota
	tokenEOF
	tokenField
	tokenNot
	tokenOr
	tokenParenL
	tokenParenR
	tokenSince
	tokenUntil
	tokenValue
)

const (
	fieldAction fieldType = iota
	fieldDestination
	fieldDestinationPort
	fieldDirection
	fieldHost
	fieldIPVersion
	fieldInterface
	fieldLabel
	fieldPort
	fieldProtocolName
	fieldProtocolNum
	fieldReason
	fieldSource
	fieldSourcePort
)

var (
	// tokens maps string representations of tokens to token types.
	tokens = map[string]tokenType{ //nolint:gochecknoglobals
		// and
		"and": tokenAnd,
		"&&":  tokenAnd,
		// not
		"not": tokenNot,
		"!":   tokenNot,
		// or
		"or": tokenOr,
		"||": tokenOr,
		// time
		"since": tokenSince,
		"until": tokenUntil,
	}

	// fields maps field names (and their aliases) to field types.
	fields = map[string]fieldType{ //nolint:gochecknoglobals
		// action
		"action": fieldAction,
		// destination
		"destination": fieldDestination,
		"dest":        fieldDestination,
		"dst":         fieldDestination,
		// destination port
		"dstport": fieldDestinationPort,
		"dport":   fieldDestinationPort,
		// direction
		"direction": fieldDirection,
		"dir":       fieldDirection,
		// host
		"host": fieldHost,
		// ip version
		"ipversion": fieldIPVersion,
		"ip":        fieldIPVersion,
		"ipver":     fieldIPVersion,
		// interface
		"interface": fieldInterface,
		"iface":     fieldInterface,
		// label
		"label": fieldLabel,
		// port
		"port": fieldPort,
		// protocol name
		"protocol": fieldProtocolName,
		"proto":    fieldProtocolName,
		// protocol number
		"protocolnum": fieldProtocolNum,
		"protonum":    fieldProtocolNum,
		// reason
		"reason": fieldReason,
		// source
		"source": fieldSource,
		"src":    fieldSource,
		// source port
		"srcport": fieldSourcePort,
		"sport":   fieldSourcePort,
	}
)

type tokenType int

// token represents a single token from the filter expression.
type token struct {
	typ   tokenType // type of token
	value string    // value of the token
}

// lexer tokenizes filter expression input into a stream of tokens.
type lexer struct {
	input string // input string being lexed
	pos   int    // current position in the input string
}

// parser parses filter expressions into a filter node tree.
type parser struct {
	lex     *lexer // provides tokens
	current token  // current token being parsed
}

type fieldType int

// Node is the interface that all filter nodes use to match log entries.
type Node interface {
	Matches(entry *stream.LogEntry) bool
}

// fieldValueParsed represents parsed field value of non-string fields.
type fieldValueParsed struct {
	prefix netip.Prefix
	u8     uint8
	u16    uint16
}

// fieldFilter matches a specific field against a value.
type fieldFilter struct {
	field  fieldType        // type of field
	value  string           // field value
	parsed fieldValueParsed // parsed (non-string) field values
}

// andFilter matches only if both child filters match.
type andFilter struct {
	left  Node // left side of the and expression
	right Node // right side of the and expression
}

// orFilter matches if either child filter matches.
type orFilter struct {
	left  Node // left side of the or expression
	right Node // right side of the or expression
}

// notFilter inverts the result of its child filter.
type notFilter struct {
	child Node // filter expression to invert
}

// sinceFilter matches entries after or at a specific time.
type sinceFilter struct {
	time time.Time // time to compare against
}

// untilFilter matches entries before or at a specific time.
type untilFilter struct {
	time time.Time // time to compare against
}

// lexer

// readWord reads a word token (letters, numbers, etc.) until space or parentheses.
func (l *lexer) readWord() string {
	start := l.pos
	for l.pos < len(l.input) {
		if ch := l.input[l.pos]; ch == ' ' || ch == '(' || ch == ')' {
			break
		}
		l.pos++
	}
	return l.input[start:l.pos]
}

// nextToken returns the next token.
func (l *lexer) nextToken() token {
	// skip space(s)
	for l.pos < len(l.input) && l.input[l.pos] == ' ' {
		l.pos++
	}
	// check for eof
	if l.pos >= len(l.input) {
		return token{typ: tokenEOF}
	}
	// check for parenthesis
	switch ch := l.input[l.pos : l.pos+1]; ch {
	case "(":
		l.pos++
		return token{typ: tokenParenL, value: ch}
	case ")":
		l.pos++
		return token{typ: tokenParenR, value: ch}
	}
	word := l.readWord()
	// check for eof again
	if word == "" {
		return token{typ: tokenEOF}
	}
	wordLower := strings.ToLower(word)
	// check for operators
	if typ, ok := tokens[wordLower]; ok {
		return token{typ: typ, value: wordLower}
	}
	// check for field names
	if _, ok := fields[wordLower]; ok {
		return token{typ: tokenField, value: wordLower}
	}
	// everything else is a value
	return token{typ: tokenValue, value: word}
}

// newLexer creates a new lexer for the given input string.
func newLexer(input string) *lexer {
	return &lexer{
		input: strings.TrimSpace(input),
		pos:   0,
	}
}

// parser

// newParser creates a new parser for the given input string.
func newParser(input string) *parser {
	lex := newLexer(input)
	return &parser{
		lex:     lex,
		current: lex.nextToken(), // pre-load the first token
	}
}

// advance moves to the next token.
func (p *parser) advance() {
	p.current = p.lex.nextToken()
}

// parse parses the entire filter expression and returns the root Node or nil if empty.
func (p *parser) parse() (Node, error) {
	if p.current.typ == tokenEOF {
		return nil, nil
	}
	return p.parseOr()
}

// parseOr handles or expressions (lowest precedence).
func (p *parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.current.typ == tokenOr {
		p.advance()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &orFilter{left: left, right: right}
	}
	return left, nil
}

// parseAnd handles and expressions (medium precedence).
func (p *parser) parseAnd() (Node, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.current.typ == tokenAnd {
		p.advance()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &andFilter{left: left, right: right}
	}
	return left, nil
}

// parseNot handles not expressions (highest precedence).
func (p *parser) parseNot() (Node, error) {
	if p.current.typ == tokenNot {
		p.advance()
		child, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return &notFilter{child: child}, nil
	}
	return p.parsePrimary()
}

// parsePrimary handles parentheses, time filters and field filters.
func (p *parser) parsePrimary() (Node, error) {
	// handle parentheses for grouping
	if p.current.typ == tokenParenL {
		p.advance()
		node, err := p.parseOr() // start from the bottom of precedence
		if err != nil {
			return nil, err
		}
		if p.current.typ != tokenParenR {
			return nil, fmt.Errorf("expected \")\" but got %q", p.current.value)
		}
		p.advance()
		return node, nil
	}
	// handle time
	if p.current.typ == tokenSince || p.current.typ == tokenUntil {
		keyword := p.current
		p.advance()
		if p.current.typ != tokenValue {
			return nil, fmt.Errorf("expected time value after %q but got %q", keyword.value, p.current.value)
		}
		timeParsed, err := stime.ParseTimestamp(p.current.value)
		if err != nil {
			return nil, fmt.Errorf("invalid time: %w", err)
		}
		p.advance()
		if keyword.typ == tokenSince {
			return &sinceFilter{time: timeParsed}, nil
		}
		return &untilFilter{time: timeParsed}, nil
	}
	// handle fields
	if p.current.typ == tokenField {
		field := p.current.value
		p.advance()

		if p.current.typ != tokenValue {
			return nil, fmt.Errorf("expected value after field %q but got %q", field, p.current.value)
		}
		value := p.current.value
		p.advance()

		f := &fieldFilter{field: fields[field], value: value}
		var err error
		switch f.field { //nolint:exhaustive
		case fieldDestination, fieldHost, fieldSource:
			if strings.Contains(value, "/") {
				f.parsed.prefix, err = netip.ParsePrefix(value)
			} else {
				var addr netip.Addr
				addr, err = netip.ParseAddr(value)
				f.parsed.prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
		case fieldDestinationPort, fieldPort, fieldSourcePort:
			f.parsed.u16, err = parse.Uint[uint16](value)
		case fieldIPVersion, fieldProtocolNum:
			f.parsed.u8, err = parse.Uint[uint8](value)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", field, err)
		}
		return f, nil
	}
	return nil, fmt.Errorf("unexpected token %q", p.current.value)
}

// filter nodes

// matchPointer returns true if p is not nil and points to a value equal to v.
func matchPointer[T comparable](p *T, v T) bool {
	return p != nil && *p == v
}

// Matches (fieldFilter) returns true if the log entry matches the field filter criteria.
func (f *fieldFilter) Matches(entry *stream.LogEntry) bool {
	switch f.field {
	case fieldAction:
		return entry.Action == f.value
	case fieldDestination:
		return f.parsed.prefix.Contains(entry.Destination)
	case fieldDestinationPort:
		return matchPointer(entry.DestinationPort, f.parsed.u16)
	case fieldDirection:
		return entry.Direction == f.value
	case fieldHost:
		return f.parsed.prefix.Contains(entry.Destination) || f.parsed.prefix.Contains(entry.Source)
	case fieldIPVersion:
		return entry.IPVersion == f.parsed.u8
	case fieldInterface:
		return entry.Interface == f.value
	case fieldLabel:
		return entry.Label == f.value
	case fieldPort:
		return matchPointer(entry.DestinationPort, f.parsed.u16) || matchPointer(entry.SourcePort, f.parsed.u16)
	case fieldProtocolName:
		return entry.ProtocolName == f.value
	case fieldProtocolNum:
		return entry.ProtocolNum == f.parsed.u8
	case fieldReason:
		return entry.Reason == f.value
	case fieldSource:
		return f.parsed.prefix.Contains(entry.Source)
	case fieldSourcePort:
		return matchPointer(entry.SourcePort, f.parsed.u16)
	}
	return false
}

// Matches (andFilter) returns true only if both left and right filters match.
func (f *andFilter) Matches(entry *stream.LogEntry) bool {
	return f.left.Matches(entry) && f.right.Matches(entry)
}

// Matches (orFilter) returns true if either left or right filter matches.
func (f *orFilter) Matches(entry *stream.LogEntry) bool {
	return f.left.Matches(entry) || f.right.Matches(entry)
}

// Matches (notFilter) returns the opposite of what the child filter returns.
func (f *notFilter) Matches(entry *stream.LogEntry) bool {
	return !f.child.Matches(entry)
}

// Matches (sinceFilter) returns true if the log entry time is after or equal to the filter time.
func (f *sinceFilter) Matches(entry *stream.LogEntry) bool {
	return entry.Time.Compare(f.time) >= 0
}

// Matches (untilFilter) returns true if the log entry time is before or equal to the filter time.
func (f *untilFilter) Matches(entry *stream.LogEntry) bool {
	return entry.Time.Compare(f.time) <= 0
}

// public

// Compile compiles a filter expression string into a Node tree.
func Compile(expression string) (Node, error) {
	node, err := newParser(expression).parse()
	if err != nil {
		return nil, fmt.Errorf("error(filter): %w", err)
	}
	return node, nil
}
