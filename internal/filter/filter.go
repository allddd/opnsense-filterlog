package filter

import (
	"fmt"
	"strings"

	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
)

type tokenType int

const (
	tokenField  tokenType = iota // field name like src, dst, action, etc.
	tokenValue                   // a value to match against
	tokenAnd                     // AND operator (and, &&)
	tokenOr                      // OR operator (or, ||)
	tokenNot                     // NOT operator (not, !)
	tokenLParen                  // left parenthesis
	tokenRParen                  // right parenthesis
	tokenEOF                     // end of input
)

// token represents a single token from the filter expression
type token struct {
	typ   tokenType // what kind of token this is
	value string    // the actual text value of the token
}

type lexer struct {
	input string // the full input string being lexed
	pos   int    // current position in the input string
}

// parser parses filter expressions into a FilterNode tree
type parser struct {
	lex     *lexer // lexer that provides tokens
	current token  // current token being examined
}

// FilterNode is the interface that all filter nodes implement to match log entries
type FilterNode interface {
	Matches(entry *stream.LogEntry) bool
}

// fieldFilter matches a specific field against a value
type fieldFilter struct {
	field string // field name (src, dst, action, etc.)
	value string // value to match against
}

// anyFilter matches any field containing the value (for simple searches)
type anyFilter struct {
	value string // value to search for in any field
}

// andFilter matches only if both child filters match
type andFilter struct {
	left  FilterNode // left side of the AND expression
	right FilterNode // right side of the AND expression
}

// orFilter matches if either child filter matches
type orFilter struct {
	left  FilterNode // left side of the OR expression
	right FilterNode // right side of the OR expression
}

// notFilter inverts the result of its child filter
type notFilter struct {
	child FilterNode // filter expression to invert
}

// lexer
// lexer tokenizes a filter expression string into a sequence of tokens, e.g.:
// src 10.0.0.1 and proto tcp -> [token{field, "src"}, token{value, "10.0.0.1"}, token{and, "and"}, ...]

// newLexer creates a new lexer for the given input string
func newLexer(input string) *lexer {
	return &lexer{
		input: strings.TrimSpace(input),
		pos:   0,
	}
}

// peek returns the current character without advancing the position or 0 if we're at the end of input
func (l *lexer) peek() byte {
	if l.pos >= len(l.input) {
		return 0
	}
	return l.input[l.pos]
}

// advance advances to the next position
func (l *lexer) advance() {
	if l.pos < len(l.input) {
		l.pos++
	}
}

// skipSpace advances past space characters
func (l *lexer) skipSpace() {
	for l.pos < len(l.input) && l.input[l.pos] == ' ' {
		l.pos++
	}
}

// readWord reads a word token (letters, numbers, etc.) until space or parentheses
func (l *lexer) readWord() string {
	start := l.pos
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if ch == ' ' || ch == '(' || ch == ')' {
			break
		}
		l.pos++
	}
	return l.input[start:l.pos]
}

// nextToken returns the next token from the input stream
func (l *lexer) nextToken() token {
	l.skipSpace()

	// check for end of input
	if l.pos >= len(l.input) {
		return token{typ: tokenEOF}
	}

	ch := l.peek()

	if ch == '(' {
		l.advance()
		return token{typ: tokenLParen, value: "("}
	}
	if ch == ')' {
		l.advance()
		return token{typ: tokenRParen, value: ")"}
	}

	// read a word and determine what it is
	word := l.readWord()

	if word == "" {
		return token{typ: tokenEOF}
	}

	switch wordLower := strings.ToLower(word); wordLower {
	case "and", "&&":
		return token{typ: tokenAnd, value: word}
	case "or", "||":
		return token{typ: tokenOr, value: word}
	case "not", "!":
		return token{typ: tokenNot, value: word}
	case "action",
		"dir", "direction",
		"dst", "dest", "destination",
		"iface", "interface",
		"ip", "ipver", "ipversion",
		"port",
		"sport", "srcport",
		"dport", "dstport",
		"proto", "protocol",
		"reason",
		"src", "source":
		return token{typ: tokenField, value: wordLower}
	}

	// everything else is a value
	return token{typ: tokenValue, value: word}
}

// filter nodes

// Matches (fieldFilter) returns true if the log entry matches the field filter criteria
func (f *fieldFilter) Matches(entry *stream.LogEntry) bool {
	valueLower := strings.ToLower(f.value)

	switch f.field {
	case "action":
		return strings.HasPrefix(strings.ToLower(entry.Action), valueLower)
	case "dir", "direction":
		return strings.HasPrefix(strings.ToLower(entry.Direction), valueLower)
	case "dst", "dest", "destination":
		return strings.HasPrefix(strings.ToLower(entry.Dst), valueLower)
	case "iface", "interface":
		return strings.HasPrefix(strings.ToLower(entry.Interface), valueLower)
	case "ip", "ipver", "ipversion":
		return fmt.Sprintf("%d", entry.IPVersion) == f.value
	case "port":
		// match either source or destination port
		portStr := f.value
		if entry.SrcPort > 0 && fmt.Sprintf("%d", entry.SrcPort) == portStr {
			return true
		}
		if entry.DstPort > 0 && fmt.Sprintf("%d", entry.DstPort) == portStr {
			return true
		}
		return false
	case "sport", "srcport":
		return entry.SrcPort > 0 && fmt.Sprintf("%d", entry.SrcPort) == f.value
	case "dport", "dstport":
		return entry.DstPort > 0 && fmt.Sprintf("%d", entry.DstPort) == f.value
	case "proto", "protocol":
		return strings.HasPrefix(strings.ToLower(entry.ProtoName), valueLower)
	case "reason":
		return strings.HasPrefix(strings.ToLower(entry.Reason), valueLower)
	case "src", "source":
		return strings.HasPrefix(strings.ToLower(entry.Src), valueLower)
	}

	return false
}

// Matches (anyFilter) returns true if any field in the log entry contains the filter value
func (f *anyFilter) Matches(entry *stream.LogEntry) bool {
	valueLower := strings.ToLower(f.value)
	return strings.Contains(strings.ToLower(entry.Action), valueLower) ||
		strings.Contains(strings.ToLower(entry.Src), valueLower) ||
		strings.Contains(strings.ToLower(entry.Dst), valueLower) ||
		strings.Contains(strings.ToLower(entry.Interface), valueLower) ||
		strings.Contains(strings.ToLower(entry.ProtoName), valueLower) ||
		strings.Contains(strings.ToLower(entry.Reason), valueLower) ||
		strings.Contains(strings.ToLower(entry.Direction), valueLower)
}

// Matches (andFilter) returns true only if both left and right filters match
func (f *andFilter) Matches(entry *stream.LogEntry) bool {
	return f.left.Matches(entry) && f.right.Matches(entry)
}

// Matches (orFilter) returns true if either left or right filter matches
func (f *orFilter) Matches(entry *stream.LogEntry) bool {
	return f.left.Matches(entry) || f.right.Matches(entry)
}

// Matches (notFilter) returns the opposite of what the child filter returns
func (f *notFilter) Matches(entry *stream.LogEntry) bool {
	return !f.child.Matches(entry)
}

// parser
// parser takes tokens from the lexer and builds a tree of FilterNodes

// newParser creates a new parser for the given input string
func newParser(input string) *parser {
	lex := newLexer(input)
	return &parser{
		lex:     lex,
		current: lex.nextToken(), // pre-load the first token
	}
}

// advance moves to the next token
func (p *parser) advance() {
	p.current = p.lex.nextToken()
}

// parse parses the entire filter expression and returns the root FilterNode or nil if empty
func (p *parser) parse() (FilterNode, error) {
	if p.current.typ == tokenEOF {
		return nil, nil
	}
	return p.parseOr()
}

// parseOr handles OR expressions (lowest precedence)
func (p *parser) parseOr() (FilterNode, error) {
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

// parseAnd handles AND expressions (medium precedence)
func (p *parser) parseAnd() (FilterNode, error) {
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

// parseNot handles NOT expressions (highest precedence)
func (p *parser) parseNot() (FilterNode, error) {
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

// parsePrimary handles parenthesized expressions, field filters, and bare values
func (p *parser) parsePrimary() (FilterNode, error) {
	// handle parentheses for grouping
	if p.current.typ == tokenLParen {
		p.advance()
		node, err := p.parseOr() // start from the bottom of precedence
		if err != nil {
			return nil, err
		}
		if p.current.typ != tokenRParen {
			return nil, fmt.Errorf("error: expected ')' but got %v", p.current)
		}
		p.advance()
		return node, nil
	}

	// handle field-specific filters, e.g.: src 192.168.1.1
	if p.current.typ == tokenField {
		field := p.current.value
		p.advance()

		if p.current.typ != tokenValue {
			return nil, fmt.Errorf("error: expected value after field '%s' but got %v", field, p.current)
		}

		value := p.current.value
		p.advance()

		return &fieldFilter{field: field, value: value}, nil
	}

	// handle bare values (search in any field)
	if p.current.typ == tokenValue {
		value := p.current.value
		p.advance()
		return &anyFilter{value: value}, nil
	}

	return nil, fmt.Errorf("error: unexpected token: %v", p.current)
}

// public

// Compile compiles a filter expression string into a FilterNode tree
func Compile(expression string) (FilterNode, error) {
	if expression == "" {
		return nil, nil
	}
	parser := newParser(expression)
	return parser.parse()
}
