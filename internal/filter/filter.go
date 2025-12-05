package filter

import (
	"fmt"
	"strings"

	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
)

const (
	tokenAnd    tokenTyp = iota // and operator
	tokenEOF                    // eof
	tokenField                  // field name
	tokenNot                    // not operator
	tokenOr                     // or operator
	tokenParenL                 // left parenthesis
	tokenParenR                 // right parenthesis
	tokenValue                  // value
)

const (
	fieldAction      fieldTyp = iota // action taken
	fieldDestination                 // destination ip address
	fieldDirection                   // traffic direction
	fieldDstPort                     // destination port
	fieldIPVersion                   // ip version
	fieldInterface                   // network interface
	fieldPort                        // source or destination port
	fieldProtocol                    // protocol
	fieldReason                      // reason for action
	fieldSource                      // source IP address
	fieldSrcPort                     // source port
)

var (
	// tokens maps string representations of tokens to token types
	tokens = map[string]tokenTyp{
		// and
		"and": tokenAnd,
		"&&":  tokenAnd,
		// not
		"not": tokenNot,
		"!":   tokenNot,
		// or
		"or": tokenOr,
		"||": tokenOr,
	}

	// fields maps field names (and their aliases) to field types
	fields = map[string]fieldTyp{
		// action
		"action": fieldAction,
		// direction
		"direction": fieldDirection,
		"dir":       fieldDirection,
		// destination
		"destination": fieldDestination,
		"dest":        fieldDestination,
		"dst":         fieldDestination,
		// destination port
		"dstport": fieldDstPort,
		"dport":   fieldDstPort,
		// ip version
		"ipversion": fieldIPVersion,
		"ip":        fieldIPVersion,
		"ipver":     fieldIPVersion,
		// interface
		"interface": fieldInterface,
		"iface":     fieldInterface,
		// port
		"port": fieldPort,
		// protocol
		"protocol": fieldProtocol,
		"proto":    fieldProtocol,
		// reason
		"reason": fieldReason,
		// source
		"source": fieldSource,
		"src":    fieldSource,
		// source port
		"srcport": fieldSrcPort,
		"sport":   fieldSrcPort,
	}
)

type tokenTyp int

// token represents a single token from the filter expression
type token struct {
	typ   tokenTyp // type of token
	value string   // value of the token
}

// lexer tokenizes filter expression input into a stream of tokens
type lexer struct {
	input string // input string being lexed
	pos   int    // current position in the input string
}

// parser parses filter expressions into a filter node tree
type parser struct {
	lex     *lexer // provides tokens
	current token  // current token being parsed
}

type fieldTyp int

// FilterNode is the interface that all filter nodes use to match log entries
type FilterNode interface {
	Matches(entry *stream.LogEntry) bool
}

// anyFilter matches any field containing the value
type anyFilter struct {
	value string // value to search for in any field
}

// fieldFilter matches a specific field against a value
type fieldFilter struct {
	field fieldTyp // type of field
	value string   // value to match against
}

// andFilter matches only if both child filters match
type andFilter struct {
	left  FilterNode // left side of the and expression
	right FilterNode // right side of the and expression
}

// orFilter matches if either child filter matches
type orFilter struct {
	left  FilterNode // left side of the or expression
	right FilterNode // right side of the or expression
}

// notFilter inverts the result of its child filter
type notFilter struct {
	child FilterNode // filter expression to invert
}

// lexer

// readWord reads a word token (letters, numbers, etc.) until space or parentheses
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

// nextToken returns the next token
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

// newLexer creates a new lexer for the given input string
func newLexer(input string) *lexer {
	return &lexer{
		input: strings.TrimSpace(input),
		pos:   0,
	}
}

// parser

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

// parseOr handles or expressions (lowest precedence)
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

// parseAnd handles and expressions (medium precedence)
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

// parseNot handles not expressions (highest precedence)
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

// parsePrimary handles parentheses, field filters and bare values
func (p *parser) parsePrimary() (FilterNode, error) {
	// handle parentheses for grouping
	if p.current.typ == tokenParenL {
		p.advance()
		node, err := p.parseOr() // start from the bottom of precedence
		if err != nil {
			return nil, err
		}
		if p.current.typ != tokenParenR {
			return nil, fmt.Errorf("error(filter): expected \")\" but got %q", p.current.value)
		}
		p.advance()
		return node, nil
	}
	// handle fields
	if p.current.typ == tokenField {
		field := p.current.value
		p.advance()

		if p.current.typ != tokenValue {
			return nil, fmt.Errorf("error(filter): expected value after field %q but got %q", field, p.current.value)
		}
		value := p.current.value
		p.advance()

		return &fieldFilter{field: fields[field], value: value}, nil
	}
	// handle bare values
	if p.current.typ == tokenValue {
		value := p.current.value
		p.advance()
		return &anyFilter{value: value}, nil
	}
	// TODO: make this err msg more helpful
	return nil, fmt.Errorf("error(filter): unexpected token %q", p.current.value)
}

// filter nodes

// Matches (anyFilter) returns true if any field in the log entry contains the filter value
func (f *anyFilter) Matches(entry *stream.LogEntry) bool {
	value := strings.ToLower(f.value)
	searchFields := []string{
		entry.Action,
		entry.Direction,
		entry.Interface,
		entry.Reason,
		entry.Time,
		entry.Dst,
		entry.ProtoName,
		entry.Src,
	}
	for _, field := range searchFields {
		if strings.Contains(strings.ToLower(field), value) {
			return true
		}
	}
	return false
}

// Matches (fieldFilter) returns true if the log entry matches the field filter criteria
func (f *fieldFilter) Matches(entry *stream.LogEntry) bool {
	value := strings.ToLower(f.value)
	matchInt := func(i any) bool {
		return fmt.Sprintf("%d", i) == f.value
	}
	matchStr := func(s string) bool {
		return strings.HasPrefix(strings.ToLower(s), value)
	}
	switch f.field {
	case fieldAction:
		return matchStr(entry.Action)
	case fieldDestination:
		return matchStr(entry.Dst)
	case fieldDirection:
		return matchStr(entry.Direction)
	case fieldDstPort:
		return matchInt(entry.DstPort)
	case fieldIPVersion:
		return matchInt(entry.IPVersion)
	case fieldInterface:
		return matchStr(entry.Interface)
	case fieldPort:
		return matchInt(entry.SrcPort) || matchInt(entry.DstPort)
	case fieldProtocol:
		return matchStr(entry.ProtoName)
	case fieldReason:
		return matchStr(entry.Reason)
	case fieldSource:
		return matchStr(entry.Src)
	case fieldSrcPort:
		return matchInt(entry.SrcPort)
	}
	return false
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

// public

// Compile compiles a filter expression string into a FilterNode tree
func Compile(expression string) (FilterNode, error) {
	if expression == "" {
		return nil, nil
	}
	parser := newParser(expression)
	return parser.parse()
}
