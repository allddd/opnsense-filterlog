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

package tui

import (
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"gitlab.com/allddd/opnsense-filterlog/internal/filter"
	"gitlab.com/allddd/opnsense-filterlog/internal/meta"
	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
)

const (
	formatLine = "%s %s %s %s %s%s > %s%s"
	formatPort = " %d"

	loadEntriesMax       = 600
	loadEntriesThreshold = 200

	scrollColumns = 10

	widthAction    = 7
	widthInterface = 10
	widthProtocol  = 9
	widthTime      = 16
)

type model struct {
	stream  *stream.Stream // log file stream
	indexed bool           // whether file has been indexed

	// details
	details     []string // formatted entry lines
	detailsView bool     // whether showing details

	// entries
	entries              []stream.LogEntry       // contiguous block of entries
	entriesStart         int                     // number of first line in entries block
	entriesFiltered      map[int]stream.LogEntry // non-contiguous block of entries matching current filter
	entriesFilteredStart int                     // index (in entriesAvailable) of first line in entriesFiltered block
	entriesFilteredEnd   int                     // index (in entriesAvailable) after last line in entriesFiltered block
	entriesTotal         int                     // total number of valid log entries
	entriesAvailable     []int                   // line numbers matching current filter

	// errors
	errors     []string // parse errors
	errorsView bool     // whether showing errors

	// filter
	filterApplied bool            // whether filter is currently applied
	filterInput   textinput.Model // filter input field
	filterView    bool            // whether the user is currently typing filter expression

	// ui
	uiHeight         int           // terminal height (in lines)
	uiWidth          int           // terminal width (in chars)
	uiLoading        bool          // whether showing loading view
	uiLoadingSpinner spinner.Model // loading spinner
	uiOffsetH        int           // first visible column
	uiOffsetHPrev    int           // saved uiOffsetH for use with alternative views
	uiOffsetV        int           // first visible line
	uiOffsetVPrev    int           // saved uiOffsetV for use with alternative views
	uiSelected       int           // selected line
	uiSelectedPrev   int           // saved uiSelected for use with alternative views
	uiStatusMsg      string        // status bar message
	uiStyles         *styles       // styles for rendering
}

type styles struct {
	alert    lipgloss.Style
	bar      lipgloss.Style
	barAlert lipgloss.Style
	bold     lipgloss.Style
	italic   lipgloss.Style
	ip       lipgloss.Style
	plain    lipgloss.Style
	port     lipgloss.Style
	selected lipgloss.Style
}

// message
// messages are processed in the Update method and represent events that update the model

// indexMsg is sent when the file has been successfully indexed.
type indexMsg struct {
	entriesTotal int // total number of valid log entries
}

// entriesMsg is sent when contiguous block of entries has been loaded.
type entriesMsg struct {
	entries      []stream.LogEntry // contiguous block of entries (default view)
	entriesStart int               // number of first line in entries block
}

// entriesFilteredMsg is sent when non-contiguous block of entries matching current filter has been loaded.
type entriesFilteredMsg struct {
	entriesFiltered      map[int]stream.LogEntry // non-contiguous block of entries matching current filter
	entriesFilteredStart int                     // index (in entriesAvailable) of first line in entriesFiltered block
	entriesFilteredEnd   int                     // index (in entriesAvailable) after last line in entriesFiltered block
}

// filterMsg is sent when filtering has completed.
type filterMsg struct {
	entriesAvailable []int // line numbers matching current filter
}

// streamErrorMsg is sent when a stream operation fails (e.g. SeekToLine).
type streamErrorMsg struct {
	err error // error that occurred
}

// bubbletea

// countLines returns the number of lines in the current view.
func (m model) countLines() int {
	switch {
	case m.detailsView:
		return len(m.details)
	case m.errorsView:
		return len(m.errors)
	default:
		if m.filterApplied {
			return len(m.entriesAvailable)
		}
		return max(m.entriesTotal, 0)
	}
}

// formatEntry returns a formatted log entry used in details view.
func formatEntry(entry *stream.LogEntry) ([]string, error) {
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	v := reflect.ValueOf(*entry)
	for i := range v.NumField() {
		ft := v.Type().Field(i)
		fv := v.Field(i)
		if fv.Kind() == reflect.Pointer {
			if fv.IsNil() {
				continue
			}
			fv = fv.Elem()
		}
		var value string
		switch v := fv.Interface().(type) {
		case string:
			value = v
		case uint8, uint16, uint32:
			value = fmt.Sprint(v)
		case netip.Addr:
			value = v.String()
		case time.Time:
			value = v.Format(time.RFC1123Z)
		default:
			return nil, fmt.Errorf("unhandled field %q of type %q", ft.Name, ft.Type)
		}
		if value == "" {
			continue
		}
		if _, err := fmt.Fprintf(tw, "%s:\t%s\n", ft.Name, value); err != nil {
			return nil, err
		}
	}
	if err := tw.Flush(); err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(b.String()), "\n"), nil
}

// savePosition saves the current position and resets it for details or errors view.
func (m *model) savePosition() {
	m.uiOffsetHPrev = m.uiOffsetH
	m.uiOffsetVPrev = m.uiOffsetV
	m.uiSelectedPrev = m.uiSelected
	m.uiOffsetH = 0
	m.uiOffsetV = 0
	m.uiSelected = 0
}

// scrollDown moves the selected line down by n lines and keeps it visible.
func (m *model) scrollDown(n int) {
	m.uiSelected = min(m.uiSelected+n, max(m.countLines()-1, 0))
	m.uiOffsetV = max(m.uiOffsetV, m.uiSelected-m.visibleHeight()+1) // +1 to keep selected line visible at bottom
}

// scrollUp moves the selected line up by n lines and keeps it visible.
func (m *model) scrollUp(n int) {
	m.uiSelected = max(m.uiSelected-n, 0)
	m.uiOffsetV = min(m.uiOffsetV, m.uiSelected)
}

// sliceString returns a substring starting at uiOffsetH and up to uiWidth chars.
func (m model) sliceString(s string) string {
	sw := ansi.StringWidth(s)
	if m.uiOffsetH <= 0 && m.uiWidth >= sw {
		return s
	}
	if m.uiOffsetH >= sw {
		return ""
	}
	end := m.uiOffsetH + m.uiWidth
	if end < sw {
		return ansi.Cut(s, m.uiOffsetH, end-1) + m.uiStyles.selected.Render(">")
	}
	return ansi.Cut(s, m.uiOffsetH, end)
}

// styleString truncates, styles, and pads a string.
func styleString(str string, width int, style lipgloss.Style) string {
	if width > 0 && ansi.StringWidth(str) > width {
		str = ansi.Truncate(str, width-1, "+")
	}
	if width > 0 {
		return style.Width(width).Render(str)
	}
	return style.Render(str)
}

// visibleHeight returns the number of lines available for content display.
func (m model) visibleHeight() int {
	return m.uiHeight - 3 // -3 for header, status, and help lines
}

// withLoadingView enables loading state and batches the command with spinner tick.
func (m *model) withLoadingView(cmd tea.Cmd) tea.Cmd {
	m.uiLoading = true
	return tea.Batch(cmd, m.uiLoadingSpinner.Tick)
}

// Init starts the indexing process.
func (m model) Init() tea.Cmd {
	return tea.Batch(index(m.stream), m.uiLoadingSpinner.Tick)
}

// Update handles all messages (and is the main event loop).
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case spinner.TickMsg:
		if !m.uiLoading {
			return m, nil
		}
		var cmd tea.Cmd
		m.uiLoadingSpinner, cmd = m.uiLoadingSpinner.Update(msg)
		return m, cmd

	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" || (msg.String() == "q" && !m.filterView) {
			return m, tea.Quit
		}
		if !m.indexed || m.uiLoading {
			return m, nil
		}

		if m.filterView {
			switch msg.String() {
			case "enter":
				filterValue := m.filterInput.Value()
				m.filterInput.Blur()
				m.filterView = false
				if filterValue == "" {
					m.clearFilter()
					return m, m.checkLoadEntries()
				}
				m.filterApplied = true
				m.uiOffsetH = 0
				m.uiOffsetV = 0
				m.uiSelected = 0
				// compile the filter
				compiled, err := filter.Compile(filterValue)
				if err != nil {
					m.uiStatusMsg = m.uiStyles.barAlert.Render(err.Error())
					m.entriesAvailable = []int{}
					return m, nil
				}
				return m, m.withLoadingView(scanAndFilter(m.stream, compiled, m.entriesTotal))

			case "esc":
				m.filterInput.Blur()
				m.filterInput.SetValue("")
				m.filterView = false
				return m, nil

			default:
				// let textinput handle all other keys
				var cmd tea.Cmd
				m.filterInput, cmd = m.filterInput.Update(msg)
				return m, cmd
			}
		}

		switch msg.String() {
		case "e":
			if !m.detailsView && !m.errorsView && len(m.errors) > 0 {
				m.savePosition()
				m.errorsView = true
			}
			return m, nil

		case "j", "down":
			m.scrollDown(1)
			return m, m.checkLoad()

		case "k", "up":
			m.scrollUp(1)
			return m, m.checkLoad()

		case "d", "pgdown":
			m.scrollDown(m.uiHeight / 2)
			return m, m.checkLoad()

		case "u", "pgup":
			m.scrollUp(m.uiHeight / 2)
			return m, m.checkLoad()

		case "g", "home":
			m.uiSelected = 0
			m.uiOffsetV = 0
			return m, m.checkLoad()

		case "G", "end":
			lines := m.countLines()
			m.uiSelected = max(lines-1, 0)
			m.uiOffsetV = max(lines-m.visibleHeight(), 0)
			return m, m.checkLoad()

		case "h", "left":
			m.uiOffsetH = max(m.uiOffsetH-scrollColumns, 0)
			return m, nil

		case "l", "right":
			m.uiOffsetH += scrollColumns
			return m, nil

		case "enter":
			if m.detailsView || m.errorsView || m.uiSelected >= m.countLines() {
				return m, nil
			}
			entry := m.entryAtLine(m.lineNumAt(m.uiSelected))
			if entry == nil {
				return m, nil
			}
			m.savePosition()
			m.detailsView = true
			if details, err := formatEntry(entry); err != nil {
				m.uiStatusMsg = m.uiStyles.barAlert.Render(fmt.Sprintf("error(tui): could not format entry: %v", err))
				m.details = []string{}
			} else {
				m.details = details
			}
			return m, nil

		case "/":
			if !m.detailsView && !m.errorsView {
				m.filterView = true
				return m, m.filterInput.Focus()
			}
			return m, nil

		case "esc":
			if m.detailsView || m.errorsView {
				m.detailsView = false
				m.errorsView = false
				m.uiOffsetH = m.uiOffsetHPrev
				m.uiOffsetV = m.uiOffsetVPrev
				m.uiSelected = m.uiSelectedPrev
				return m, nil
			}
			if m.filterApplied {
				m.clearFilter()
				return m, m.checkLoadEntries()
			}
			return m, nil

		default:
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.filterInput.SetWidth(msg.Width - len(m.filterInput.Prompt) - 1) // -1 for cursor
		m.uiHeight = msg.Height
		m.uiWidth = msg.Width
		// keep selected line visible after resize (+1 to keep selected line visible at bottom)
		m.uiOffsetV = max(min(m.uiSelected, max(m.uiOffsetV, m.uiSelected-m.visibleHeight()+1)), 0)
		return m, nil

	case indexMsg:
		m.entriesTotal = msg.entriesTotal
		m.errors = m.stream.Errors()
		m.indexed = true
		m.uiLoading = false
		if m.entriesTotal <= 0 {
			m.uiStatusMsg = m.uiStyles.barAlert.Render("error(tui): no valid entries found")
			return m, nil
		}
		return m, loadEntries(m.stream, 0)

	case entriesMsg:
		m.entries = msg.entries
		m.entriesStart = msg.entriesStart
		return m, nil

	case entriesFilteredMsg:
		if !m.filterApplied {
			return m, nil
		}
		m.uiLoading = false
		m.entriesFilteredStart = msg.entriesFilteredStart
		m.entriesFilteredEnd = msg.entriesFilteredEnd
		// evict entries (but keep overlapping)
		newEntriesFiltered := make(map[int]stream.LogEntry, msg.entriesFilteredEnd-msg.entriesFilteredStart)
		for i := msg.entriesFilteredStart; i < msg.entriesFilteredEnd; i++ {
			lineNum := m.entriesAvailable[i]
			if entry, exists := m.entriesFiltered[lineNum]; exists {
				newEntriesFiltered[lineNum] = entry
			}
		}
		m.entriesFiltered = newEntriesFiltered
		// merge new entries into map
		maps.Copy(m.entriesFiltered, msg.entriesFiltered)
		return m, nil

	case filterMsg:
		m.entriesFiltered = make(map[int]stream.LogEntry)
		m.entriesFilteredStart = 0
		m.entriesFilteredEnd = 0
		m.entriesAvailable = msg.entriesAvailable
		m.uiLoading = false
		m.uiStatusMsg = fmt.Sprintf("filter: %q", m.filterInput.Value())
		if len(m.entriesAvailable) > 0 {
			return m, m.withLoadingView(m.checkLoadEntriesFiltered())
		}
		return m, nil

	case streamErrorMsg:
		m.uiLoading = false
		m.uiStatusMsg = m.uiStyles.barAlert.Render(msg.err.Error())
		return m, nil

	default:
		if m.filterView {
			var cmd tea.Cmd
			m.filterInput, cmd = m.filterInput.Update(msg)
			return m, cmd
		}
		return m, nil
	}
}

// View renders the current state of the UI.
func (m model) View() tea.View {
	var v tea.View
	v.AltScreen = true

	// show loading view during initialization or on request
	if m.uiLoading || m.uiWidth == 0 || m.uiHeight == 0 {
		loading := fmt.Sprintf("%s\n\n%s %s", m.uiLoadingSpinner.View(), meta.Name, meta.Version)
		if m.uiWidth == 0 || m.uiHeight == 0 {
			v.SetContent(loading)
		} else {
			v.SetContent(
				lipgloss.NewStyle().
					Height(m.uiHeight).
					Width(m.uiWidth).
					Align(lipgloss.Center, lipgloss.Center).
					Render(loading),
			)
		}
		return v
	}

	var b strings.Builder
	var visibleEnd int
	visibleHeight := m.visibleHeight()
	visibleStart := m.uiOffsetV

	switch {
	// details and error view
	case m.detailsView || m.errorsView:
		headerLine := "Details"
		lines := m.details
		if m.errorsView {
			headerLine = "Error"
			lines = m.errors
		}
		visibleEnd = min(visibleStart+visibleHeight, len(lines))

		// header
		b.WriteString(m.uiStyles.bar.Width(m.uiWidth).Render(headerLine))
		b.WriteByte('\n')

		// main
		for i := visibleStart; i < visibleEnd; i++ {
			line := m.sliceString(lines[i])
			if i == m.uiSelected {
				line = m.uiStyles.selected.Width(m.uiWidth).Render(line)
			}
			b.WriteString(line)
			b.WriteByte('\n')
		}

	// default view
	default:
		visibleEnd = min(visibleStart+visibleHeight, m.countLines())

		// header
		headerLine := fmt.Sprintf(formatLine,
			styleString("Time", widthTime, m.uiStyles.plain),
			styleString("Action", widthAction, m.uiStyles.plain),
			styleString("Protocol", widthProtocol, m.uiStyles.plain),
			styleString("Interface", widthInterface, m.uiStyles.plain),
			"Source",
			"",
			"Destination",
			"")
		headerLine = m.sliceString(headerLine)
		b.WriteString(m.uiStyles.bar.Width(m.uiWidth).Render(headerLine))
		b.WriteByte('\n')

		// main
		for i := visibleStart; i < visibleEnd; i++ {
			entry := m.entryAtLine(m.lineNumAt(i))
			if entry == nil {
				// entry not loaded in memory
				b.WriteString(m.uiStyles.bold.Render("loading..."))
				b.WriteByte('\n')
				continue
			}
			// action
			var actionStyle lipgloss.Style
			switch entry.Action {
			case "block":
				actionStyle = m.uiStyles.alert
			case "pass":
				actionStyle = m.uiStyles.plain
			default:
				actionStyle = m.uiStyles.bold
			}
			// interface
			iface := entry.Interface
			switch entry.Direction {
			case "in":
				iface = "I " + iface
			case "out":
				iface = "O " + iface
			default:
				iface = m.uiStyles.bold.Render("?") + " " + iface
			}
			// source
			var sourcePort string
			if entry.SourcePort != nil {
				sourcePort = fmt.Sprintf(formatPort, *entry.SourcePort)
			}
			// destination
			var destinationPort string
			if entry.DestinationPort != nil {
				destinationPort = fmt.Sprintf(formatPort, *entry.DestinationPort)
			}
			line := fmt.Sprintf(formatLine,
				styleString(entry.Time.Format("Jan 02 15:04:05"), widthTime, m.uiStyles.plain),
				styleString(entry.Action, widthAction, actionStyle),
				styleString(entry.ProtocolName, widthProtocol, m.uiStyles.plain),
				styleString(iface, widthInterface, m.uiStyles.plain),
				styleString(entry.Source.String(), 0, m.uiStyles.ip),
				styleString(sourcePort, 0, m.uiStyles.port),
				styleString(entry.Destination.String(), 0, m.uiStyles.ip),
				styleString(destinationPort, 0, m.uiStyles.port))
			line = m.sliceString(line)
			switch {
			case i == m.uiSelected:
				line = m.uiStyles.selected.Width(m.uiWidth).Render(ansi.Strip(line))
			case entry.ErrMsg != "":
				line = m.uiStyles.italic.Render(ansi.Strip(line))
			}
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	for i := visibleEnd - visibleStart; i < visibleHeight; i++ {
		b.WriteByte('\n') // fill remaining space
	}

	// status
	var statusLine string
	if m.filterView {
		statusLine = m.filterInput.View()
	} else {
		lines := m.countLines()
		position := min(m.uiSelected+1, lines)
		statusLine = fmt.Sprintf("position: %d/%d", position, lines)
		if m.errorsView {
			statusLine += fmt.Sprintf(" (limit: %d)", stream.MaxErrorsInMemory)
		}
		if m.uiStatusMsg != "" {
			statusLine += " | " + m.uiStatusMsg
		}
	}
	b.WriteString(m.uiStyles.bar.Width(m.uiWidth).Render(statusLine))
	b.WriteByte('\n')

	// help
	helpLine := "q: quit | hjkl: move | ud: page | gG: jump"
	switch {
	case m.detailsView || m.errorsView:
		helpLine += " | esc: back"
	case m.filterView:
		helpLine = "enter: apply | esc: cancel"
	default:
		helpLine += " | enter: details | /: filter"
		if m.filterApplied {
			helpLine += " | esc: clear"
		}
		if len(m.errors) > 0 {
			errorCount := strconv.Itoa(len(m.errors))
			if len(m.errors) >= stream.MaxErrorsInMemory {
				errorCount += "+"
			}
			helpLine += " | e: " + m.uiStyles.barAlert.Render(fmt.Sprintf("show %s errors", errorCount))
		}
	}
	b.WriteString(helpLine)

	v.SetContent(b.String())
	return v
}

// async

// index builds the file index.
func index(s *stream.Stream) tea.Cmd {
	return func() tea.Msg {
		if err := s.BuildIndex(); err != nil {
			return streamErrorMsg{err: err}
		}
		return indexMsg{entriesTotal: s.TotalLines()}
	}
}

// loadEntries loads a contiguous block of log entries starting at a specific line.
func loadEntries(s *stream.Stream, startLine int) tea.Cmd {
	return func() tea.Msg {
		if err := s.SeekToLine(startLine); err != nil {
			return streamErrorMsg{err: err}
		}
		entries := make([]stream.LogEntry, 0, loadEntriesMax)
		for range loadEntriesMax {
			entry, err := s.Next()
			if err != nil {
				return streamErrorMsg{err: err}
			}
			if entry == nil {
				break
			}
			entries = append(entries, *entry)
		}
		return entriesMsg{
			entries:      entries,
			entriesStart: startLine,
		}
	}
}

// loadEntriesFiltered loads non-contiguous block of entries matching current filter.
func loadEntriesFiltered(s *stream.Stream, lineNums []int, entriesFilteredStart, entriesFilteredEnd int) tea.Cmd {
	return func() tea.Msg {
		entries := make(map[int]stream.LogEntry)
		for i, lineNum := range lineNums {
			// only seek if line doesn't directly follow previous one
			if i == 0 || lineNum != lineNums[i-1]+1 {
				if err := s.SeekToLine(lineNum); err != nil {
					return streamErrorMsg{err: err}
				}
			}
			entry, err := s.Next()
			if err != nil {
				return streamErrorMsg{err: err}
			}
			if entry != nil {
				entries[lineNum] = *entry
			}
		}
		return entriesFilteredMsg{
			entriesFiltered:      entries,
			entriesFilteredStart: entriesFilteredStart,
			entriesFilteredEnd:   entriesFilteredEnd,
		}
	}
}

// scanAndFilter scans the entire file and builds the list of matching line numbers.
func scanAndFilter(s *stream.Stream, node filter.Node, entriesTotal int) tea.Cmd {
	return func() tea.Msg {
		lineNums := make([]int, 0)
		if err := s.SeekToLine(0); err != nil {
			return streamErrorMsg{err: err}
		}
		for i := range entriesTotal {
			entry, err := s.Next()
			if err != nil {
				return streamErrorMsg{err: err}
			}
			if entry == nil {
				break
			}
			if node.Matches(entry) {
				lineNums = append(lineNums, i)
			}
		}
		return filterMsg{entriesAvailable: lineNums}
	}
}

// view management

// checkLoad uses checkLoadEntriesFiltered if a filter is applied and checkLoadEntries otherwise
// (nothing is loaded in details and errors view).
func (m model) checkLoad() tea.Cmd {
	if m.detailsView || m.errorsView {
		return nil
	}
	if m.filterApplied {
		return m.checkLoadEntriesFiltered()
	}
	return m.checkLoadEntries()
}

// checkLoadEntries checks if the currently loaded contiguous block needs reloading
// and returns a command to load it if needed.
func (m model) checkLoadEntries() tea.Cmd {
	if len(m.entries) == m.entriesTotal || m.countLines() == 0 {
		return nil
	}
	visibleStart := m.uiOffsetV
	visibleEnd := min(visibleStart+m.visibleHeight(), m.countLines())
	firstLine := m.lineNumAt(visibleStart)
	lastLine := m.lineNumAt(visibleEnd - 1)
	if firstLine < m.entriesStart+loadEntriesThreshold || lastLine >= m.entriesStart+len(m.entries)-loadEntriesThreshold {
		// center around the middle of visible range
		centerLine := (firstLine + lastLine) / 2
		newStart := min(max(centerLine-loadEntriesMax/2, 0), max(m.entriesTotal-loadEntriesMax, 0))
		// only reload if start position would change
		if newStart != m.entriesStart {
			return loadEntries(m.stream, newStart)
		}
	}
	return nil
}

// checkLoadEntriesFiltered checks if the currently loaded non-contiguous block needs reloading
// and returns a command to load it if needed.
func (m model) checkLoadEntriesFiltered() tea.Cmd {
	if len(m.entriesAvailable) == 0 {
		return nil
	}
	visibleStart := m.uiOffsetV
	visibleEnd := min(visibleStart+m.visibleHeight(), len(m.entriesAvailable))
	if visibleStart < m.entriesFilteredStart+loadEntriesThreshold ||
		visibleEnd >= m.entriesFilteredEnd-loadEntriesThreshold {
		// center around the middle of visible range
		centerLine := (visibleStart + visibleEnd) / 2
		newStart := max(centerLine-loadEntriesMax/2, 0)
		newEnd := min(newStart+loadEntriesMax, len(m.entriesAvailable))
		newStart = max(newEnd-loadEntriesMax, 0)
		// only reload if start/end position would change
		if newStart != m.entriesFilteredStart || newEnd != m.entriesFilteredEnd {
			linesToLoad := make([]int, 0, newEnd-newStart)
			for i := newStart; i < newEnd; i++ {
				lineNum := m.entriesAvailable[i]
				if _, exists := m.entriesFiltered[lineNum]; !exists {
					linesToLoad = append(linesToLoad, lineNum)
				}
			}
			if len(linesToLoad) > 0 {
				return loadEntriesFiltered(m.stream, linesToLoad, newStart, newEnd)
			}
		}
	}
	return nil
}

// entryAtLine returns the log entry for a specific line number.
func (m model) entryAtLine(lineNum int) *stream.LogEntry {
	if m.filterApplied {
		if entry, exists := m.entriesFiltered[lineNum]; exists {
			return &entry
		}
		return nil
	}
	if lineNum < m.entriesStart || lineNum >= m.entriesStart+len(m.entries) {
		return nil
	}
	return &m.entries[lineNum-m.entriesStart]
}

// lineNumAt returns the line number for a specific position (all lines or matching filter).
func (m model) lineNumAt(position int) int {
	if m.filterApplied {
		return m.entriesAvailable[position]
	}
	return position
}

// filtering

// clearFilter clears the applied filter and shows all lines.
func (m *model) clearFilter() {
	m.entriesAvailable = nil
	m.filterApplied = false
	m.filterInput.SetValue("")
	m.uiOffsetH = 0
	m.uiOffsetV = 0
	m.uiSelected = 0
	m.uiStatusMsg = ""
}

// public

// Display starts the TUI and displays the log file from the given stream.
func Display(s *stream.Stream) error {
	// uiStyles
	st := &styles{
		alert: lipgloss.NewStyle().
			Foreground(lipgloss.Color("202")),
		bar: lipgloss.NewStyle().
			// width must be set before rendering
			Background(lipgloss.Color("237")).
			Foreground(lipgloss.Color("15")),
		barAlert: lipgloss.NewStyle().
			Background(lipgloss.Color("196")).
			Foreground(lipgloss.Color("231")),
		bold: lipgloss.NewStyle().
			Bold(true),
		italic: lipgloss.NewStyle().
			Italic(true),
		ip: lipgloss.NewStyle().
			Foreground(lipgloss.Color("2")),
		plain: lipgloss.NewStyle(),
		port: lipgloss.NewStyle().
			Foreground(lipgloss.Color("4")),
		selected: lipgloss.NewStyle().
			// width must be set before rendering
			Reverse(true),
	}
	// uiLoadingSpinner
	sp := spinner.New()
	sp.Spinner = spinner.Line
	// filterInput
	ti := textinput.New()
	ti.Prompt = "filter: "
	tis := ti.Styles()
	tis.Focused.Prompt = st.bar
	tis.Focused.Text = st.bar
	ti.SetStyles(tis)
	// model
	m := model{
		stream:           s,
		indexed:          false,
		entries:          nil,
		entriesFiltered:  nil,
		entriesAvailable: nil,
		filterApplied:    false,
		filterInput:      ti,
		uiLoading:        true,
		uiLoadingSpinner: sp,
		uiStyles:         st,
	}

	if _, err := tea.NewProgram(m).Run(); err != nil {
		return fmt.Errorf("error(tui): %w", err)
	}
	return nil
}
