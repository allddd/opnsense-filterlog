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
	"reflect"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"gitlab.com/allddd/opnsense-filterlog/internal/filter"
	"gitlab.com/allddd/opnsense-filterlog/internal/meta"
	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
)

const (
	formatDetail = "%-14s%s"
	formatLine   = "%s %s %s %s %s%s > %s%s"
	formatPort   = " %s"

	loadEntriesMax       = 600
	loadEntriesThreshold = 200

	widthAction    = 7
	widthInterface = 10
	widthProtocol  = 9
	widthTime      = 15
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
	entriesFilteredStart int                     // number of first line in entriesFiltered block
	entriesFilteredEnd   int                     // number of last line in entriesFiltered block
	entriesTotal         int                     // total number of valid log entries
	entriesAvailable     []int                   // line numbers that can be displayed (all or matching filter)

	// error
	errors     []string // parse errors
	errorsView bool     // whether showing errors

	// filter
	filterApplied  bool              // whether filter is currently applied
	filterCompiled filter.FilterNode // compiled filter expression
	filterInput    textinput.Model   // filter input field
	filterView     bool              // whether the user is currently typing filter expression

	// ui
	uiHeight         int           // terminal height (in lines)
	uiWidth          int           // terminal width (in chars)
	uiLoading        bool          // whether showing loading view
	uiLoadingSpinner spinner.Model // loading spinner
	uiOffsetH        int           // first visible column
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
	entriesFilteredStart int                     // number of first line in entriesFiltered block
	entriesFilteredEnd   int                     // number of last line in entriesFiltered block
}

// filterMsg is sent when filtering has completed.
type filterMsg struct {
	entriesAvailable []int // line numbers that can be displayed
}

// streamErrorMsg is sent when a stream operation fails (e.g. SeekToLine).
type streamErrorMsg struct {
	err error // error that occurred
}

// bubbletea

// sliceString returns a substring starting at offset and up to width chars.
func sliceString(s string, offset int, width int) string {
	sw := ansi.StringWidth(s)
	if offset <= 0 && width >= sw {
		return s
	}
	if offset >= sw {
		return ""
	}
	return ansi.Cut(s, offset, offset+width)
}

// styleString truncates, styles, and pads a string.
func styleString(str string, width int, style ...lipgloss.Style) string {
	if width > 0 && ansi.StringWidth(str) > width {
		if width <= 1 {
			str = ansi.Truncate(str, width, "")
		} else {
			str = ansi.Truncate(str, width-1, "+")
		}
	}
	if len(style) > 0 {
		if width > 0 {
			return style[0].Width(width).Render(str)
		}
		return style[0].Render(str)
	}
	return str
}

// formatEntry returns a formatted log entry.
func formatEntry(entry *stream.LogEntry) ([]string, error) {
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	v := reflect.ValueOf(*entry)
	for i := range v.NumField() {
		ft := v.Type().Field(i)
		fv := v.Field(i)
		switch v := fv.Interface().(type) {
		case string:
			if v != "" {
				if _, err := fmt.Fprintf(tw, "%s:\t%s\n", ft.Name, v); err != nil {
					return nil, err
				}
			}
		case time.Time:
			if _, err := fmt.Fprintf(tw, "%s:\t%s\n", ft.Name, v.Format(time.RFC1123Z)); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Flush(); err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(b.String()), "\n"), nil
}

func (m *model) scrollDown(n int) {
	var lines int
	switch {
	case m.detailsView:
		lines = len(m.details)
	case m.errorsView:
		lines = len(m.errors)
	default:
		lines = len(m.entriesAvailable)
	}
	m.uiSelected = min(m.uiSelected+n, lines-1)
	m.uiOffsetV = max(m.uiOffsetV, m.uiSelected-m.visibleHeight()+1) // +1 to keep selected line visible at bottom
}

func (m *model) scrollUp(n int) {
	m.uiSelected = max(m.uiSelected-n, 0)
	m.uiOffsetV = min(m.uiOffsetV, m.uiSelected)
}

// withLoadingView enables loading state and batches the command with spinner tick.
func (m *model) withLoadingView(cmd tea.Cmd) tea.Cmd {
	m.uiLoading = true
	return tea.Batch(cmd, m.uiLoadingSpinner.Tick)
}

// Init starts the indexing process.
func (m model) Init() tea.Cmd {
	return m.withLoadingView(index(m.stream))
}

// Update handles all messages (and is the main event loop).
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.uiLoadingSpinner, cmd = m.uiLoadingSpinner.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		if !m.indexed {
			return m, nil
		}

		if m.filterView {
			switch msg.String() {
			case "enter":
				filterValue := m.filterInput.Value()
				m.filterApplied = len(filterValue) > 0
				m.filterInput.Blur()
				m.filterView = false
				m.uiOffsetH = 0
				m.uiOffsetV = 0
				m.uiSelected = 0
				if m.filterApplied {
					// compile the filter
					compiled, err := filter.Compile(filterValue)
					if err != nil {
						m.uiStatusMsg = m.uiStyles.barAlert.Render(err.Error())
						m.filterCompiled = nil
						m.entriesAvailable = []int{}
					} else {
						m.filterCompiled = compiled
						m.uiStatusMsg = ""
						return m, m.withLoadingView(m.scanAndFilter())
					}
				} else {
					m.filterCompiled = nil
					m.uiStatusMsg = ""
					m.showAllLines()
				}
				return m, m.checkLoadEntries()

			case "esc":
				m.filterInput.Blur()
				m.filterInput.SetValue("")
				m.filterView = false
				m.uiStatusMsg = ""
				return m, nil

			default:
				// let textinput handle all other keys
				var cmd tea.Cmd
				m.filterInput, cmd = m.filterInput.Update(msg)
				return m, cmd
			}
		}

		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit

		case "e":
			if !m.detailsView && !m.errorsView && len(m.errors) > 0 {
				m.uiOffsetVPrev = m.uiOffsetV
				m.uiSelectedPrev = m.uiSelected
				m.uiOffsetH = 0
				m.uiOffsetV = 0
				m.uiSelected = 0
				m.errorsView = true
			}
			return m, nil

		case "j", "down":
			m.scrollDown(1)
			if m.detailsView || m.errorsView {
				return m, nil
			}
			if m.filterApplied {
				return m, m.checkLoadEntriesFiltered()
			}
			return m, m.checkLoadEntries()

		case "k", "up":
			m.scrollUp(1)
			if m.detailsView || m.errorsView {
				return m, nil
			}
			if m.filterApplied {
				return m, m.checkLoadEntriesFiltered()
			}
			return m, m.checkLoadEntries()

		case "d", "pgdown":
			m.scrollDown(m.uiHeight / 2)
			if m.detailsView || m.errorsView {
				return m, nil
			}
			if m.filterApplied {
				return m, m.checkLoadEntriesFiltered()
			}
			return m, m.checkLoadEntries()

		case "u", "pgup":
			m.scrollUp(m.uiHeight / 2)
			if m.detailsView || m.errorsView {
				return m, nil
			}
			if m.filterApplied {
				return m, m.checkLoadEntriesFiltered()
			}
			return m, m.checkLoadEntries()

		case "g", "home":
			m.uiSelected = 0
			m.uiOffsetV = 0
			if m.detailsView || m.errorsView {
				return m, nil
			}
			if m.filterApplied {
				return m, m.checkLoadEntriesFiltered()
			}
			return m, m.checkLoadEntries()

		case "G", "end":
			var lines int
			switch {
			case m.detailsView:
				lines = len(m.details)
			case m.errorsView:
				lines = len(m.errors)
			default:
				lines = len(m.entriesAvailable)
			}
			m.uiSelected = max(lines-1, 0)
			m.uiOffsetV = max(lines-m.visibleHeight(), 0)
			if m.detailsView || m.errorsView {
				return m, nil
			}
			if m.filterApplied {
				return m, m.checkLoadEntriesFiltered()
			}
			return m, m.checkLoadEntries()

		case "h", "left":
			m.uiOffsetH = max(m.uiOffsetH-10, 0)
			return m, nil

		case "l", "right":
			m.uiOffsetH += 10
			return m, nil

		case "enter":
			if !m.detailsView && !m.errorsView {
				if len(m.entriesAvailable) > 0 && m.uiSelected < len(m.entriesAvailable) {
					entry := m.getEntryAtLine(m.entriesAvailable[m.uiSelected])
					if entry != nil {
						m.uiOffsetVPrev = m.uiOffsetV
						m.uiSelectedPrev = m.uiSelected
						m.detailsView = true
						m.uiOffsetH = 0
						m.uiOffsetV = 0
						m.uiSelected = 0
						if details, err := formatEntry(entry); err != nil {
							m.uiStatusMsg = m.uiStyles.barAlert.Render(fmt.Sprintf("error(tui): could not format entry: %v", err))
							m.details = []string{}
						} else {
							m.details = details
						}
					}
				}
			}
			return m, nil

		case "/":
			if !m.detailsView && !m.errorsView {
				m.filterView = true
				return m, m.filterInput.Focus()
			}
			return m, nil

		case "esc":
			if m.detailsView {
				m.detailsView = false
				m.uiOffsetV = m.uiOffsetVPrev
				m.uiSelected = m.uiSelectedPrev
				m.uiStatusMsg = ""
				return m, nil
			}
			if m.errorsView {
				m.errorsView = false
				m.uiOffsetV = m.uiOffsetVPrev
				m.uiSelected = m.uiSelectedPrev
				return m, nil
			}
			if m.filterApplied {
				m.entriesFiltered = make(map[int]stream.LogEntry)
				m.entriesFilteredStart = 0
				m.entriesFilteredEnd = 0
				m.filterApplied = false
				m.filterCompiled = nil
				m.filterInput.SetValue("")
				m.uiOffsetH = 0
				m.uiOffsetV = 0
				m.uiSelected = 0
				m.uiStatusMsg = ""
				m.showAllLines()
				return m, m.checkLoadEntries()
			}
			return m, nil

		default:
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.filterInput.Width = msg.Width - len(m.filterInput.Prompt) - 1 // -1 for cursor
		m.uiHeight = msg.Height
		m.uiWidth = msg.Width
		// keep selected line visible after resize (+1 to keep selected line visible at bottom)
		m.uiOffsetV = max(0, min(m.uiSelected, max(m.uiOffsetV, m.uiSelected-m.visibleHeight()+1)))
		return m, nil

	case indexMsg:
		m.entriesTotal = msg.entriesTotal
		m.errors = m.stream.GetErrors()
		m.indexed = true
		m.uiLoading = false
		if m.entriesTotal <= 0 {
			m.uiStatusMsg = m.uiStyles.barAlert.Render("error(tui): no valid entries found")
			return m, nil
		}
		m.showAllLines()
		return m, loadEntries(m.stream, 0, loadEntriesMax)

	case entriesMsg:
		m.entries = msg.entries
		m.entriesStart = msg.entriesStart
		return m, nil

	case entriesFilteredMsg:
		m.uiLoading = false
		m.entriesFilteredStart = msg.entriesFilteredStart
		m.entriesFilteredEnd = msg.entriesFilteredEnd
		// evict entries (but keep overlapping)
		if msg.entriesFilteredEnd > 0 {
			newEntriesFiltered := make(map[int]stream.LogEntry, msg.entriesFilteredEnd-msg.entriesFilteredStart)
			for i := msg.entriesFilteredStart; i < msg.entriesFilteredEnd; i++ {
				lineNum := m.entriesAvailable[i]
				if entry, exists := m.entriesFiltered[lineNum]; exists {
					newEntriesFiltered[lineNum] = entry
				}
			}
			m.entriesFiltered = newEntriesFiltered
		}
		// merge new entries into map
		maps.Copy(m.entriesFiltered, msg.entriesFiltered)
		return m, nil

	case filterMsg:
		m.entriesFiltered = make(map[int]stream.LogEntry)
		m.entriesFilteredStart = 0
		m.entriesFilteredEnd = 0
		m.entriesAvailable = msg.entriesAvailable
		m.uiLoading = false
		m.uiOffsetH = 0
		m.uiOffsetV = 0
		m.uiSelected = 0
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

// visibleHeight returns the number of lines available for content display.
func (m model) visibleHeight() int {
	return m.uiHeight - 3 // -3 for header, status, and help lines
}

// View renders the current state of the UI (as a string).
func (m model) View() string {
	// show loading view during initialization or on request
	if m.uiLoading || m.uiWidth == 0 || m.uiHeight == 0 {
		loading := fmt.Sprintf("%s%s%s %s", m.uiLoadingSpinner.View(), "\n\n", meta.Name, meta.Version)
		if m.uiWidth == 0 || m.uiHeight == 0 {
			return loading
		}
		return lipgloss.NewStyle().
			Height(m.uiHeight).
			Width(m.uiWidth).
			Align(lipgloss.Center, lipgloss.Center).
			Render(loading)
	}

	var b strings.Builder
	var visibleEnd int
	visibleHeight := m.visibleHeight()
	visibleStart := m.uiOffsetV

	if m.detailsView { //nolint:gocritic // details view
		visibleEnd = min(visibleStart+visibleHeight, len(m.details))
		// header
		b.WriteString(m.uiStyles.bar.Width(m.uiWidth).Render("Details") + "\n")

		// main
		for i := visibleStart; i < visibleEnd; i++ {
			line := sliceString(m.details[i], m.uiOffsetH, m.uiWidth)
			if i == m.uiSelected {
				line = m.uiStyles.selected.Width(m.uiWidth).Render(line)
			}
			b.WriteString(line + "\n")
		}
		for i := visibleEnd - visibleStart; i < visibleHeight; i++ {
			b.WriteString("\n") // fill remaining space
		}

	} else if m.errorsView { // error view
		visibleEnd = min(visibleStart+visibleHeight, len(m.errors))

		// header
		b.WriteString(m.uiStyles.bar.Width(m.uiWidth).Render("Error") + "\n")

		// main
		for i := visibleStart; i < visibleEnd; i++ {
			line := sliceString(m.errors[i], m.uiOffsetH, m.uiWidth)
			if i == m.uiSelected {
				line = m.uiStyles.selected.Width(m.uiWidth).Render(line)
			}
			b.WriteString(line + "\n")
		}
		for i := visibleEnd - visibleStart; i < visibleHeight; i++ {
			b.WriteString("\n") // fill remaining space
		}

	} else { // default view
		visibleEnd = min(visibleStart+visibleHeight, len(m.entriesAvailable))

		// header
		headerLine := fmt.Sprintf(formatLine,
			styleString("Time", widthTime, m.uiStyles.plain),
			styleString("Action", widthAction, m.uiStyles.plain),
			styleString("Protocol", widthProtocol, m.uiStyles.plain),
			styleString("Interface", widthInterface, m.uiStyles.plain),
			styleString("Source", 0, m.uiStyles.plain),
			styleString("", 0, m.uiStyles.plain),
			styleString("Destination", 0, m.uiStyles.plain),
			styleString("", 0, m.uiStyles.plain))
		headerLine = sliceString(headerLine, m.uiOffsetH, m.uiWidth)
		b.WriteString(m.uiStyles.bar.Width(m.uiWidth).Render(headerLine) + "\n")

		// main
		for i := visibleStart; i < visibleEnd; i++ {
			if i >= len(m.entriesAvailable) {
				break
			}
			entry := m.getEntryAtLine(m.entriesAvailable[i])
			if entry == nil {
				// entry not loaded in memory
				b.WriteString(m.uiStyles.bold.Render("loading...") + "\n")
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
			if entry.SourcePort != "" {
				sourcePort = fmt.Sprintf(formatPort, entry.SourcePort)
			}
			// destination
			var destinationPort string
			if entry.DestinationPort != "" {
				destinationPort = fmt.Sprintf(formatPort, entry.DestinationPort)
			}
			line := fmt.Sprintf(formatLine,
				styleString(entry.Time.Format("Jan02-15:04:05"), widthTime, m.uiStyles.plain),
				styleString(entry.Action, widthAction, actionStyle),
				styleString(entry.ProtocolName, widthProtocol, m.uiStyles.plain),
				styleString(iface, widthInterface, m.uiStyles.plain),
				styleString(entry.Source, 0, m.uiStyles.ip),
				styleString(sourcePort, 0, m.uiStyles.port),
				styleString(entry.Destination, 0, m.uiStyles.ip),
				styleString(destinationPort, 0, m.uiStyles.port))
			line = sliceString(line, m.uiOffsetH, m.uiWidth)
			if i == m.uiSelected {
				line = m.uiStyles.selected.Width(m.uiWidth).Render(ansi.Strip(line))
			}
			b.WriteString(line + "\n")
		}
		for i := visibleEnd - visibleStart; i < visibleHeight; i++ {
			b.WriteString("\n") // fill remaining space
		}
	}

	// status
	var statusLine string
	if m.filterView {
		statusLine = m.filterInput.View()
	} else {
		var lines int
		switch {
		case m.detailsView:
			lines = len(m.details)
		case m.errorsView:
			lines = len(m.errors)
		default:
			lines = len(m.entriesAvailable)
		}
		statusLine = fmt.Sprintf("position: %d/%d", m.uiSelected+1, lines)
		if m.errorsView {
			statusLine += fmt.Sprintf(" (limit: %d)", stream.MaxErrorsInMemory)
		}
		if m.uiStatusMsg != "" {
			statusLine += " | " + m.uiStatusMsg
		}
	}
	b.WriteString(m.uiStyles.bar.Width(m.uiWidth).Render(statusLine) + "\n")

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

	return b.String()
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
func loadEntries(s *stream.Stream, startLine int, count int) tea.Cmd {
	return func() tea.Msg {
		startLine = max(startLine, 0)
		totalLines := s.TotalLines()
		if startLine >= totalLines {
			startLine = max(totalLines-count, 0)
		}
		if err := s.SeekToLine(startLine); err != nil {
			return streamErrorMsg{err: err}
		}
		entries := make([]stream.LogEntry, 0, count)
		for i := 0; i < count && startLine+i < totalLines; i++ {
			entry := s.Next()
			if entry == nil {
				// EOF
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
		for _, lineNum := range lineNums {
			// TODO: handle this error
			if err := s.SeekToLine(lineNum); err != nil {
				continue
			}
			entry := s.Next()
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

// view management

// checkLoadEntries checks if the currently loaded contiguous block needs reloading
// and returns a command to load it if needed.
func (m model) checkLoadEntries() tea.Cmd {
	if m.uiLoading || len(m.entries) == m.entriesTotal || len(m.entriesAvailable) == 0 || !m.indexed {
		return nil
	}
	visibleStart := m.uiOffsetV
	visibleEnd := min(visibleStart+m.visibleHeight(), len(m.entriesAvailable))
	firstLine := m.entriesAvailable[visibleStart]
	lastLine := m.entriesAvailable[visibleEnd-1]
	if firstLine < m.entriesStart+loadEntriesThreshold || lastLine >= m.entriesStart+len(m.entries)-loadEntriesThreshold {
		// center around the middle of visible range
		centerLine := (firstLine + lastLine) / 2
		newStart := min(max(centerLine-loadEntriesMax/2, 0), max(m.entriesTotal-loadEntriesMax, 0))
		// only reload if start position would change
		if newStart != m.entriesStart {
			return loadEntries(m.stream, newStart, loadEntriesMax)
		}
	}
	return nil
}

// checkLoadEntriesFiltered checks if the currently loaded non-contiguous block needs reloading
// and returns a command to load it if needed.
func (m model) checkLoadEntriesFiltered() tea.Cmd {
	if m.uiLoading || !m.filterApplied || len(m.entriesAvailable) == 0 || !m.indexed {
		return nil
	}
	// if filtered results fit in loadEntriesMax, load once and never reload
	if len(m.entriesAvailable) <= loadEntriesMax && len(m.entriesFiltered) == len(m.entriesAvailable) {
		return nil
	}
	visibleStart := m.uiOffsetV
	visibleEnd := min(visibleStart+m.visibleHeight(), len(m.entriesAvailable))
	if visibleStart < m.entriesFilteredStart+loadEntriesThreshold ||
		visibleEnd >= m.entriesFilteredEnd-loadEntriesThreshold {
		// center around the middle of visible range
		centerLine := (visibleStart + visibleEnd) / 2
		newStart := max(0, centerLine-loadEntriesMax/2)
		newEnd := min(len(m.entriesAvailable), newStart+loadEntriesMax)
		newStart = max(0, newEnd-loadEntriesMax)
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

// getEntryAtLine returns the log entry for a specific line number.
func (m model) getEntryAtLine(lineNum int) *stream.LogEntry {
	if m.filterApplied && len(m.entriesFiltered) > 0 {
		if entry, exists := m.entriesFiltered[lineNum]; exists {
			return &entry
		}
		return nil
	}
	if lineNum < m.entriesStart || lineNum >= m.entriesStart+len(m.entries) {
		return nil
	}
	idx := lineNum - m.entriesStart
	if idx < 0 || idx >= len(m.entries) {
		return nil
	}
	return &m.entries[idx]
}

// filtering

// showAllLines populates visibleLines with all line numbers and is used when initializing or when clearing a filter.
func (m *model) showAllLines() {
	m.entriesAvailable = m.entriesAvailable[:0]
	for i := range m.entriesTotal {
		m.entriesAvailable = append(m.entriesAvailable, i)
	}
}

// scanAndFilter scans the entire file and builds the list of matching line numbers.
func (m model) scanAndFilter() tea.Cmd {
	return func() tea.Msg {
		entries := make([]int, 0)
		if err := m.stream.SeekToLine(0); err != nil {
			return streamErrorMsg{err: err}
		}
		for i := range m.entriesTotal {
			entry := m.stream.Next()
			if entry == nil {
				break
			}
			if m.filterCompiled.Matches(entry) {
				entries = append(entries, i)
			}
		}
		return filterMsg{entriesAvailable: entries}
	}
}

// public

// Display starts the TUI and displays the log file from the given stream.
func Display(s *stream.Stream) error {
	defer s.Close() //nolint:errcheck
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
		plain: lipgloss.NewStyle(),
		ip: lipgloss.NewStyle().
			Foreground(lipgloss.Color("2")),
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
	ti.TextStyle = st.bar
	ti.Cursor.Style = st.bar
	ti.Cursor.TextStyle = st.bar
	// model
	m := model{
		stream:           s,
		indexed:          false,
		entries:          make([]stream.LogEntry, 0, loadEntriesMax),
		entriesFiltered:  make(map[int]stream.LogEntry),
		entriesAvailable: make([]int, 0),
		filterApplied:    false,
		filterInput:      ti,
		uiLoading:        true,
		uiLoadingSpinner: sp,
		uiStyles:         st,
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}
