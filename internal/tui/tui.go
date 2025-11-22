package tui

import (
	"fmt"
	"maps"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"gitlab.com/allddd/opnsense-filterlog/internal/filter"
	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
)

const (
	maxEntriesInMemory = 1000
)

type model struct {
	stream           *stream.Stream          // the log file stream
	entries          []stream.LogEntry       // contiguous block of log entries
	entriesFiltered  map[int]stream.LogEntry // filtered entries
	entriesStartLine int                     // file line number where the entries block begins
	indexBuilt       bool                    // whether the file has been indexed
	totalLines       int                     // number of valid log entries
	visibleLines     []int                   // line numbers to display on screen

	// filter
	filterEditing  bool              // whether the user is currently typing a filter expression
	filterActive   bool              // whether a filter is currently applied
	filterInput    string            // filter expression text
	filterCompiled filter.FilterNode // compiled filter expression
	filterError    string            // error message from filter compilation

	// view
	width          int           // terminal width (in chars)
	height         int           // terminal height (in lines)
	scrollPos      int           // current scroll position in the visible lines list
	errorActive    bool          // whether we're viewing parse errors instead of logs
	errorScrollPos int           // scroll position when viewing the error list
	errorList      []string      // parse errors encountered while indexing the log file
	loading        bool          // whether the loading screen should be displayed
	statusMsg      string        // status message to display in the status bar
	spinner        spinner.Model // loading spinner
}

// message
// messages are processed in the Update method and represent events that update the model

// indexBuiltMsg is sent when the file has been successfully indexed
type indexBuiltMsg struct {
	totalLines int // number of valid log entries found
}

// indexErrorMsg is sent when indexing fails
type indexErrorMsg struct {
	err error // the error that occurred
}

// entriesLoadedMsg is sent when a block of entries has been loaded
type entriesLoadedMsg struct {
	entries   []stream.LogEntry // loaded log entries
	startLine int               // line number of the first entry
}

// entriesFilteredLoadedMsg is sent when filtered entries have been loaded
type entriesFilteredLoadedMsg struct {
	entries map[int]stream.LogEntry // map of line number to entry
}

// filteredMsg is sent when filtering has completed
type filteredMsg struct {
	visibleLines []int // line numbers of entries that matched the filter
}

// bubbletea

// truncateString truncates a string to a maximum length
func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// Init starts the indexing process and the loading spinner
func (m model) Init() tea.Cmd {
	return tea.Batch(
		buildIndex(m.stream),
		m.spinner.Tick,
	)
}

// Update handles all messages (and is the main event loop)
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.filterEditing {
			return m.handleFilterInput(msg)
		}
		return m.handleNormalInput(msg)

	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.width = msg.Width
		return m, nil

	case indexBuiltMsg:
		m.errorList = m.stream.GetErrors()
		m.indexBuilt = true
		m.loading = false
		m.totalLines = msg.totalLines

		if m.totalLines <= 0 {
			m.statusMsg = "error: no valid entries found"
		}

		if m.totalLines > 0 {
			m.showAllLines()
			return m, loadEntries(m.stream, 0, maxEntriesInMemory)
		}
		return m, nil

	case indexErrorMsg:
		m.loading = false
		m.statusMsg = msg.err.Error()
		return m, nil

	case entriesLoadedMsg:
		m.entries = msg.entries
		m.entriesStartLine = msg.startLine
		return m, nil

	case filteredMsg:
		return m.handleFilteredMsg(msg)

	case entriesFilteredLoadedMsg:
		m.loading = false
		// merge new entries into entriesFiltered map
		maps.Copy(m.entriesFiltered, msg.entries)
		// check if we need to load more visible entries
		return m, m.loadVisibleEntries()

	default:
		// update spinner
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
}

// View renders the current state of the UI (as a string)
func (m model) View() string {
	// show loading screen during initialization or on request
	if m.width == 0 || m.height == 0 || !m.indexBuilt || m.loading {
		return m.loadingView()
	}

	var b strings.Builder

	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("11")).
		Bold(true)

	blockStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("31"))
	passStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	statusStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("7")).
		Foreground(lipgloss.Color("0")).
		Width(m.width)

	contentHeight := m.height - 3 // -3 for the header, status, and help lines

	if m.errorActive {
		b.WriteString(headerStyle.Render("Error"))
		b.WriteString("\n")

		visibleStart := m.errorScrollPos
		visibleEnd := min(m.errorScrollPos+contentHeight, len(m.errorList))

		for i := visibleStart; i < visibleEnd; i++ {
			b.WriteString(m.errorList[i] + "\n")
		}

		// fill remaining space
		for i := visibleEnd - visibleStart; i < contentHeight; i++ {
			b.WriteString("\n")
		}
	} else {
		headerFormat := "%-16s %-10s %-10s %-5s %-40s %-7s %-40s %-7s %-10s %-20s"

		b.WriteString(headerStyle.Render(
			fmt.Sprintf(headerFormat, "Time", "Action", "Interface", "Dir", "Source", "SrcPort", "Destination", "DstPort", "Proto", "Reason"),
		))
		b.WriteString("\n")

		visibleStart := m.scrollPos
		visibleEnd := min(m.scrollPos+contentHeight, len(m.visibleLines))

		for i := visibleStart; i < visibleEnd; i++ {
			if i >= len(m.visibleLines) {
				break
			}

			lineNum := m.visibleLines[i]
			entry := m.getEntryAtLine(lineNum)
			if entry == nil {
				// entry not in memory
				b.WriteString(dimStyle.Render("loading..."))
				b.WriteString("\n")
				continue
			}

			var style lipgloss.Style
			switch entry.Action {
			case stream.ActionBlock:
				style = blockStyle
			case stream.ActionPass:
				style = passStyle
			default:
				style = dimStyle
			}

			srcPort := ""
			if entry.SrcPort > 0 {
				srcPort = fmt.Sprintf("%d", entry.SrcPort)
			}
			dstPort := ""
			if entry.DstPort > 0 {
				dstPort = fmt.Sprintf("%d", entry.DstPort)
			}

			line := fmt.Sprintf(headerFormat,
				truncateString(entry.Time.Format("Jan 02 15:04:05"), 15),
				truncateString(entry.Action, 10),
				truncateString(entry.Interface, 10),
				truncateString(entry.Direction, 5),
				truncateString(entry.Src, 40),
				truncateString(srcPort, 7),
				truncateString(entry.Dst, 40),
				truncateString(dstPort, 7),
				truncateString(entry.ProtoName, 10),
				truncateString(entry.Reason, 20))
			b.WriteString(style.Render(line))
			b.WriteString("\n")
		}

		// fill remaining space
		for i := visibleEnd - visibleStart; i < contentHeight; i++ {
			b.WriteString("\n")
		}
	}

	// status line
	statusText := fmt.Sprintf("position: %d/%d", m.scrollPos+1, len(m.visibleLines))
	if m.errorActive {
		statusText = fmt.Sprintf("position: %d/%d (max. %d stored)", m.errorScrollPos+1, len(m.errorList), stream.MaxErrorsInMemory)
	} else if m.filterEditing {
		statusText = fmt.Sprintf("filter: %s", m.filterInput)
	} else {
		if m.filterError != "" {
			statusText += " | " + m.filterError
		} else if m.statusMsg != "" {
			statusText += " | " + m.statusMsg
		}
	}

	b.WriteString(statusStyle.Render(statusText))
	b.WriteString("\n")

	// help line
	helpText := ""
	if m.errorActive {
		helpText = "↑↓/jk: scroll | d/u: page | g/G: top/bottom | e/esc: back to log view | q: quit"
	} else if m.filterEditing {
		helpText = "enter: apply | esc: cancel | example: iface eth0 and action block and (src 192.168.1.1 or dstport 80)"
	} else {
		helpText = "↑↓/jk: scroll | d/u: page | g/G: top/bottom | /: filter | esc: clear filter | q: quit"
		if len(m.errorList) > 0 {
			errorCount := fmt.Sprintf("%d", len(m.errorList))
			if len(m.errorList) >= stream.MaxErrorsInMemory {
				errorCount += "+"
			}
			helpText += fmt.Sprintf(" | e: show %s parse errors", errorCount)
		}
	}
	b.WriteString(helpText)

	return b.String()
}

// loadingView returns a centered loading message with an animated spinner
func (m model) loadingView() string {
	s := fmt.Sprintf("loading %s", m.spinner.View())

	if m.width == 0 || m.height == 0 {
		return s
	}

	style := lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center)

	return style.Render(s)
}

// async

// buildIndex builds the file index by scanning the entire log file
func buildIndex(s *stream.Stream) tea.Cmd {
	return func() tea.Msg {
		if err := s.BuildIndex(); err != nil {
			return indexErrorMsg{err: err}
		}
		return indexBuiltMsg{totalLines: s.TotalLines()}
	}
}

// loadEntries loads a contiguous block of log entries starting at a specific line
func loadEntries(s *stream.Stream, startLine int, count int) tea.Cmd {
	return func() tea.Msg {
		totalLines := s.TotalLines()
		if startLine < 0 {
			startLine = 0
		}
		if startLine >= totalLines {
			startLine = max(totalLines-count, 0)
		}

		// seek to start position
		if err := s.SeekToLine(startLine); err != nil {
			return indexErrorMsg{err: err}
		}

		// load entries
		entries := make([]stream.LogEntry, 0, count)
		for i := 0; i < count && startLine+i < totalLines; i++ {
			entry := s.Next()
			if entry == nil {
				break
			}
			entries = append(entries, *entry)
		}

		return entriesLoadedMsg{
			entries:   entries,
			startLine: startLine,
		}
	}
}

// loadFilteredEntries loads specific non-contiguous lines from the log file
func loadFilteredEntries(s *stream.Stream, lineNumbers []int) tea.Cmd {
	return func() tea.Msg {
		entries := make(map[int]stream.LogEntry)
		for _, lineNum := range lineNumbers {
			if err := s.SeekToLine(lineNum); err != nil {
				continue
			}
			entry := s.Next()
			if entry != nil {
				entries[lineNum] = *entry
			}
		}

		return entriesFilteredLoadedMsg{entries: entries}
	}
}

// handlers

// handleNormalInput handles keyboard input when in normal viewing mode
func (m model) handleNormalInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if !m.indexBuilt {
		return m, nil
	}

	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit

	case "e":
		// toggle error view
		if len(m.errorList) > 0 {
			m.errorActive = !m.errorActive
			m.errorScrollPos = 0
		}
		return m, nil

	case "j", "down":
		m.scrollDown(1)
		if m.filterActive {
			return m, m.loadVisibleEntries()
		}
		return m, m.checkReloadEntries()

	case "k", "up":
		m.scrollUp(1)
		if m.filterActive {
			return m, m.loadVisibleEntries()
		}
		return m, m.checkReloadEntries()

	case "d", "pgdown":
		m.scrollDown(m.height / 2)
		if m.filterActive {
			return m, m.loadVisibleEntries()
		}
		return m, m.checkReloadEntries()

	case "u", "pgup":
		m.scrollUp(m.height / 2)
		if m.filterActive {
			return m, m.loadVisibleEntries()
		}
		return m, m.checkReloadEntries()

	case "g", "home":
		if m.errorActive {
			m.errorScrollPos = 0
			return m, nil
		}
		m.scrollPos = 0
		if m.filterActive {
			return m, m.loadVisibleEntries()
		}
		return m, m.checkReloadEntries()

	case "G", "end":
		contentHeight := m.height - 3
		if m.errorActive {
			m.errorScrollPos = max(len(m.errorList)-contentHeight, 0)
			return m, nil
		}
		m.scrollPos = max(len(m.visibleLines)-contentHeight, 0)
		if m.filterActive {
			return m, m.loadVisibleEntries()
		}
		return m, m.checkReloadEntries()

	case "/":
		// filter mode
		m.filterEditing = true
		m.statusMsg = "filter: "
		return m, nil

	case "esc":
		// exit error view if active
		if m.errorActive {
			m.errorActive = false
			return m, nil
		}
		// clear filter
		if m.filterActive {
			m.filterInput = ""
			m.filterActive = false
			m.filterCompiled = nil
			m.scrollPos = 0
			m.showAllLines()
			m.statusMsg = ""
			return m, m.checkReloadEntries()
		}
		return m, nil
	}

	return m, nil
}

// handleFilterInput handles keyboard input when in filter input mode
func (m model) handleFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		m.filterEditing = false
		m.filterActive = len(m.filterInput) > 0
		m.scrollPos = 0

		// compile the filter
		if m.filterActive {
			compiled, err := filter.Compile(m.filterInput)
			if err != nil {
				m.filterError = err.Error()
				m.filterActive = false
				m.filterCompiled = nil
			} else {
				m.filterCompiled = compiled
				m.filterError = ""
				m.loading = true
				return m, m.scanAndFilter()
			}
		} else {
			m.filterCompiled = nil
			m.filterError = ""
		}

		if !m.filterActive {
			m.showAllLines()
			m.statusMsg = ""
		}
		return m, m.checkReloadEntries()

	case "esc":
		m.filterEditing = false
		m.filterInput = ""
		m.statusMsg = ""
		return m, nil

	case "backspace":
		if len(m.filterInput) > 0 {
			m.filterInput = m.filterInput[:len(m.filterInput)-1]
		}
		return m, nil

	default:
		if len(msg.String()) == 1 {
			m.filterInput += msg.String()
		}
		return m, nil
	}
}

// handleFilteredMsg updates the model with the filtered results and loads visible entries
func (m model) handleFilteredMsg(msg filteredMsg) (tea.Model, tea.Cmd) {
	m.visibleLines = msg.visibleLines
	m.loading = false
	m.statusMsg = fmt.Sprintf("filter: %q (%d matches)", m.filterInput, len(m.visibleLines))
	m.scrollPos = 0
	m.entriesFiltered = make(map[int]stream.LogEntry)

	if len(m.visibleLines) > 0 {
		m.loading = true
		return m, m.loadVisibleEntries()
	}

	return m, nil
}

// scrolling

func (m *model) scrollDown(n int) {
	contentHeight := m.height - 3 // -3 for header, status, and help line

	if m.errorActive {
		maxScroll := max(len(m.errorList)-contentHeight, 0)
		m.errorScrollPos += n
		if m.errorScrollPos > maxScroll {
			m.errorScrollPos = maxScroll
		}
	} else {
		maxScroll := max(len(m.visibleLines)-contentHeight, 0)
		m.scrollPos += n
		if m.scrollPos > maxScroll {
			m.scrollPos = maxScroll
		}
	}
}

func (m *model) scrollUp(n int) {
	if m.errorActive {
		m.errorScrollPos -= n
		if m.errorScrollPos < 0 {
			m.errorScrollPos = 0
		}
	} else {
		m.scrollPos -= n
		if m.scrollPos < 0 {
			m.scrollPos = 0
		}
	}
}

// view management

// loadVisibleEntries loads entries for currently visible filtered lines
func (m *model) loadVisibleEntries() tea.Cmd {
	if !m.filterActive || len(m.visibleLines) == 0 {
		return nil
	}

	contentHeight := m.height - 3 // -3 for header, status, and help line
	if contentHeight < 1 {
		contentHeight = 10 // default if height not set yet
	}

	visibleStart := m.scrollPos
	visibleEnd := min(m.scrollPos+contentHeight, len(m.visibleLines))

	// get line numbers we need to load
	linesToLoad := make([]int, 0, visibleEnd-visibleStart)
	for i := visibleStart; i < visibleEnd; i++ {
		if i < 0 || i >= len(m.visibleLines) {
			continue
		}
		lineNum := m.visibleLines[i]
		// only load if not already in filtered entries
		if _, exists := m.entriesFiltered[lineNum]; !exists {
			linesToLoad = append(linesToLoad, lineNum)
		}
	}

	if len(linesToLoad) > 0 {
		m.loading = true
		return loadFilteredEntries(m.stream, linesToLoad)
	}
	return nil
}

// checkReloadEntries checks if we need to reload a different block of entries when scrolling in normal mode
func (m *model) checkReloadEntries() tea.Cmd {
	if !m.indexBuilt || m.loading || len(m.visibleLines) == 0 {
		return nil
	}

	contentHeight := m.height - 3 // -3 for header, status, and help line
	visibleStart := m.scrollPos
	visibleEnd := min(m.scrollPos+contentHeight, len(m.visibleLines))

	minLine := m.totalLines
	maxLine := 0
	for i := visibleStart; i < visibleEnd; i++ {
		lineNum := m.visibleLines[i]
		if lineNum < minLine {
			minLine = lineNum
		}
		if lineNum > maxLine {
			maxLine = lineNum
		}
	}

	if minLine < m.entriesStartLine || maxLine >= m.entriesStartLine+len(m.entries) {
		// center around the middle of visible range
		centerLine := (minLine + maxLine) / 2
		newStart := max(centerLine-maxEntriesInMemory/2, 0)
		return loadEntries(m.stream, newStart, maxEntriesInMemory)
	}

	return nil
}

// getEntryAtLine returns the log entry for a specific line number
func (m *model) getEntryAtLine(lineNum int) *stream.LogEntry {
	// if filtering is active, check filtered entries first
	if m.filterActive && len(m.entriesFiltered) > 0 {
		if entry, exists := m.entriesFiltered[lineNum]; exists {
			return &entry
		}
		return nil
	}

	if lineNum < m.entriesStartLine || lineNum >= m.entriesStartLine+len(m.entries) {
		return nil
	}
	idx := lineNum - m.entriesStartLine
	if idx < 0 || idx >= len(m.entries) {
		return nil
	}
	return &m.entries[idx]
}

// filtering

// showAllLines populates visibleLines with all line numbers and is used when initializing or when clearing a filter
func (m *model) showAllLines() {
	m.visibleLines = m.visibleLines[:0]
	for i := 0; i < m.totalLines; i++ {
		m.visibleLines = append(m.visibleLines, i)
	}
}

// scanAndFilter scans the entire file and builds the list of matching line numbers
func (m *model) scanAndFilter() tea.Cmd {
	return func() tea.Msg {
		filtered := make([]int, 0)

		if err := m.stream.SeekToLine(0); err != nil {
			return indexErrorMsg{err: err}
		}

		for i := 0; i < m.totalLines; i++ {
			entry := m.stream.Next()
			if entry == nil {
				break
			}

			if m.filterCompiled.Matches(entry) {
				filtered = append(filtered, i)
			}
		}

		return filteredMsg{visibleLines: filtered}
	}
}

// public

// Display starts the TUI and displays the log file from the given stream
func Display(s *stream.Stream) error {
	defer s.Close()

	sp := spinner.New()
	sp.Spinner = spinner.Line

	m := model{
		entries:         make([]stream.LogEntry, 0, maxEntriesInMemory),
		entriesFiltered: make(map[int]stream.LogEntry),
		filterActive:    false,
		filterInput:     "",
		indexBuilt:      false,
		loading:         true,
		spinner:         sp,
		stream:          s,
		visibleLines:    make([]int, 0),
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}
