package tui

import (
	"fmt"
	"maps"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"gitlab.com/allddd/opnsense-filterlog/internal/filter"
	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
)

const (
	maxEntriesInMemory = 1000

	// log view column widths
	colWidthTime      = 16
	colWidthAction    = 10
	colWidthInterface = 10
	colWidthDir       = 5
	colWidthSource    = 40
	colWidthSrcPort   = 7
	colWidthDest      = 40
	colWidthDstPort   = 7
	colWidthProto     = 10
	colWidthReason    = 20

	// contentWidth is the total width of the log view
	contentWidth = colWidthTime + colWidthAction + colWidthInterface + colWidthDir + colWidthSource +
		colWidthSrcPort + colWidthDest + colWidthDstPort + colWidthProto + colWidthReason
)

var (
	// headerFormat is the format string for rendering the log view header
	headerFormat = fmt.Sprintf("%%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds",
		colWidthTime, colWidthAction, colWidthInterface, colWidthDir, colWidthSource,
		colWidthSrcPort, colWidthDest, colWidthDstPort, colWidthProto, colWidthReason,
	)
)

type model struct {
	entriesFiltered  map[int]stream.LogEntry // filtered entries
	entriesList      []stream.LogEntry       // log entries
	entriesListStart int                     // line number where the entries starts
	indexBuilt       bool                    // whether the file has been indexed
	stream           *stream.Stream          // log file stream
	totalLines       int                     // number of valid log entries
	visibleLines     []int                   // numbers of lines to display on screen

	// filter
	filterActive   bool              // whether a filter is currently applied
	filterCompiled filter.FilterNode // compiled filter expression
	filterError    string            // error message from filter compilation
	filterInput    textinput.Model   // filter expression input field
	filterView     bool              // whether the user is currently typing a filter expression

	// error
	errorView bool     // whether we're viewing parse errors instead of logs
	errorList []string // parse errors encountered while indexing the log file

	// view
	width      int           // terminal width (in chars)
	height     int           // terminal height (in lines)
	vScrollPos int           // vertical scroll position
	hScrollPos int           // horizontal scroll position
	loading    bool          // whether the loading view should be displayed
	statusMsg  string        // status message to display in the status bar
	spinner    spinner.Model // loading spinner
	style      *styles       // styles for rendering
}

type styles struct {
	header       lipgloss.Style
	status       lipgloss.Style
	statusError  lipgloss.Style
	entryBlock   lipgloss.Style
	entryLoading lipgloss.Style
}

// message
// messages are processed in the Update method and represent events that update the model

// indexBuiltMsg is sent when the file has been successfully indexed
type indexBuiltMsg struct {
	total int // number of valid log entries found
}

// indexErrorMsg is sent when indexing fails
type indexErrorMsg struct {
	err error // the error that occurred
}

// entriesLoadedMsg is sent when a block of entries has been loaded
type entriesLoadedMsg struct {
	entries []stream.LogEntry // loaded log entries
	start   int               // line number of the first entry
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

// sliceString returns a substring starting at offset and up to width chars
func sliceString(s string, offset int, width int) string {
	if offset <= 0 && width >= len(s) {
		return s
	}
	if offset >= len(s) {
		return ""
	}
	return s[offset:min(offset+width, len(s))]
}

func newStyles() *styles {
	return &styles{
		header: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("46")),
		status: lipgloss.NewStyle().
			// width must be set before rendering
			Background(lipgloss.Color("237")).
			Foreground(lipgloss.Color("252")),
		statusError: lipgloss.NewStyle().
			Background(lipgloss.Color("196")).
			Foreground(lipgloss.Color("231")),
		entryBlock: lipgloss.NewStyle().
			Foreground(lipgloss.Color("202")),
		entryLoading: lipgloss.NewStyle().
			Foreground(lipgloss.Color("244")),
	}
}

// Init starts the indexing process
func (m model) Init() tea.Cmd {
	return m.withLoadingView(buildIndex(m.stream))
}

// withLoadingView enables loading state and batches the command with spinner tick
func (m *model) withLoadingView(cmd tea.Cmd) tea.Cmd {
	m.loading = true
	return tea.Batch(cmd, m.spinner.Tick)
}

// Update handles all messages (and is the main event loop)
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		if m.filterView {
			return m.handleFilterInput(msg)
		}
		return m.handleNormalInput(msg)

	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.width = msg.Width
		m.filterInput.Width = m.width - len(m.filterInput.Prompt) - 1 // -1 for cursor
		return m, nil

	case indexBuiltMsg:
		m.errorList = m.stream.GetErrors()
		m.indexBuilt = true
		m.loading = false
		m.totalLines = msg.total

		if m.totalLines <= 0 {
			m.statusMsg = m.style.statusError.Render("error: no valid entries found")
			return m, nil
		}
		m.showAllLines()
		return m, loadEntries(m.stream, 0, maxEntriesInMemory)

	case indexErrorMsg:
		m.loading = false
		m.statusMsg = m.style.statusError.Render(msg.err.Error())
		return m, nil

	case entriesLoadedMsg:
		m.entriesList = msg.entries
		m.entriesListStart = msg.start
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
		if m.filterView {
			var cmd tea.Cmd
			m.filterInput, cmd = m.filterInput.Update(msg)
			return m, cmd
		}
		return m, nil
	}
}

// View renders the current state of the UI (as a string)
func (m model) View() string {
	// show loading view during initialization or on request
	if m.loading || m.width == 0 || m.height == 0 {
		return m.loadingView()
	}

	contentHeight := m.height - 3 // -3 for the header, status, and help lines
	newLine := "\n"
	var b strings.Builder

	if m.errorView {
		b.WriteString(m.style.header.Render("Error") + newLine)

		visibleStart := m.vScrollPos
		visibleEnd := min(m.vScrollPos+contentHeight, len(m.errorList))

		for i := visibleStart; i < visibleEnd; i++ {
			line := sliceString(m.errorList[i], m.hScrollPos, m.width)
			b.WriteString(line + newLine)
		}

		// fill remaining space
		for i := visibleEnd - visibleStart; i < contentHeight; i++ {
			b.WriteString(newLine)
		}
	} else {
		headerLine := fmt.Sprintf(headerFormat, "Time", "Action", "Interface", "Dir", "Source", "SrcPort", "Destination", "DstPort", "Proto", "Reason")
		headerLine = sliceString(headerLine, m.hScrollPos, m.width)
		b.WriteString(m.style.header.Render(headerLine) + newLine)

		visibleStart := m.vScrollPos
		visibleEnd := min(m.vScrollPos+contentHeight, len(m.visibleLines))

		for i := visibleStart; i < visibleEnd; i++ {
			if i >= len(m.visibleLines) {
				break
			}

			lineNum := m.visibleLines[i]
			entry := m.getEntryAtLine(lineNum)
			if entry == nil {
				// entry not in memory
				b.WriteString(m.style.entryLoading.Render("loading...") + newLine)
				continue
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
				truncateString(entry.Time.Format("Jan 02 15:04:05"), colWidthTime),
				truncateString(entry.Action, colWidthAction),
				truncateString(entry.Interface, colWidthInterface),
				truncateString(entry.Direction, colWidthDir),
				truncateString(entry.Src, colWidthSource),
				truncateString(srcPort, colWidthSrcPort),
				truncateString(entry.Dst, colWidthDest),
				truncateString(dstPort, colWidthDstPort),
				truncateString(entry.ProtoName, colWidthProto),
				truncateString(entry.Reason, colWidthReason))

			line = sliceString(line, m.hScrollPos, m.width)
			if entry.Action == stream.ActionBlock {
				line = m.style.entryBlock.Render(line)
			}
			b.WriteString(line + newLine)
		}

		// fill remaining space
		for i := visibleEnd - visibleStart; i < contentHeight; i++ {
			b.WriteString(newLine)
		}
	}

	// status line
	statusText := fmt.Sprintf("position: %d/%d", m.vScrollPos+1, len(m.visibleLines))
	if m.errorView {
		statusText = fmt.Sprintf("position: %d/%d (max. %d stored)", m.vScrollPos+1, len(m.errorList), stream.MaxErrorsInMemory)
	} else if m.filterView {
		statusText = m.filterInput.View()
	} else {
		if m.filterError != "" {
			statusText += " | " + m.style.statusError.Render(m.filterError)
		} else if m.statusMsg != "" {
			statusText += " | " + m.statusMsg
		}
	}
	b.WriteString(m.style.status.Width(m.width).Render(statusText) + newLine)

	// help line
	helpText := "q: quit | k/▲ j/▼ h/◄ l/►: scroll | u/pgup d/pgdn: page | g/home G/end 0 $: jump"
	if m.errorView {
		helpText += " | e/esc: back to log view"
	} else if m.filterView {
		helpText = "enter: apply | esc: cancel | example: iface eth0 and (src 192.168.1.1 or dstport 80)"
	} else {
		helpText += " | /: filter"
		if m.filterActive {
			helpText += " | esc: clear filter"
		}
		if len(m.errorList) > 0 {
			errorCount := fmt.Sprintf("%d", len(m.errorList))
			if len(m.errorList) >= stream.MaxErrorsInMemory {
				errorCount += "+"
			}
			helpText += " | e: " + m.style.statusError.Render(fmt.Sprintf("show %s errors", errorCount))
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
		return indexBuiltMsg{total: s.TotalLines()}
	}
}

// loadEntries loads a contiguous block of log entries starting at a specific line
func loadEntries(s *stream.Stream, startLine int, count int) tea.Cmd {
	return func() tea.Msg {
		totalLines := s.TotalLines()
		startLine = max(startLine, 0)
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
			entries: entries,
			start:   startLine,
		}
	}
}

// loadFilteredEntries loads specific non-contiguous lines from the log file
func loadFilteredEntries(s *stream.Stream, lineNums []int) tea.Cmd {
	return func() tea.Msg {
		entries := make(map[int]stream.LogEntry)
		for _, lineNum := range lineNums {
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
			m.errorView = !m.errorView
			m.vScrollPos = 0
			m.hScrollPos = 0
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
		m.vScrollPos = 0
		if m.errorView {
			return m, nil
		}
		if m.filterActive {
			return m, m.loadVisibleEntries()
		}
		return m, m.checkReloadEntries()

	case "G", "end":
		var lines int
		if m.errorView {
			lines = len(m.errorList)
		} else {
			lines = len(m.visibleLines)
		}
		contentHeight := m.height - 3 // -3 for header, status, and help line
		m.vScrollPos = max(lines-contentHeight, 0)
		if m.errorView {
			return m, nil
		}
		if m.filterActive {
			return m, m.loadVisibleEntries()
		}
		return m, m.checkReloadEntries()

	case "h", "left":
		if contentWidth > m.width {
			m.hScrollPos = max(m.hScrollPos-1, 0)
		}
		return m, nil

	case "l", "right":
		if contentWidth > m.width {
			m.hScrollPos = min(m.hScrollPos+1, contentWidth-m.width)
		}
		return m, nil

	case "0":
		m.hScrollPos = 0
		return m, nil

	case "$":
		if contentWidth > m.width {
			m.hScrollPos = contentWidth - m.width
		}
		return m, nil

	case "/":
		m.filterView = true
		return m, m.filterInput.Focus()

	case "esc":
		// exit error view
		if m.errorView {
			m.errorView = false
			return m, nil
		}
		// clear filter
		if m.filterActive {
			m.filterInput.SetValue("")
			m.filterActive = false
			m.filterCompiled = nil
			m.vScrollPos = 0
			m.hScrollPos = 0
			m.statusMsg = ""
			m.showAllLines()
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
		m.filterView = false
		m.filterInput.Blur()
		filterValue := m.filterInput.Value()
		m.filterActive = len(filterValue) > 0
		m.vScrollPos = 0
		m.hScrollPos = 0

		// compile the filter
		if m.filterActive {
			compiled, err := filter.Compile(filterValue)
			if err != nil {
				m.filterError = err.Error()
				m.filterActive = false
				m.filterCompiled = nil
			} else {
				m.filterCompiled = compiled
				m.filterError = ""
				return m, m.withLoadingView(m.scanAndFilter())
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
		m.filterView = false
		m.filterInput.Blur()
		m.filterInput.SetValue("")
		m.statusMsg = ""
		return m, nil

	default:
		// let textinput handle all other keys
		var cmd tea.Cmd
		m.filterInput, cmd = m.filterInput.Update(msg)
		return m, cmd
	}
}

// handleFilteredMsg updates the model with the filtered results and loads visible entries
func (m model) handleFilteredMsg(msg filteredMsg) (tea.Model, tea.Cmd) {
	m.visibleLines = msg.visibleLines
	m.loading = false
	m.statusMsg = fmt.Sprintf("filter: %q (%d matches)", m.filterInput.Value(), len(m.visibleLines))
	m.vScrollPos = 0
	m.hScrollPos = 0
	m.entriesFiltered = make(map[int]stream.LogEntry)

	if len(m.visibleLines) > 0 {
		return m, m.withLoadingView(m.loadVisibleEntries())
	}

	return m, nil
}

// scrolling

func (m *model) scrollDown(n int) {
	var lines int
	if m.errorView {
		lines = len(m.errorList)
	} else {
		lines = len(m.visibleLines)
	}
	contentHeight := m.height - 3 // -3 for header, status, and help line
	maxScroll := max(lines-contentHeight, 0)
	m.vScrollPos = min(m.vScrollPos+n, maxScroll)
}

func (m *model) scrollUp(n int) {
	m.vScrollPos = max(m.vScrollPos-n, 0)
}

// view management

// loadVisibleEntries loads entries for currently visible filtered lines
func (m model) loadVisibleEntries() tea.Cmd {
	if !m.filterActive || len(m.visibleLines) == 0 {
		return nil
	}
	contentHeight := m.height - 3 // -3 for header, status, and help line
	visibleStart := m.vScrollPos
	visibleEnd := min(m.vScrollPos+contentHeight, len(m.visibleLines))
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
		return m.withLoadingView(loadFilteredEntries(m.stream, linesToLoad))
	}
	return nil
}

// checkReloadEntries checks if we need to reload a different block of entries when scrolling in normal mode
func (m model) checkReloadEntries() tea.Cmd {
	if !m.indexBuilt || m.loading || len(m.visibleLines) == 0 {
		return nil
	}

	contentHeight := m.height - 3 // -3 for header, status, and help line
	visibleStart := m.vScrollPos
	visibleEnd := min(m.vScrollPos+contentHeight, len(m.visibleLines))

	minLine := m.totalLines
	maxLine := 0
	for i := visibleStart; i < visibleEnd; i++ {
		lineNum := m.visibleLines[i]
		minLine = min(minLine, lineNum)
		maxLine = max(maxLine, lineNum)
	}

	if minLine < m.entriesListStart || maxLine >= m.entriesListStart+len(m.entriesList) {
		// center around the middle of visible range
		centerLine := (minLine + maxLine) / 2
		newStart := max(centerLine-maxEntriesInMemory/2, 0)
		return loadEntries(m.stream, newStart, maxEntriesInMemory)
	}

	return nil
}

// getEntryAtLine returns the log entry for a specific line number
func (m model) getEntryAtLine(lineNum int) *stream.LogEntry {
	// if filtering is active, check filtered entries first
	if m.filterActive && len(m.entriesFiltered) > 0 {
		if entry, exists := m.entriesFiltered[lineNum]; exists {
			return &entry
		}
		return nil
	}

	if lineNum < m.entriesListStart || lineNum >= m.entriesListStart+len(m.entriesList) {
		return nil
	}
	idx := lineNum - m.entriesListStart
	if idx < 0 || idx >= len(m.entriesList) {
		return nil
	}
	return &m.entriesList[idx]
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
func (m model) scanAndFilter() tea.Cmd {
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

	st := newStyles()

	sp := spinner.New()
	sp.Spinner = spinner.Dot

	ti := textinput.New()
	ti.Prompt = "filter: "
	ti.TextStyle = st.status
	ti.Cursor.Style = st.status
	ti.Cursor.TextStyle = st.status

	m := model{
		entriesFiltered: make(map[int]stream.LogEntry),
		entriesList:     make([]stream.LogEntry, 0, maxEntriesInMemory),
		indexBuilt:      false,
		stream:          s,
		visibleLines:    make([]int, 0),
		filterActive:    false,
		filterInput:     ti,
		loading:         true,
		spinner:         sp,
		style:           st,
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}
