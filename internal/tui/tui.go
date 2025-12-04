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

	// column widths (default view)
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

	// contentWidth is the total width of default view
	contentWidth = colWidthTime + colWidthAction + colWidthInterface + colWidthDir + colWidthSource +
		colWidthSrcPort + colWidthDest + colWidthDstPort + colWidthProto + colWidthReason
)

var (
	// headerLineFormat is the format string for rendering the log view header
	headerLineFormat = fmt.Sprintf("%%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds",
		colWidthTime, colWidthAction, colWidthInterface, colWidthDir, colWidthSource,
		colWidthSrcPort, colWidthDest, colWidthDstPort, colWidthProto, colWidthReason,
	)
)

type model struct {
	stream  *stream.Stream // log file stream
	indexed bool           // whether file has been indexed

	// entries
	entries          []stream.LogEntry       // contiguous block of entries (default view)
	entriesStart     int                     // number of first line in entries block
	entriesFiltered  map[int]stream.LogEntry // non-contiguous block of entries matching current filter (filter view)
	entriesTotal     int                     // total number of valid log entries
	entriesAvailable []int                   // line numbers that can be displayed (all lines in default view, matching lines in filter view)

	// filter
	filterApplied  bool              // whether filter is currently applied
	filterCompiled filter.FilterNode // compiled filter expression
	filterError    string            // error message from filter compilation
	filterInput    textinput.Model   // filter input field
	filterView     bool              // whether the user is currently typing filter expression

	// error
	errors     []string // parse errors
	errorsView bool     // whether showing errors instead of logs (error view)

	// ui
	uiHeight         int           // terminal height (in lines)
	uiWidth          int           // terminal width (in chars)
	uiLoading        bool          // whether showing loading spinner (loading view)
	uiLoadingSpinner spinner.Model // loading spinner
	uiScrollH        int           // horizontal scroll position
	uiScrollV        int           // vertical scroll position
	uiStatusMsg      string        // status bar message
	uiStyles         *styles       // styles for rendering
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

// indexMsg is sent when the file has been successfully indexed
type indexMsg struct {
	entriesTotal int // total number of valid log entries
}

// entriesMsg is sent when contiguous block of entries has been loaded
type entriesMsg struct {
	entries      []stream.LogEntry // contiguous block of entries (default view)
	entriesStart int               // number of first line in entries block
}

// entriesFilteredMsg is sent when non-contiguous block of entries matching current filter has been loaded
type entriesFilteredMsg struct {
	entriesFiltered map[int]stream.LogEntry // non-contiguous block of entries matching current filter (filter view)
}

// filterMsg is sent when filtering has completed
type filterMsg struct {
	entriesAvailable []int // line numbers that can be displayed
}

// streamErrorMsg is sent when a stream operation fails (e.g. SeekToLine)
type streamErrorMsg struct {
	err error // error that occurred
}

// bubbletea

// truncateString truncates a string to a maximum length
func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	if length <= 3 {
		return s[:length]
	}
	return s[:length-3] + "..."
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

// loadingView returns a centered loading message with an animated spinner
func (m model) loadingView() string {
	s := fmt.Sprintf("loading %s", m.uiLoadingSpinner.View())
	if m.uiWidth == 0 || m.uiHeight == 0 {
		return s
	}
	style := lipgloss.NewStyle().
		Width(m.uiWidth).
		Height(m.uiHeight).
		Align(lipgloss.Center, lipgloss.Center)
	return style.Render(s)
}

// withLoadingView enables loading state and batches the command with spinner tick
func (m *model) withLoadingView(cmd tea.Cmd) tea.Cmd {
	m.uiLoading = true
	return tea.Batch(cmd, m.uiLoadingSpinner.Tick)
}

// Init starts the indexing process
func (m model) Init() tea.Cmd {
	return m.withLoadingView(index(m.stream))
}

// Update handles all messages (and is the main event loop)
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.uiLoadingSpinner, cmd = m.uiLoadingSpinner.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		if m.filterView {
			return m.handleFilterInput(msg)
		}
		return m.handleNormalInput(msg)

	case tea.WindowSizeMsg:
		m.filterInput.Width = msg.Width - len(m.filterInput.Prompt) - 1 // -1 for cursor
		m.uiHeight = msg.Height
		m.uiWidth = msg.Width
		return m, nil

	case indexMsg:
		m.entriesTotal = msg.entriesTotal
		m.errors = m.stream.GetErrors()
		m.indexed = true
		m.uiLoading = false
		if m.entriesTotal <= 0 {
			m.uiStatusMsg = m.uiStyles.statusError.Render("error: no valid entries found")
			return m, nil
		}
		m.showAllLines()
		return m, loadEntries(m.stream, 0, maxEntriesInMemory)

	case entriesMsg:
		m.entries = msg.entries
		m.entriesStart = msg.entriesStart
		return m, nil

	case entriesFilteredMsg:
		m.uiLoading = false
		// merge new entries into entriesFiltered map
		maps.Copy(m.entriesFiltered, msg.entriesFiltered)
		return m, m.checkLoadEntriesFiltered()

	case filterMsg:
		m.entriesFiltered = make(map[int]stream.LogEntry)
		m.entriesAvailable = msg.entriesAvailable
		m.uiLoading = false
		m.uiScrollH = 0
		m.uiScrollV = 0
		m.uiStatusMsg = fmt.Sprintf("filter: %q (%d matches)", m.filterInput.Value(), len(m.entriesAvailable))
		if len(m.entriesAvailable) > 0 {
			return m, m.withLoadingView(m.checkLoadEntriesFiltered())
		}
		return m, nil

	case streamErrorMsg:
		m.uiLoading = false
		m.uiStatusMsg = m.uiStyles.statusError.Render(msg.err.Error())
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

// View renders the current state of the UI (as a string)
func (m model) View() string {
	// show loading view during initialization or on request
	if m.uiLoading || m.uiWidth == 0 || m.uiHeight == 0 {
		return m.loadingView()
	}

	var b strings.Builder
	var visibleEnd int

	contentHeight := m.uiHeight - 3 // -3 for the header, status, and help lines
	newLine := "\n"
	visibleStart := m.uiScrollV

	if m.errorsView {
		visibleEnd = min(visibleStart+contentHeight, len(m.errors))

		// header
		b.WriteString(m.uiStyles.header.Render("Error") + newLine)

		// main
		for i := visibleStart; i < visibleEnd; i++ {
			line := sliceString(m.errors[i], m.uiScrollH, m.uiWidth)
			b.WriteString(line + newLine)
		}
		for i := visibleEnd - visibleStart; i < contentHeight; i++ {
			b.WriteString(newLine) // fill remaining space
		}
	} else {
		visibleEnd = min(visibleStart+contentHeight, len(m.entriesAvailable))

		// header
		headerLine := fmt.Sprintf(headerLineFormat, "Time", "Action", "Interface", "Dir", "Source", "SrcPort", "Destination", "DstPort", "Proto", "Reason")
		headerLine = sliceString(headerLine, m.uiScrollH, m.uiWidth)
		b.WriteString(m.uiStyles.header.Render(headerLine) + newLine)

		// main
		for i := visibleStart; i < visibleEnd; i++ {
			if i >= len(m.entriesAvailable) {
				break
			}
			lineNum := m.entriesAvailable[i]
			entry := m.getEntryAtLine(lineNum)
			if entry == nil {
				// entry not loaded in memory
				b.WriteString(m.uiStyles.entryLoading.Render("loading...") + newLine)
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
			line := fmt.Sprintf(headerLineFormat,
				truncateString(entry.Time, colWidthTime),
				truncateString(entry.Action, colWidthAction),
				truncateString(entry.Interface, colWidthInterface),
				truncateString(entry.Direction, colWidthDir),
				truncateString(entry.Src, colWidthSource),
				truncateString(srcPort, colWidthSrcPort),
				truncateString(entry.Dst, colWidthDest),
				truncateString(dstPort, colWidthDstPort),
				truncateString(entry.ProtoName, colWidthProto),
				truncateString(entry.Reason, colWidthReason))

			line = sliceString(line, m.uiScrollH, m.uiWidth)
			if entry.Action == stream.ActionBlock {
				line = m.uiStyles.entryBlock.Render(line)
			}
			b.WriteString(line + newLine)
		}
		for i := visibleEnd - visibleStart; i < contentHeight; i++ {
			b.WriteString(newLine) // fill remaining space
		}
	}

	// status
	statusLine := "viewing: %d-%d of %d"
	if m.errorsView {
		statusLine = fmt.Sprintf(statusLine+" (limit: %d)", visibleStart+1, visibleEnd, len(m.errors), stream.MaxErrorsInMemory)
	} else if m.filterView {
		statusLine = m.filterInput.View()
	} else {
		statusLine = fmt.Sprintf(statusLine, visibleStart+1, visibleEnd, len(m.entriesAvailable))
		if m.filterError != "" {
			statusLine += " | " + m.uiStyles.statusError.Render(m.filterError)
		} else if m.uiStatusMsg != "" {
			statusLine += " | " + m.uiStatusMsg
		}
	}
	b.WriteString(m.uiStyles.status.Width(m.uiWidth).Render(statusLine) + newLine)

	// help
	helpLine := "q: quit | k/▲ j/▼ h/◄ l/►: scroll | u/pgup d/pgdn: page | g/home G/end 0 $: jump"
	if m.errorsView {
		helpLine += " | e/esc: back to log view"
	} else if m.filterView {
		helpLine = "enter: apply | esc: cancel | example: iface eth0 and (src 192.168.1.1 or dstport 80)"
	} else {
		helpLine += " | /: filter"
		if m.filterApplied {
			helpLine += " | esc: clear filter"
		}
		if len(m.errors) > 0 {
			errorCount := fmt.Sprintf("%d", len(m.errors))
			if len(m.errors) >= stream.MaxErrorsInMemory {
				errorCount += "+"
			}
			helpLine += " | e: " + m.uiStyles.statusError.Render(fmt.Sprintf("show %s errors", errorCount))
		}
	}
	b.WriteString(helpLine)

	return b.String()
}

// async

// index builds the file index
func index(s *stream.Stream) tea.Cmd {
	return func() tea.Msg {
		if err := s.BuildIndex(); err != nil {
			return streamErrorMsg{err: err}
		}
		return indexMsg{entriesTotal: s.TotalLines()}
	}
}

// loadEntries loads a contiguous block of log entries starting at a specific line
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

// loadEntriesFiltered loads non-contiguous block of entries matching current filter
func loadEntriesFiltered(s *stream.Stream, lineNums []int) tea.Cmd {
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
		return entriesFilteredMsg{entriesFiltered: entries}
	}
}

// handlers

// handleNormalInput handles keyboard input when in default view
func (m model) handleNormalInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if !m.indexed {
		return m, nil
	}

	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit

	case "e":
		if len(m.errors) > 0 {
			m.errorsView = !m.errorsView
			m.uiScrollH = 0
			m.uiScrollV = 0
		}
		return m, nil

	case "j", "down":
		m.scrollDown(1)
		if m.filterApplied {
			return m, m.checkLoadEntriesFiltered()
		}
		return m, m.checkLoadEntries()

	case "k", "up":
		m.scrollUp(1)
		if m.filterApplied {
			return m, m.checkLoadEntriesFiltered()
		}
		return m, m.checkLoadEntries()

	case "d", "pgdown":
		m.scrollDown(m.uiHeight / 2)
		if m.filterApplied {
			return m, m.checkLoadEntriesFiltered()
		}
		return m, m.checkLoadEntries()

	case "u", "pgup":
		m.scrollUp(m.uiHeight / 2)
		if m.filterApplied {
			return m, m.checkLoadEntriesFiltered()
		}
		return m, m.checkLoadEntries()

	case "g", "home":
		m.uiScrollV = 0
		if m.errorsView {
			return m, nil
		}
		if m.filterApplied {
			return m, m.checkLoadEntriesFiltered()
		}
		return m, m.checkLoadEntries()

	case "G", "end":
		var lines int
		if m.errorsView {
			lines = len(m.errors)
		} else {
			lines = len(m.entriesAvailable)
		}
		contentHeight := m.uiHeight - 3 // -3 for header, status, and help line
		m.uiScrollV = max(lines-contentHeight, 0)
		if m.errorsView {
			return m, nil
		}
		if m.filterApplied {
			return m, m.checkLoadEntriesFiltered()
		}
		return m, m.checkLoadEntries()

	case "h", "left":
		if contentWidth > m.uiWidth {
			m.uiScrollH = max(m.uiScrollH-1, 0)
		}
		return m, nil

	case "l", "right":
		if contentWidth > m.uiWidth {
			m.uiScrollH = min(m.uiScrollH+1, contentWidth-m.uiWidth)
		}
		return m, nil

	case "0":
		m.uiScrollH = 0
		return m, nil

	case "$":
		if contentWidth > m.uiWidth {
			m.uiScrollH = contentWidth - m.uiWidth
		}
		return m, nil

	case "/":
		if !m.errorsView {
			m.filterView = true
			return m, m.filterInput.Focus()
		}
		return m, nil

	case "esc":
		if m.errorsView {
			m.errorsView = false
			return m, nil
		}
		if m.filterApplied {
			m.filterApplied = false
			m.filterCompiled = nil
			m.filterInput.SetValue("")
			m.uiScrollH = 0
			m.uiScrollV = 0
			m.uiStatusMsg = ""
			m.showAllLines()
			return m, m.checkLoadEntries()
		}
		return m, nil
	}

	return m, nil
}

// handleFilterInput handles keyboard input when in filter view
func (m model) handleFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		filterValue := m.filterInput.Value()
		m.filterApplied = len(filterValue) > 0
		m.filterInput.Blur()
		m.filterView = false
		m.uiScrollH = 0
		m.uiScrollV = 0
		// compile the filter
		if m.filterApplied {
			compiled, err := filter.Compile(filterValue)
			if err != nil {
				m.filterError = err.Error()
				m.filterApplied = false
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
		if !m.filterApplied {
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

// scrolling

func (m *model) scrollDown(n int) {
	var lines int
	if m.errorsView {
		lines = len(m.errors)
	} else {
		lines = len(m.entriesAvailable)
	}
	contentHeight := m.uiHeight - 3 // -3 for header, status, and help line
	maxScroll := max(lines-contentHeight, 0)
	m.uiScrollV = min(m.uiScrollV+n, maxScroll)
}

func (m *model) scrollUp(n int) {
	m.uiScrollV = max(m.uiScrollV-n, 0)
}

// view management

// checkLoadEntries checks if the currently loaded contiguous block needs reloading and returns a command to load it if needed
func (m model) checkLoadEntries() tea.Cmd {
	if !m.indexed || m.uiLoading || len(m.entriesAvailable) == 0 {
		return nil
	}
	contentHeight := m.uiHeight - 3 // -3 for header, status, and help line
	visibleStart := m.uiScrollV
	visibleEnd := min(visibleStart+contentHeight, len(m.entriesAvailable))
	minLine := m.entriesTotal
	maxLine := 0
	for i := visibleStart; i < visibleEnd; i++ {
		lineNum := m.entriesAvailable[i]
		minLine = min(minLine, lineNum)
		maxLine = max(maxLine, lineNum)
	}
	if minLine < m.entriesStart || maxLine >= m.entriesStart+len(m.entries) {
		// center around the middle of visible range
		centerLine := (minLine + maxLine) / 2
		newStart := max(centerLine-maxEntriesInMemory/2, 0)
		return loadEntries(m.stream, newStart, maxEntriesInMemory)
	}
	return nil
}

// checkLoadEntriesFiltered checks if any visible filtered entries are missing and returns a command to load them if needed
func (m model) checkLoadEntriesFiltered() tea.Cmd {
	if !m.filterApplied || len(m.entriesAvailable) == 0 {
		return nil
	}
	contentHeight := m.uiHeight - 3 // -3 for header, status, and help line
	visibleStart := m.uiScrollV
	visibleEnd := min(visibleStart+contentHeight, len(m.entriesAvailable))
	linesToLoad := make([]int, 0, visibleEnd-visibleStart)
	for i := visibleStart; i < visibleEnd; i++ {
		if i < 0 || i >= len(m.entriesAvailable) {
			continue
		}
		lineNum := m.entriesAvailable[i]
		// only load if not already in filtered entries
		if _, exists := m.entriesFiltered[lineNum]; !exists {
			linesToLoad = append(linesToLoad, lineNum)
		}
	}
	if len(linesToLoad) > 0 {
		return m.withLoadingView(loadEntriesFiltered(m.stream, linesToLoad))
	}
	return nil
}

// getEntryAtLine returns the log entry for a specific line number
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

// showAllLines populates visibleLines with all line numbers and is used when initializing or when clearing a filter
func (m *model) showAllLines() {
	m.entriesAvailable = m.entriesAvailable[:0]
	for i := 0; i < m.entriesTotal; i++ {
		m.entriesAvailable = append(m.entriesAvailable, i)
	}
}

// scanAndFilter scans the entire file and builds the list of matching line numbers
func (m model) scanAndFilter() tea.Cmd {
	return func() tea.Msg {
		entries := make([]int, 0)
		if err := m.stream.SeekToLine(0); err != nil {
			return streamErrorMsg{err: err}
		}
		for i := 0; i < m.entriesTotal; i++ {
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
		stream:           s,
		indexed:          false,
		entries:          make([]stream.LogEntry, 0, maxEntriesInMemory),
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
