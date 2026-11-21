// Package tui implements the interactive enki dashboard.
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/remediate"
	"github.com/yogenpoonudurai/enki/internal/report"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

// ScanFunc runs a full host scan, optionally emitting per-module progress.
type ScanFunc func(ctx context.Context, onProgress func(scanner.Progress)) (*report.Report, error)

type moduleRow struct {
	name     string
	state    scanner.ProgressState
	detail   string
	findings int
	duration time.Duration
}

type progressMsg scanner.Progress

type resultMsg struct {
	rep *report.Report
	err error
}

// Model is the dashboard state.
type Model struct {
	version string
	scan    ScanFunc
	ch      chan tea.Msg
	spinner spinner.Model

	width  int
	height int

	modules []*moduleRow
	byName  map[string]*moduleRow

	rep      *report.Report
	err      error
	scanning bool
	started  time.Time

	sel        int
	detail     bool
	showFixes  bool
	fixPlan    []remediate.Action
	fixStatus  map[int]string
	fixPending int
	fixMessage string
}

// New builds the dashboard model.
func New(version string, scan ScanFunc) *Model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	return &Model{
		version: version,
		scan:    scan,
		ch:      make(chan tea.Msg, 256),
		spinner: sp,
		byName:  map[string]*moduleRow{},
	}
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.startScan())
}

func (m *Model) startScan() tea.Cmd {
	m.scanning = true
	m.started = time.Now()
	m.rep = nil
	m.err = nil
	m.modules = nil
	m.byName = map[string]*moduleRow{}
	m.sel = 0
	m.detail = false
	m.showFixes = false
	m.fixPlan = nil
	m.fixStatus = map[int]string{}
	m.fixPending = 0
	m.fixMessage = ""

	ch := m.ch
	scan := m.scan
	go func() {
		rep, err := scan(context.Background(), func(p scanner.Progress) {
			ch <- progressMsg(p)
		})
		ch <- resultMsg{rep: rep, err: err}
	}()
	return waitFor(ch)
}

func waitFor(ch chan tea.Msg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case progressMsg:
		m.applyProgress(scanner.Progress(msg))
		return m, waitFor(m.ch)
	case resultMsg:
		m.scanning = false
		m.rep = msg.rep
		m.err = msg.err
		if msg.rep != nil {
			for _, mi := range msg.rep.Modules {
				row, ok := m.byName[mi.Name]
				if !ok {
					continue
				}
				row.findings = mi.Findings
				row.duration = time.Duration(mi.DurationMS) * time.Millisecond
				row.state = scanner.StateDone
				if mi.Error != "" {
					row.state = scanner.StateError
					row.detail = mi.Error
				}
			}
			m.fixPlan = remediate.BuildPlan(msg.rep)
			m.fixStatus = map[int]string{}
			m.fixPending = 0
			m.fixMessage = ""
		}
	case tea.KeyMsg:
		if m.showFixes && m.handleFixKey(msg.String()) {
			return m, nil
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "r":
			return m, m.startScan()
		case "up", "k":
			if m.sel > 0 {
				m.sel--
			}
		case "down", "j":
			if m.rep != nil && m.sel < len(m.rep.Findings)-1 {
				m.sel++
			}
		case "home", "g":
			m.sel = 0
		case "end", "G":
			if m.rep != nil {
				m.sel = len(m.rep.Findings) - 1
			}
		case "enter", "right", "l":
			m.detail = !m.detail
		case "f":
			m.showFixes = !m.showFixes
		case "esc", "left", "h":
			m.showFixes = false
			m.detail = false
			m.fixPending = 0
		}
	}
	return m, nil
}

func (m *Model) applyProgress(p scanner.Progress) {
	row, ok := m.byName[p.Module]
	if !ok {
		row = &moduleRow{name: p.Module}
		m.byName[p.Module] = row
		m.modules = append(m.modules, row)
	}
	row.state = p.State
	if p.Detail != "" {
		row.detail = p.Detail
	}
}

func (m *Model) View() string {
	w := m.width
	if w <= 0 {
		w = 88
	}
	if w < 64 {
		w = 64
	}

	var b strings.Builder
	b.WriteString(m.renderHeader(w))
	b.WriteString("\n")
	b.WriteString(bold(report.Brand) + dim(" - "+report.Tagline+" · v"+m.version))
	b.WriteString("\n\n")

	meta := "hosting scan…"
	status := "scanning " + m.started.Format("15:04:05")
	if m.rep != nil {
		meta = fmt.Sprintf("%s · %s/%s · %s", m.rep.Scan.Host, m.rep.Scan.OS, m.rep.Scan.Arch, m.rep.Scan.User)
		status = fmt.Sprintf("scan %s · %dms", m.rep.Scan.ID, m.rep.Scan.DurationMS)
	}
	fmt.Fprintf(&b, "%s\n%s\n\n", bold(meta), dim(status))

	columns := lipgloss.JoinHorizontal(lipgloss.Top,
		m.renderModules(), "    ", m.renderSummary())
	b.WriteString(columns)
	b.WriteString("\n\n")

	if m.err != nil {
		b.WriteString(sevStyle(finding.SeverityCritical).Render("scan error: "+m.err.Error()) + "\n\n")
	}

	if m.showFixes {
		b.WriteString(m.renderFixes(w))
	} else {
		b.WriteString(m.renderFindings(w))
	}
	b.WriteString("\n")

	if m.detail && m.rep != nil && m.sel >= 0 && m.sel < len(m.rep.Findings) {
		b.WriteString(m.renderDetail(m.rep.Findings[m.sel], w))
		b.WriteString("\n")
	}

	footer := "↑↓/jk move · enter details · f fixes · r rescan · q quit"
	if m.showFixes {
		footer = "1-9 apply · a apply safe · u undo · esc back · r rescan · q quit"
	}
	state := ""
	switch {
	case m.scanning:
		state = m.spinner.View() + " scanning…"
	case m.rep != nil:
		state = fmt.Sprintf("%d findings · posture %d/100 · %s", len(m.rep.Findings), m.rep.Summary.Score, m.rep.Summary.Verdict)
	}
	fmt.Fprintf(&b, "\n%s\n%s", dim(footer), state)
	return b.String()
}

func (m *Model) renderHeader(w int) string {
	if w >= report.SmallLogoWidth() && m.height >= len(report.SmallLogoLines())+12 {
		lines := report.SmallLogoGradient(true)
		var b strings.Builder
		for i, line := range lines {
			b.WriteString(line)
			if i < len(lines)-1 {
				b.WriteString("\n")
			}
		}
		return b.String()
	}
	return strings.Join(report.GradientLines(true, report.BannerLines), "\n")
}

func (m *Model) renderModules() string {
	var b strings.Builder
	b.WriteString(bold("MODULES") + "\n")
	for _, row := range m.modules {
		icon := "·"
		switch row.state {
		case scanner.StateRunning:
			icon = m.spinner.View()
		case scanner.StateDone:
			icon = "✔"
		case scanner.StateError:
			icon = "✖"
		}
		tail := row.detail
		if !m.scanning && row.findings > 0 {
			tail = fmt.Sprintf("%d", row.findings)
		}
		line := fmt.Sprintf("%s %-20s %s", icon, row.name, dim(tail))
		b.WriteString(strings.TrimRight(line, " ") + "\n")
	}
	if len(m.modules) == 0 {
		b.WriteString(dim("waiting for modules…") + "\n")
	}
	return b.String()
}

func (m *Model) renderSummary() string {
	var b strings.Builder
	b.WriteString(bold("FINDINGS") + "\n")
	if m.rep == nil {
		b.WriteString(dim("waiting for results…"))
		return b.String()
	}
	fmt.Fprintf(&b, "%s %d/100\n", bold("POSTURE"), m.rep.Summary.Score)
	order := []finding.Severity{
		finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
		finding.SeverityLow, finding.SeverityInfo,
	}
	max := 1
	for _, s := range order {
		if c := m.rep.Summary.Counts[string(s)]; c > max {
			max = c
		}
	}
	for _, s := range order {
		count := m.rep.Summary.Counts[string(s)]
		barLen := count * 10 / max
		if count > 0 && barLen == 0 {
			barLen = 1
		}
		bar := sevStyle(s).Render(strings.Repeat("█", barLen))
		fmt.Fprintf(&b, "%-8s %3d %s\n", sevStyle(s).Render(label(s)), count, bar)
	}
	return b.String()
}

func (m *Model) renderFindings(w int) string {
	var b strings.Builder
	b.WriteString(bold("FINDINGS") + "\n")
	if m.rep == nil {
		return b.String() + dim("scan in progress…")
	}
	if len(m.rep.Findings) == 0 {
		return b.String() + dim("no findings — clean AI posture")
	}

	window := 10
	if m.height > 0 && m.height < len(report.SmallLogoLines())+40 {
		window = 6
	}
	start := 0
	if m.sel >= window {
		start = m.sel - window + 1
	}
	end := start + window
	if end > len(m.rep.Findings) {
		end = len(m.rep.Findings)
	}
	maxTitle := w - 34
	if maxTitle < 24 {
		maxTitle = 24
	}
	for i := start; i < end; i++ {
		f := m.rep.Findings[i]
		marker := "  "
		line := fmt.Sprintf("%s %s %-8s %s", marker, sevStyle(f.Severity).Render(padPlain(label(f.Severity), 7)), f.RuleID, truncPlain(f.Title, maxTitle))
		if i == m.sel {
			line = "▸ " + strings.TrimPrefix(line, "  ")
			line = lipgloss.NewStyle().Bold(true).Render(line)
		}
		b.WriteString(line + "\n")
	}
	if len(m.rep.Findings) > window {
		fmt.Fprintf(&b, "%s\n", dim(fmt.Sprintf("… %d–%d of %d (↑↓ to scroll)", start+1, end, len(m.rep.Findings))))
	}
	return b.String()
}

func (m *Model) renderDetail(f finding.Finding, w int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n", sevStyle(f.Severity).Render(label(f.Severity)), bold(f.RuleID+" · "+f.Title))
	if loc := f.Location.String(); loc != "" {
		b.WriteString(dim(loc) + "\n")
	}
	b.WriteString("\n" + wrapPlain(f.Description, w-6) + "\n")
	if f.Evidence != "" {
		b.WriteString("\n" + dim("evidence: "+wrapPlain(f.Evidence, w-16)) + "\n")
	}
	if f.Remediation != nil {
		fmt.Fprintf(&b, "\n%s %s\n", bold("respond ("+string(f.Remediation.Class)+"):"), f.Remediation.Summary)
		if f.Remediation.Command != "" {
			b.WriteString(dim("run: "+f.Remediation.Command) + "\n")
		}
		if f.Remediation.Guidance != "" {
			b.WriteString(dim(wrapPlain(f.Remediation.Guidance, w-6)) + "\n")
		}
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#5f5f5f")).
		Padding(0, 1).
		Width(w - 6).
		Render(strings.TrimRight(b.String(), "\n"))
}

func (m *Model) renderFixes(w int) string {
	var b strings.Builder
	b.WriteString(bold("FIX PLAN") + "\n")
	if len(m.fixPlan) == 0 {
		b.WriteString(dim("no automated or guided remediations"))
		return b.String()
	}
	for i, a := range m.fixPlan {
		line := fmt.Sprintf("[%d] %-8s %s", i+1, remediate.DisplayClass(a), truncPlain(a.Summary, w-46))
		if status := m.fixStatus[i]; status != "" {
			line += "  → " + status
		}
		b.WriteString(sevStyle(actionSeverity(a)).Render(line) + "\n")
		if a.Command != "" {
			b.WriteString(dim("     run: "+truncPlain(a.Command, w-12)) + "\n")
		}
	}
	b.WriteString("\n")
	if m.fixPending > 0 && m.fixPending <= len(m.fixPlan) {
		a := m.fixPlan[m.fixPending-1]
		fmt.Fprintf(&b, "%s\n", bold(fmt.Sprintf("Apply [%d] %q?", m.fixPending, truncPlain(a.Summary, w-24)))+"  [y] yes · [n] cancel")
	} else {
		b.WriteString(dim("press 1-9 to apply · a applies all SAFE actions · u undoes the last change"))
	}
	if m.fixMessage != "" {
		b.WriteString("\n" + dim(m.fixMessage))
	}
	return b.String()
}

// handleFixKey processes fix-panel keys. It returns true when the key was
// consumed by the fix panel.
func (m *Model) handleFixKey(key string) bool {
	if m.fixPending > 0 {
		switch key {
		case "y", "Y":
			idx := m.fixPending - 1
			m.fixPending = 0
			m.applyFixAt(idx)
			return true
		case "n", "N", "esc":
			m.fixPending = 0
			m.fixMessage = "cancelled"
			return true
		}
	}
	switch key {
	case "esc":
		m.showFixes = false
		m.fixPending = 0
		return true
	case "a":
		m.applySafeFixes()
		return true
	case "u":
		m.undoLast()
		return true
	}
	if len(key) == 1 && key[0] >= '1' && key[0] <= '9' {
		idx := int(key[0] - '1')
		if idx >= len(m.fixPlan) {
			return true
		}
		a := m.fixPlan[idx]
		if !a.Auto {
			m.fixMessage = "manual action · " + a.Summary
			if a.Command != "" {
				m.fixMessage += " · run: " + a.Command
			}
			return true
		}
		if a.Class == finding.ActionModerate {
			m.fixPending = idx + 1
			return true
		}
		m.applyFixAt(idx)
		return true
	}
	return false
}

func (m *Model) applyFixAt(idx int) {
	a := m.fixPlan[idx]
	res, err := remediate.Apply(a, false)
	if err != nil {
		if m.fixStatus == nil {
			m.fixStatus = map[int]string{}
		}
		m.fixStatus[idx] = "error: " + err.Error()
		m.fixMessage = "error applying " + a.RuleID
		return
	}
	if m.fixStatus == nil {
		m.fixStatus = map[int]string{}
	}
	switch {
	case res.Applied:
		m.fixStatus[idx] = "applied"
		m.fixMessage = "applied " + a.RuleID + " · undo with u"
	case res.Skipped:
		m.fixStatus[idx] = "skipped: " + res.Reason
		m.fixMessage = "skipped " + a.RuleID + " · " + res.Reason
	}
}

func (m *Model) applySafeFixes() {
	applied := 0
	for i, a := range m.fixPlan {
		if !a.Auto || a.Class != finding.ActionSafe {
			continue
		}
		if status := m.fixStatus[i]; status == "applied" {
			continue
		}
		m.applyFixAt(i)
		if m.fixStatus[i] == "applied" {
			applied++
		}
	}
	if applied == 0 {
		m.fixMessage = "no safe actions to apply"
	} else {
		m.fixMessage = fmt.Sprintf("%d safe action(s) applied · undo with u", applied)
	}
}

func (m *Model) undoLast() {
	msgs, err := remediate.Undo(1, false)
	if err != nil {
		m.fixMessage = "undo failed: " + err.Error()
		return
	}
	if len(msgs) == 0 {
		m.fixMessage = "nothing to undo"
		return
	}
	m.fixMessage = "undo: " + strings.Join(msgs, "; ")
}

func actionSeverity(a remediate.Action) finding.Severity {
	if !a.Auto {
		return finding.SeverityInfo
	}
	return classSeverity(a.Class)
}

func classSeverity(c finding.ActionClass) finding.Severity {
	switch c {
	case finding.ActionSafe:
		return finding.SeverityLow
	case finding.ActionModerate:
		return finding.SeverityMedium
	default:
		return finding.SeverityHigh
	}
}

func label(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "CRIT"
	case finding.SeverityHigh:
		return "HIGH"
	case finding.SeverityMedium:
		return "MED"
	case finding.SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

func sevStyle(s finding.Severity) lipgloss.Style {
	var c lipgloss.Color
	switch s {
	case finding.SeverityCritical:
		c = lipgloss.Color("#ff4757")
	case finding.SeverityHigh:
		c = lipgloss.Color("#ff9f43")
	case finding.SeverityMedium:
		c = lipgloss.Color("#ffd93d")
	case finding.SeverityLow:
		c = lipgloss.Color("#4dabf7")
	default:
		c = lipgloss.Color("#adb5bd")
	}
	return lipgloss.NewStyle().Foreground(c)
}

func dim(s string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#7d7d7d")).Render(s)
}

func bold(s string) string {
	return lipgloss.NewStyle().Bold(true).Render(s)
}

func padPlain(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func truncPlain(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

func wrapPlain(s string, width int) string {
	if width < 10 {
		width = 10
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	var cur string
	for _, w := range words {
		if cur == "" {
			cur = w
			continue
		}
		if len([]rune(cur))+1+len([]rune(w)) <= width {
			cur += " " + w
			continue
		}
		lines = append(lines, cur)
		cur = w
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return strings.Join(lines, "\n")
}
