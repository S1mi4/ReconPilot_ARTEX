package server

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Registration requires source/sink anchors and symbols from code actually read
// in this chunk. API-family heuristics and excerpt matching measure completeness;
// failures lower confidence without discarding grounded static leads.

const (
	taskCodeAuditSourceSymbolWindow = 5
	taskCodeAuditFlowSymbolWindow   = 3
	taskCodeAuditSinkWindow         = 2
	taskCodeAuditExcerptMinMatch    = 0.6
)

var taskCodeAuditIdentifierPattern = regexp.MustCompile(`[\p{L}_$][\p{L}\p{N}_$]*`)
var taskCodeAuditExcerptSplitPattern = regexp.MustCompile(`→|->|=>|\.{3}|…|\||\n`)
var taskCodeAuditExcerptPrefixPattern = regexp.MustCompile(`^\s*(?:[\w./$\\-]+\.(?:java|jsp|jspx|html|xml|py|pyi|c|h)\s*[:#L]\s*)?L?\d+\s*[:：]?\s*`)

// taskCodeAuditSinkPatterns are broad API-family hints. A mismatch lowers the
// registration tier rather than rejecting custom wrappers or indirect APIs.
var taskCodeAuditSinkPatterns = map[string]*regexp.Regexp{
	"SQL_INJECTION":          regexp.MustCompile(`(?i)execute|query|update|prepare|statement|sql|select\b|insert\b|delete\b|\$\{|createnative|jdbc|hql|criteria|mapper|exec`),
	"COMMAND_INJECTION":      regexp.MustCompile(`(?i)exec|processbuilder|runtime|/bin/|sh\b|cmd|command|shell|start\(|process`),
	"PATH_TRAVERSAL":         regexp.MustCompile(`(?i)file|path|stream|read|write|resource|transfer|zip|download|upload|open|delete|copy|move|dir`),
	"SSRF":                   regexp.MustCompile(`(?i)url|http|uri|socket|resttemplate|webclient|connect|fetch|openstream|request|client|exchange|forobject|get\(|post\(`),
	"XSS":                    regexp.MustCompile(`(?i)write|print|append|html|out\.|response|model|jsp|<%=|\$\{|escape|render|attribute|writer|return`),
	"UNSAFE_DESERIALIZATION": regexp.MustCompile(`(?i)readobject|objectinputstream|xmldecoder|xstream|fromxml|parseobject|defaulttyping|yaml|load\(|hessian|deserial|unserialize|kryo|readvalue|jackson|fastjson|autotype`),
}

// recordLine remembers the text of one line the model has seen.
func (state *taskCodeAuditToolState) recordLine(path string, line int, text string) {
	if state == nil || line <= 0 {
		return
	}
	if state.lines == nil {
		state.lines = map[string]map[int]string{}
	}
	if state.lines[path] == nil {
		state.lines[path] = map[int]string{}
	}
	state.lines[path][line] = text
}

// recordFormattedLines parses "N: text" read output and records every line.
func (state *taskCodeAuditToolState) recordFormattedLines(path, content string) {
	for _, row := range strings.Split(content, "\n") {
		colon := strings.Index(row, ": ")
		if colon <= 0 {
			continue
		}
		number, err := strconv.Atoi(row[:colon])
		if err != nil {
			continue
		}
		state.recordLine(path, number, row[colon+2:])
	}
}

// windowText joins the recorded lines within radius of line.
func (state *taskCodeAuditToolState) windowText(path string, line, radius int) string {
	var builder strings.Builder
	for number := line - radius; number <= line+radius; number++ {
		if text, ok := state.lines[path][number]; ok {
			builder.WriteString(text)
			builder.WriteByte('\n')
		}
	}
	return builder.String()
}

func taskCodeAuditSymbolIdentifiers(symbol string) []string {
	if cut := strings.Index(symbol, "("); cut > 0 {
		symbol = symbol[:cut]
	}
	return taskCodeAuditIdentifierPattern.FindAllString(symbol, -1)
}

func containsTaskCodeAuditIdentifier(text, identifier string) bool {
	if identifier == "" {
		return false
	}
	for _, found := range taskCodeAuditIdentifierPattern.FindAllString(text, -1) {
		if found == identifier {
			return true
		}
	}
	return false
}

// symbolNearLine reports whether the claimed symbol is visible around the line.
// With lastOnly set, the final identifier (the invoked method / API name) must
// appear; otherwise any identifier of the symbol is enough.
func (state *taskCodeAuditToolState) symbolNearLine(path string, line, radius int, symbol string, lastOnly bool) bool {
	identifiers := taskCodeAuditSymbolIdentifiers(symbol)
	if len(identifiers) == 0 {
		return false
	}
	text := state.windowText(path, line, radius)
	if text == "" {
		return false
	}
	if lastOnly {
		return containsTaskCodeAuditIdentifier(text, identifiers[len(identifiers)-1])
	}
	for _, identifier := range identifiers {
		if containsTaskCodeAuditIdentifier(text, identifier) {
			return true
		}
	}
	return false
}

func compactTaskCodeAuditCode(text string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n', ' ':
			return -1
		}
		return r
	}, strings.ToLower(text))
}

// excerptMatchesReadCode checks that the evidence excerpt is made of fragments
// of lines the model actually read in the cited files.
func (state *taskCodeAuditToolState) excerptMatchesReadCode(excerpt string, files map[string]bool) bool {
	var corpus []string
	for file := range files {
		for _, text := range state.lines[file] {
			if compact := compactTaskCodeAuditCode(text); compact != "" {
				corpus = append(corpus, compact)
			}
		}
	}
	total, matched := 0, 0
	for _, segment := range taskCodeAuditExcerptSplitPattern.Split(excerpt, -1) {
		segment = taskCodeAuditExcerptPrefixPattern.ReplaceAllString(segment, "")
		compact := compactTaskCodeAuditCode(segment)
		if len(compact) < 4 {
			continue
		}
		total++
		for _, line := range corpus {
			if strings.Contains(line, compact) {
				matched++
				break
			}
		}
	}
	return total > 0 && matched > 0 && float64(matched) >= math.Ceil(float64(total)*taskCodeAuditExcerptMinMatch)
}

// validateTaskCodeAuditCandidateEvidence performs the content checks that go
// beyond "the line number was shown to the model".
func validateTaskCodeAuditCandidateEvidence(candidate taskCodeAuditCandidate, state *taskCodeAuditToolState) (bool, string) {
	issues := validateTaskCodeAuditCandidateEvidenceIssues(candidate, state)
	if len(issues) == 0 {
		return true, ""
	}
	return false, strings.Join(issues, "；")
}

func validateTaskCodeAuditCandidateEvidenceIssues(candidate taskCodeAuditCandidate, state *taskCodeAuditToolState) []string {
	hard, soft := assessTaskCodeAuditCandidateEvidence(candidate, state)
	return append(hard, soft...)
}

func assessTaskCodeAuditCandidateEvidence(candidate taskCodeAuditCandidate, state *taskCodeAuditToolState) (issues, soft []string) {
	addIssue := func(issue string) {
		if issue == "" {
			return
		}
		for _, existing := range issues {
			if existing == issue {
				return
			}
		}
		issues = append(issues, issue)
	}
	if state == nil {
		return []string{"本轮已读取代码证据不可用，无法校验代码摘录。"}, nil
	}
	sourceFile := filepath.ToSlash(candidate.Source.File)
	sinkFile := filepath.ToSlash(candidate.Sink.File)
	sourcePresent := taskCodeAuditLocationPresent(candidate.Source)
	sinkPresent := taskCodeAuditLocationPresent(candidate.Sink)
	if (sourcePresent && state.lines[sourceFile][candidate.Source.Line] == "") ||
		(sinkPresent && state.lines[sinkFile][candidate.Sink.Line] == "") {
		addIssue("无法在本轮读取内容中找到 source 或 sink 行的代码文本。")
	}
	if sourceFile != "" && candidate.Source.Line > 0 && state.lines[sourceFile][candidate.Source.Line] != "" &&
		!state.symbolNearLine(sourceFile, candidate.Source.Line, taskCodeAuditSourceSymbolWindow, candidate.Source.Symbol, false) {
		addIssue("source.symbol 没有出现在所声明行附近的已读代码中。")
	}
	if sinkFile != "" && candidate.Sink.Line > 0 && state.lines[sinkFile][candidate.Sink.Line] != "" &&
		!state.symbolNearLine(sinkFile, candidate.Sink.Line, taskCodeAuditSinkWindow, candidate.Sink.Symbol, true) {
		addIssue("sink.symbol（调用的方法/API）没有出现在所声明行附近的已读代码中。")
	}
	sinkText := ""
	if sinkPresent {
		sinkText = state.windowText(sinkFile, candidate.Sink.Line, taskCodeAuditSinkWindow)
	}
	if pattern := taskCodeAuditSinkPatterns[normalizeTaskCodeAuditVulnClass(candidate.Category)]; state.codebase.fileLanguage(sinkFile) == "java" && pattern != nil && sinkText != "" &&
		!pattern.MatchString(sinkText) {
		soft = append(soft, "sink 附近的代码与所声明的漏洞类型对应的危险 API 不符，需要人工确认自定义封装或间接调用。")
	}
	if sinkPresent && state.codebase.fileLanguage(sinkFile) == "java" && normalizeTaskCodeAuditVulnClass(candidate.Category) == "COMMAND_INJECTION" &&
		!taskCodeAuditCommandSinkIsExecution(candidate, sinkText, state.windowText(sinkFile, candidate.Sink.Line, taskCodeAuditSinkWindow+4), state) {
		soft = append(soft, "COMMAND_INJECTION 的 sink 必须是实际启动进程的 ProcessBuilder.start() 或 Runtime.exec()；尚未确认执行点，构造 ProcessBuilder 或拼接 shell 命令本身不足以证明命令执行。")
	}
	files := map[string]bool{sourceFile: true, sinkFile: true, filepath.ToSlash(candidate.EntryPoint.File): true}
	for index, anchor := range candidate.Anchors {
		file := filepath.ToSlash(anchor.File)
		files[file] = true
		if anchor.Excerpt != "" && !state.excerptMatchesReadCode(anchor.Excerpt, map[string]bool{file: true}) {
			soft = append(soft, fmt.Sprintf("anchors[%d].excerpt 不是该文件的已读原文片段。", index))
		}
		if file != "" && anchor.Line > 0 && state.lines[file][anchor.Line] != "" &&
			!state.symbolNearLine(file, anchor.Line, taskCodeAuditFlowSymbolWindow, anchor.Symbol, false) {
			addIssue(fmt.Sprintf("anchors[%d] 的 symbol %q 没有出现在所声明行附近的已读代码中。", index, anchor.Symbol))
		}
	}
	for _, step := range candidate.Flow {
		file := filepath.ToSlash(step.File)
		files[file] = true
		if file != "" && step.Line > 0 && state.lines[file][step.Line] != "" &&
			!state.symbolNearLine(file, step.Line, taskCodeAuditFlowSymbolWindow, step.Symbol, false) {
			addIssue(fmt.Sprintf("数据流步骤 %s:%d 的 symbol 没有出现在所声明行附近。", file, step.Line))
		}
	}
	if strings.TrimSpace(candidate.EvidenceExcerpt) != "" && !state.excerptMatchesReadCode(candidate.EvidenceExcerpt, files) {
		soft = append(soft, "evidence_excerpt 不是本轮已读取代码的原文片段（至少 60% 的片段必须能在引用的文件中找到）。")
	}
	return issues, soft
}

func taskCodeAuditCommandSinkIsExecution(candidate taskCodeAuditCandidate, sinkWindow, extendedWindow string, state *taskCodeAuditToolState) bool {
	symbol := strings.ToLower(strings.TrimSpace(candidate.Sink.Symbol))
	code := strings.ToLower(extendedWindow + "\n" + candidate.EvidenceExcerpt)
	if strings.Contains(symbol, "runtime.exec") || strings.Contains(symbol, "runtime#exec") {
		return strings.Contains(code, ".exec(") || strings.Contains(code, ".exec (")
	}
	if strings.Contains(symbol, "processbuilder.start") || strings.Contains(symbol, "processbuilder#start") {
		return strings.Contains(code, ".start(") || strings.Contains(code, ".start (")
	}
	// Java source calls the inherited API through a variable (for example,
	// builder.start()), so verify that receiver's declared type from code the
	// model read instead of requiring it to misquote the call as a static method.
	if strings.Contains(symbol, "start") && state != nil {
		file := filepath.ToSlash(candidate.Sink.File)
		line := state.lines[file][candidate.Sink.Line]
		call := regexp.MustCompile(`(?i)\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*start\s*\(`).FindStringSubmatch(line)
		if len(call) == 2 {
			receiver := regexp.QuoteMeta(call[1])
			declaration := regexp.MustCompile(`(?i)\bProcessBuilder\s+` + receiver + `\b|\b` + receiver + `\s*=\s*new\s+ProcessBuilder\s*\(`)
			for _, readLine := range state.lines[file] {
				if declaration.MatchString(readLine) {
					return true
				}
			}
		}
	}
	return false
}
