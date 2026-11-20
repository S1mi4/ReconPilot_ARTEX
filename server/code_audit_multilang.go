package server

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

func taskCodeAuditLanguages() []taskCodeAuditLanguageAdapter {
	return []taskCodeAuditLanguageAdapter{taskCodeAuditJavaAdapter{}, taskCodeAuditPythonAdapter{}, taskCodeAuditCAdapter{}}
}

func taskCodeAuditSelectLanguages(ids []string) (taskCodeAuditLanguageAdapter, error) {
	if len(ids) == 0 {
		return defaultTaskCodeAuditLanguage(), nil
	}
	var adapters []taskCodeAuditLanguageAdapter
	for _, id := range uniqueSorted(ids) {
		adapter, ok := taskCodeAuditLanguage(id)
		if !ok {
			return nil, fmt.Errorf("不支持的源码审计语言：%s", id)
		}
		adapters = append(adapters, adapter)
	}
	if len(adapters) == 1 {
		return adapters[0], nil
	}
	return taskCodeAuditMixedAdapter{adapters: adapters}, nil
}

// A mixed service retains one inventory, scope and run. Classification and
// reading notes vary by file; primary audit groups never mix languages.
type taskCodeAuditMixedAdapter struct {
	adapters []taskCodeAuditLanguageAdapter
}

func (m taskCodeAuditMixedAdapter) Language() string { return "mixed" }
func (m taskCodeAuditMixedAdapter) ClassifyFile(scope, rel string) (string, bool) {
	for _, adapter := range m.adapters {
		if kind, ok := adapter.ClassifyFile(scope, rel); ok {
			return kind, true
		}
	}
	return "", false
}
func (m taskCodeAuditMixedAdapter) PruneDirectory(scope, rel string) bool {
	if taskCodeAuditMixedSharedPrune(scope, rel) {
		return true
	}
	allPrune := len(m.adapters) > 0
	for _, adapter := range m.adapters {
		if !adapter.PruneDirectory(scope, rel) {
			allPrune = false
		}
	}
	return allPrune
}

func taskCodeAuditMixedSharedPrune(scope, rel string) bool {
	full := strings.ToLower(strings.Trim(path.Join(scope, rel), "/"))
	if full == "." || full == "" {
		return false
	}
	insideSource := false
	for _, part := range strings.Split(full, "/") {
		switch part {
		case ".git", ".svn", ".idea", ".gradle", "node_modules", ".venv", ".tox", ".nox", "__pycache__",
			".cache", ".pytest_cache", ".mypy_cache", ".ruff_cache", "site-packages", "dist-packages", ".eggs",
			"cmakefiles", "meson-private", "meson-logs", "autom4te.cache", ".deps", ".libs", "_deps",
			".conan", ".conan2", "vcpkg_installed", "subprojects":
			return true
		}
		if strings.HasPrefix(part, "cmake-build-") {
			return true
		}
		if !insideSource {
			switch part {
			case "target", "build", "dist", "out", "_build", "generated", "generated-sources":
				return true
			case "vendor", "third_party", "third-party", "deps", "venv", "env", "__pypackages__":
				return true
			}
		}
		if part == "src" || part == "include" || part == "java" || part == "lib" || part == "libs" {
			insideSource = true
		}
	}
	return false
}
func (m taskCodeAuditMixedAdapter) DiscoveryFile(name string, body []byte) taskCodeAuditDiscoveryFile {
	var info taskCodeAuditDiscoveryFile
	for _, adapter := range m.adapters {
		file := adapter.DiscoveryFile(name, body)
		info.Source = info.Source || file.Source
		info.Build = info.Build || file.Build
		info.Tokens = append(info.Tokens, file.Tokens...)
		info.Signals = append(info.Signals, file.Signals...)
	}
	return info
}
func (m taskCodeAuditMixedAdapter) DiscoveryEvidence(tokens, signals []string) ([]string, string) {
	var strong []string
	all := append([]string(nil), signals...)
	for _, adapter := range m.adapters {
		extra, evidence := adapter.DiscoveryEvidence(tokens, signals)
		all = append(all, extra...)
		if evidence != "" {
			strong = append(strong, evidence)
		}
	}
	return uniqueSorted(all), strings.Join(uniqueSorted(strong), "; ")
}
func (m taskCodeAuditMixedAdapter) ReadingNotes() string {
	var notes []string
	for _, adapter := range m.adapters {
		notes = append(notes, adapter.ReadingNotes())
	}
	return strings.Join(notes, "\n\n")
}

func (c *taskCodeAuditCodebase) fileLanguage(rel string) string {
	adapter := c.languageAdapter()
	if mixed, ok := adapter.(taskCodeAuditMixedAdapter); ok {
		for _, language := range mixed.adapters {
			if _, eligible := language.ClassifyFile(c.ScopePath, rel); eligible {
				return language.Language()
			}
		}
	}
	return adapter.Language()
}

func (c *taskCodeAuditCodebase) supportsJavaBinary() bool {
	adapter := c.languageAdapter()
	if mixed, ok := adapter.(taskCodeAuditMixedAdapter); ok {
		for _, language := range mixed.adapters {
			if language.Language() == "java" {
				return true
			}
		}
		return false
	}
	return adapter.Language() == "java"
}

func (c *taskCodeAuditCodebase) languages() []string {
	var ids []string
	for _, file := range c.Files {
		if isTaskCodeAuditProductionFile(file) {
			ids = append(ids, c.fileLanguage(file.Path))
		}
	}
	if len(ids) == 0 && len(c.BinaryClassFiles) > 0 {
		ids = append(ids, "java")
	}
	return uniqueSorted(ids)
}

func taskCodeAuditCandidateLanguage(candidate taskCodeAuditCandidate, c *taskCodeAuditCodebase) string {
	var ids []string
	files := []string{candidate.Source.File, candidate.Sink.File}
	for _, anchor := range candidate.Anchors {
		files = append(files, anchor.File)
	}
	for _, file := range files {
		if file != "" {
			ids = append(ids, c.fileLanguage(file))
		}
	}
	ids = uniqueSorted(ids)
	if len(ids) == 1 {
		return ids[0]
	}
	if len(ids) > 1 {
		return "mixed"
	}
	return c.languageAdapter().Language()
}

// Stable language-first ordering makes existing checkpoints repeatable. The
// coverage ledger is authoritative on resume; line shifts do not affect it.
func taskCodeAuditOrderedSourcePaths(c *taskCodeAuditCodebase) []string {
	paths := taskCodeAuditProductionPaths(c.Files)
	sort.Slice(paths, func(i, j int) bool {
		a, b := c.fileLanguage(paths[i]), c.fileLanguage(paths[j])
		if a != b {
			return a < b
		}
		return paths[i] < paths[j]
	})
	return paths
}

func taskCodeAuditLanguageChunkRanges(c *taskCodeAuditCodebase, paths []string) ([]taskCodeAuditChunkRange, error) {
	var chunks []taskCodeAuditChunkRange
	for start := 0; start < len(paths); {
		end := start + 1
		for end < len(paths) && c.fileLanguage(paths[end]) == c.fileLanguage(paths[start]) {
			end++
		}
		ranges, err := taskCodeAuditSourceChunkRanges(paths[start:end], c.Files, 0)
		if err != nil {
			return nil, err
		}
		for _, group := range ranges {
			chunks = append(chunks, taskCodeAuditChunkRange{Start: start + group.Start, End: start + group.End})
		}
		start = end
	}
	return chunks, nil
}
