package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const taskJavaExecutableEnv = "ARTEX_JAVA_BIN"

var javaVersionPattern = regexp.MustCompile(`(?im)^\s*(?:openjdk|java)\s+(?:version\s*)?["']?(\d+)(?:\.(\d+))?`)

type taskCodeAuditProvenanceLocation struct {
	ReconstructedFile string `json:"reconstructed_file"`
	OriginalClassFile string `json:"original_class_file"`
	Package           string `json:"package"`
	Class             string `json:"class"`
	Method            string `json:"method"`
}

type taskCodeAuditProvenance struct {
	JavaCodeDB       string                          `json:"javacodedb"`
	JavaCodeDBSHA256 string                          `json:"javacodedb_sha256"`
	ArtifactName     string                          `json:"artifact_name"`
	ArtifactFormat   string                          `json:"artifact_format"`
	ArtifactSHA256   string                          `json:"artifact_sha256"`
	Source           taskCodeAuditProvenanceLocation `json:"source"`
	Sink             taskCodeAuditProvenanceLocation `json:"sink"`
	// Anchors carries provenance for each cited anchor when the candidate has
	// no source/sink pair (access control, races, lifetime bugs).
	Anchors []taskCodeAuditProvenanceLocation `json:"anchors,omitempty"`
}

type limitedTaskProcessOutput struct {
	bytes.Buffer
	limit int
}

func (w *limitedTaskProcessOutput) Write(p []byte) (int, error) {
	written := len(p)
	if remaining := w.limit - w.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = w.Buffer.Write(p)
	}
	return written, nil
}

func parseTaskJavaVersion(output string) (string, int, bool) {
	match := javaVersionPattern.FindStringSubmatch(strings.TrimSpace(output))
	if len(match) < 3 {
		return "", 0, false
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return "", 0, false
	}
	if major == 1 {
		major, err = strconv.Atoi(match[2])
		if err != nil {
			return "", 0, false
		}
	}
	version := match[1]
	if match[2] != "" {
		version += "." + match[2]
	}
	return version, major, true
}

func candidateTaskCodeAuditProvenance(candidate taskCodeAuditCandidate, codebase *taskCodeAuditCodebase) (taskCodeAuditProvenance, bool) {
	if codebase == nil || codebase.ArtifactSHA256 == "" {
		return taskCodeAuditProvenance{}, false
	}
	if codebase.JavaCodeDBName == "" || codebase.JavaCodeDBSHA256 == "" {
		return taskCodeAuditProvenance{}, false
	}
	result := taskCodeAuditProvenance{
		JavaCodeDB:       codebase.JavaCodeDBName,
		JavaCodeDBSHA256: codebase.JavaCodeDBSHA256,
		ArtifactName:     codebase.ArtifactName,
		ArtifactFormat:   codebase.ArtifactFormat,
		ArtifactSHA256:   codebase.ArtifactSHA256,
	}
	locate := func(file, symbol string) (taskCodeAuditProvenanceLocation, bool) {
		location, ok := codebase.ProvenanceByPath[filepath.ToSlash(file)]
		if !ok {
			return location, false
		}
		location.Method = taskCodeAuditMethodFromSymbol(symbol)
		return location, location.Method != ""
	}
	if taskCodeAuditLocationPresent(candidate.Source) || taskCodeAuditLocationPresent(candidate.Sink) || len(candidate.Anchors) == 0 {
		var ok bool
		if result.Source, ok = locate(candidate.Source.File, candidate.Source.Symbol); !ok {
			return taskCodeAuditProvenance{}, false
		}
		if result.Sink, ok = locate(candidate.Sink.File, candidate.Sink.Symbol); !ok {
			return taskCodeAuditProvenance{}, false
		}
	}
	for _, anchor := range candidate.Anchors {
		location, ok := locate(anchor.File, anchor.Symbol)
		if !ok {
			return taskCodeAuditProvenance{}, false
		}
		result.Anchors = append(result.Anchors, location)
	}
	return result, true
}

func taskCodeAuditMethodFromSymbol(symbol string) string {
	symbol = strings.TrimSpace(symbol)
	if index := strings.IndexByte(symbol, '('); index >= 0 {
		symbol = symbol[:index]
	}
	if index := strings.LastIndexByte(symbol, '.'); index >= 0 {
		symbol = symbol[index+1:]
	}
	return strings.TrimSpace(symbol)
}

func sha256File(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func restrictedTaskJavaCodeDBEnvironment(tempDir string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + tempDir,
		"TMPDIR=" + tempDir,
		"TMP=" + tempDir,
		"TEMP=" + tempDir,
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}
}

func sortTaskCodeAuditFiles(files []taskCodeAuditFile) {
	// Keep source and reconstructed-class inventories stable between audit runs.
	sort.Slice(files, func(i, j int) bool {
		if files[i].Kind != files[j].Kind {
			order := map[string]int{"java": 0, "config": 1, "test": 2, "template": 3}
			return order[files[i].Kind] < order[files[j].Kind]
		}
		return files[i].Path < files[j].Path
	})
}
