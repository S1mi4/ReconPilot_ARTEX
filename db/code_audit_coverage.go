package db

import (
	"database/sql"
	"encoding/json"
	"strings"
)

type TaskCodeAuditCoverage struct {
	Files                []TaskCodeAuditFileCoverage  `json:"files"`
	SweepCompleted       bool                         `json:"sweep_completed"`
	SweepChunksCompleted int                          `json:"sweep_chunks_completed"`
	JavaBinary           *TaskCodeAuditBinaryCoverage `json:"java_binary,omitempty"`
}

type TaskCodeAuditBinaryCoverage struct {
	ClassCount      int  `json:"class_count"`
	ClassesAnalyzed int  `json:"classes_analyzed"`
	NextClassIndex  int  `json:"next_class_index"`
	ChunksCompleted int  `json:"chunks_completed"`
	Completed       bool `json:"completed"`
}

type TaskCodeAuditFileCoverage struct {
	Path      string `json:"path"`
	Language  string `json:"language"`
	Read      bool   `json:"read"`
	Analyzed  bool   `json:"analyzed"`
	Attempts  int    `json:"attempts"`
	LinesRead int    `json:"lines_read"`
}

// Old runs (including Java binary audits) have no ledger. For source audits,
// counters alone cannot establish enough coverage to retire older findings.
func taskCodeAuditCoverageAllowsReconciliation(raw []byte, filesTotal int) bool {
	switch strings.TrimSpace(string(raw)) {
	case "", "{}", "null":
		return true
	}
	var coverage TaskCodeAuditCoverage
	if json.Unmarshal(raw, &coverage) != nil {
		return false
	}
	if len(coverage.Files)+taskCodeAuditBinaryClassCount(coverage.JavaBinary) != filesTotal {
		return false
	}
	seen := make(map[string]bool, len(coverage.Files))
	for _, file := range coverage.Files {
		if file.Path == "" || seen[file.Path] || !file.Read || !file.Analyzed {
			return false
		}
		seen[file.Path] = true
	}
	if len(coverage.Files) > 0 && !coverage.SweepCompleted {
		return false
	}
	if binary := coverage.JavaBinary; binary != nil && (binary.ClassCount <= 0 || !binary.Completed ||
		binary.NextClassIndex != binary.ClassCount || binary.ClassesAnalyzed != binary.ClassCount) {
		return false
	}
	return len(seen) > 0 || coverage.JavaBinary != nil
}

func taskCodeAuditBinaryClassCount(coverage *TaskCodeAuditBinaryCoverage) int {
	if coverage == nil || coverage.ClassCount < 0 {
		return 0
	}
	return coverage.ClassCount
}

// SaveTaskCodeAuditCoverage replaces the ledger only while the run is running.
// A stopped or missing run returns sql.ErrNoRows so callers can stop processing.
func (d *DB) SaveTaskCodeAuditCoverage(runID int64, coverage TaskCodeAuditCoverage) error {
	raw, err := json.Marshal(coverage)
	if err != nil {
		return err
	}
	result, err := d.Exec(`UPDATE task_code_audit_runs SET coverage=$2::jsonb,updated_at=now()
WHERE id=$1 AND status='running'`, runID, string(raw))
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 0 {
		return sql.ErrNoRows
	}
	return nil
}
