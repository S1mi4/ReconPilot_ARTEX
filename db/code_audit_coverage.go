package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
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

// TaskCodeAuditCoverageAllowsCompletion validates that a completed audit run
// possesses an authentic, complete file-read & closing-sweep/binary ledger before
// advancing an assessment code_audit obligation (§8.3 / §10 Step 5).
func TaskCodeAuditCoverageAllowsCompletion(run *TaskCodeAuditRun) (bool, string) {
	if run == nil {
		return false, "白盒审计运行记录不存在"
	}
	if run.Status != "completed" {
		return false, fmt.Sprintf("白盒审计尚未完成（当前状态：%s）", run.Status)
	}
	if run.FilesTotal <= 0 || run.FilesAnalyzed != run.FilesTotal {
		return false, fmt.Sprintf("代码审计覆盖不完整（已分析 %d/%d）", run.FilesAnalyzed, run.FilesTotal)
	}
	if run.Coverage == nil {
		return false, "缺少白盒覆盖台账（coverage），无法验证真实读取记录"
	}
	cov := run.Coverage
	if len(cov.Files)+taskCodeAuditBinaryClassCount(cov.JavaBinary) != run.FilesTotal {
		return false, "覆盖台账文件计数与总文件数不一致"
	}
	seen := make(map[string]bool, len(cov.Files))
	for _, file := range cov.Files {
		if file.Path == "" || seen[file.Path] {
			return false, "覆盖台账存在重复或空路径记录"
		}
		if !file.Read || !file.Analyzed || file.LinesRead <= 0 {
			return false, fmt.Sprintf("文件 %s 缺乏真实读取或完整分析台账（read=%v analyzed=%v lines=%d）",
				file.Path, file.Read, file.Analyzed, file.LinesRead)
		}
		seen[file.Path] = true
	}
	if len(cov.Files) > 0 && !cov.SweepCompleted {
		return false, "源码审计跨文件收尾扫描（closing sweep）尚未完成"
	}
	if binary := cov.JavaBinary; binary != nil {
		if binary.ClassCount <= 0 || !binary.Completed ||
			binary.NextClassIndex != binary.ClassCount || binary.ClassesAnalyzed != binary.ClassCount {
			return false, fmt.Sprintf("Java 反编译类覆盖不完整（%d/%d，next=%d，completed=%v）",
				binary.ClassesAnalyzed, binary.ClassCount, binary.NextClassIndex, binary.Completed)
		}
	}
	if len(seen) == 0 && cov.JavaBinary == nil {
		return false, "覆盖台账没有任何实际审计文件或反编译类记录"
	}
	return true, ""
}
