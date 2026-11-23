package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

const TaskCodeAuditConcurrencyLimit = 4

type TaskCodeAuditRun struct {
	ID                 int64                    `json:"id"`
	TaskID             int64                    `json:"task_id"`
	CodeServiceID      int64                    `json:"code_service_id"`
	TargetEntityID     *int64                   `json:"target_entity_id,omitempty"`
	ServiceName        string                   `json:"service_name"`
	TargetType         string                   `json:"target_type,omitempty"`
	CodebaseID         string                   `json:"codebase_id"`
	VersionID          string                   `json:"version_id"`
	RelativePath       string                   `json:"relative_path,omitempty"`
	ScopePath          string                   `json:"scope_path"`
	Languages          []string                 `json:"languages,omitempty"`
	ObligationID       *int64                   `json:"obligation_id,omitempty"`
	ExecutionOrigin    string                   `json:"execution_origin,omitempty"`
	Status             string                   `json:"status"`
	ProfileID          *int64                   `json:"profile_id,omitempty"`
	ProfileSource      string                   `json:"profile_source"`
	ProfileName        string                   `json:"profile_name"`
	ProfileFormat      string                   `json:"profile_format"`
	Model              string                   `json:"model"`
	Endpoint           string                   `json:"endpoint"`
	SourceAcknowledged bool                     `json:"source_acknowledged"`
	FilesTotal         int                      `json:"files_total"`
	FilesAnalyzed      int                      `json:"files_analyzed"`
	FilesSkipped       int                      `json:"files_skipped"`
	ChunksTotal        int                      `json:"chunks_total"`
	ChunksCompleted    int                      `json:"chunks_completed"`
	NextFileIndex      int                      `json:"next_file_index"`
	BudgetTokens       int                      `json:"budget_tokens"`
	UsedTokens         int                      `json:"used_tokens"`
	CandidateCount     int                      `json:"candidate_count"`
	Summary            string                   `json:"summary"`
	Error              string                   `json:"error,omitempty"`
	CreatedAt          time.Time                `json:"created_at"`
	StartedAt          *time.Time               `json:"started_at,omitempty"`
	CompletedAt        *time.Time               `json:"completed_at,omitempty"`
	UpdatedAt          time.Time                `json:"updated_at"`
	Candidates         []TaskCodeAuditCandidate `json:"candidates,omitempty"`
	Coverage           *TaskCodeAuditCoverage   `json:"coverage,omitempty"`
}

// CreateEngineCodeAuditInput creates or resumes an assessment-engine driven
// whitebox audit run for any confirmed service, non-service module, or shared library.
type CreateEngineCodeAuditInput struct {
	TaskID             int64
	ObligationID       int64
	TargetEntityID     *int64
	CodeServiceID      *int64
	TargetName         string
	TargetType         string
	CodebaseID         string
	VersionID          string
	RelativePath       string
	ScopePath          string
	Languages          []string
	ProfileID          *int64
	ProfileSource      string
	ProfileName        string
	ProfileFormat      string
	Model              string
	Endpoint           string
	SourceAcknowledged bool
	BudgetTokens       int
	ReuseRunID         *int64
}

type TaskCodeAuditCandidate struct {
	ID                  int64                           `json:"id"`
	RunID               int64                           `json:"run_id"`
	CandidateKey        string                          `json:"candidate_key"`
	ReviewStatus        string                          `json:"review_status"`
	Candidate           json.RawMessage                 `json:"candidate"`
	Variants            []TaskCodeAuditCandidateVariant `json:"variants,omitempty"`
	ReviewerSummary     string                          `json:"reviewer_summary"`
	VerificationSummary string                          `json:"verification_summary"`
	CreatedAt           time.Time                       `json:"created_at"`
	UpdatedAt           time.Time                       `json:"updated_at"`
}

type TaskCodeAuditCandidateVariant struct {
	Candidate        json.RawMessage `json:"candidate"`
	ValidationIssues []string        `json:"validation_issues,omitempty"`
	AnalysisChunk    int             `json:"analysis_chunk,omitempty"`
}

type TaskCodeAuditCandidateReviewInput struct {
	Accepted            bool
	VerificationSummary string
	VulnClass           string
	Name                string
	Severity            string
	Summary             string
	Evidence            string
	CodeAuditEvidence   json.RawMessage
	UsedTokens          int
}

type TaskCodeAuditCandidateReviewResult struct {
	Status    string `json:"status"`
	FindingID int64  `json:"finding_id,omitempty"`
}

type TaskCodeAuditFindingInput struct {
	CandidateKey      string
	Candidate         json.RawMessage
	VulnClass         string
	Name              string
	Severity          string
	Summary           string
	Evidence          string
	CodeAuditEvidence json.RawMessage
	AnalysisChunk     int
}

type TaskCodeAuditFindingResult struct {
	Status         string `json:"status"`
	FindingID      int64  `json:"finding_id,omitempty"`
	ReportRequired bool   `json:"report_required"`
}

var (
	ErrTaskCodeAuditCandidateReviewConflict = errors.New("task code audit candidate is no longer reviewable")
	ErrTaskCodeAuditCandidateReviewInvalid  = errors.New("task code audit review is incomplete or invalid")
)

type CreateTaskCodeAudit struct {
	TaskID             int64
	CodeServiceID      int64
	CodebaseID         string
	VersionID          string
	ScopePath          string
	ProfileID          *int64
	ProfileSource      string
	ProfileName        string
	ProfileFormat      string
	Model              string
	Endpoint           string
	SourceAcknowledged bool
	FilesTotal         int
	FilesSkipped       int
	ChunksTotal        int
	BudgetTokens       int
}

type TaskCodeAuditProgress struct {
	FilesTotal      int
	FilesAnalyzed   int
	FilesSkipped    int
	ChunksTotal     int
	ChunksCompleted int
	NextFileIndex   int
	UsedTokens      int
	Summary         string
}

const taskCodeAuditRunColumns = `run.id,run.task_id,COALESCE(run.code_service_id,0),run.target_entity_id,
COALESCE(NULLIF(service.name,''),NULLIF(run.target_name,''),run.relative_path),run.target_type,
run.codebase_id,run.version_id,COALESCE(NULLIF(service.relative_path,''),run.relative_path),run.scope_path,
array_to_json(CASE WHEN cardinality(run.languages)>0 THEN run.languages ELSE COALESCE(service.languages,'{}'::text[]) END),
run.obligation_id,run.execution_origin,run.status,run.profile_id,run.profile_source,run.profile_name,run.profile_format,run.model,run.endpoint,
run.source_acknowledged,run.files_total,run.files_analyzed,run.files_skipped,run.chunks_total,run.chunks_completed,
run.next_file_index,run.budget_tokens,run.used_tokens,run.candidate_count,run.summary,run.error,run.created_at,
run.started_at,run.completed_at,run.updated_at,run.coverage`

func scanTaskCodeAuditRun(row interface{ Scan(...any) error }) (*TaskCodeAuditRun, error) {
	var run TaskCodeAuditRun
	var profileID, targetEntityID, obligationID sql.NullInt64
	var started, completed sql.NullTime
	var coverageJSON []byte
	var languages codeServiceLanguages
	err := row.Scan(&run.ID, &run.TaskID, &run.CodeServiceID, &targetEntityID, &run.ServiceName, &run.TargetType,
		&run.CodebaseID, &run.VersionID, &run.RelativePath, &run.ScopePath, &languages, &obligationID, &run.ExecutionOrigin,
		&run.Status, &profileID, &run.ProfileSource, &run.ProfileName, &run.ProfileFormat, &run.Model,
		&run.Endpoint, &run.SourceAcknowledged, &run.FilesTotal, &run.FilesAnalyzed, &run.FilesSkipped, &run.ChunksTotal,
		&run.ChunksCompleted, &run.NextFileIndex, &run.BudgetTokens, &run.UsedTokens, &run.CandidateCount,
		&run.Summary, &run.Error, &run.CreatedAt, &started, &completed, &run.UpdatedAt, &coverageJSON)
	if err != nil {
		return nil, err
	}
	run.Languages = []string(languages)
	if len(coverageJSON) > 0 {
		var coverage TaskCodeAuditCoverage
		if err := json.Unmarshal(coverageJSON, &coverage); err != nil {
			return nil, fmt.Errorf("decode task code audit coverage: %w", err)
		}
		if len(coverage.Files) > 0 || coverage.JavaBinary != nil || coverage.SweepCompleted || coverage.SweepChunksCompleted > 0 {
			run.Coverage = &coverage
		}
	}
	if targetEntityID.Valid {
		id := targetEntityID.Int64
		run.TargetEntityID = &id
	}
	if obligationID.Valid {
		id := obligationID.Int64
		run.ObligationID = &id
	}
	if profileID.Valid {
		id := profileID.Int64
		run.ProfileID = &id
	}
	if started.Valid {
		run.StartedAt = &started.Time
	}
	if completed.Valid {
		run.CompletedAt = &completed.Time
	}
	return &run, nil
}

func (d *DB) CreateTaskCodeAudit(input CreateTaskCodeAudit) (*TaskCodeAuditRun, error) {
	var profileID any
	if input.ProfileID != nil {
		profileID = *input.ProfileID
	}
	row := d.QueryRow(`INSERT INTO task_code_audit_runs(task_id,code_service_id,codebase_id,version_id,scope_path,status,
profile_id,profile_source,profile_name,profile_format,model,endpoint,source_acknowledged,files_total,files_skipped,chunks_total,budget_tokens)
SELECT $1,$2,$3,$4,$5,'queued',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
WHERE EXISTS (SELECT 1 FROM task_code_services WHERE task_id=$1 AND id=$2 AND decision='confirmed' AND latest_present
AND codebase_id=$3 AND latest_version_id=$4)
-- 锁任务行：FOR UPDATE 与 FinalizeAssessmentCompletion 的任务行锁互斥，
-- 消除“完成检查之后、done 提交之前入队”的窗口（完成判定 §6.3）。
-- 评估模式任务在终态后拒绝入队（已完成/失败/超时的任务不再产生需要
-- 消化的白盒工作）；非评估任务行为不变。
AND COALESCE((SELECT NOT (t.assessment_mode AND t.status IN ('done','failed','timeout'))
              FROM tasks t WHERE t.id=$1 FOR UPDATE), false)
RETURNING id`, input.TaskID, input.CodeServiceID, input.CodebaseID, input.VersionID, input.ScopePath, profileID,
		input.ProfileSource, input.ProfileName, input.ProfileFormat, input.Model, input.Endpoint, input.SourceAcknowledged,
		input.FilesTotal, input.FilesSkipped, input.ChunksTotal, input.BudgetTokens)
	var id int64
	if err := row.Scan(&id); err != nil {
		return nil, err
	}
	return d.GetTaskCodeAudit(input.TaskID, id)
}

func (d *DB) ClaimNextTaskCodeAudit() (*TaskCodeAuditRun, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended('task-code-audit-queue',0))`); err != nil {
		return nil, err
	}
	var active int
	if err := tx.QueryRow(`SELECT count(*) FROM task_code_audit_runs WHERE status='running'`).Scan(&active); err != nil {
		return nil, err
	}
	if active >= TaskCodeAuditConcurrencyLimit {
		return nil, nil
	}
	var runID, taskID int64
	// One running audit per service: concurrent runs would share the same
	// JavaCodeDB workspace (and its Lucene index lock). Queue workers only claim
	// legacy/manual execution_origin='queue' runs; assessment engine runs are
	// driven inside Engine.runIntent.
	err = tx.QueryRow(`SELECT id,task_id FROM task_code_audit_runs run WHERE run.status='queued' AND run.execution_origin='queue'
AND NOT EXISTS (SELECT 1 FROM task_code_audit_runs other WHERE other.status='running' AND other.code_service_id IS NOT NULL AND other.code_service_id=run.code_service_id)
ORDER BY run.created_at,run.id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&runID, &taskID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE task_code_audit_runs SET status='running',started_at=COALESCE(started_at,now()),
completed_at=NULL,error='',updated_at=now() WHERE id=$1`, runID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetTaskCodeAudit(taskID, runID)
}

func (d *DB) RequeueInterruptedTaskCodeAudits() error {
	if _, err := d.Exec(`UPDATE task_code_audit_runs SET status='queued',error='服务重启后从最近检查点恢复',updated_at=now()
WHERE status='running' AND execution_origin='queue'`); err != nil {
		return err
	}
	_, err := d.Exec(`UPDATE task_code_audit_runs SET status='incomplete',error='服务重启后保留检查点，等待评估意图恢复续跑',completed_at=now(),updated_at=now()
WHERE status='running' AND execution_origin='engine'`)
	return err
}

// CreateOrResumeEngineCodeAuditRun creates a new running engine-driven audit run
// for any service, module, or shared library, or resumes an interrupted/incomplete
// checkpoint for the same obligation/version scope.
func (d *DB) CreateOrResumeEngineCodeAuditRun(in CreateEngineCodeAuditInput) (*TaskCodeAuditRun, bool, error) {
	if in.TaskID <= 0 || strings.TrimSpace(in.CodebaseID) == "" || strings.TrimSpace(in.VersionID) == "" {
		return nil, false, errors.New("task_id, codebase_id, and version_id are required")
	}
	relPath := strings.TrimSpace(in.RelativePath)
	if relPath == "" {
		relPath = "."
	}
	scopePath := strings.TrimSpace(in.ScopePath)
	if scopePath == "" {
		scopePath = "."
	}
	targetType := strings.TrimSpace(in.TargetType)
	if targetType == "" {
		targetType = "module"
	}
	targetName := strings.TrimSpace(in.TargetName)
	if targetName == "" {
		targetName = relPath
	}
	langsJSON, err := json.Marshal(normalizedCodeServiceLanguages(in.Languages))
	if err != nil {
		return nil, false, err
	}
	var profileID any
	if in.ProfileID != nil && *in.ProfileID > 0 {
		profileID = *in.ProfileID
	}
	var codeServiceID any
	if in.CodeServiceID != nil && *in.CodeServiceID > 0 {
		codeServiceID = *in.CodeServiceID
	}
	var targetEntityID any
	if in.TargetEntityID != nil && *in.TargetEntityID > 0 {
		targetEntityID = *in.TargetEntityID
	}
	var obligationID any
	if in.ObligationID > 0 {
		obligationID = in.ObligationID
	}

	tx, err := d.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback() //nolint:errcheck

	var assessmentMode bool
	var taskStatus string
	if err := tx.QueryRow(`SELECT assessment_mode, status FROM tasks WHERE id=$1 FOR UPDATE`, in.TaskID).Scan(&assessmentMode, &taskStatus); err != nil {
		return nil, false, err
	}
	if assessmentMode && (taskStatus == "done" || taskStatus == "failed" || taskStatus == "timeout") {
		return nil, false, ErrObligationAlreadyTerminal
	}

	var resumeID int64
	if in.ReuseRunID != nil && *in.ReuseRunID > 0 {
		err = tx.QueryRow(`SELECT id FROM task_code_audit_runs
WHERE id=$1 AND task_id=$2 AND execution_origin='engine' AND codebase_id=$3 AND version_id=$4
  AND relative_path=$5 AND scope_path=$6 AND status='incomplete' FOR UPDATE`,
			*in.ReuseRunID, in.TaskID, in.CodebaseID, in.VersionID, relPath, scopePath).Scan(&resumeID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, false, err
		}
	}
	if resumeID == 0 && in.ObligationID > 0 {
		err = tx.QueryRow(`SELECT id FROM task_code_audit_runs
WHERE task_id=$1 AND obligation_id=$2 AND execution_origin='engine'
  AND codebase_id=$3 AND version_id=$4 AND relative_path=$5 AND scope_path=$6 AND status='incomplete'
ORDER BY id DESC LIMIT 1 FOR UPDATE`,
			in.TaskID, in.ObligationID, in.CodebaseID, in.VersionID, relPath, scopePath).Scan(&resumeID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, false, err
		}
	}

	if resumeID > 0 {
		if _, err := tx.Exec(`UPDATE task_code_audit_runs
SET status='running',
    profile_id=$2, profile_source=$3, profile_name=$4, profile_format=$5, model=$6, endpoint=$7,
    source_acknowledged=$8, started_at=COALESCE(started_at, now()), completed_at=NULL, error='', updated_at=now()
WHERE id=$1`,
			resumeID, profileID, in.ProfileSource, in.ProfileName, in.ProfileFormat, in.Model, in.Endpoint,
			in.SourceAcknowledged); err != nil {
			return nil, false, err
		}
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		run, err := d.GetTaskCodeAudit(in.TaskID, resumeID)
		return run, true, err
	}

	var newID int64
	err = tx.QueryRow(`INSERT INTO task_code_audit_runs(
    task_id, code_service_id, target_entity_id, target_name, target_type,
    codebase_id, version_id, relative_path, scope_path, languages, obligation_id, execution_origin,
    status, profile_id, profile_source, profile_name, profile_format, model, endpoint,
    source_acknowledged, budget_tokens, started_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,ARRAY(SELECT jsonb_array_elements_text($10::jsonb)),$11,'engine',
        'running',$12,$13,$14,$15,$16,$17,$18,$19,now())
RETURNING id`,
		in.TaskID, codeServiceID, targetEntityID, targetName, targetType,
		in.CodebaseID, in.VersionID, relPath, scopePath, string(langsJSON), obligationID,
		profileID, in.ProfileSource, in.ProfileName, in.ProfileFormat, in.Model, in.Endpoint,
		in.SourceAcknowledged, in.BudgetTokens).Scan(&newID)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	run, err := d.GetTaskCodeAudit(in.TaskID, newID)
	return run, false, err
}

func (d *DB) UpdateTaskCodeAuditProgress(runID int64, progress TaskCodeAuditProgress) error {
	_, err := d.Exec(`UPDATE task_code_audit_runs SET files_total=$2,files_analyzed=$3,files_skipped=$4,
chunks_total=$5,chunks_completed=$6,next_file_index=$7,used_tokens=$8,summary=$9,updated_at=now()
WHERE id=$1 AND status='running'`, runID, progress.FilesTotal, progress.FilesAnalyzed, progress.FilesSkipped,
		progress.ChunksTotal, progress.ChunksCompleted, progress.NextFileIndex, progress.UsedTokens, progress.Summary)
	return err
}

func (d *DB) AddTaskCodeAuditCandidate(runID int64, key string, candidate json.RawMessage, reviewerSummary string) error {
	return d.AddTaskCodeAuditCandidateWithStatus(runID, key, "pending_review", candidate, reviewerSummary)
}

func (d *DB) AddTaskCodeAuditCandidateWithStatus(runID int64, key, status string, candidate json.RawMessage, reviewerSummary string) error {
	var issues []string
	if strings.TrimSpace(reviewerSummary) != "" {
		issues = []string{strings.TrimSpace(reviewerSummary)}
	}
	_, err := d.AddTaskCodeAuditCandidateVariant(runID, key, status, candidate, issues, 0)
	return err
}

func (d *DB) AddTaskCodeAuditCandidateVariant(runID int64, key, status string, candidate json.RawMessage,
	issues []string, analysisChunk int) (string, error) {
	if status != "pending_review" && status != "incomplete" && status != "rejected" {
		return "", errors.New("invalid code audit candidate status")
	}
	key = strings.TrimSpace(key)
	if runID <= 0 || key == "" || !json.Valid(candidate) {
		return "", errors.New("invalid code audit candidate JSON")
	}
	issues = uniqueTaskCodeAuditIssues(issues)
	variant := TaskCodeAuditCandidateVariant{Candidate: append(json.RawMessage(nil), candidate...), ValidationIssues: issues, AnalysisChunk: analysisChunk}
	variantJSON, err := json.Marshal(variant)
	if err != nil {
		return "", err
	}
	tx, err := d.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck
	var candidateID int64
	var existingStatus string
	var existingCandidate, existingVariants []byte
	var existingSummary string
	inserted, err := tx.Exec(`INSERT INTO task_code_audit_candidates
(run_id,candidate_key,review_status,candidate,candidate_variants,reviewer_summary)
VALUES($1,$2,$3,$4::jsonb,jsonb_build_array($5::jsonb),$6)
ON CONFLICT(run_id,candidate_key) DO NOTHING`, runID, key, status, string(candidate), string(variantJSON),
		formatTaskCodeAuditIssues(issues))
	if err != nil {
		return "", err
	}
	insertedCount, err := inserted.RowsAffected()
	if err != nil {
		return "", err
	}
	if insertedCount > 0 {
		if _, err := tx.Exec(`UPDATE task_code_audit_runs SET candidate_count=candidate_count+1,updated_at=now() WHERE id=$1`, runID); err != nil {
			return "", err
		}
	}
	err = tx.QueryRow(`SELECT id,review_status,candidate,candidate_variants,reviewer_summary
FROM task_code_audit_candidates WHERE run_id=$1 AND candidate_key=$2 FOR UPDATE`, runID, key).
		Scan(&candidateID, &existingStatus, &existingCandidate, &existingVariants, &existingSummary)
	if err != nil {
		return "", err
	}
	variants, err := appendTaskCodeAuditCandidateVariant(existingVariants, variant)
	if err != nil {
		return "", err
	}
	variantBytes, err := json.Marshal(variants)
	if err != nil {
		return "", err
	}
	mergedIssues := append([]string(nil), issues...)
	for _, item := range variants {
		mergedIssues = append(mergedIssues, item.ValidationIssues...)
	}
	mergedSummary := mergeTaskCodeAuditIssueSummary(existingSummary, formatTaskCodeAuditIssues(mergedIssues))
	nextStatus := existingStatus
	nextCandidate := existingCandidate
	if existingStatus == "published" || existingStatus == "dismissed" || existingStatus == "rejected" {
		mergedSummary = existingSummary
	}
	if existingStatus == "pending_review" && (status == "incomplete" || status == "rejected") {
		nextStatus = status
		nextCandidate = candidate
	}
	if _, err := tx.Exec(`UPDATE task_code_audit_candidates SET review_status=$2,candidate=$3::jsonb,
candidate_variants=$4::jsonb,reviewer_summary=$5,updated_at=now() WHERE id=$1`, candidateID, nextStatus,
		string(nextCandidate), string(variantBytes), mergedSummary); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return nextStatus, nil
}

func appendTaskCodeAuditCandidateVariant(existing []byte, incoming TaskCodeAuditCandidateVariant) ([]TaskCodeAuditCandidateVariant, error) {
	variants := make([]TaskCodeAuditCandidateVariant, 0)
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &variants); err != nil {
			return nil, err
		}
	}
	for _, variant := range variants {
		if sameTaskCodeAuditCandidateVariant(variant, incoming) {
			return variants, nil
		}
	}
	variants = append(variants, incoming)
	return variants, nil
}

func sameTaskCodeAuditCandidateVariant(left, right TaskCodeAuditCandidateVariant) bool {
	if left.AnalysisChunk != right.AnalysisChunk || !reflect.DeepEqual(left.ValidationIssues, right.ValidationIssues) {
		return false
	}
	var leftCandidate, rightCandidate any
	if json.Unmarshal(left.Candidate, &leftCandidate) != nil || json.Unmarshal(right.Candidate, &rightCandidate) != nil {
		return string(left.Candidate) == string(right.Candidate)
	}
	return reflect.DeepEqual(leftCandidate, rightCandidate)
}

func uniqueTaskCodeAuditIssues(issues []string) []string {
	seen := make(map[string]struct{}, len(issues))
	out := make([]string, 0, len(issues))
	for _, issue := range issues {
		issue = strings.TrimSpace(issue)
		if issue == "" {
			continue
		}
		if _, ok := seen[issue]; ok {
			continue
		}
		seen[issue] = struct{}{}
		out = append(out, issue)
	}
	return out
}

func formatTaskCodeAuditIssues(issues []string) string {
	issues = uniqueTaskCodeAuditIssues(issues)
	if len(issues) == 0 {
		return ""
	}
	lines := make([]string, 0, len(issues))
	for _, issue := range issues {
		lines = append(lines, "• "+issue)
	}
	return strings.Join(lines, "\n")
}

func mergeTaskCodeAuditIssueSummary(existing, incoming string) string {
	lines := append(strings.Split(strings.TrimSpace(existing), "\n"), strings.Split(strings.TrimSpace(incoming), "\n")...)
	return strings.Join(uniqueTaskCodeAuditIssues(lines), "\n")
}

func (d *DB) CompleteTaskCodeAudit(runID int64, progress TaskCodeAuditProgress) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	result, err := tx.Exec(`UPDATE task_code_audit_runs SET status='completed',files_total=$2,files_analyzed=$3,
files_skipped=$4,chunks_total=$5,chunks_completed=$6,next_file_index=$7,used_tokens=$8,summary=$9,error='',
	completed_at=now(),updated_at=now() WHERE id=$1 AND status='running'`, runID, progress.FilesTotal,
		progress.FilesAnalyzed, progress.FilesSkipped, progress.ChunksTotal, progress.ChunksCompleted,
		progress.NextFileIndex, progress.UsedTokens, progress.Summary)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 1 {
		if err := reconcileTaskCodeAuditFindingsTx(context.Background(), tx, runID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) IncompleteTaskCodeAudit(runID int64, progress TaskCodeAuditProgress, reason string) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	result, err := tx.Exec(`UPDATE task_code_audit_runs SET status='incomplete',files_total=$2,files_analyzed=$3,
files_skipped=$4,chunks_total=$5,chunks_completed=$6,next_file_index=$7,used_tokens=$8,summary=$9,error=$10,
completed_at=now(),updated_at=now() WHERE id=$1 AND status='running'`, runID, progress.FilesTotal,
		progress.FilesAnalyzed, progress.FilesSkipped, progress.ChunksTotal, progress.ChunksCompleted,
		progress.NextFileIndex, progress.UsedTokens, progress.Summary, reason)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 1 {
		if err := reconcileTaskCodeAuditFindingsTx(context.Background(), tx, runID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// StopQueuedTaskCodeAudit parks a run that has not been claimed yet as a
// resumable "incomplete" run. It reports false when the run is no longer queued.
func (d *DB) StopQueuedTaskCodeAudit(taskID, runID int64, reason string) (bool, error) {
	result, err := d.Exec(`UPDATE task_code_audit_runs SET status='incomplete',error=$3,completed_at=now(),updated_at=now()
WHERE task_id=$1 AND id=$2 AND status='queued'`, taskID, runID, reason)
	if err != nil {
		return false, err
	}
	updated, err := result.RowsAffected()
	return updated == 1, err
}

func (d *DB) FailTaskCodeAudit(runID int64, reason string) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	result, err := tx.Exec(`UPDATE task_code_audit_runs SET status='failed',error=$2,completed_at=now(),updated_at=now()
WHERE id=$1 AND status IN ('queued','running')`, runID, reason)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 1 {
		if err := reconcileTaskCodeAuditFindingsTx(context.Background(), tx, runID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// requeueTaskCodeAudit is the shared body of Resume/Retry: it puts a stopped
// run back into the queue. It acquires the task-row lock (FOR UPDATE) first,
// which both serializes with FinalizeAssessmentCompletion's queue re-check and
// enforces the same terminal guard as CreateTaskCodeAudit: an assessment-mode
// task can no longer requeue white-box work after it finished (the completion
// report must not omit pending audit work, §6.3-6.4).
func (d *DB) requeueTaskCodeAudit(taskID, runID int64, additionalBudget int, fromStatus string) (*TaskCodeAuditRun, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	var assessmentMode bool
	var status string
	if err := tx.QueryRow(`SELECT assessment_mode, status FROM tasks WHERE id=$1 FOR UPDATE`, taskID).
		Scan(&assessmentMode, &status); err != nil {
		return nil, err
	}
	if assessmentMode && (status == "done" || status == "failed" || status == "timeout") {
		return nil, sql.ErrNoRows
	}
	// 追加预算语义（累加，绝不静默清零）：0=不追加、保留存量预算；正数必须
	// 在 1,000~500,000 之间并在存量基础上累加。此前版本会把 0 请求写成
	// "预算清零"，且一旦清零就永远加不回来——worker 会在开工前判定预算耗尽。
	result, err := tx.Exec(`UPDATE task_code_audit_runs SET status='queued',budget_tokens=budget_tokens+$3,
error='',completed_at=NULL,updated_at=now() WHERE task_id=$1 AND id=$2 AND status=$4
AND ($3=0 OR $3 BETWEEN 1000 AND 500000)`, taskID, runID, additionalBudget, fromStatus)
	if err != nil {
		return nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetTaskCodeAudit(taskID, runID)
}

func (d *DB) ResumeTaskCodeAudit(taskID, runID int64, additionalBudget int) (*TaskCodeAuditRun, error) {
	return d.requeueTaskCodeAudit(taskID, runID, additionalBudget, "incomplete")
}

func (d *DB) RetryTaskCodeAudit(taskID, runID int64, additionalBudget int) (*TaskCodeAuditRun, error) {
	return d.requeueTaskCodeAudit(taskID, runID, additionalBudget, "failed")
}

func (d *DB) AddTaskCodeAuditReviewUsage(runID int64, usedTokens int) error {
	if usedTokens <= 0 {
		return nil
	}
	_, err := d.Exec(`UPDATE task_code_audit_runs SET used_tokens=used_tokens+$2,updated_at=now()
WHERE id=$1 AND status IN ('completed','incomplete')`, runID, usedTokens)
	return err
}

func (d *DB) IncompleteTaskCodeAuditReview(runID int64, usedTokens int, reason string) error {
	if usedTokens < 0 {
		return ErrTaskCodeAuditCandidateReviewInvalid
	}
	_, err := d.Exec(`UPDATE task_code_audit_runs SET status='incomplete',used_tokens=used_tokens+$2,error=$3,
completed_at=now(),updated_at=now() WHERE id=$1 AND status IN ('completed','incomplete')`, runID, usedTokens, reason)
	return err
}

func (d *DB) ListTaskCodeAudits(taskID int64) ([]TaskCodeAuditRun, error) {
	rows, err := d.Query(`SELECT `+taskCodeAuditRunColumns+` FROM task_code_audit_runs run
LEFT JOIN task_code_services service ON service.id=run.code_service_id WHERE run.task_id=$1
ORDER BY run.created_at DESC,run.id DESC LIMIT 100`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TaskCodeAuditRun, 0)
	for rows.Next() {
		item, err := scanTaskCodeAuditRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	byID := make(map[int64]int, len(out))
	for index := range out {
		byID[out[index].ID] = index
		out[index].Candidates = []TaskCodeAuditCandidate{}
	}
	candidates, err := d.Query(`SELECT candidate.id,candidate.run_id,candidate.candidate_key,candidate.review_status,
candidate.candidate,candidate.candidate_variants,candidate.reviewer_summary,candidate.verification_summary,candidate.created_at,candidate.updated_at
FROM task_code_audit_candidates candidate JOIN task_code_audit_runs run ON run.id=candidate.run_id
WHERE run.task_id=$1 ORDER BY CASE WHEN candidate.review_status='published' THEN
CASE WHEN candidate.candidate->>'registration_tier'='B' THEN 1 ELSE 0 END ELSE 2 END,candidate.id`, taskID)
	if err != nil {
		return nil, err
	}
	defer candidates.Close()
	for candidates.Next() {
		var item TaskCodeAuditCandidate
		var variants []byte
		if err := candidates.Scan(&item.ID, &item.RunID, &item.CandidateKey, &item.ReviewStatus, &item.Candidate,
			&variants, &item.ReviewerSummary, &item.VerificationSummary, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if len(variants) > 0 {
			if err := json.Unmarshal(variants, &item.Variants); err != nil {
				return nil, err
			}
		}
		if index, ok := byID[item.RunID]; ok {
			out[index].Candidates = append(out[index].Candidates, item)
		}
	}
	return out, candidates.Err()
}

func (d *DB) GetTaskCodeAudit(taskID, runID int64) (*TaskCodeAuditRun, error) {
	run, err := scanTaskCodeAuditRun(d.QueryRow(`SELECT `+taskCodeAuditRunColumns+` FROM task_code_audit_runs run
LEFT JOIN task_code_services service ON service.id=run.code_service_id WHERE run.task_id=$1 AND run.id=$2`, taskID, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	rows, err := d.Query(`SELECT id,run_id,candidate_key,review_status,candidate,candidate_variants,reviewer_summary,verification_summary,created_at,updated_at
FROM task_code_audit_candidates WHERE run_id=$1 ORDER BY CASE WHEN review_status='published' THEN
CASE WHEN candidate->>'registration_tier'='B' THEN 1 ELSE 0 END ELSE 2 END,id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	run.Candidates = make([]TaskCodeAuditCandidate, 0)
	for rows.Next() {
		var candidate TaskCodeAuditCandidate
		var variants []byte
		if err := rows.Scan(&candidate.ID, &candidate.RunID, &candidate.CandidateKey, &candidate.ReviewStatus,
			&candidate.Candidate, &variants, &candidate.ReviewerSummary, &candidate.VerificationSummary,
			&candidate.CreatedAt, &candidate.UpdatedAt); err != nil {
			return nil, err
		}
		if len(variants) > 0 {
			if err := json.Unmarshal(variants, &candidate.Variants); err != nil {
				return nil, err
			}
		}
		run.Candidates = append(run.Candidates, candidate)
	}
	return run, rows.Err()
}

// RecordTaskCodeAuditFinding atomically persists a graded worker-produced
// source-to-sink candidate as a pending Finding. It deliberately performs no
// independent LLM review; source-code evidence validation remains the worker's
// responsibility before this persistence boundary.
func (d *DB) RecordTaskCodeAuditFinding(ctx context.Context, taskID, runID int64, input TaskCodeAuditFindingInput) (*TaskCodeAuditFindingResult, error) {
	input.CandidateKey = strings.TrimSpace(input.CandidateKey)
	input.Name = strings.TrimSpace(input.Name)
	input.Summary = strings.TrimSpace(input.Summary)
	input.Evidence = strings.TrimSpace(input.Evidence)
	if taskID <= 0 || runID <= 0 || input.CandidateKey == "" || !json.Valid(input.Candidate) ||
		!ValidTaskCodeAuditVulnClass(input.VulnClass) || !ValidSeverity(input.Severity) || input.Name == "" ||
		input.Summary == "" || input.Evidence == "" || !json.Valid(input.CodeAuditEvidence) {
		return nil, errors.New("invalid task code audit finding")
	}
	var auditEvidence struct {
		CandidateKey     string          `json:"candidate_key"`
		CodebaseID       string          `json:"codebase_id"`
		VersionID        string          `json:"version_id"`
		RelativePath     string          `json:"relative_path"`
		Candidate        json.RawMessage `json:"candidate"`
		RegistrationTier string          `json:"registration_tier"`
		ValidationIssues []string        `json:"validation_issues"`
	}
	if err := json.Unmarshal(input.CodeAuditEvidence, &auditEvidence); err != nil ||
		auditEvidence.CandidateKey != input.CandidateKey || auditEvidence.CodebaseID == "" ||
		auditEvidence.VersionID == "" || auditEvidence.RelativePath == "" || !json.Valid(auditEvidence.Candidate) {
		return nil, errors.New("task code audit evidence does not match the candidate")
	}
	verificationSummary := "worker 已完成 source-to-sink 污点分析；A 级 Finding 状态为待确认。"
	if auditEvidence.RegistrationTier == "B" {
		verificationSummary = "B 级低置信度 Finding；链路或可利用性待确认，报告 Agent 不自动排队。"
	}
	variantJSON, err := json.Marshal(TaskCodeAuditCandidateVariant{
		Candidate: append(json.RawMessage(nil), input.Candidate...), AnalysisChunk: input.AnalysisChunk,
		ValidationIssues: auditEvidence.ValidationIssues,
	})
	if err != nil {
		return nil, err
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	var runStatus, codebaseID, versionID, scopePath, relativePath, executionOrigin string
	var explorationID int64
	var codeServiceID, targetEntityID, assetID sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT run.status,run.codebase_id,run.version_id,run.scope_path,run.relative_path,
run.execution_origin,run.code_service_id,run.target_entity_id,task.exploration_id
FROM task_code_audit_runs run
JOIN tasks task ON task.id=run.task_id
WHERE run.task_id=$1 AND run.id=$2
FOR UPDATE OF run`, taskID, runID).Scan(&runStatus, &codebaseID, &versionID, &scopePath, &relativePath,
		&executionOrigin, &codeServiceID, &targetEntityID, &explorationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTaskCodeAuditCandidateReviewConflict
	}
	if err != nil {
		return nil, err
	}
	if codeServiceID.Valid {
		var serviceDecision, latestVersion string
		var latestPresent bool
		err = tx.QueryRowContext(ctx, `SELECT relative_path,decision,latest_version_id,latest_present,asset_id
FROM task_code_services WHERE id=$1 FOR UPDATE`, codeServiceID.Int64).
			Scan(&relativePath, &serviceDecision, &latestVersion, &latestPresent, &assetID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTaskCodeAuditCandidateReviewConflict
		}
		if err != nil {
			return nil, err
		}
		if runStatus != "running" || serviceDecision != "confirmed" || !latestPresent || latestVersion != versionID || !assetID.Valid ||
			auditEvidence.CodebaseID != codebaseID || auditEvidence.VersionID != versionID || auditEvidence.RelativePath != relativePath {
			return nil, ErrTaskCodeAuditCandidateReviewConflict
		}
	} else {
		if runStatus != "running" || executionOrigin != "engine" ||
			auditEvidence.CodebaseID != codebaseID || auditEvidence.VersionID != versionID || auditEvidence.RelativePath != relativePath {
			return nil, ErrTaskCodeAuditCandidateReviewConflict
		}
		if targetEntityID.Valid {
			_ = tx.QueryRowContext(ctx, `SELECT asset_id FROM task_target_entities WHERE id=$1 AND task_id=$2`,
				targetEntityID.Int64, taskID).Scan(&assetID)
		}
	}

	identityKey, err := taskCodeAuditIdentityKey(input.VulnClass, input.CodeAuditEvidence)
	if err != nil {
		return nil, err
	}
	lockKey := fmt.Sprintf("%d:%s:%s:%s", taskID, codebaseID, relativePath, identityKey)
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
		return nil, err
	}
	result := &TaskCodeAuditFindingResult{Status: "published"}
	result.ReportRequired = auditEvidence.RegistrationTier != "B"

	var candidateID int64
	inserted, err := tx.ExecContext(ctx, `INSERT INTO task_code_audit_candidates
(run_id,candidate_key,review_status,candidate,candidate_variants,reviewer_summary,verification_summary)
VALUES($1,$2,'published',$3::jsonb,jsonb_build_array($4::jsonb),'',$5)
ON CONFLICT(run_id,candidate_key) DO NOTHING`, runID, input.CandidateKey, string(input.Candidate), string(variantJSON), verificationSummary)
	if err != nil {
		return nil, err
	}
	insertedCount, err := inserted.RowsAffected()
	if err != nil {
		return nil, err
	}
	if insertedCount > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE task_code_audit_runs SET candidate_count=candidate_count+1,updated_at=now() WHERE id=$1`, runID); err != nil {
			return nil, err
		}
	}
	var candidateStatus string
	if err := tx.QueryRowContext(ctx, `SELECT id,review_status FROM task_code_audit_candidates
WHERE run_id=$1 AND candidate_key=$2 FOR UPDATE`, runID, input.CandidateKey).Scan(&candidateID, &candidateStatus); err != nil {
		return nil, err
	}
	if candidateStatus == "dismissed" || candidateStatus == "rejected" {
		return &TaskCodeAuditFindingResult{Status: candidateStatus}, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE task_code_audit_candidates SET review_status='published',
candidate=CASE WHEN review_status='published' AND COALESCE(candidate->>'registration_tier','A')='A'
AND $2::jsonb->>'registration_tier'='B' THEN candidate ELSE $2::jsonb END,
candidate_variants=CASE WHEN candidate_variants @> jsonb_build_array($3::jsonb) THEN candidate_variants
ELSE candidate_variants || jsonb_build_array($3::jsonb) END,
reviewer_summary='',verification_summary=CASE WHEN review_status='published' AND COALESCE(candidate->>'registration_tier','A')='A'
AND $2::jsonb->>'registration_tier'='B' THEN verification_summary ELSE $4 END,updated_at=now() WHERE id=$1`,
		candidateID, string(input.Candidate), string(variantJSON), verificationSummary); err != nil {
		return nil, err
	}

	legacyIdentityKey, err := taskCodeAuditLegacyIdentityKey(input.VulnClass, input.CodeAuditEvidence)
	if err != nil {
		return nil, err
	}
	existing, err := findTaskCodeAuditFindingTx(ctx, tx, taskID, identityKey, legacyIdentityKey, input.VulnClass, codebaseID, relativePath)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		initialEvidence, _, err := mergeTaskCodeAuditFindingEvidence(nil, input.CodeAuditEvidence, identityKey, runID, time.Time{}, "")
		if err != nil {
			return nil, err
		}
		var findAssetIDs []int64
		if assetID.Valid && assetID.Int64 > 0 {
			findAssetIDs = []int64{assetID.Int64}
		}
		recorded, err := RecordFindingTx(ctx, tx, RecordFindingInput{
			TaskID: taskID, ExplorationID: explorationID, VulnClass: input.VulnClass, Name: input.Name,
			Severity: input.Severity, Summary: input.Summary, Evidence: input.Evidence, Worker: "whitebox_java_audit",
			AssetIDs: findAssetIDs, CodeAuditEvidence: initialEvidence,
			VerifyLevel: "theoretical", ImpactObserved: "none",
		}, nil)
		if err != nil {
			return nil, err
		}
		result.FindingID = recorded.FindingID
	} else {
		result.FindingID = existing.id
		var previousEvidence map[string]any
		_ = json.Unmarshal(existing.codeAuditEvidence, &previousEvidence)
		previousVersion := codeAuditEvidenceString(previousEvidence, "last_seen_version_id")
		if previousVersion == "" {
			previousVersion = codeAuditEvidenceString(previousEvidence, "version_id")
		}
		result.ReportRequired = auditEvidence.RegistrationTier != "B" &&
			(previousVersion != versionID || codeAuditEvidenceString(previousEvidence, "registration_tier") == "B")
		preserveEvidence := previousVersion == versionID && auditEvidence.RegistrationTier == "B" &&
			codeAuditEvidenceString(previousEvidence, "registration_tier") != "B"
		mergedEvidence, reopen, err := mergeTaskCodeAuditFindingEvidence(existing.codeAuditEvidence, input.CodeAuditEvidence,
			identityKey, runID, existing.createdAt, existing.status)
		if err != nil {
			return nil, err
		}
		newStatus := existing.status
		if reopen {
			newStatus = FindingPending
		}
		// A re-observation refreshes the evidence only. Name, severity, summary and
		// class may have been edited by a human and are never overwritten here.
		payload, _ := json.Marshal(map[string]any{
			"evidence":            map[string]any{"by": "whitebox_java_audit", "poc": input.Evidence},
			"code_audit_evidence": mergedEvidence,
		})
		if preserveEvidence {
			payload, _ = json.Marshal(map[string]any{"code_audit_evidence": mergedEvidence})
		}
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET evidence=CASE WHEN $5 THEN evidence ELSE $2 END,code_audit_evidence=$3::jsonb,status=$4,
verify_level=CASE WHEN verify_level IN ('unknown','theoretical') THEN 'theoretical' ELSE verify_level END
WHERE id=$1`, existing.id, input.Evidence, string(mergedEvidence), newStatus, preserveEvidence); err != nil {
			return nil, err
		}
		if existing.nodeID.Valid {
			if _, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET payload=payload || $2::jsonb,updated_at=now()
WHERE id=$1 AND kind='finding'`, existing.nodeID.Int64, string(payload)); err != nil {
				return nil, err
			}
		}
	}
	if err := reconcileTaskCodeAuditFindingsTx(ctx, tx, runID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (d *DB) FinalizeTaskCodeAuditCandidateReview(ctx context.Context, taskID, runID, candidateID int64, input TaskCodeAuditCandidateReviewInput) (*TaskCodeAuditCandidateReviewResult, error) {
	if taskID <= 0 || runID <= 0 || candidateID <= 0 || input.UsedTokens < 0 {
		return nil, ErrTaskCodeAuditCandidateReviewInvalid
	}
	input.VerificationSummary = strings.TrimSpace(input.VerificationSummary)
	if input.VerificationSummary == "" || len(input.VerificationSummary) > 4000 {
		return nil, ErrTaskCodeAuditCandidateReviewInvalid
	}
	if input.Accepted {
		if !ValidTaskCodeAuditVulnClass(input.VulnClass) || !ValidSeverity(input.Severity) ||
			strings.TrimSpace(input.Name) == "" || strings.TrimSpace(input.Summary) == "" ||
			strings.TrimSpace(input.Evidence) == "" || !json.Valid(input.CodeAuditEvidence) {
			return nil, ErrTaskCodeAuditCandidateReviewInvalid
		}
		var auditEvidence struct {
			CandidateKey string `json:"candidate_key"`
			CodebaseID   string `json:"codebase_id"`
			VersionID    string `json:"version_id"`
			RelativePath string `json:"relative_path"`
		}
		if json.Unmarshal(input.CodeAuditEvidence, &auditEvidence) != nil || auditEvidence.CandidateKey == "" ||
			auditEvidence.CodebaseID == "" || auditEvidence.VersionID == "" || auditEvidence.RelativePath == "" {
			return nil, ErrTaskCodeAuditCandidateReviewInvalid
		}
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	var status, runStatus, codebaseID, versionID, candidateKey, relativePath, executionOrigin string
	var explorationID int64
	var codeServiceID, targetEntityID, assetID sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT candidate.review_status,run.status,run.codebase_id,run.version_id,candidate.candidate_key,
run.relative_path,run.execution_origin,run.code_service_id,run.target_entity_id,task.exploration_id
FROM task_code_audit_candidates candidate
JOIN task_code_audit_runs run ON run.id=candidate.run_id
JOIN tasks task ON task.id=run.task_id
WHERE run.task_id=$1 AND run.id=$2 AND candidate.id=$3 FOR UPDATE OF candidate, run`, taskID, runID, candidateID).
		Scan(&status, &runStatus, &codebaseID, &versionID, &candidateKey, &relativePath,
			&executionOrigin, &codeServiceID, &targetEntityID, &explorationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTaskCodeAuditCandidateReviewConflict
	}
	if err != nil {
		return nil, err
	}
	if status != "pending_review" || (runStatus != "running" && runStatus != "completed" && runStatus != "incomplete") {
		return nil, ErrTaskCodeAuditCandidateReviewConflict
	}
	result := &TaskCodeAuditCandidateReviewResult{}
	if !input.Accepted {
		result.Status = "rejected"
		if _, err := tx.ExecContext(ctx, `UPDATE task_code_audit_candidates SET review_status='rejected',verification_summary=$2,updated_at=now() WHERE id=$1`, candidateID, input.VerificationSummary); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE task_code_audit_runs SET used_tokens=used_tokens+$2,updated_at=now() WHERE id=$1`, runID, input.UsedTokens); err != nil {
			return nil, err
		}
		if err := reconcileTaskCodeAuditFindingsTx(ctx, tx, runID); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return result, nil
	}
	if codeServiceID.Valid {
		var serviceDecision, latestVersion string
		var latestPresent bool
		err = tx.QueryRowContext(ctx, `SELECT relative_path,decision,latest_version_id,latest_present,asset_id
FROM task_code_services WHERE id=$1 FOR UPDATE`, codeServiceID.Int64).
			Scan(&relativePath, &serviceDecision, &latestVersion, &latestPresent, &assetID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (serviceDecision != "confirmed" || !latestPresent || latestVersion != versionID || !assetID.Valid)) {
			return nil, ErrTaskCodeAuditCandidateReviewConflict
		}
		if err != nil {
			return nil, err
		}
	} else {
		if executionOrigin != "engine" {
			return nil, ErrTaskCodeAuditCandidateReviewConflict
		}
		if targetEntityID.Valid {
			_ = tx.QueryRowContext(ctx, `SELECT asset_id FROM task_target_entities WHERE id=$1 AND task_id=$2`,
				targetEntityID.Int64, taskID).Scan(&assetID)
		}
	}
	var acceptedEvidence struct {
		CandidateKey string `json:"candidate_key"`
		CodebaseID   string `json:"codebase_id"`
		VersionID    string `json:"version_id"`
		RelativePath string `json:"relative_path"`
	}
	if err := json.Unmarshal(input.CodeAuditEvidence, &acceptedEvidence); err != nil ||
		acceptedEvidence.CandidateKey != candidateKey || acceptedEvidence.CodebaseID != codebaseID || acceptedEvidence.VersionID != versionID || acceptedEvidence.RelativePath != relativePath {
		return nil, ErrTaskCodeAuditCandidateReviewInvalid
	}
	identityKey, err := taskCodeAuditIdentityKey(input.VulnClass, input.CodeAuditEvidence)
	if err != nil {
		return nil, ErrTaskCodeAuditCandidateReviewInvalid
	}
	lockKey := fmt.Sprintf("%d:%s:%s:%s", taskID, codebaseID, acceptedEvidence.RelativePath, identityKey)
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
		return nil, err
	}
	legacyIdentityKey, err := taskCodeAuditLegacyIdentityKey(input.VulnClass, input.CodeAuditEvidence)
	if err != nil {
		return nil, err
	}
	existing, err := findTaskCodeAuditFindingTx(ctx, tx, taskID, identityKey, legacyIdentityKey, input.VulnClass, codebaseID, acceptedEvidence.RelativePath)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		mergedEvidence, reopen, err := mergeTaskCodeAuditFindingEvidence(existing.codeAuditEvidence, input.CodeAuditEvidence,
			identityKey, runID, existing.createdAt, existing.status)
		if err != nil {
			return nil, err
		}
		status := existing.status
		if reopen {
			status = FindingPending
		}
		payloadFields := map[string]any{
			"vulnclass": input.VulnClass, "name": input.Name, "severity": input.Severity,
			"summary": input.Summary, "evidence": map[string]any{"by": "whitebox_java_audit", "poc": input.Evidence},
			"code_audit_evidence": mergedEvidence,
		}
		payload, _ := json.Marshal(payloadFields)
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET vulnclass=$2,name=$3,severity=$4,summary=$5,evidence=$6,
code_audit_evidence=$7::jsonb,status=$8 WHERE id=$1`, existing.id, input.VulnClass, input.Name, input.Severity,
			input.Summary, input.Evidence, string(mergedEvidence), status); err != nil {
			return nil, err
		}
		if existing.nodeID.Valid {
			if _, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET payload=payload || $2::jsonb,updated_at=now()
WHERE id=$1 AND kind='finding'`, existing.nodeID.Int64, string(payload)); err != nil {
				return nil, err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE task_code_audit_candidates SET review_status='published',verification_summary=$2,updated_at=now() WHERE id=$1`, candidateID, input.VerificationSummary); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE task_code_audit_runs SET used_tokens=used_tokens+$2,updated_at=now() WHERE id=$1`, runID, input.UsedTokens); err != nil {
			return nil, err
		}
		if err := reconcileTaskCodeAuditFindingsTx(ctx, tx, runID); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &TaskCodeAuditCandidateReviewResult{Status: "published", FindingID: existing.id}, nil
	}
	initialEvidence, _, err := mergeTaskCodeAuditFindingEvidence(nil, input.CodeAuditEvidence, identityKey, runID, time.Time{}, "")
	if err != nil {
		return nil, err
	}
	var assets []int64
	if assetID.Valid && assetID.Int64 > 0 {
		assets = []int64{assetID.Int64}
	}
	recorded, err := RecordFindingTx(ctx, tx, RecordFindingInput{
		TaskID: taskID, ExplorationID: explorationID, VulnClass: input.VulnClass, Name: input.Name,
		Severity: input.Severity, Summary: input.Summary, Evidence: input.Evidence, Worker: "whitebox_java_audit",
		AssetIDs: assets, CodeAuditEvidence: initialEvidence,
	}, nil)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE task_code_audit_candidates SET review_status='published',verification_summary=$2,updated_at=now() WHERE id=$1`, candidateID, input.VerificationSummary); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE task_code_audit_runs SET used_tokens=used_tokens+$2,updated_at=now() WHERE id=$1`, runID, input.UsedTokens); err != nil {
		return nil, err
	}
	if err := reconcileTaskCodeAuditFindingsTx(ctx, tx, runID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	result.Status = "published"
	result.FindingID = recorded.FindingID
	return result, nil
}

type taskCodeAuditIdentityLocation struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Symbol      string `json:"symbol"`
	Description string `json:"description"`
	Parameter   string `json:"parameter"`
}

type taskCodeAuditIdentityEvidence struct {
	CodebaseID   string `json:"codebase_id"`
	RelativePath string `json:"relative_path"`
	Candidate    struct {
		Language   string                          `json:"language,omitempty"`
		Anchors    []taskCodeAuditIdentityAnchor   `json:"anchors,omitempty"`
		Source     taskCodeAuditIdentityLocation   `json:"source"`
		Sink       taskCodeAuditIdentityLocation   `json:"sink"`
		EntryPoint taskCodeAuditIdentityLocation   `json:"entry_point"`
		Flow       []taskCodeAuditIdentityFlowStep `json:"flow"`
	} `json:"candidate"`
	Source taskCodeAuditIdentityLocation `json:"source"`
	Sink   taskCodeAuditIdentityLocation `json:"sink"`
	Key    string                        `json:"candidate_key"`
}

type taskCodeAuditIdentityFlowStep struct {
	Symbol string `json:"symbol"`
}

type taskCodeAuditIdentityAnchor struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Symbol string `json:"symbol"`
}

// taskCodeAuditAnchorIdentity builds a line-independent identity from the
// anchors a candidate cites. Anchors are deduplicated and sorted so a model
// that lists them in a different order or shifts line numbers still maps to
// the same candidate.
func taskCodeAuditAnchorIdentity(category, language string, anchors []taskCodeAuditIdentityAnchor) (string, bool) {
	seen := map[string]struct{}{}
	var parts []string
	for _, anchor := range anchors {
		file := normalizeTaskCodeAuditIdentityPath(anchor.File)
		symbol := normalizeTaskCodeAuditIdentitySymbolForLanguage(anchor.Symbol, language)
		if strings.TrimSpace(anchor.File) == "" || symbol == "" {
			continue
		}
		item := file + "\x00" + symbol
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		parts = append(parts, item)
	}
	if len(parts) == 0 {
		return "", false
	}
	sort.Strings(parts)
	encoded, err := json.Marshal(append([]string{"anchors-v1", category, language}, parts...))
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), true
}

// TaskCodeAuditCandidateIdentityKey returns a stable per-chain key. It uses
// normalized file and symbol anchors instead of line numbers so chunk overlap,
// wording changes, and decompiler line shifts do not split one issue into
// multiple candidates. Java command injection retains its more specific chain
// identity.
func TaskCodeAuditCandidateIdentityKey(vulnClass string, candidate json.RawMessage) (string, error) {
	var value struct {
		Language   string                          `json:"language,omitempty"`
		Source     taskCodeAuditIdentityLocation   `json:"source"`
		Sink       taskCodeAuditIdentityLocation   `json:"sink"`
		EntryPoint taskCodeAuditIdentityLocation   `json:"entry_point"`
		Flow       []taskCodeAuditIdentityFlowStep `json:"flow"`
		Anchors    []taskCodeAuditIdentityAnchor   `json:"anchors"`
	}
	if err := json.Unmarshal(candidate, &value); err != nil {
		return "", err
	}
	category := strings.ToUpper(strings.TrimSpace(vulnClass))
	javaChain := value.Language == "" || value.Language == "java"
	if category == "COMMAND_INJECTION" && javaChain {
		source := normalizeTaskCodeAuditSourceIdentity(value.Source)
		entryFile := normalizeTaskCodeAuditCommandPath(value.EntryPoint.File)
		sinkFile := normalizeTaskCodeAuditCommandPath(value.Sink.File)
		flowContext := normalizeTaskCodeAuditFlowContext(value.Flow)
		if source != "" && entryFile != "" && sinkFile != "" && flowContext != "" {
			parts := []string{"command-chain-v1", source, entryFile, sinkFile, flowContext}
			encoded, err := json.Marshal(parts)
			if err != nil {
				return "", err
			}
			sum := sha256.Sum256(encoded)
			return hex.EncodeToString(sum[:]), nil
		}
	}
	locationKey := func(location taskCodeAuditIdentityLocation) string {
		file := normalizeTaskCodeAuditIdentityPath(location.File)
		symbol := normalizeTaskCodeAuditIdentitySymbolForLanguage(location.Symbol, value.Language)
		parameter := strings.TrimSpace(location.Parameter)
		if value.Language != "python" && value.Language != "c" {
			parameter = strings.ToLower(parameter)
		}
		if symbol == "" {
			symbol = parameter
		}
		if file == "" || symbol == "" {
			return ""
		}
		return file + "\x00" + symbol + "\x00" + parameter
	}
	sourceKey, sinkKey := locationKey(value.Source), locationKey(value.Sink)
	if sourceKey != "" && sinkKey != "" {
		parts := []string{"source-sink-v2", category, value.Language, sourceKey, sinkKey}
		if entryKey := locationKey(value.EntryPoint); entryKey != "" {
			parts = append(parts, entryKey)
		}
		encoded, err := json.Marshal(parts)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(encoded)
		return hex.EncodeToString(sum[:]), nil
	}
	if key, ok := taskCodeAuditAnchorIdentity(category, value.Language, value.Anchors); ok {
		return key, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(candidate, &payload); err != nil {
		return "", err
	}
	delete(payload, "analysis_chunk")
	encoded, err := json.Marshal([]any{category, payload})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

var taskCodeAuditSourceFieldPattern = regexp.MustCompile(`(?i)(?:字段|field|parameter|property)\s*[:：]?\s*([A-Za-z_$][A-Za-z0-9_$]*)|\.([A-Za-z_$][A-Za-z0-9_$]*)\s*\(|([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:字段|field|parameter|property)`)

func normalizeTaskCodeAuditSourceIdentity(source taskCodeAuditIdentityLocation) string {
	symbol := strings.TrimSpace(source.Symbol)
	if slash := strings.LastIndex(symbol, "/"); slash >= 0 {
		symbol = symbol[slash+1:]
	}
	if bracket := strings.Index(symbol, "("); bracket >= 0 {
		symbol = symbol[:bracket]
	}
	identifiers := taskCodeAuditSymbolIdentifier.FindAllString(symbol, -1)
	if len(identifiers) > 2 {
		identifiers = identifiers[len(identifiers)-2:]
	}
	field := ""
	typedClass := ""
	channel := normalizeTaskCodeAuditSourceChannel(source.Description)
	descriptionField, accessorField := "", ""
	for _, match := range taskCodeAuditSourceFieldPattern.FindAllStringSubmatch(source.Description, -1) {
		for _, index := range []int{2, 1, 3} {
			if match[index] != "" {
				if index == 2 {
					accessorField = match[index]
				} else {
					descriptionField = match[index]
				}
				break
			}
		}
	}
	if len(identifiers) >= 2 {
		previous := identifiers[len(identifiers)-2]
		if previous[0] >= 'A' && previous[0] <= 'Z' || strings.EqualFold(previous, "input") || strings.EqualFold(previous, "request") {
			field = identifiers[len(identifiers)-1]
			if previous[0] >= 'A' && previous[0] <= 'Z' {
				typedClass = previous
			}
		}
	} else if len(identifiers) == 1 && identifiers[0][0] >= 'a' && identifiers[0][0] <= 'z' {
		field = identifiers[0]
	}
	// The source symbol may be an accessor, controller method, or request object.
	// Prefer a concrete accessor from the description, and use a labelled field
	// when the symbol itself is only a generic request variable.
	if accessorField != "" {
		field = accessorField
	} else if descriptionField != "" && (field == "" || strings.EqualFold(field, "input") || strings.EqualFold(field, "request") || strings.EqualFold(field, "body")) {
		field = descriptionField
	}
	if field == "" {
		field = descriptionField
	}
	if field == "" {
		field = strings.TrimSpace(source.Parameter)
	}
	if field != "" {
		if channel != "" {
			return channel + "." + strings.ToLower(field)
		}
	}
	if field != "" && typedClass != "" {
		return strings.ToLower(typedClass + "." + field)
	}
	class := auditSourceClassFromFile(source.File)
	if field != "" && class != "" {
		return strings.ToLower(class + "." + field)
	}
	if field != "" {
		return strings.ToLower(field)
	}
	if len(identifiers) == 0 {
		return ""
	}
	if len(identifiers) > 2 {
		identifiers = identifiers[len(identifiers)-2:]
	}
	for index := range identifiers {
		identifiers[index] = strings.ToLower(identifiers[index])
	}
	return strings.Join(identifiers, ".")
}

func normalizeTaskCodeAuditSourceChannel(description string) string {
	value := strings.ToLower(strings.TrimSpace(description))
	switch {
	case strings.Contains(value, "请求体"), strings.Contains(value, "request body"), strings.Contains(value, "json body"):
		return "body"
	case strings.Contains(value, "请求头"), strings.Contains(value, "request header"), strings.Contains(value, "http header"):
		return "header"
	case strings.Contains(value, "查询参数"), strings.Contains(value, "query parameter"), strings.Contains(value, "query string"):
		return "query"
	case strings.Contains(value, "路径参数"), strings.Contains(value, "pathvariable"), strings.Contains(value, "path parameter"):
		return "path"
	case strings.Contains(value, "cookie"):
		return "cookie"
	case strings.Contains(value, "消息"), strings.Contains(value, "message body"), strings.Contains(value, "kafka"):
		return "message"
	default:
		return ""
	}
}

func auditSourceClassFromFile(file string) string {
	file = strings.TrimSpace(strings.ReplaceAll(file, `\`, "/"))
	if bang := strings.LastIndex(file, "!"); bang >= 0 {
		file = file[bang+1:]
	}
	base := path.Base(file)
	base = strings.TrimSuffix(base, path.Ext(base))
	if inner := strings.LastIndex(base, "$"); inner >= 0 && inner+1 < len(base) {
		base = base[inner+1:]
	}
	identifiers := taskCodeAuditSymbolIdentifier.FindAllString(base, -1)
	if len(identifiers) == 0 {
		return ""
	}
	return identifiers[len(identifiers)-1]
}

func normalizeTaskCodeAuditIdentityPath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, `\`, "/"))
	if value == "" {
		return ""
	}
	return strings.TrimPrefix(path.Clean(value), "./")
}

// Command-injection candidates commonly mix a basename returned by a worker
// with an archive-qualified path saved by an earlier run. Identity is scoped to
// one task code service, so the class basename keeps those representations
// comparable while source-field and sink-class context distinguish chains.
func normalizeTaskCodeAuditCommandPath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, `\`, "/"))
	if value == "" {
		return ""
	}
	return strings.ToLower(path.Base(value))
}

func normalizeTaskCodeAuditFlowContext(flow []taskCodeAuditIdentityFlowStep) string {
	ignored := map[string]struct{}{
		"start": {}, "exec": {}, "strip": {}, "list": {}, "of": {}, "builder": {}, "processbuilder": {},
		"runtime": {}, "command": {}, "shell": {}, "target": {}, "process": {}, "input": {}, "output": {},
		"carrierhost": {}, "getcarrierhost": {}, "host": {}, "get": {}, "set": {}, "valueof": {}, "tostring": {},
	}
	methods := make([]string, 0, len(flow))
	seen := make(map[string]struct{}, len(flow))
	for index, step := range flow {
		if index == 0 {
			continue // source wording is normalized separately and is not call-path context
		}
		symbol := strings.TrimSpace(step.Symbol)
		if bracket := strings.Index(symbol, "("); bracket >= 0 {
			symbol = symbol[:bracket]
		}
		identifiers := taskCodeAuditSymbolIdentifier.FindAllString(symbol, -1)
		if len(identifiers) == 0 {
			continue
		}
		method := ""
		for index := len(identifiers) - 1; index >= 0; index-- {
			candidate := identifiers[index]
			lower := strings.ToLower(candidate)
			if _, skip := ignored[lower]; skip || (candidate[0] >= 'A' && candidate[0] <= 'Z') {
				continue
			}
			method = lower
			break
		}
		if method == "" {
			continue
		}
		if _, exists := seen[method]; exists {
			continue
		}
		seen[method] = struct{}{}
		methods = append(methods, method)
	}
	if len(methods) == 0 {
		return ""
	}
	if len(methods) > 1 {
		methods = methods[len(methods)-1:]
	}
	// The innermost application helper is the stable context nearest the sink.
	// Wider flows often omit an intermediate method in one worker's summary.
	return strings.Join(methods, ">")
}

// taskCodeAuditIdentityKey is the finding identity. Command injection uses the
// normalized source/entry/sink-class/call-path chain key so equivalent chunk
// variants and decompiler line shifts do not create a second Finding. Other
// vulnerability classes retain symbol and parameter normalization.
func taskCodeAuditIdentityKey(vulnClass string, evidence json.RawMessage) (string, error) {
	return computeTaskCodeAuditIdentityKey(vulnClass, evidence, true)
}

// taskCodeAuditLegacyIdentityKey is the pre-normalization identity. Findings
// recorded before the change still carry it, so lookups accept both.
func taskCodeAuditLegacyIdentityKey(vulnClass string, evidence json.RawMessage) (string, error) {
	return computeTaskCodeAuditIdentityKey(vulnClass, evidence, false)
}

var taskCodeAuditSymbolIdentifier = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]*`)

func normalizeTaskCodeAuditIdentitySymbol(symbol string) string {
	symbol = strings.TrimSpace(symbol)
	if cut := strings.Index(symbol, "("); cut > 0 {
		symbol = symbol[:cut]
	}
	if identifiers := taskCodeAuditSymbolIdentifier.FindAllString(symbol, -1); len(identifiers) > 0 {
		return strings.ToLower(identifiers[len(identifiers)-1])
	}
	return strings.ToLower(symbol)
}

// Native identifiers retain case and qualification. Collapsing Handler/handler
// or module_a.lookup/module_b.lookup could merge different Python/C findings.
// The legacy Java normalization remains unchanged for existing identities.
func normalizeTaskCodeAuditIdentitySymbolForLanguage(symbol, language string) string {
	if language != "python" && language != "c" {
		return normalizeTaskCodeAuditIdentitySymbol(symbol)
	}
	if cut := strings.Index(symbol, "("); cut >= 0 {
		symbol = symbol[:cut]
	}
	return strings.Join(strings.Fields(symbol), "")
}

func computeTaskCodeAuditIdentityKey(vulnClass string, evidence json.RawMessage, normalize bool) (string, error) {
	var value taskCodeAuditIdentityEvidence
	if err := json.Unmarshal(evidence, &value); err != nil {
		return "", err
	}
	if normalize && (value.Candidate.Language == "" || value.Candidate.Language == "java") && strings.ToUpper(strings.TrimSpace(vulnClass)) == "COMMAND_INJECTION" {
		candidate := value.Candidate
		if candidate.Source.File == "" && candidate.Source.Symbol == "" {
			candidate.Source = value.Source
		}
		if candidate.Sink.File == "" && candidate.Sink.Symbol == "" {
			candidate.Sink = value.Sink
		}
		candidateJSON, err := json.Marshal(candidate)
		if err != nil {
			return "", err
		}
		chainKey, err := TaskCodeAuditCandidateIdentityKey(vulnClass, candidateJSON)
		if err != nil {
			return "", err
		}
		identity := []string{strings.TrimSpace(value.CodebaseID), normalizeCodeAuditScopePath(value.RelativePath),
			"COMMAND_INJECTION", "chain:" + chainKey}
		if identity[0] == "" {
			return "", errors.New("code audit identity is incomplete")
		}
		encoded, err := json.Marshal(identity)
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(encoded)
		return hex.EncodeToString(digest[:]), nil
	}
	source, sink := value.Candidate.Source, value.Candidate.Sink
	if source.File == "" && source.Symbol == "" {
		source = value.Source
	}
	if sink.File == "" && sink.Symbol == "" {
		sink = value.Sink
	}
	locationIdentity := func(location taskCodeAuditIdentityLocation) string {
		file := strings.TrimPrefix(path.Clean(strings.ReplaceAll(strings.TrimSpace(location.File), `\`, "/")), "./")
		symbol := strings.TrimSpace(location.Symbol)
		parameter := strings.TrimSpace(location.Parameter)
		if normalize {
			symbol = normalizeTaskCodeAuditIdentitySymbolForLanguage(symbol, value.Candidate.Language)
			if value.Candidate.Language != "python" && value.Candidate.Language != "c" {
				parameter = strings.ToLower(parameter)
			}
		}
		if symbol == "" && parameter == "" {
			symbol = strings.TrimSpace(location.Description)
		}
		if symbol == "" && parameter == "" {
			// Older evidence may have only file and line coordinates. It remains
			// matchable, while new evidence uses symbols and survives line movement.
			symbol = fmt.Sprintf("line:%d", location.Line)
		}
		return file + "\x00" + symbol + "\x00" + parameter
	}
	identity := []string{
		strings.TrimSpace(value.CodebaseID),
		normalizeCodeAuditScopePath(value.RelativePath),
		strings.ToUpper(strings.TrimSpace(vulnClass)),
		locationIdentity(source),
		locationIdentity(sink),
	}
	if identity[0] == "" || identity[2] == "" {
		return "", errors.New("code audit identity is incomplete")
	}
	if source.File == "" && source.Symbol == "" && source.Description == "" && source.Line == 0 ||
		sink.File == "" && sink.Symbol == "" && sink.Description == "" && sink.Line == 0 {
		if strings.TrimSpace(value.Key) == "" {
			return "", errors.New("code audit source or sink identity is missing")
		}
		identity = append(identity, strings.TrimSpace(value.Key))
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func normalizeCodeAuditScopePath(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), `\`, "/")
	value = strings.TrimPrefix(path.Clean(value), "./")
	if value == "" {
		return "."
	}
	return value
}

type taskCodeAuditFindingRow struct {
	id                int64
	nodeID            sql.NullInt64
	vulnClass         string
	status            string
	codeAuditEvidence []byte
	createdAt         time.Time
}

func findTaskCodeAuditFindingTx(ctx context.Context, tx *sql.Tx, taskID int64, identityKey, legacyIdentityKey, vulnClass, codebaseID, relativePath string) (*taskCodeAuditFindingRow, error) {
	var existing taskCodeAuditFindingRow
	err := tx.QueryRowContext(ctx, `SELECT id,node_id,vulnclass,status,code_audit_evidence,created_at FROM findings
WHERE task_id=$1 AND code_audit_evidence->>'identity_key' IN ($2,$3)
ORDER BY (code_audit_evidence->>'identity_key'=$2) DESC, id LIMIT 1 FOR UPDATE`, taskID, identityKey, legacyIdentityKey).
		Scan(&existing.id, &existing.nodeID, &existing.vulnClass, &existing.status, &existing.codeAuditEvidence, &existing.createdAt)
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,node_id,vulnclass,status,code_audit_evidence,created_at FROM findings
WHERE task_id=$1 AND code_audit_evidence->>'codebase_id'=$2 AND code_audit_evidence->>'relative_path'=$3
AND upper(vulnclass)=upper($4) AND code_audit_evidence ? 'candidate_key' ORDER BY id FOR UPDATE`,
		taskID, codebaseID, relativePath, vulnClass)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var candidate taskCodeAuditFindingRow
		if err := rows.Scan(&candidate.id, &candidate.nodeID, &candidate.vulnClass, &candidate.status,
			&candidate.codeAuditEvidence, &candidate.createdAt); err != nil {
			return nil, err
		}
		legacyKey, err := taskCodeAuditLegacyIdentityKey(candidate.vulnClass, candidate.codeAuditEvidence)
		currentKey, currentErr := taskCodeAuditIdentityKey(candidate.vulnClass, candidate.codeAuditEvidence)
		if (err != nil || legacyKey != legacyIdentityKey) && (currentErr != nil || currentKey != identityKey) {
			continue
		}
		return &candidate, nil
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}

func mergeTaskCodeAuditFindingEvidence(existingRaw, incomingRaw json.RawMessage, identityKey string, runID int64, existingCreatedAt time.Time, existingStatus string) (json.RawMessage, bool, error) {
	var incoming map[string]any
	if err := json.Unmarshal(incomingRaw, &incoming); err != nil {
		return nil, false, err
	}
	var existing map[string]any
	if len(existingRaw) > 0 {
		if err := json.Unmarshal(existingRaw, &existing); err != nil {
			return nil, false, err
		}
	}
	if incoming == nil {
		incoming = map[string]any{}
	}
	merged := map[string]any{}
	history := make([]any, 0)
	if existing != nil {
		for key, value := range existing {
			merged[key] = value
		}
		if items, ok := existing["history"].([]any); ok {
			history = append(history, items...)
		}
		if len(history) == 0 && codeAuditEvidenceString(existing, "version_id") != "" {
			observedAt := existingCreatedAt.UTC().Format(time.RFC3339Nano)
			history = append(history, map[string]any{
				"kind": "observed", "version_id": existing["version_id"], "scope_path": existing["scope_path"],
				"candidate_key": existing["candidate_key"], "candidate": existing["candidate"], "review": existing["review"],
				"observed_at": observedAt,
			})
		}
	}
	firstSeen := ""
	if existing != nil {
		firstSeen = codeAuditEvidenceString(existing, "first_seen_version_id")
		if firstSeen == "" {
			firstSeen = codeAuditEvidenceString(existing, "version_id")
		}
	}
	if firstSeen == "" {
		firstSeen = codeAuditEvidenceString(incoming, "version_id")
	}
	autoFixedVersion := ""
	if existing != nil {
		autoFixedVersion = codeAuditEvidenceString(existing, "fixed_in_version_id")
	}
	// Within a version, a later partial observation must not replace complete
	// evidence. New versions use their own tier; an old A does not validate new code.
	preserveComplete := existing != nil && codeAuditEvidenceString(existing, "version_id") == codeAuditEvidenceString(incoming, "version_id") &&
		codeAuditEvidenceString(existing, "registration_tier") != "B" && codeAuditEvidenceString(incoming, "registration_tier") == "B"
	// Clear stale reasons when B is promoted to A (omitempty omits the new list).
	if !preserveComplete {
		delete(merged, "validation_issues")
	}
	for key, value := range incoming {
		if preserveComplete && (key == "candidate" || key == "candidate_key" || key == "registration_tier" || key == "validation_issues") {
			continue
		}
		if key == "history" || key == "first_seen_version_id" {
			continue
		}
		merged[key] = value
	}
	merged["identity_key"] = identityKey
	merged["first_seen_version_id"] = firstSeen
	merged["last_seen_version_id"] = incoming["version_id"]
	merged["last_seen_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	reopen := autoFixedVersion != "" && existingStatus == FindingFixed
	eventKind, eventReason := "observed", ""
	if reopen {
		delete(merged, "fixed_in_version_id")
		delete(merged, "fixed_audit_run_id")
		eventKind, eventReason = "reproduced", "漏洞在后续版本中再次出现"
	}
	if !hasTaskCodeAuditHistoryEvent(history, eventKind, runID, strings.TrimSpace(fmt.Sprint(incoming["candidate_key"]))) {
		history = append(history, taskCodeAuditHistoryEvent(incoming, runID, eventKind, eventReason))
	}
	merged["history"] = history
	encoded, err := json.Marshal(merged)
	return encoded, reopen, err
}

func codeAuditEvidenceString(evidence map[string]any, key string) string {
	value, ok := evidence[key]
	if !ok || value == nil {
		return ""
	}
	result := strings.TrimSpace(fmt.Sprint(value))
	if result == "<nil>" {
		return ""
	}
	return result
}

func taskCodeAuditHistoryEvent(evidence map[string]any, runID int64, kind, reason string) map[string]any {
	event := map[string]any{
		"kind": kind, "version_id": evidence["version_id"], "scope_path": evidence["scope_path"],
		"audit_run_id": runID, "candidate_key": evidence["candidate_key"], "observed_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if kind == "observed" || kind == "reproduced" {
		event["candidate"] = evidence["candidate"]
		event["review"] = evidence["review"]
	}
	if reason != "" {
		event["reason"] = reason
	}
	return event
}

func hasTaskCodeAuditHistoryEvent(history []any, kind string, runID int64, candidateKey string) bool {
	for _, item := range history {
		event, ok := item.(map[string]any)
		if !ok || event["kind"] != kind || fmt.Sprint(event["audit_run_id"]) != fmt.Sprint(runID) {
			continue
		}
		if kind != "observed" || fmt.Sprint(event["candidate_key"]) == candidateKey {
			return true
		}
	}
	return false
}

func reconcileTaskCodeAuditFindingsTx(ctx context.Context, tx *sql.Tx, runID int64) error {
	var taskID int64
	var codeServiceIDNullable sql.NullInt64
	var codebaseID, relativePath, versionID, scopePath, runStatus, latestVersionID string
	var latestPresent bool
	var filesTotal, filesAnalyzed, filesSkipped, chunksTotal, chunksCompleted int
	var coverageJSON []byte
	err := tx.QueryRowContext(ctx, `SELECT run.task_id,run.code_service_id,run.codebase_id,run.relative_path,run.version_id,run.scope_path,
run.status,run.files_total,run.files_analyzed,run.files_skipped,run.chunks_total,run.chunks_completed,run.coverage
FROM task_code_audit_runs run
WHERE run.id=$1 FOR UPDATE`, runID).Scan(&taskID, &codeServiceIDNullable, &codebaseID, &relativePath, &versionID, &scopePath,
		&runStatus, &filesTotal, &filesAnalyzed, &filesSkipped, &chunksTotal, &chunksCompleted, &coverageJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !codeServiceIDNullable.Valid || codeServiceIDNullable.Int64 <= 0 {
		return nil
	}
	codeServiceID := codeServiceIDNullable.Int64
	if err := tx.QueryRowContext(ctx, `SELECT relative_path,latest_version_id,latest_present
FROM task_code_services WHERE id=$1 FOR UPDATE`, codeServiceID).Scan(&relativePath, &latestVersionID, &latestPresent); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if runStatus != "completed" || filesTotal <= 0 ||
		filesAnalyzed != filesTotal || filesSkipped != 0 || chunksTotal <= 0 || chunksCompleted != chunksTotal {
		var alternativeRunID int64
		alternativeErr := tx.QueryRowContext(ctx, `SELECT id FROM task_code_audit_runs
WHERE code_service_id=$1 AND version_id=$2 AND scope_path=$3 AND id<>$4 AND status='completed'
AND files_total>0 AND files_analyzed=files_total AND files_skipped=0 AND chunks_total>0 AND chunks_completed=chunks_total
ORDER BY completed_at DESC,id DESC LIMIT 1 FOR UPDATE`, codeServiceID, versionID, scopePath, runID).Scan(&alternativeRunID)
		if errors.Is(alternativeErr, sql.ErrNoRows) {
			return nil
		}
		if alternativeErr != nil {
			return alternativeErr
		}
		return reconcileTaskCodeAuditFindingsTx(ctx, tx, alternativeRunID)
	}
	if !taskCodeAuditCoverageAllowsReconciliation(coverageJSON, filesTotal) {
		return nil
	}
	if !latestPresent || latestVersionID != versionID {
		return nil
	}
	var anotherRunActive bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM task_code_audit_runs
WHERE code_service_id=$1 AND version_id=$2 AND scope_path=$3 AND id<>$4 AND status IN ('queued','running'))`,
		codeServiceID, versionID, scopePath, runID).Scan(&anotherRunActive); err != nil {
		return err
	}
	if anotherRunActive {
		return nil
	}
	var pending int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM task_code_audit_candidates candidate
JOIN task_code_audit_runs run ON run.id=candidate.run_id
WHERE run.code_service_id=$1 AND run.version_id=$2 AND run.scope_path=$3
AND run.status IN ('completed','incomplete') AND candidate.review_status IN ('pending_review','incomplete')`,
		codeServiceID, versionID, scopePath).Scan(&pending); err != nil {
		return err
	}
	if pending > 0 {
		return nil
	}
	versionRows, err := tx.QueryContext(ctx, `SELECT version_id,version_created_at FROM task_code_service_versions
WHERE code_service_id=$1`, codeServiceID)
	if err != nil {
		return err
	}
	versionTimes := map[string]time.Time{}
	for versionRows.Next() {
		var observedVersion string
		var createdAt time.Time
		if err := versionRows.Scan(&observedVersion, &createdAt); err != nil {
			versionRows.Close()
			return err
		}
		versionTimes[observedVersion] = createdAt
	}
	if err := versionRows.Close(); err != nil {
		return err
	}
	currentAt, exists := versionTimes[versionID]
	if !exists {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,node_id,vulnclass,status,code_audit_evidence FROM findings
WHERE task_id=$1 AND code_audit_evidence->>'codebase_id'=$2 AND code_audit_evidence->>'relative_path'=$3
ORDER BY id FOR UPDATE`, taskID, codebaseID, relativePath)
	if err != nil {
		return err
	}
	type findingSnapshot struct {
		id        int64
		nodeID    sql.NullInt64
		vulnClass string
		status    string
		evidence  []byte
	}
	findings := make([]findingSnapshot, 0)
	for rows.Next() {
		var finding findingSnapshot
		if err := rows.Scan(&finding.id, &finding.nodeID, &finding.vulnClass, &finding.status, &finding.evidence); err != nil {
			rows.Close()
			return err
		}
		findings = append(findings, finding)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, finding := range findings {
		if finding.status == FindingFalsePositive || finding.status == FindingIgnored || finding.status == FindingDuplicate ||
			finding.status == FindingRiskAccepted {
			continue
		}
		if finding.status == FindingFixed {
			var existing map[string]any
			if err := json.Unmarshal(finding.evidence, &existing); err != nil || codeAuditEvidenceString(existing, "fixed_in_version_id") == "" {
				continue // preserve manually triaged fixed findings
			}
		}
		var evidence map[string]any
		if err := json.Unmarshal(finding.evidence, &evidence); err != nil || evidence == nil {
			continue
		}
		if normalizeCodeAuditScopePath(fmt.Sprint(evidence["scope_path"])) != normalizeCodeAuditScopePath(scopePath) {
			continue
		}
		lastSeenVersion := codeAuditEvidenceString(evidence, "last_seen_version_id")
		if lastSeenVersion == "" || lastSeenVersion == "<nil>" {
			lastSeenVersion = codeAuditEvidenceString(evidence, "version_id")
		}
		if lastSeenVersion == "" || lastSeenVersion == "<nil>" || lastSeenVersion == versionID {
			continue
		}
		previousAt, exists := versionTimes[lastSeenVersion]
		if !exists || previousAt.After(currentAt) || previousAt.Equal(currentAt) && lastSeenVersion >= versionID {
			continue
		}
		identityKey := codeAuditEvidenceString(evidence, "identity_key")
		if identityKey == "" {
			identityKey, err = taskCodeAuditIdentityKey(finding.vulnClass, finding.evidence)
			if err != nil {
				continue
			}
		}
		evidence["identity_key"] = identityKey
		if codeAuditEvidenceString(evidence, "first_seen_version_id") == "" {
			evidence["first_seen_version_id"] = codeAuditEvidenceString(evidence, "version_id")
		}
		event := map[string]any{
			"kind": "fixed", "version_id": versionID, "scope_path": scopePath, "audit_run_id": runID,
			"observed_at": time.Now().UTC().Format(time.RFC3339Nano), "reason": "完整审计未复现该污点路径",
		}
		history, _ := evidence["history"].([]any)
		if !hasTaskCodeAuditHistoryEvent(history, "fixed", runID, "") {
			history = append(history, event)
		}
		evidence["history"] = history
		if codeAuditEvidenceString(evidence, "fixed_in_version_id") == "" {
			evidence["fixed_in_version_id"] = versionID
			evidence["fixed_audit_run_id"] = runID
		}
		encoded, err := json.Marshal(evidence)
		if err != nil {
			return err
		}
		newStatus := finding.status
		if newStatus != FindingFixed {
			newStatus = FindingFixed
		}
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET status=$2,code_audit_evidence=$3::jsonb WHERE id=$1`, finding.id, newStatus, string(encoded)); err != nil {
			return err
		}
		if finding.nodeID.Valid {
			if _, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET payload=jsonb_set(payload,'{code_audit_evidence}',$2::jsonb,true),updated_at=now()
WHERE id=$1 AND kind='finding'`, finding.nodeID.Int64, string(encoded)); err != nil {
				return err
			}
		}
	}
	return nil
}

var taskCodeAuditVulnClassPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// ValidTaskCodeAuditVulnClass only checks the shape of a normalized class
// label. The platform does not decide which vulnerability types the model may
// report; the server maps free-form model labels to known buckets or OTHER
// before they reach this layer.
func ValidTaskCodeAuditVulnClass(value string) bool {
	return taskCodeAuditVulnClassPattern.MatchString(value)
}

func (d *DB) ValidateTaskCodeAuditService(taskID, codeServiceID int64) (TaskCodeService, error) {
	var service TaskCodeService
	var assetID sql.NullInt64
	var languagesJSON []byte
	err := d.QueryRow(`SELECT id,task_id,codebase_id,relative_path,name,decision,decision_source,asset_id,
latest_version_id,latest_present,evidence,reason,created_at,updated_at,to_json(languages) FROM task_code_services
WHERE task_id=$1 AND id=$2`, taskID, codeServiceID).Scan(
		&service.ID, &service.TaskID, &service.CodebaseID, &service.RelativePath, &service.Name,
		&service.Decision, &service.DecisionSource, &assetID, &service.LatestVersionID, &service.LatestPresent,
		&service.Evidence, &service.Reason, &service.CreatedAt, &service.UpdatedAt, &languagesJSON)
	if err != nil {
		return service, err
	}
	if err := json.Unmarshal(languagesJSON, &service.Languages); err != nil {
		return service, err
	}
	if assetID.Valid {
		service.AssetID = &assetID.Int64
	}
	if service.Decision != "confirmed" || !service.LatestPresent || service.LatestVersionID == "" {
		return service, fmt.Errorf("code service is not confirmed or is absent in the latest version")
	}
	return service, nil
}
