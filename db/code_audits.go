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
	"strings"
	"time"
)

const TaskCodeAuditConcurrencyLimit = 4

type TaskCodeAuditRun struct {
	ID                 int64                    `json:"id"`
	TaskID             int64                    `json:"task_id"`
	CodeServiceID      int64                    `json:"code_service_id"`
	ServiceName        string                   `json:"service_name"`
	CodebaseID         string                   `json:"codebase_id"`
	VersionID          string                   `json:"version_id"`
	ScopePath          string                   `json:"scope_path"`
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
}

type TaskCodeAuditCandidate struct {
	ID                  int64           `json:"id"`
	RunID               int64           `json:"run_id"`
	CandidateKey        string          `json:"candidate_key"`
	ReviewStatus        string          `json:"review_status"`
	Candidate           json.RawMessage `json:"candidate"`
	ReviewerSummary     string          `json:"reviewer_summary"`
	VerificationSummary string          `json:"verification_summary"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
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

const taskCodeAuditRunColumns = `run.id,run.task_id,run.code_service_id,service.name,run.codebase_id,run.version_id,
run.scope_path,run.status,run.profile_id,run.profile_source,run.profile_name,run.profile_format,run.model,run.endpoint,
run.source_acknowledged,run.files_total,run.files_analyzed,run.files_skipped,run.chunks_total,run.chunks_completed,
run.next_file_index,run.budget_tokens,run.used_tokens,run.candidate_count,run.summary,run.error,run.created_at,
run.started_at,run.completed_at,run.updated_at`

func scanTaskCodeAuditRun(row interface{ Scan(...any) error }) (*TaskCodeAuditRun, error) {
	var run TaskCodeAuditRun
	var profileID sql.NullInt64
	var started, completed sql.NullTime
	err := row.Scan(&run.ID, &run.TaskID, &run.CodeServiceID, &run.ServiceName, &run.CodebaseID, &run.VersionID,
		&run.ScopePath, &run.Status, &profileID, &run.ProfileSource, &run.ProfileName, &run.ProfileFormat, &run.Model,
		&run.Endpoint, &run.SourceAcknowledged, &run.FilesTotal, &run.FilesAnalyzed, &run.FilesSkipped, &run.ChunksTotal,
		&run.ChunksCompleted, &run.NextFileIndex, &run.BudgetTokens, &run.UsedTokens, &run.CandidateCount,
		&run.Summary, &run.Error, &run.CreatedAt, &started, &completed, &run.UpdatedAt)
	if err != nil {
		return nil, err
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
	err = tx.QueryRow(`SELECT id,task_id FROM task_code_audit_runs WHERE status='queued'
ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&runID, &taskID)
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
	_, err := d.Exec(`UPDATE task_code_audit_runs SET status='queued',error='服务重启后从最近检查点恢复',updated_at=now()
WHERE status='running'`)
	return err
}

func (d *DB) UpdateTaskCodeAuditProgress(runID int64, progress TaskCodeAuditProgress) error {
	_, err := d.Exec(`UPDATE task_code_audit_runs SET files_total=$2,files_analyzed=$3,files_skipped=$4,
chunks_total=$5,chunks_completed=$6,next_file_index=$7,used_tokens=$8,summary=$9,updated_at=now()
WHERE id=$1 AND status='running'`, runID, progress.FilesTotal, progress.FilesAnalyzed, progress.FilesSkipped,
		progress.ChunksTotal, progress.ChunksCompleted, progress.NextFileIndex, progress.UsedTokens, progress.Summary)
	return err
}

func (d *DB) AddTaskCodeAuditCandidate(runID int64, key string, candidate json.RawMessage, reviewerSummary string) error {
	if !json.Valid(candidate) {
		return errors.New("invalid code audit candidate JSON")
	}
	result, err := d.Exec(`INSERT INTO task_code_audit_candidates(run_id,candidate_key,review_status,candidate,reviewer_summary)
VALUES($1,$2,'pending_review',$3,$4) ON CONFLICT(run_id,candidate_key) DO NOTHING`, runID, key, string(candidate), reviewerSummary)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil || inserted == 0 {
		return err
	}
	_, err = d.Exec(`UPDATE task_code_audit_runs SET candidate_count=candidate_count+1,updated_at=now() WHERE id=$1`, runID)
	return err
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
		progress.NextFileIndex, progress.UsedTokens, reason, progress.Summary)
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

func (d *DB) ResumeTaskCodeAudit(taskID, runID int64, additionalBudget int) (*TaskCodeAuditRun, error) {
	result, err := d.Exec(`UPDATE task_code_audit_runs SET status='queued',budget_tokens=budget_tokens+$3,
error='',completed_at=NULL,updated_at=now() WHERE task_id=$1 AND id=$2 AND status='incomplete'
AND $3 BETWEEN 1000 AND 500000`, taskID, runID, additionalBudget)
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
	return d.GetTaskCodeAudit(taskID, runID)
}

func (d *DB) RetryTaskCodeAudit(taskID, runID int64, additionalBudget int) (*TaskCodeAuditRun, error) {
	result, err := d.Exec(`UPDATE task_code_audit_runs SET status='queued',budget_tokens=budget_tokens+$3,
error='',completed_at=NULL,updated_at=now() WHERE task_id=$1 AND id=$2 AND status='failed'
AND $3 BETWEEN 1000 AND 500000`, taskID, runID, additionalBudget)
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
	return d.GetTaskCodeAudit(taskID, runID)
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
JOIN task_code_services service ON service.id=run.code_service_id WHERE run.task_id=$1
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
candidate.candidate,candidate.reviewer_summary,candidate.verification_summary,candidate.created_at,candidate.updated_at
FROM task_code_audit_candidates candidate JOIN task_code_audit_runs run ON run.id=candidate.run_id
WHERE run.task_id=$1 ORDER BY candidate.id`, taskID)
	if err != nil {
		return nil, err
	}
	defer candidates.Close()
	for candidates.Next() {
		var item TaskCodeAuditCandidate
		if err := candidates.Scan(&item.ID, &item.RunID, &item.CandidateKey, &item.ReviewStatus, &item.Candidate,
			&item.ReviewerSummary, &item.VerificationSummary, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if index, ok := byID[item.RunID]; ok {
			out[index].Candidates = append(out[index].Candidates, item)
		}
	}
	return out, candidates.Err()
}

func (d *DB) GetTaskCodeAudit(taskID, runID int64) (*TaskCodeAuditRun, error) {
	run, err := scanTaskCodeAuditRun(d.QueryRow(`SELECT `+taskCodeAuditRunColumns+` FROM task_code_audit_runs run
JOIN task_code_services service ON service.id=run.code_service_id WHERE run.task_id=$1 AND run.id=$2`, taskID, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	rows, err := d.Query(`SELECT id,run_id,candidate_key,review_status,candidate,reviewer_summary,verification_summary,created_at,updated_at
FROM task_code_audit_candidates WHERE run_id=$1 ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	run.Candidates = make([]TaskCodeAuditCandidate, 0)
	for rows.Next() {
		var candidate TaskCodeAuditCandidate
		if err := rows.Scan(&candidate.ID, &candidate.RunID, &candidate.CandidateKey, &candidate.ReviewStatus,
			&candidate.Candidate, &candidate.ReviewerSummary, &candidate.VerificationSummary, &candidate.CreatedAt, &candidate.UpdatedAt); err != nil {
			return nil, err
		}
		run.Candidates = append(run.Candidates, candidate)
	}
	return run, rows.Err()
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
	var status, runStatus, codebaseID, versionID, candidateKey, relativePath, serviceDecision, latestVersion string
	var explorationID int64
	var assetID sql.NullInt64
	var latestPresent bool
	err = tx.QueryRowContext(ctx, `SELECT candidate.review_status,run.status,run.codebase_id,run.version_id,candidate.candidate_key,
service.relative_path,service.decision,service.latest_version_id,service.latest_present,service.asset_id,task.exploration_id
FROM task_code_audit_candidates candidate
JOIN task_code_audit_runs run ON run.id=candidate.run_id
JOIN task_code_services service ON service.id=run.code_service_id
JOIN tasks task ON task.id=run.task_id
WHERE run.task_id=$1 AND run.id=$2 AND candidate.id=$3 FOR UPDATE OF candidate`, taskID, runID, candidateID).
		Scan(&status, &runStatus, &codebaseID, &versionID, &candidateKey, &relativePath,
			&serviceDecision, &latestVersion, &latestPresent, &assetID, &explorationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTaskCodeAuditCandidateReviewConflict
	}
	if err != nil {
		return nil, err
	}
	if status != "pending_review" || (runStatus != "completed" && runStatus != "incomplete") {
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
	if serviceDecision != "confirmed" || !latestPresent || latestVersion != versionID || !assetID.Valid {
		return nil, ErrTaskCodeAuditCandidateReviewConflict
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
	existing, err := findTaskCodeAuditFindingTx(ctx, tx, taskID, identityKey, codebaseID, acceptedEvidence.RelativePath)
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
	assets := []int64{assetID.Int64}
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
		Source taskCodeAuditIdentityLocation `json:"source"`
		Sink   taskCodeAuditIdentityLocation `json:"sink"`
	} `json:"candidate"`
	Source taskCodeAuditIdentityLocation `json:"source"`
	Sink   taskCodeAuditIdentityLocation `json:"sink"`
	Key    string                        `json:"candidate_key"`
}

func taskCodeAuditIdentityKey(vulnClass string, evidence json.RawMessage) (string, error) {
	var value taskCodeAuditIdentityEvidence
	if err := json.Unmarshal(evidence, &value); err != nil {
		return "", err
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

func findTaskCodeAuditFindingTx(ctx context.Context, tx *sql.Tx, taskID int64, identityKey, codebaseID, relativePath string) (*taskCodeAuditFindingRow, error) {
	var existing taskCodeAuditFindingRow
	err := tx.QueryRowContext(ctx, `SELECT id,node_id,vulnclass,status,code_audit_evidence,created_at FROM findings
WHERE task_id=$1 AND code_audit_evidence->>'identity_key'=$2 ORDER BY id LIMIT 1 FOR UPDATE`, taskID, identityKey).
		Scan(&existing.id, &existing.nodeID, &existing.vulnClass, &existing.status, &existing.codeAuditEvidence, &existing.createdAt)
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,node_id,vulnclass,status,code_audit_evidence,created_at FROM findings
WHERE task_id=$1 AND code_audit_evidence->>'codebase_id'=$2 AND code_audit_evidence->>'relative_path'=$3
AND code_audit_evidence ? 'candidate_key' AND NOT (code_audit_evidence ? 'identity_key') ORDER BY id FOR UPDATE`,
		taskID, codebaseID, relativePath)
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
		legacyKey, err := taskCodeAuditIdentityKey(candidate.vulnClass, candidate.codeAuditEvidence)
		if err != nil || legacyKey != identityKey {
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
	for key, value := range incoming {
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
	var taskID, codeServiceID int64
	var codebaseID, relativePath, versionID, scopePath, runStatus, latestVersionID string
	var latestPresent bool
	var filesTotal, filesAnalyzed, filesSkipped, chunksTotal, chunksCompleted int
	err := tx.QueryRowContext(ctx, `SELECT run.task_id,run.code_service_id,run.codebase_id,service.relative_path,run.version_id,run.scope_path,
run.status,run.files_total,run.files_analyzed,run.files_skipped,run.chunks_total,run.chunks_completed
FROM task_code_audit_runs run JOIN task_code_services service ON service.id=run.code_service_id
WHERE run.id=$1 FOR UPDATE OF run`, runID).Scan(&taskID, &codeServiceID, &codebaseID, &relativePath, &versionID, &scopePath,
		&runStatus, &filesTotal, &filesAnalyzed, &filesSkipped, &chunksTotal, &chunksCompleted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
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
	if err := tx.QueryRowContext(ctx, `SELECT relative_path,latest_version_id,latest_present
FROM task_code_services WHERE id=$1 FOR UPDATE`, codeServiceID).Scan(&relativePath, &latestVersionID, &latestPresent); err != nil {
		return err
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
AND run.status IN ('completed','incomplete') AND candidate.review_status='pending_review'`,
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

func ValidTaskCodeAuditVulnClass(value string) bool {
	switch value {
	case "SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL", "SSRF", "XSS", "UNSAFE_DESERIALIZATION":
		return true
	default:
		return false
	}
}

func (d *DB) ValidateTaskCodeAuditService(taskID, codeServiceID int64) (TaskCodeService, error) {
	var service TaskCodeService
	var assetID sql.NullInt64
	err := d.QueryRow(`SELECT id,task_id,codebase_id,relative_path,name,decision,decision_source,asset_id,
latest_version_id,latest_present,evidence,reason,created_at,updated_at FROM task_code_services
WHERE task_id=$1 AND id=$2`, taskID, codeServiceID).Scan(
		&service.ID, &service.TaskID, &service.CodebaseID, &service.RelativePath, &service.Name,
		&service.Decision, &service.DecisionSource, &assetID, &service.LatestVersionID, &service.LatestPresent,
		&service.Evidence, &service.Reason, &service.CreatedAt, &service.UpdatedAt)
	if err != nil {
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
