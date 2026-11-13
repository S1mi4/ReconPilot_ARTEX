package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

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
	ID              int64           `json:"id"`
	RunID           int64           `json:"run_id"`
	CandidateKey    string          `json:"candidate_key"`
	ReviewStatus    string          `json:"review_status"`
	Candidate       json.RawMessage `json:"candidate"`
	ReviewerSummary string          `json:"reviewer_summary"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

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
	var id int64
	err = tx.QueryRow(`SELECT id FROM task_code_audit_runs WHERE status='queued'
ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE task_code_audit_runs SET status='running',started_at=COALESCE(started_at,now()),
completed_at=NULL,error='',updated_at=now() WHERE id=$1`, id); err != nil {
		return nil, err
	}
	var taskID int64
	if err := tx.QueryRow(`SELECT task_id FROM task_code_audit_runs WHERE id=$1`, id).Scan(&taskID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetTaskCodeAudit(taskID, id)
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
	_, err := d.Exec(`UPDATE task_code_audit_runs SET status='completed',files_total=$2,files_analyzed=$3,
files_skipped=$4,chunks_total=$5,chunks_completed=$6,next_file_index=$7,used_tokens=$8,summary=$9,error='',
completed_at=now(),updated_at=now() WHERE id=$1 AND status='running'`, runID, progress.FilesTotal,
		progress.FilesAnalyzed, progress.FilesSkipped, progress.ChunksTotal, progress.ChunksCompleted,
		progress.NextFileIndex, progress.UsedTokens, progress.Summary)
	return err
}

func (d *DB) IncompleteTaskCodeAudit(runID int64, progress TaskCodeAuditProgress, reason string) error {
	_, err := d.Exec(`UPDATE task_code_audit_runs SET status='incomplete',files_total=$2,files_analyzed=$3,
files_skipped=$4,chunks_total=$5,chunks_completed=$6,next_file_index=$7,used_tokens=$8,summary=$9,error=$10,
completed_at=now(),updated_at=now() WHERE id=$1 AND status='running'`, runID, progress.FilesTotal,
		progress.FilesAnalyzed, progress.FilesSkipped, progress.ChunksTotal, progress.ChunksCompleted,
		progress.NextFileIndex, progress.UsedTokens, reason, progress.Summary)
	return err
}

func (d *DB) FailTaskCodeAudit(runID int64, reason string) error {
	_, err := d.Exec(`UPDATE task_code_audit_runs SET status='failed',error=$2,completed_at=now(),updated_at=now()
WHERE id=$1 AND status IN ('queued','running')`, runID, reason)
	return err
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
candidate.candidate,candidate.reviewer_summary,candidate.created_at,candidate.updated_at
FROM task_code_audit_candidates candidate JOIN task_code_audit_runs run ON run.id=candidate.run_id
WHERE run.task_id=$1 ORDER BY candidate.id`, taskID)
	if err != nil {
		return nil, err
	}
	defer candidates.Close()
	for candidates.Next() {
		var item TaskCodeAuditCandidate
		if err := candidates.Scan(&item.ID, &item.RunID, &item.CandidateKey, &item.ReviewStatus, &item.Candidate,
			&item.ReviewerSummary, &item.CreatedAt, &item.UpdatedAt); err != nil {
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
	rows, err := d.Query(`SELECT id,run_id,candidate_key,review_status,candidate,reviewer_summary,created_at,updated_at
FROM task_code_audit_candidates WHERE run_id=$1 ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	run.Candidates = make([]TaskCodeAuditCandidate, 0)
	for rows.Next() {
		var candidate TaskCodeAuditCandidate
		if err := rows.Scan(&candidate.ID, &candidate.RunID, &candidate.CandidateKey, &candidate.ReviewStatus,
			&candidate.Candidate, &candidate.ReviewerSummary, &candidate.CreatedAt, &candidate.UpdatedAt); err != nil {
			return nil, err
		}
		run.Candidates = append(run.Candidates, candidate)
	}
	return run, rows.Err()
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
