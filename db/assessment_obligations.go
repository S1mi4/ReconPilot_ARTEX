package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestAttempt represents one persisted execution attempt in task_test_attempts.
type TestAttempt struct {
	ID             int64           `json:"id"`
	TaskID         int64           `json:"task_id"`
	RoundID        *int64          `json:"round_id,omitempty"`
	ObligationID   int64           `json:"obligation_id"`
	AttemptNo      int             `json:"attempt_no"`
	IntentNodeID   *int64          `json:"intent_node_id,omitempty"`
	CodeAuditRunID *int64          `json:"code_audit_run_id,omitempty"`
	ExecutionMode  string          `json:"execution_mode,omitempty"`
	AttemptUID     string          `json:"attempt_uid,omitempty"`
	ProfileVersion int             `json:"profile_version,omitempty"`
	Status         string          `json:"status"`
	Outcome        string          `json:"outcome"`
	EvidenceRefID  *int64          `json:"evidence_ref_id,omitempty"`
	Output         json.RawMessage `json:"output,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
}

// CoverageObligationFilter filters coverage obligations for querying.
type CoverageObligationFilter struct {
	TaskID          int64
	RoundID         int64
	Status          string
	Dimension       string
	ExecutionMode   string
	Origin          string
	TargetEntityID  int64
	ExcludeTerminal bool
	Limit           int
	Offset          int
}

// DimensionCoverageSummary summarizes required obligations per coverage dimension (§6.2).
// When ApplicableTotal == 0, NotApplicableDimension=true so UI/Planner never displays "100%".
type DimensionCoverageSummary struct {
	Dimension              string `json:"dimension"`
	RequiredTotal          int    `json:"required_total"`
	ApplicableTotal        int    `json:"applicable_total"`
	Satisfied              int    `json:"satisfied"`
	NotApplicable          int    `json:"not_applicable"`
	Pending                int    `json:"pending"`
	Ready                  int    `json:"ready"`
	Running                int    `json:"running"`
	Blocked                int    `json:"blocked"`
	Stale                  int    `json:"stale"`
	NotApplicableDimension bool   `json:"not_applicable_dimension"`
}

// CodeAuditCoverageSummary summarizes one whitebox audit run for assessment planning.
type CodeAuditCoverageSummary struct {
	RunID           int64  `json:"run_id"`
	ServiceID       int64  `json:"service_id"`
	ServiceName     string `json:"service_name"`
	TargetType      string `json:"target_type,omitempty"`
	RelativePath    string `json:"relative_path,omitempty"`
	CodebaseID      string `json:"codebase_id"`
	VersionID       string `json:"version_id"`
	ScopePath       string `json:"scope_path"`
	ExecutionOrigin string `json:"execution_origin,omitempty"`
	Status          string `json:"status"`
	FilesTotal      int    `json:"files_total"`
	FilesAnalyzed   int    `json:"files_analyzed"`
	FilesSkipped    int    `json:"files_skipped"`
	ChunksTotal     int    `json:"chunks_total"`
	ChunksCompleted int    `json:"chunks_completed"`
	NextFileIndex   int    `json:"next_file_index"`
	CandidateCount  int    `json:"candidate_count"`
}

// AssessmentEventRecord is one persisted row in task_assessment_events.
type AssessmentEventRecord struct {
	ID        int64           `json:"id"`
	TaskID    int64           `json:"task_id"`
	RoundID   *int64          `json:"round_id,omitempty"`
	EventType string          `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
	Processed bool            `json:"processed"`
	CreatedAt time.Time       `json:"created_at"`
}

// DispatchAssessmentIntentInput binds a scheduled Intent to an obligation and attempt.
type DispatchAssessmentIntentInput struct {
	TaskID         int64
	RoundID        int64
	ObligationID   int64
	ExecutionMode  string
	Summary        string
	Priority       int
	IdempotencyKey string
	AssetIDs       []int64
	ParentIDs      []int64
	WorkOrder      json.RawMessage
	Origin         string
}

// DispatchAssessmentIntentResult describes the created or deduplicated active Intent + Attempt.
type DispatchAssessmentIntentResult struct {
	AlreadyActive  bool   `json:"already_active"`
	IntentID       int64  `json:"intent_id"`
	IntentState    string `json:"intent_state"`
	ObligationID   int64  `json:"obligation_id"`
	RoundID        int64  `json:"round_id"`
	AttemptID      int64  `json:"attempt_id"`
	AttemptUID     string `json:"attempt_uid"`
	AttemptNo      int    `json:"attempt_no,omitempty"`
	ExecutionMode  string `json:"execution_mode"`
	ProfileVersion int    `json:"profile_version"`
	IdempotencyKey string `json:"idempotency_key"`
}

// FinalizeObligationAttemptInput settles an active attempt with strict late-write & evidence checks.
type FinalizeObligationAttemptInput struct {
	TaskID            int64
	ObligationID      int64
	AttemptID         int64
	IntentNodeID      *int64
	CodeAuditRunID    *int64
	Outcome           string
	EvidenceRefID     *int64
	Output            json.RawMessage
	SatisfyObligation bool
	BlockedReason     string
}

// FinalizeObligationAttemptResult reports whether the obligation actually advanced.
type FinalizeObligationAttemptResult struct {
	AttemptID            int64  `json:"attempt_id"`
	ObligationID         int64  `json:"obligation_id"`
	AttemptOutcome       string `json:"attempt_outcome"`
	NewObligationStatus  string `json:"new_obligation_status"`
	ObligationAdvanced   bool   `json:"obligation_advanced"`
	InsufficientEvidence bool   `json:"insufficient_evidence,omitempty"`
	RejectionReason      string `json:"rejection_reason,omitempty"`
	UnlockedCount        int    `json:"unlocked_count,omitempty"`
}

var coverageDimensionOrder = []string{
	DimensionCodeAudit,
	DimensionConfigAudit,
	DimensionEntryTest,
	DimensionIdentityResource,
	DimensionCrossModule,
	DimensionRuntimeAsset,
	DimensionHypothesis,
}

// ValidateObligationExecutionMode verifies whether execMode is compatible with
// both the obligation dimension and the task's configured execution_mode.
func ValidateObligationExecutionMode(dimension, execMode, taskExecMode string) error {
	if !IsValidCoverageDimension(dimension) {
		return fmt.Errorf("%w: %q", ErrObligationDimensionInvalid, dimension)
	}
	if !IsValidExecutionMode(execMode) {
		return fmt.Errorf("%w: %q", ErrExecutionModeInvalid, execMode)
	}
	if strings.TrimSpace(taskExecMode) == AssessmentExecOffline && execMode == ExecModeDynamicVerify {
		return fmt.Errorf("%w: offline task cannot dispatch %s", ErrExecutionModeInvalid, execMode)
	}
	switch execMode {
	case ExecModeCodeAuditBatch:
		if dimension != DimensionCodeAudit {
			return fmt.Errorf("%w: %s is only valid for dimension code_audit, got %s", ErrExecutionModeInvalid, execMode, dimension)
		}
	case ExecModeDynamicVerify:
		switch dimension {
		case DimensionRuntimeAsset, DimensionEntryTest, DimensionIdentityResource, DimensionCrossModule, DimensionHypothesis:
		default:
			return fmt.Errorf("%w: %s is not valid for dimension %s", ErrExecutionModeInvalid, execMode, dimension)
		}
	case ExecModeCodeInvestigate:
		switch dimension {
		case DimensionConfigAudit, DimensionCrossModule, DimensionHypothesis, DimensionCodeAudit, DimensionEntryTest:
		default:
			return fmt.Errorf("%w: %s is not valid for dimension %s", ErrExecutionModeInvalid, execMode, dimension)
		}
	}
	return nil
}

func normalizeObligationPriority(p int) int {
	if p <= 0 {
		return 5
	}
	if p > 10 {
		return 10
	}
	return p
}

func normalizePositiveIDs(ids []int64) []int64 {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func formatBigIntArray(ids []int64) string {
	if len(ids) == 0 {
		return "{}"
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatInt(id, 10)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func validateObligationDependenciesTx(tx *sql.Tx, taskID, roundID, selfID int64, deps []int64) error {
	if len(deps) == 0 {
		return nil
	}
	for _, dep := range deps {
		if selfID > 0 && dep == selfID {
			return fmt.Errorf("%w: obligation %d cannot depend on itself", ErrObligationDependencyCycle, selfID)
		}
	}
	rows, err := tx.Query(`
SELECT id, COALESCE(to_jsonb(dependency_ids), '[]'::jsonb)
FROM task_coverage_obligations
WHERE task_id=$1 AND round_id=$2`, taskID, roundID)
	if err != nil {
		return err
	}
	defer rows.Close()

	graph := map[int64][]int64{}
	for rows.Next() {
		var id int64
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return err
		}
		var itemDeps []int64
		_ = json.Unmarshal(raw, &itemDeps)
		graph[id] = itemDeps
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, dep := range deps {
		if _, ok := graph[dep]; !ok {
			return fmt.Errorf("%w: dependency obligation %d does not exist in task %d round %d",
				ErrObligationOwnershipMismatch, dep, taskID, roundID)
		}
	}
	if selfID <= 0 {
		return nil
	}
	// BFS from proposed dependencies to detect whether selfID is reachable (cycle).
	visited := map[int64]bool{}
	queue := append([]int64(nil), deps...)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == selfID {
			return fmt.Errorf("%w: dependency introduces cycle involving obligation %d", ErrObligationDependencyCycle, selfID)
		}
		if visited[cur] {
			continue
		}
		visited[cur] = true
		for _, next := range graph[cur] {
			if !visited[next] {
				queue = append(queue, next)
			}
		}
	}
	return nil
}

// GetCoverageObligation returns one obligation belonging to taskID with target entity summary
// and unmet dependencies populated.
func (d *DB) GetCoverageObligation(taskID, obligationID int64) (*CoverageObligation, error) {
	var o CoverageObligation
	var rule, ctxSnap, depsJSON []byte
	var targetName, targetType string
	err := d.QueryRow(`
SELECT o.id, o.task_id, o.round_id, o.dimension, o.target_entity_id, o.purpose, o.required, o.status,
       o.dedupe_key, o.requires_credentials, o.credential_ref, o.blocked_reason, o.stale_reason,
       o.not_applicable_reason, o.evidence_ref_id, o.acceptance_rule, o.execution_mode, o.origin,
       o.priority, o.profile_version, o.context_snapshot,
       COALESCE(to_jsonb(o.dependency_ids), '[]'::jsonb), o.active_attempt_id,
       o.created_at, o.updated_at, o.satisfied_at,
       COALESCE(e.name, ''), COALESCE(e.entity_type, '')
FROM task_coverage_obligations o
LEFT JOIN task_target_entities e ON e.id = o.target_entity_id
WHERE o.id=$1 AND o.task_id=$2`, obligationID, taskID).Scan(
		&o.ID, &o.TaskID, &o.RoundID, &o.Dimension, &o.TargetEntityID, &o.Purpose,
		&o.Required, &o.Status, &o.DedupeKey, &o.RequiresCredentials, &o.CredentialRef,
		&o.BlockedReason, &o.StaleReason, &o.NotApplicableReason, &o.EvidenceRefID,
		&rule, &o.ExecutionMode, &o.Origin, &o.Priority, &o.ProfileVersion, &ctxSnap,
		&depsJSON, &o.ActiveAttemptID, &o.CreatedAt, &o.UpdatedAt, &o.SatisfiedAt,
		&targetName, &targetType,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(rule) > 0 {
		o.AcceptanceRule = json.RawMessage(rule)
	}
	if len(ctxSnap) > 0 {
		o.ContextSnapshot = json.RawMessage(ctxSnap)
	}
	if len(depsJSON) > 0 {
		_ = json.Unmarshal(depsJSON, &o.DependencyIDs)
	}
	o.TargetName = targetName
	o.TargetType = targetType
	if o.RoundID != nil && len(o.DependencyIDs) > 0 {
		statuses, sErr := d.roundObligationStatusMap(o.TaskID, *o.RoundID)
		if sErr != nil {
			return nil, sErr
		}
		o.UnmetDependencyIDs = computeUnmetDeps(o.DependencyIDs, statuses)
	}
	return &o, nil
}

func (d *DB) roundObligationStatusMap(taskID, roundID int64) (map[int64]string, error) {
	rows, err := d.Query(`
SELECT id, status FROM task_coverage_obligations
WHERE task_id=$1 AND round_id=$2`, taskID, roundID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var st string
		if err := rows.Scan(&id, &st); err != nil {
			return nil, err
		}
		out[id] = st
	}
	return out, rows.Err()
}

func computeUnmetDeps(deps []int64, statuses map[int64]string) []int64 {
	var unmet []int64
	for _, depID := range deps {
		st := statuses[depID]
		if st != ObligationSatisfied && st != ObligationNotApplicable {
			unmet = append(unmet, depID)
		}
	}
	return unmet
}

// ListCoverageObligations returns obligations matching the filter ordered by scheduling priority.
func (d *DB) ListCoverageObligations(f CoverageObligationFilter) ([]CoverageObligation, error) {
	query := `
SELECT o.id, o.task_id, o.round_id, o.dimension, o.target_entity_id, o.purpose, o.required, o.status,
       o.dedupe_key, o.requires_credentials, o.credential_ref, o.blocked_reason, o.stale_reason,
       o.not_applicable_reason, o.evidence_ref_id, o.acceptance_rule, o.execution_mode, o.origin,
       o.priority, o.profile_version, o.context_snapshot,
       COALESCE(to_jsonb(o.dependency_ids), '[]'::jsonb), o.active_attempt_id,
       o.created_at, o.updated_at, o.satisfied_at,
       COALESCE(e.name, ''), COALESCE(e.entity_type, '')
FROM task_coverage_obligations o
LEFT JOIN task_target_entities e ON e.id = o.target_entity_id
WHERE o.task_id=$1`
	args := []any{f.TaskID}
	if f.RoundID > 0 {
		args = append(args, f.RoundID)
		query += fmt.Sprintf(" AND o.round_id=$%d", len(args))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		query += fmt.Sprintf(" AND o.status=$%d", len(args))
	} else if f.ExcludeTerminal {
		query += " AND o.status NOT IN ('satisfied','not_applicable')"
	}
	if f.Dimension != "" {
		args = append(args, f.Dimension)
		query += fmt.Sprintf(" AND o.dimension=$%d", len(args))
	}
	if f.ExecutionMode != "" {
		args = append(args, f.ExecutionMode)
		query += fmt.Sprintf(" AND o.execution_mode=$%d", len(args))
	}
	if f.Origin != "" {
		args = append(args, f.Origin)
		query += fmt.Sprintf(" AND o.origin=$%d", len(args))
	}
	if f.TargetEntityID > 0 {
		args = append(args, f.TargetEntityID)
		query += fmt.Sprintf(" AND o.target_entity_id=$%d", len(args))
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	offset := max(f.Offset, 0)
	args = append(args, limit, offset)
	query += fmt.Sprintf(" ORDER BY (o.status IN ('ready','stale','running')) DESC, o.priority DESC, o.id ASC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]CoverageObligation, 0)
	var statusMap map[int64]string
	for rows.Next() {
		var o CoverageObligation
		var rule, ctxSnap, depsJSON []byte
		var targetName, targetType string
		if err := rows.Scan(
			&o.ID, &o.TaskID, &o.RoundID, &o.Dimension, &o.TargetEntityID, &o.Purpose,
			&o.Required, &o.Status, &o.DedupeKey, &o.RequiresCredentials, &o.CredentialRef,
			&o.BlockedReason, &o.StaleReason, &o.NotApplicableReason, &o.EvidenceRefID,
			&rule, &o.ExecutionMode, &o.Origin, &o.Priority, &o.ProfileVersion, &ctxSnap,
			&depsJSON, &o.ActiveAttemptID, &o.CreatedAt, &o.UpdatedAt, &o.SatisfiedAt,
			&targetName, &targetType,
		); err != nil {
			return nil, err
		}
		if len(rule) > 0 {
			o.AcceptanceRule = json.RawMessage(rule)
		}
		if len(ctxSnap) > 0 {
			o.ContextSnapshot = json.RawMessage(ctxSnap)
		}
		if len(depsJSON) > 0 {
			_ = json.Unmarshal(depsJSON, &o.DependencyIDs)
		}
		o.TargetName = targetName
		o.TargetType = targetType
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if len(out[i].DependencyIDs) == 0 || out[i].RoundID == nil {
			continue
		}
		if statusMap == nil {
			roundID := f.RoundID
			if roundID <= 0 {
				roundID = *out[i].RoundID
			}
			var sErr error
			statusMap, sErr = d.roundObligationStatusMap(f.TaskID, roundID)
			if sErr != nil {
				return nil, sErr
			}
		}
		out[i].UnmetDependencyIDs = computeUnmetDeps(out[i].DependencyIDs, statusMap)
	}
	return out, nil
}

// GetCoverageSummaryByDimension returns per-dimension obligation progress for the round (§6.2).
func (d *DB) GetCoverageSummaryByDimension(taskID, roundID int64) ([]DimensionCoverageSummary, error) {
	byDim := make(map[string]*DimensionCoverageSummary, len(coverageDimensionOrder))
	out := make([]DimensionCoverageSummary, len(coverageDimensionOrder))
	for i, dim := range coverageDimensionOrder {
		out[i] = DimensionCoverageSummary{Dimension: dim, NotApplicableDimension: true}
		byDim[dim] = &out[i]
	}
	rows, err := d.Query(`
SELECT dimension, status, count(*)
FROM task_coverage_obligations
WHERE task_id=$1 AND round_id=$2 AND required
GROUP BY dimension, status`, taskID, roundID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var dim, status string
		var cnt int
		if err := rows.Scan(&dim, &status, &cnt); err != nil {
			return nil, err
		}
		s, ok := byDim[dim]
		if !ok {
			continue
		}
		s.RequiredTotal += cnt
		switch status {
		case ObligationSatisfied:
			s.Satisfied += cnt
		case ObligationNotApplicable:
			s.NotApplicable += cnt
		case ObligationPending:
			s.Pending += cnt
		case ObligationReady:
			s.Ready += cnt
		case ObligationRunning:
			s.Running += cnt
		case ObligationBlocked:
			s.Blocked += cnt
		case ObligationStale:
			s.Stale += cnt
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].ApplicableTotal = out[i].RequiredTotal - out[i].NotApplicable
		out[i].NotApplicableDimension = out[i].ApplicableTotal <= 0
	}
	return out, nil
}

// ReconcileObligationReadiness promotes pending obligations whose dependency_ids
// are all satisfied/not_applicable into ready (or blocked when missing credentials).
// Execution readiness depends strictly on dependency_ids, never exploration_edges.
func (d *DB) ReconcileObligationReadiness(taskID, roundID int64) (newlyReady int, newlyBlocked int, err error) {
	tx, err := d.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	var roundStatus string
	if err := tx.QueryRow(`SELECT status FROM task_assessment_rounds WHERE id=$1 AND task_id=$2 FOR UPDATE`,
		roundID, taskID).Scan(&roundStatus); err != nil {
		if err == sql.ErrNoRows {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	if roundStatus != "open" {
		return 0, 0, nil
	}

	type rowItem struct {
		id        int64
		status    string
		reqCreds  bool
		credRef   string
		blkReason string
		deps      []int64
	}
	rows, err := tx.Query(`
SELECT id, status, requires_credentials, credential_ref, blocked_reason,
       COALESCE(to_jsonb(dependency_ids), '[]'::jsonb)
FROM task_coverage_obligations
WHERE task_id=$1 AND round_id=$2 AND required
FOR UPDATE`, taskID, roundID)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	var items []rowItem
	statuses := map[int64]string{}
	for rows.Next() {
		var it rowItem
		var depsJSON []byte
		if err := rows.Scan(&it.id, &it.status, &it.reqCreds, &it.credRef, &it.blkReason, &depsJSON); err != nil {
			return 0, 0, err
		}
		_ = json.Unmarshal(depsJSON, &it.deps)
		statuses[it.id] = it.status
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

	for _, it := range items {
		if it.status != ObligationPending {
			continue
		}
		if len(computeUnmetDeps(it.deps, statuses)) > 0 {
			continue
		}
		if it.reqCreds && strings.TrimSpace(it.credRef) == "" {
			reason := strings.TrimSpace(it.blkReason)
			if reason == "" {
				reason = "缺少执行所需凭证引用（credential_ref）"
			}
			if _, err := tx.Exec(`
UPDATE task_coverage_obligations
SET status='blocked', blocked_reason=$2, updated_at=now()
WHERE id=$1 AND status='pending'`, it.id, reason); err != nil {
				return 0, 0, err
			}
			statuses[it.id] = ObligationBlocked
			newlyBlocked++
			continue
		}
		if _, err := tx.Exec(`
UPDATE task_coverage_obligations
SET status='ready', blocked_reason='', updated_at=now()
WHERE id=$1 AND status='pending'`, it.id); err != nil {
			return 0, 0, err
		}
		statuses[it.id] = ObligationReady
		newlyReady++
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return newlyReady, newlyBlocked, nil
}

// IsObligationExecutable checks whether an obligation bound to an open Intent is
// currently runnable (open round, non-terminal/non-blocked, deps satisfied, creds present,
// and matching active attempt when expectedAttemptID > 0).
func (d *DB) IsObligationExecutable(taskID, obligationID, roundID, expectedAttemptID int64) (bool, string, error) {
	var obTask int64
	var obRound sql.NullInt64
	var status, credRef string
	var reqCreds bool
	var depsJSON []byte
	var activeAttempt sql.NullInt64
	err := d.QueryRow(`
SELECT task_id, round_id, status, requires_credentials, credential_ref,
       COALESCE(to_jsonb(dependency_ids), '[]'::jsonb), active_attempt_id
FROM task_coverage_obligations
WHERE id=$1`, obligationID).Scan(&obTask, &obRound, &status, &reqCreds, &credRef, &depsJSON, &activeAttempt)
	if err == sql.ErrNoRows {
		return false, "coverage obligation not found", nil
	}
	if err != nil {
		return false, "", err
	}
	if obTask != taskID {
		return false, "obligation belongs to another task", nil
	}
	if !obRound.Valid {
		return false, "obligation is not bound to an assessment round", nil
	}
	if roundID > 0 && obRound.Int64 != roundID {
		return false, "obligation round mismatch", nil
	}
	var roundStatus string
	if err := d.QueryRow(`SELECT status FROM task_assessment_rounds WHERE id=$1 AND task_id=$2`, obRound.Int64, taskID).
		Scan(&roundStatus); err != nil {
		if err == sql.ErrNoRows {
			return false, "assessment round not found", nil
		}
		return false, "", err
	}
	if roundStatus != "open" {
		return false, fmt.Sprintf("assessment round is %s", roundStatus), nil
	}
	switch status {
	case ObligationReady:
	case ObligationPending:
		// Check whether dependencies are already satisfied (even before ReconcileObligationReadiness ran).
	case ObligationSatisfied, ObligationNotApplicable, ObligationBlocked, ObligationStale, ObligationRunning:
		return false, fmt.Sprintf("obligation status is %s", status), nil
	default:
		return false, fmt.Sprintf("unsupported obligation status %s", status), nil
	}
	if reqCreds && strings.TrimSpace(credRef) == "" {
		return false, "obligation requires credentials but credential_ref is empty", nil
	}
	if expectedAttemptID > 0 {
		if !activeAttempt.Valid || activeAttempt.Int64 != expectedAttemptID {
			return false, "intent attempt is superseded or inactive", nil
		}
	}
	var deps []int64
	_ = json.Unmarshal(depsJSON, &deps)
	if len(deps) > 0 {
		statuses, err := d.roundObligationStatusMap(taskID, obRound.Int64)
		if err != nil {
			return false, "", err
		}
		if unmet := computeUnmetDeps(deps, statuses); len(unmet) > 0 {
			return false, fmt.Sprintf("unmet dependency obligations: %v", unmet), nil
		}
	}
	return true, "", nil
}

// UpdateObligationPriority updates priority (1-10) on non-terminal obligations.
func (d *DB) UpdateObligationPriority(taskID, obligationID int64, priority int) error {
	p := normalizeObligationPriority(priority)
	res, err := d.Exec(`
UPDATE task_coverage_obligations
SET priority=$3, updated_at=now()
WHERE id=$1 AND task_id=$2 AND status NOT IN ('satisfied','not_applicable')`, obligationID, taskID, p)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: obligation %d not found or terminal", ErrObligationStateConflict, obligationID)
	}
	return nil
}

// TransitionObligationStatusByActor enforces §8.3 guardrails: Planner/Worker can
// never mark a required obligation not_applicable, and cannot bypass evidence checks.
func (d *DB) TransitionObligationStatusByActor(taskID, obligationID int64, actor, expected, next string, opts TransitionObligationOptions) (bool, error) {
	if (actor == ObligationOriginPlanner || actor == "worker") && next == ObligationNotApplicable {
		return false, ErrObligationProtectedByProgram
	}
	var ownerTask int64
	if err := d.QueryRow(`SELECT task_id FROM task_coverage_obligations WHERE id=$1`, obligationID).Scan(&ownerTask); err != nil {
		if err == sql.ErrNoRows {
			return false, fmt.Errorf("%w: obligation %d not found", ErrObligationOwnershipMismatch, obligationID)
		}
		return false, err
	}
	if ownerTask != taskID {
		return false, fmt.Errorf("%w: obligation %d belongs to task %d, not %d",
			ErrObligationOwnershipMismatch, obligationID, ownerTask, taskID)
	}
	return d.TransitionObligationStatus(obligationID, expected, next, opts)
}

// DeleteCoverageObligationByActor enforces §8.3 denominator guardrail:
// Planner/Worker can never delete any required coverage obligation.
func (d *DB) DeleteCoverageObligationByActor(taskID, obligationID int64, actor string) error {
	if actor == ObligationOriginPlanner || actor == "worker" {
		return ErrObligationProtectedByProgram
	}
	var origin string
	var ownerTask int64
	var required bool
	err := d.QueryRow(`SELECT task_id, origin, required FROM task_coverage_obligations WHERE id=$1`, obligationID).
		Scan(&ownerTask, &origin, &required)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if ownerTask != taskID {
		return fmt.Errorf("%w: obligation %d belongs to task %d, not %d",
			ErrObligationOwnershipMismatch, obligationID, ownerTask, taskID)
	}
	if origin == ObligationOriginProgram && required {
		return ErrObligationProtectedByProgram
	}
	_, err = d.Exec(`DELETE FROM task_coverage_obligations WHERE id=$1 AND task_id=$2`, obligationID, taskID)
	return err
}

// DispatchAssessmentIntent atomically validates dependencies, enforces idempotency
// for the same obligation/key, opens a dispatched attempt, and creates the bound Intent node.
func (d *DB) DispatchAssessmentIntent(in DispatchAssessmentIntentInput) (*DispatchAssessmentIntentResult, error) {
	if in.TaskID <= 0 || in.ObligationID <= 0 {
		return nil, errors.New("task_id and obligation_id are required")
	}
	summary := strings.TrimSpace(in.Summary)
	if summary == "" {
		return nil, errors.New("summary cannot be empty")
	}
	if err := rejectSecretInProfileText(summary, in.IdempotencyKey, string(in.WorkOrder)); err != nil {
		return nil, err
	}
	execMode := strings.TrimSpace(in.ExecutionMode)
	if !IsValidExecutionMode(execMode) {
		return nil, fmt.Errorf("%w: %q", ErrExecutionModeInvalid, in.ExecutionMode)
	}
	origin := strings.TrimSpace(in.Origin)
	if origin == "" {
		origin = ObligationOriginPlanner
	}

	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	var ob CoverageObligation
	var depsJSON []byte
	var roundStatus, taskExecMode string
	var explorationID int64
	var cfgRaw []byte
	err = tx.QueryRow(`
SELECT o.id, o.task_id, o.round_id, o.dimension, o.target_entity_id, o.status,
       o.requires_credentials, o.credential_ref, o.execution_mode, o.priority,
       COALESCE(to_jsonb(o.dependency_ids), '[]'::jsonb), o.active_attempt_id,
       t.exploration_id, t.assessment_config
FROM task_coverage_obligations o
JOIN tasks t ON t.id = o.task_id
WHERE o.id=$1
FOR UPDATE OF o`, in.ObligationID).Scan(
		&ob.ID, &ob.TaskID, &ob.RoundID, &ob.Dimension, &ob.TargetEntityID, &ob.Status,
		&ob.RequiresCredentials, &ob.CredentialRef, &ob.ExecutionMode, &ob.Priority,
		&depsJSON, &ob.ActiveAttemptID, &explorationID, &cfgRaw,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: obligation %d not found", ErrObligationOwnershipMismatch, in.ObligationID)
	}
	if err != nil {
		return nil, err
	}
	if ob.TaskID != in.TaskID {
		return nil, fmt.Errorf("%w: obligation %d belongs to task %d, not %d",
			ErrObligationOwnershipMismatch, in.ObligationID, ob.TaskID, in.TaskID)
	}
	if ob.RoundID == nil {
		return nil, errors.New("obligation must be bound to an assessment round")
	}
	if in.RoundID > 0 && *ob.RoundID != in.RoundID {
		return nil, fmt.Errorf("%w: obligation %d belongs to round %d, not %d",
			ErrObligationOwnershipMismatch, in.ObligationID, *ob.RoundID, in.RoundID)
	}
	var cfg AssessmentConfig
	if len(cfgRaw) > 0 {
		_ = json.Unmarshal(cfgRaw, &cfg)
		taskExecMode = cfg.ExecutionMode
	}
	var profileVer int
	if err := tx.QueryRow(`SELECT status, profile_version FROM task_assessment_rounds WHERE id=$1 AND task_id=$2`,
		*ob.RoundID, in.TaskID).Scan(&roundStatus, &profileVer); err != nil {
		return nil, err
	}
	if roundStatus != "open" {
		return nil, fmt.Errorf("%w: assessment round %d is %s", ErrObligationAlreadyTerminal, *ob.RoundID, roundStatus)
	}
	if ob.Status == ObligationSatisfied || ob.Status == ObligationNotApplicable {
		return nil, fmt.Errorf("%w: obligation %d is already %s", ErrObligationAlreadyTerminal, ob.ID, ob.Status)
	}
	if err := ValidateObligationExecutionMode(ob.Dimension, execMode, taskExecMode); err != nil {
		return nil, err
	}
	if ob.RequiresCredentials && strings.TrimSpace(ob.CredentialRef) == "" {
		return nil, fmt.Errorf("%w: obligation %d requires credential_ref before dispatch", ErrObligationCredentialsMissing, ob.ID)
	}

	_ = json.Unmarshal(depsJSON, &ob.DependencyIDs)
	if len(ob.DependencyIDs) > 0 {
		depRows, err := tx.Query(`
SELECT id, status FROM task_coverage_obligations
WHERE task_id=$1 AND round_id=$2`, in.TaskID, *ob.RoundID)
		if err != nil {
			return nil, err
		}
		depStatus := map[int64]string{}
		for depRows.Next() {
			var did int64
			var dst string
			if err := depRows.Scan(&did, &dst); err != nil {
				depRows.Close()
				return nil, err
			}
			depStatus[did] = dst
		}
		if err := depRows.Err(); err != nil {
			depRows.Close()
			return nil, err
		}
		depRows.Close()
		if unmet := computeUnmetDeps(ob.DependencyIDs, depStatus); len(unmet) > 0 {
			return nil, fmt.Errorf("%w: obligation %d waiting on %v", ErrObligationDependencyUnmet, ob.ID, unmet)
		}
	}

	idempKey := strings.TrimSpace(in.IdempotencyKey)
	if idempKey == "" {
		idempKey = fmt.Sprintf("r%d:o%d:%s", *ob.RoundID, ob.ID, execMode)
	}

	// Idempotency check BEFORE returning blocked error if there is already an active intent.
	if existing, ok, findErr := findActiveAssessmentIntentTx(tx, explorationID, ob.ID, idempKey); findErr != nil {
		return nil, findErr
	} else if ok {
		existing.RoundID = *ob.RoundID
		existing.ExecutionMode = execMode
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return existing, nil
	}

	if ob.Status == ObligationBlocked {
		return nil, fmt.Errorf("%w: obligation %d is blocked", ErrObligationDependencyUnmet, ob.ID)
	}

	// Verify anchors belong to exploration/project if passed; ParentIDs are purely lineage.
	parents := normalizePositiveIDs(in.ParentIDs)
	for _, pidVal := range parents {
		var kind string
		err := tx.QueryRow(`SELECT kind FROM exploration_nodes WHERE id=$1 AND exploration_id=$2`,
			pidVal, explorationID).Scan(&kind)
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w: parent node %d does not belong to exploration %d",
				ErrObligationOwnershipMismatch, pidVal, explorationID)
		}
		if err != nil {
			return nil, err
		}
	}

	var nextAttemptNo int
	if err := tx.QueryRow(`SELECT COALESCE(max(attempt_no),0)+1 FROM task_test_attempts WHERE obligation_id=$1`,
		ob.ID).Scan(&nextAttemptNo); err != nil {
		return nil, err
	}
	attemptUID := fmt.Sprintf("r%d-o%d-a%d", *ob.RoundID, ob.ID, nextAttemptNo)

	var attemptID int64
	if err := tx.QueryRow(`
INSERT INTO task_test_attempts(
    task_id, round_id, obligation_id, attempt_no, execution_mode, attempt_uid,
    profile_version, status, outcome, output)
VALUES ($1,$2,$3,$4,$5,$6,$7,'dispatched','','{}'::jsonb)
RETURNING id`,
		in.TaskID, *ob.RoundID, ob.ID, nextAttemptNo, execMode, attemptUID, profileVer).Scan(&attemptID); err != nil {
		return nil, err
	}

	priority := ob.Priority
	if in.Priority > 0 {
		priority = normalizeObligationPriority(in.Priority)
	} else if priority <= 0 {
		priority = 5
	}
	anchors := normalizePositiveIDs(in.AssetIDs)
	payloadMap := map[string]any{
		"summary":         summary,
		"execution_mode":  execMode,
		"obligation_id":   ob.ID,
		"round_id":        *ob.RoundID,
		"attempt_id":      attemptID,
		"attempt_uid":     attemptUID,
		"profile_version": profileVer,
		"idempotency_key": idempKey,
		"dimension":       ob.Dimension,
	}
	if ob.TargetEntityID != nil {
		payloadMap["target_entity_id"] = *ob.TargetEntityID
	}
	if len(anchors) > 0 {
		payloadMap["asset_ids"] = anchors
	}
	if len(in.WorkOrder) > 0 {
		var wo any
		if json.Unmarshal(in.WorkOrder, &wo) == nil && wo != nil {
			payloadMap["work_order"] = wo
		}
	}
	payloadRaw, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, err
	}

	var intentID int64
	if err := tx.QueryRow(`
INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
VALUES ($1,'intent',$2::jsonb,$3,'open',$4)
RETURNING id`, explorationID, string(payloadRaw), priority, origin).Scan(&intentID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			_ = tx.Rollback()
			existing, ok, findErr := d.findActiveAssessmentIntent(explorationID, ob.ID, idempKey)
			if findErr == nil && ok {
				existing.RoundID = *ob.RoundID
				existing.ExecutionMode = execMode
				return existing, nil
			}
		}
		return nil, err
	}

	for _, assetID := range anchors {
		if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id, asset_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
			intentID, assetID); err != nil {
			return nil, err
		}
	}
	if len(parents) == 0 {
		var originFactID int64
		if err := tx.QueryRow(`SELECT id FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact' AND state='origin' ORDER BY id LIMIT 1`,
			explorationID).Scan(&originFactID); err == nil && originFactID > 0 {
			parents = []int64{originFactID}
		}
	}
	for _, parentID := range parents {
		if parentID == intentID {
			continue
		}
		if _, err := tx.Exec(`
INSERT INTO exploration_edges(exploration_id, src_id, rel, dst_id)
VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, explorationID, parentID, RelDerivedFrom, intentID); err != nil {
			return nil, err
		}
	}

	if _, err := tx.Exec(`UPDATE task_test_attempts SET intent_node_id=$2 WHERE id=$1`, attemptID, intentID); err != nil {
		return nil, err
	}
	nextObStatus := ob.Status
	if nextObStatus == ObligationPending || nextObStatus == ObligationStale {
		nextObStatus = ObligationReady
	}
	if _, err := tx.Exec(`
UPDATE task_coverage_obligations
SET active_attempt_id=$2,
    status=$3,
    execution_mode=CASE WHEN execution_mode='' THEN $4 ELSE execution_mode END,
    updated_at=now()
WHERE id=$1`, ob.ID, attemptID, nextObStatus, execMode); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &DispatchAssessmentIntentResult{
		AlreadyActive:  false,
		IntentID:       intentID,
		IntentState:    "open",
		ObligationID:   ob.ID,
		RoundID:        *ob.RoundID,
		AttemptID:      attemptID,
		AttemptUID:     attemptUID,
		AttemptNo:      nextAttemptNo,
		ExecutionMode:  execMode,
		ProfileVersion: profileVer,
		IdempotencyKey: idempKey,
	}, nil
}

func findActiveAssessmentIntentTx(tx *sql.Tx, explorationID, obligationID int64, idempKey string) (*DispatchAssessmentIntentResult, bool, error) {
	obText := strconv.FormatInt(obligationID, 10)
	var id int64
	var state, attemptUID, payloadIdemp string
	var attemptID int64
	err := tx.QueryRow(`
SELECT id, state,
       COALESCE(NULLIF(payload->>'attempt_id',''), '0')::bigint,
       COALESCE(payload->>'attempt_uid',''),
       COALESCE(payload->>'idempotency_key','')
FROM exploration_nodes
WHERE exploration_id=$1 AND kind='intent' AND state IN ('open','running','paused')
  AND (
       COALESCE(payload->>'obligation_id','') = $2
    OR ($3 <> '' AND COALESCE(payload->>'idempotency_key','') = $3)
  )
ORDER BY id DESC LIMIT 1`, explorationID, obText, idempKey).Scan(&id, &state, &attemptID, &attemptUID, &payloadIdemp)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &DispatchAssessmentIntentResult{
		AlreadyActive:  true,
		IntentID:       id,
		IntentState:    state,
		ObligationID:   obligationID,
		AttemptID:      attemptID,
		AttemptUID:     attemptUID,
		IdempotencyKey: payloadIdemp,
	}, true, nil
}

func (d *DB) findActiveAssessmentIntent(explorationID, obligationID int64, idempKey string) (*DispatchAssessmentIntentResult, bool, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback() //nolint:errcheck
	return findActiveAssessmentIntentTx(tx, explorationID, obligationID, idempKey)
}

// MarkObligationAttemptRunning moves a dispatched attempt/obligation to running
// when a worker claims the Intent. Returns false if the attempt was superseded/cancelled.
func (d *DB) MarkObligationAttemptRunning(taskID, obligationID, attemptID int64) (bool, error) {
	tx, err := d.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck

	var activeAttempt sql.NullInt64
	var obStatus string
	err = tx.QueryRow(`
SELECT active_attempt_id, status FROM task_coverage_obligations
WHERE id=$1 AND task_id=$2 FOR UPDATE`, obligationID, taskID).Scan(&activeAttempt, &obStatus)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !activeAttempt.Valid || activeAttempt.Int64 != attemptID {
		return false, nil
	}
	if obStatus == ObligationSatisfied || obStatus == ObligationNotApplicable || obStatus == ObligationBlocked || obStatus == ObligationStale {
		return false, nil
	}
	res, err := tx.Exec(`
UPDATE task_test_attempts
SET status='running'
WHERE id=$1 AND task_id=$2 AND obligation_id=$3 AND status IN ('dispatched','running')`,
		attemptID, taskID, obligationID)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if _, err := tx.Exec(`
UPDATE task_coverage_obligations
SET status='running', updated_at=now()
WHERE id=$1 AND status IN ('pending','ready','running')`, obligationID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// PauseObligationAttempt moves an in-flight running attempt/obligation back to
// dispatched/ready while keeping active_attempt_id intact so resume re-claims the
// same attempt without creating duplicate work or hitting an obligation status gate.
func (d *DB) PauseObligationAttempt(taskID, obligationID, attemptID int64) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var activeAttempt sql.NullInt64
	var obStatus string
	err = tx.QueryRow(`
SELECT active_attempt_id, status FROM task_coverage_obligations
WHERE id=$1 AND task_id=$2 FOR UPDATE`, obligationID, taskID).Scan(&activeAttempt, &obStatus)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if !activeAttempt.Valid || activeAttempt.Int64 != attemptID {
		return nil
	}
	if _, err := tx.Exec(`
UPDATE task_test_attempts
SET status='dispatched'
WHERE id=$1 AND task_id=$2 AND obligation_id=$3 AND status='running'`,
		attemptID, taskID, obligationID); err != nil {
		return err
	}
	if obStatus == ObligationRunning {
		if _, err := tx.Exec(`
UPDATE task_coverage_obligations
SET status='ready', updated_at=now()
WHERE id=$1`, obligationID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CancelObligationAttempt cancels an in-flight attempt (kill_work/cancel/terminal)
// and returns the obligation to ready without advancing coverage.
func (d *DB) CancelObligationAttempt(taskID, obligationID, attemptID int64, reason string) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var roundID sql.NullInt64
	var activeAttempt sql.NullInt64
	var obStatus string
	err = tx.QueryRow(`
SELECT round_id, active_attempt_id, status FROM task_coverage_obligations
WHERE id=$1 AND task_id=$2 FOR UPDATE`, obligationID, taskID).Scan(&roundID, &activeAttempt, &obStatus)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	notePayload, _ := json.Marshal(map[string]any{"cancel_reason": strings.TrimSpace(reason)})
	_, err = tx.Exec(`
UPDATE task_test_attempts
SET status='cancelled',
    output = COALESCE(output, '{}'::jsonb) || $4::jsonb,
    completed_at = now()
WHERE id=$1 AND task_id=$2 AND obligation_id=$3 AND status IN ('dispatched','running')`,
		attemptID, taskID, obligationID, string(notePayload))
	if err != nil {
		return err
	}
	if activeAttempt.Valid && activeAttempt.Int64 == attemptID {
		nextStatus := obStatus
		if obStatus == ObligationRunning {
			nextStatus = ObligationReady
		}
		if _, err := tx.Exec(`
UPDATE task_coverage_obligations
SET active_attempt_id=NULL, status=$2, updated_at=now()
WHERE id=$1`, obligationID, nextStatus); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// FinalizeObligationAttempt validates attempt currency (late-write protection) and
// evidence requirements before settling the attempt and advancing the obligation.
func (d *DB) FinalizeObligationAttempt(in FinalizeObligationAttemptInput) (*FinalizeObligationAttemptResult, error) {
	if !IsValidAttemptOutcome(in.Outcome) {
		return nil, fmt.Errorf("%w: %q", ErrAttemptOutcomeInvalid, in.Outcome)
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	var roundID sql.NullInt64
	var dimension, obStatus, credRef string
	var reqCreds bool
	var activeAttempt sql.NullInt64
	err = tx.QueryRow(`
SELECT round_id, dimension, status, requires_credentials, credential_ref, active_attempt_id
FROM task_coverage_obligations
WHERE id=$1 AND task_id=$2
FOR UPDATE`, in.ObligationID, in.TaskID).Scan(
		&roundID, &dimension, &obStatus, &reqCreds, &credRef, &activeAttempt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: obligation %d not found in task %d", ErrObligationOwnershipMismatch, in.ObligationID, in.TaskID)
	}
	if err != nil {
		return nil, err
	}
	if !roundID.Valid {
		return nil, errors.New("obligation has no bound assessment round")
	}
	var roundStatus string
	if err := tx.QueryRow(`SELECT status FROM task_assessment_rounds WHERE id=$1 AND task_id=$2`,
		roundID.Int64, in.TaskID).Scan(&roundStatus); err != nil {
		return nil, err
	}
	if roundStatus != "open" {
		return nil, fmt.Errorf("%w: round %d is %s", ErrAttemptStaleOrSuperseded, roundID.Int64, roundStatus)
	}

	var attemptTask, attemptOb int64
	var attemptStatus, attemptExecMode string
	var existingIntent, existingAudit sql.NullInt64
	err = tx.QueryRow(`
SELECT task_id, obligation_id, status, execution_mode, intent_node_id, code_audit_run_id
FROM task_test_attempts
WHERE id=$1
FOR UPDATE`, in.AttemptID).Scan(&attemptTask, &attemptOb, &attemptStatus, &attemptExecMode, &existingIntent, &existingAudit)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: attempt %d not found", ErrAttemptStaleOrSuperseded, in.AttemptID)
	}
	if err != nil {
		return nil, err
	}
	if attemptTask != in.TaskID || attemptOb != in.ObligationID {
		return nil, fmt.Errorf("%w: attempt %d belongs to task %d / obligation %d",
			ErrObligationOwnershipMismatch, in.AttemptID, attemptTask, attemptOb)
	}
	if !activeAttempt.Valid || activeAttempt.Int64 != in.AttemptID ||
		(attemptStatus != AttemptStatusDispatched && attemptStatus != AttemptStatusRunning) {
		return nil, fmt.Errorf("%w: attempt %d status=%s active_attempt=%v",
			ErrAttemptStaleOrSuperseded, in.AttemptID, attemptStatus, activeAttempt)
	}
	if obStatus == ObligationSatisfied || obStatus == ObligationNotApplicable {
		return nil, fmt.Errorf("%w: obligation %d already %s", ErrObligationAlreadyTerminal, in.ObligationID, obStatus)
	}

	var evKind string
	if in.EvidenceRefID != nil {
		var evTask int64
		err := tx.QueryRow(`SELECT task_id, kind FROM task_evidence_refs WHERE id=$1`, *in.EvidenceRefID).
			Scan(&evTask, &evKind)
		if err == sql.ErrNoRows || (err == nil && evTask != in.TaskID) {
			return nil, fmt.Errorf("%w: evidence %d does not belong to task %d",
				ErrObligationOwnershipMismatch, *in.EvidenceRefID, in.TaskID)
		}
		if err != nil {
			return nil, err
		}
	}

	intentPtr := in.IntentNodeID
	if intentPtr == nil && existingIntent.Valid {
		v := existingIntent.Int64
		intentPtr = &v
	}
	auditPtr := in.CodeAuditRunID
	if auditPtr == nil && existingAudit.Valid {
		v := existingAudit.Int64
		auditPtr = &v
	}

	hasExecAssoc := false
	if intentPtr != nil {
		var n int64
		if err := tx.QueryRow(`SELECT count(*) FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id WHERE n.id=$1 AND t.id=$2`,
			*intentPtr, in.TaskID).Scan(&n); err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, fmt.Errorf("%w: intent node %d does not belong to task %d",
				ErrObligationOwnershipMismatch, *intentPtr, in.TaskID)
		}
		hasExecAssoc = true
	}
	if auditPtr != nil {
		var n int64
		if err := tx.QueryRow(`SELECT count(*) FROM task_code_audit_runs WHERE id=$1 AND task_id=$2`,
			*auditPtr, in.TaskID).Scan(&n); err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, fmt.Errorf("%w: code audit run %d does not belong to task %d",
				ErrObligationOwnershipMismatch, *auditPtr, in.TaskID)
		}
		hasExecAssoc = true
	}
	if !hasExecAssoc && evKind == string(EvidenceExecution) {
		hasExecAssoc = true
	}

	outputMap := map[string]any{}
	if len(in.Output) > 0 {
		_ = json.Unmarshal(in.Output, &outputMap)
	}

	finalOutcome := in.Outcome
	nextObStatus := ObligationReady
	advanceSatisfied := false
	insufficient := false
	rejectionReason := ""

	_, outcomeEffective := effectiveAttemptOutcomes[in.Outcome]
	if in.SatisfyObligation {
		switch {
		case !outcomeEffective:
			insufficient = true
			rejectionReason = fmt.Sprintf("attempt outcome %s is not an effective disposition", in.Outcome)
		case in.EvidenceRefID == nil:
			insufficient = true
			rejectionReason = "satisfying obligation requires an evidence reference"
		case reqCreds && strings.TrimSpace(credRef) == "":
			insufficient = true
			rejectionReason = "obligation requires credentials but credential_ref is empty"
		case (dimension == DimensionEntryTest || dimension == DimensionIdentityResource) &&
			attemptExecMode != "" && attemptExecMode != ExecModeDynamicVerify:
			insufficient = true
			rejectionReason = fmt.Sprintf("静态只读调查（%s）不能替代入口/身份动态验证（%s）", attemptExecMode, dimension)
		case attemptExecMode == ExecModeDynamicVerify && evKind != string(EvidenceExecution) && evKind != string(EvidenceTraffic):
			insufficient = true
			rejectionReason = fmt.Sprintf("动态验证（dynamic_verify）必须绑定 execution_output 或 traffic 证据引用，不能仅凭 %s 推进覆盖", evKind)
		default:
			if _, needsExec := executionDimensions[dimension]; needsExec && !hasExecAssoc {
				insufficient = true
				rejectionReason = fmt.Sprintf("dimension %s requires an execution association", dimension)
			} else {
				advanceSatisfied = true
				nextObStatus = ObligationSatisfied
			}
		}
		if insufficient {
			finalOutcome = AttemptFailed
			outputMap["evidence_insufficient"] = true
			outputMap["evidence_error"] = rejectionReason
			if reqCreds && strings.TrimSpace(credRef) == "" {
				nextObStatus = ObligationBlocked
			}
		}
	} else if (in.Outcome == AttemptEnvMismatch || in.Outcome == AttemptDependencyMissing) && strings.TrimSpace(in.BlockedReason) != "" {
		nextObStatus = ObligationBlocked
	}

	outputBytes, err := json.Marshal(outputMap)
	if err != nil {
		return nil, err
	}

	var storedEvRef *int64
	if !insufficient {
		storedEvRef = in.EvidenceRefID
	} else if in.EvidenceRefID != nil {
		// Retain link on attempt row for auditability even when insufficient to satisfy obligation.
		storedEvRef = in.EvidenceRefID
	}

	if _, err := tx.Exec(`
UPDATE task_test_attempts
SET status='completed',
    outcome=$2,
    intent_node_id=COALESCE($3, intent_node_id),
    code_audit_run_id=COALESCE($4, code_audit_run_id),
    evidence_ref_id=$5,
    output=$6::jsonb,
    completed_at=now()
WHERE id=$1`, in.AttemptID, finalOutcome, intentPtr, auditPtr, storedEvRef, string(outputBytes)); err != nil {
		return nil, err
	}

	blockedReason := strings.TrimSpace(in.BlockedReason)
	if nextObStatus == ObligationBlocked && blockedReason == "" {
		blockedReason = rejectionReason
	}
	if advanceSatisfied {
		if _, err := tx.Exec(`
UPDATE task_coverage_obligations
SET status='satisfied',
    evidence_ref_id=$2,
    satisfied_at=now(),
    blocked_reason='',
    stale_reason='',
    active_attempt_id=NULL,
    updated_at=now()
WHERE id=$1`, in.ObligationID, *in.EvidenceRefID); err != nil {
			return nil, err
		}
	} else if nextObStatus == ObligationBlocked {
		if _, err := tx.Exec(`
UPDATE task_coverage_obligations
SET status='blocked',
    blocked_reason=$2,
    active_attempt_id=NULL,
    updated_at=now()
WHERE id=$1`, in.ObligationID, blockedReason); err != nil {
			return nil, err
		}
	} else {
		if _, err := tx.Exec(`
UPDATE task_coverage_obligations
SET status='ready',
    active_attempt_id=NULL,
    updated_at=now()
WHERE id=$1`, in.ObligationID); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	unlocked := 0
	if advanceSatisfied {
		readyCnt, _, rErr := d.ReconcileObligationReadiness(in.TaskID, roundID.Int64)
		if rErr != nil {
			return nil, rErr
		}
		unlocked = readyCnt
	}

	return &FinalizeObligationAttemptResult{
		AttemptID:            in.AttemptID,
		ObligationID:         in.ObligationID,
		AttemptOutcome:       finalOutcome,
		NewObligationStatus:  nextObStatus,
		ObligationAdvanced:   advanceSatisfied,
		InsufficientEvidence: insufficient,
		RejectionReason:      rejectionReason,
		UnlockedCount:        unlocked,
	}, nil
}

// ListTestAttempts returns recent test attempts for a task/round or specific obligation.
func (d *DB) ListTestAttempts(taskID, roundID, obligationID int64, limit int) ([]TestAttempt, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `
SELECT a.id, a.task_id, a.round_id, a.obligation_id, a.attempt_no, a.intent_node_id,
       a.code_audit_run_id, a.execution_mode, a.attempt_uid, a.profile_version,
       a.status, a.outcome, a.evidence_ref_id, a.output, a.created_at, a.completed_at
FROM task_test_attempts a
WHERE a.task_id=$1`
	args := []any{taskID}
	if roundID > 0 {
		args = append(args, roundID)
		query += fmt.Sprintf(" AND a.round_id=$%d", len(args))
	}
	if obligationID > 0 {
		args = append(args, obligationID)
		query += fmt.Sprintf(" AND a.obligation_id=$%d", len(args))
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY a.id DESC LIMIT $%d", len(args))

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]TestAttempt, 0)
	for rows.Next() {
		var a TestAttempt
		var output []byte
		if err := rows.Scan(
			&a.ID, &a.TaskID, &a.RoundID, &a.ObligationID, &a.AttemptNo, &a.IntentNodeID,
			&a.CodeAuditRunID, &a.ExecutionMode, &a.AttemptUID, &a.ProfileVersion,
			&a.Status, &a.Outcome, &a.EvidenceRefID, &output, &a.CreatedAt, &a.CompletedAt,
		); err != nil {
			return nil, err
		}
		if len(output) > 0 {
			a.Output = json.RawMessage(output)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListCodeAuditCoverageSummaries returns compact coverage summaries across whitebox runs.
func (d *DB) ListCodeAuditCoverageSummaries(taskID int64, limit int) ([]CodeAuditCoverageSummary, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.Query(`
SELECT run.id, COALESCE(run.code_service_id, 0),
       COALESCE(NULLIF(service.name, ''), NULLIF(run.target_name, ''), run.relative_path),
       run.target_type, COALESCE(NULLIF(service.relative_path, ''), run.relative_path),
       run.codebase_id, run.version_id, run.scope_path, run.execution_origin,
       run.status, run.files_total, run.files_analyzed, run.files_skipped,
       run.chunks_total, run.chunks_completed, run.next_file_index, run.candidate_count
FROM task_code_audit_runs run
LEFT JOIN task_code_services service ON service.id = run.code_service_id
WHERE run.task_id=$1
ORDER BY run.id DESC
LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]CodeAuditCoverageSummary, 0)
	for rows.Next() {
		var item CodeAuditCoverageSummary
		if err := rows.Scan(
			&item.RunID, &item.ServiceID, &item.ServiceName, &item.TargetType, &item.RelativePath,
			&item.CodebaseID, &item.VersionID, &item.ScopePath, &item.ExecutionOrigin,
			&item.Status, &item.FilesTotal, &item.FilesAnalyzed, &item.FilesSkipped,
			&item.ChunksTotal, &item.ChunksCompleted, &item.NextFileIndex, &item.CandidateCount,
		); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// CountUnprocessedAssessmentEvents returns the number of pending assessment events for taskID.
func (d *DB) CountUnprocessedAssessmentEvents(taskID int64) (int, error) {
	var count int
	err := d.QueryRow(`SELECT count(*) FROM task_assessment_events WHERE task_id=$1 AND NOT processed`, taskID).Scan(&count)
	return count, err
}

// RecordAssessmentRoundEvent records an assessment event bound to roundID.
func (d *DB) RecordAssessmentRoundEvent(taskID, roundID int64, eventType string, payload json.RawMessage) (int64, error) {
	switch eventType {
	case "new_asset", "new_entry", "profile_change", "evidence_invalidated",
		"knowledge_conflict", "code_version_change", "code_audit_chunk_completed":
	default:
		return 0, fmt.Errorf("invalid assessment event type %q", eventType)
	}
	body := "{}"
	if len(payload) > 0 {
		body = string(payload)
	}
	var roundPtr any
	if roundID > 0 {
		roundPtr = roundID
	}
	var id int64
	if err := d.QueryRow(`
INSERT INTO task_assessment_events(task_id, round_id, event_type, payload)
VALUES ($1,$2,$3,$4::jsonb) RETURNING id`, taskID, roundPtr, eventType, body).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// ListUnprocessedAssessmentEventsByType lists pending assessment events matching eventType.
func (d *DB) ListUnprocessedAssessmentEventsByType(taskID int64, eventType string, limit int) ([]AssessmentEventRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.Query(`
SELECT id, task_id, round_id, event_type, payload, processed, created_at
FROM task_assessment_events
WHERE task_id=$1 AND event_type=$2 AND NOT processed
ORDER BY id ASC LIMIT $3`, taskID, eventType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AssessmentEventRecord, 0)
	for rows.Next() {
		var rec AssessmentEventRecord
		var payload []byte
		if err := rows.Scan(&rec.ID, &rec.TaskID, &rec.RoundID, &rec.EventType, &payload, &rec.Processed, &rec.CreatedAt); err != nil {
			return nil, err
		}
		if len(payload) > 0 {
			rec.Payload = json.RawMessage(payload)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// MarkAssessmentEventIDsProcessed marks specific unprocessed event IDs as processed.
func (d *DB) MarkAssessmentEventIDsProcessed(taskID int64, eventIDs []int64) error {
	ids := normalizePositiveIDs(eventIDs)
	if len(ids) == 0 {
		return nil
	}
	_, err := d.Exec(`
UPDATE task_assessment_events
SET processed=true, processed_at=now()
WHERE task_id=$1 AND id = ANY($2::bigint[]) AND NOT processed`,
		taskID, formatBigIntArray(ids))
	return err
}

// ResetInterruptedAssessmentAttempts returns any running attempts/obligations on
// taskID back to dispatched/ready after process restart so reopened Intents can resume.
func (d *DB) ResetInterruptedAssessmentAttempts(taskID int64) (int64, error) {
	tx, err := d.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.Exec(`
UPDATE task_test_attempts
SET status='dispatched'
WHERE task_id=$1 AND status='running'`, taskID)
	if err != nil {
		return 0, err
	}
	count, _ := res.RowsAffected()

	if _, err := tx.Exec(`
UPDATE task_coverage_obligations
SET status='ready', updated_at=now()
WHERE task_id=$1 AND status='running'`, taskID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

// LinkAttemptCodeAuditRun binds a created/resumed code audit run to an in-flight attempt.
func (d *DB) LinkAttemptCodeAuditRun(taskID, attemptID, runID int64) error {
	if taskID <= 0 || attemptID <= 0 || runID <= 0 {
		return nil
	}
	_, err := d.Exec(`
UPDATE task_test_attempts
SET code_audit_run_id=$3
WHERE id=$1 AND task_id=$2`, attemptID, taskID, runID)
	return err
}

// PublishedCodeAuditFindingSummary summarizes one published static code audit
// candidate and its linked finding (if recorded) for dynamic verification.
type PublishedCodeAuditFindingSummary struct {
	CandidateID       int64           `json:"candidate_id,omitempty"`
	RunID             int64           `json:"run_id,omitempty"`
	FindingID         *int64          `json:"finding_id,omitempty"`
	TargetEntityID    *int64          `json:"target_entity_id,omitempty"`
	ServiceName       string          `json:"service_name,omitempty"`
	RelativePath      string          `json:"relative_path,omitempty"`
	CodebaseID        string          `json:"codebase_id,omitempty"`
	VersionID         string          `json:"version_id,omitempty"`
	CandidateKey      string          `json:"candidate_key"`
	VulnClass         string          `json:"vulnclass,omitempty"`
	Title             string          `json:"title,omitempty"`
	Severity          string          `json:"severity,omitempty"`
	RegistrationTier  string          `json:"registration_tier,omitempty"`
	VerifyLevel       string          `json:"verify_level,omitempty"`
	Candidate         json.RawMessage `json:"candidate,omitempty"`
	CodeAuditEvidence json.RawMessage `json:"code_audit_evidence,omitempty"`
}

// ListPublishedCodeAuditFindings returns published static A/B audit candidates
// and any static theoretical findings on taskID so dynamic_verify can generate
// verification hypotheses and anchor dynamic work orders to static findings.
func (d *DB) ListPublishedCodeAuditFindings(taskID int64) ([]PublishedCodeAuditFindingSummary, error) {
	if d == nil || taskID <= 0 {
		return nil, nil
	}
	rows, err := d.Query(`
SELECT c.id, c.run_id, f.id, r.target_entity_id, COALESCE(r.target_name,''), COALESCE(r.relative_path,''),
       COALESCE(r.codebase_id,''), COALESCE(r.version_id,''), c.candidate_key,
       COALESCE(f.vulnclass, c.candidate->>'category', ''),
       COALESCE(f.name, c.candidate->>'title', ''),
       COALESCE(f.severity, c.candidate->>'severity', ''),
       COALESCE(c.candidate->>'registration_tier', 'A'),
       COALESCE(f.verify_level, 'theoretical'),
       c.candidate,
       COALESCE(f.code_audit_evidence, '{}'::jsonb)
FROM task_code_audit_candidates c
JOIN task_code_audit_runs r ON r.id = c.run_id
LEFT JOIN LATERAL (
    SELECT id, vulnclass, name, severity, verify_level, code_audit_evidence
    FROM findings
    WHERE task_id = r.task_id
      AND code_audit_evidence->>'candidate_key' = c.candidate_key
    ORDER BY id DESC LIMIT 1
) f ON true
WHERE r.task_id = $1 AND c.review_status = 'published'
ORDER BY c.id ASC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PublishedCodeAuditFindingSummary
	seenFindingID := map[int64]bool{}
	seenCandKey := map[string]bool{}
	for rows.Next() {
		var item PublishedCodeAuditFindingSummary
		var fID, targetEntID sql.NullInt64
		var candRaw, evRaw []byte
		if err := rows.Scan(
			&item.CandidateID, &item.RunID, &fID, &targetEntID,
			&item.ServiceName, &item.RelativePath, &item.CodebaseID, &item.VersionID,
			&item.CandidateKey, &item.VulnClass, &item.Title, &item.Severity,
			&item.RegistrationTier, &item.VerifyLevel, &candRaw, &evRaw,
		); err != nil {
			return nil, err
		}
		if fID.Valid {
			v := fID.Int64
			item.FindingID = &v
			seenFindingID[v] = true
		}
		if targetEntID.Valid {
			v := targetEntID.Int64
			item.TargetEntityID = &v
		}
		if len(candRaw) > 0 {
			item.Candidate = json.RawMessage(candRaw)
		}
		if len(evRaw) > 0 && string(evRaw) != "{}" {
			item.CodeAuditEvidence = json.RawMessage(evRaw)
		}
		if item.CandidateKey != "" {
			seenCandKey[item.CandidateKey] = true
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Include any static theoretical findings not paired with a published candidate row.
	fRows, err := d.Query(`
SELECT id, COALESCE(vulnclass,''), COALESCE(name,''), COALESCE(severity,''), COALESCE(verify_level,'theoretical'),
       COALESCE(code_audit_evidence, '{}'::jsonb)
FROM findings
WHERE task_id = $1 AND COALESCE(verify_level,'') = 'theoretical'
ORDER BY id ASC`, taskID)
	if err != nil {
		return nil, err
	}
	defer fRows.Close()
	for fRows.Next() {
		var fid int64
		var vc, title, sev, vlevel string
		var evRaw []byte
		if err := fRows.Scan(&fid, &vc, &title, &sev, &vlevel, &evRaw); err != nil {
			return nil, err
		}
		if seenFindingID[fid] {
			continue
		}
		candKey := fmt.Sprintf("finding-%d", fid)
		var evMap map[string]any
		if len(evRaw) > 0 {
			_ = json.Unmarshal(evRaw, &evMap)
		}
		if k, ok := evMap["candidate_key"].(string); ok && strings.TrimSpace(k) != "" {
			candKey = strings.TrimSpace(k)
		}
		if seenCandKey[candKey] {
			continue
		}
		var item PublishedCodeAuditFindingSummary
		fidCopy := fid
		item.FindingID = &fidCopy
		item.CandidateKey = candKey
		item.VulnClass = vc
		item.Title = title
		item.Severity = sev
		item.RegistrationTier = "A"
		item.VerifyLevel = vlevel
		if len(evRaw) > 0 && string(evRaw) != "{}" {
			item.CodeAuditEvidence = json.RawMessage(evRaw)
		}
		if sName, ok := evMap["relative_path"].(string); ok {
			item.RelativePath = sName
		}
		out = append(out, item)
	}
	return out, fRows.Err()
}
