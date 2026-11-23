package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// InvalidateObligationsInput specifies which obligations and downstream dependents
// should be marked stale when code, config, auth, deployment, or profile claims change.
type InvalidateObligationsInput struct {
	TaskID             int64
	RoundID            int64
	ChangeKind         string
	Reason             string
	Dimensions         []string
	TargetEntityIDs    []int64
	ObligationIDs      []int64
	IncludeTransitive  bool
	BumpProfileVersion bool
	NewCodebaseVersion string
	NewEnvVersion      string
}

// InvalidateObligationsResult summarizes affected obligations, cancelled active
// attempts, and updated profile version after an invalidation pass.
type InvalidateObligationsResult struct {
	RoundID             int64   `json:"round_id"`
	NewProfileVersion   int     `json:"new_profile_version"`
	InvalidatedIDs      []int64 `json:"invalidated_ids,omitempty"`
	CancelledAttemptIDs []int64 `json:"cancelled_attempt_ids,omitempty"`
	StoppedIntentIDs    []int64 `json:"stopped_intent_ids,omitempty"`
	EventID             int64   `json:"event_id,omitempty"`
}

// ReopenStaleResult summarizes stale obligations transitioned back into runnable states.
type ReopenStaleResult struct {
	RoundID     int64   `json:"round_id"`
	ReopenedIDs []int64 `json:"reopened_ids,omitempty"`
	ReadyCount  int     `json:"ready_count"`
}

// MergeHypothesesResult reports surviving and deduplicated hypothesis obligations.
type MergeHypothesesResult struct {
	RoundID     int64   `json:"round_id"`
	MergedPairs int     `json:"merged_pairs"`
	PrimaryIDs  []int64 `json:"primary_ids,omitempty"`
	MergedIDs   []int64 `json:"merged_ids,omitempty"`
}

// ReopenRoundResult describes the closed historical round and newly created open round.
type ReopenRoundResult struct {
	PreviousRoundID int64            `json:"previous_round_id,omitempty"`
	NewRound        *AssessmentRound `json:"new_round"`
	EventID         int64            `json:"event_id,omitempty"`
}

// InvalidateObligationsOnChange transitions affected satisfied/running obligations
// (and optionally transitive dependents) to stale, cancels obsolete active attempts
// so late writes fail with ErrAttemptStaleOrSuperseded, bumps profile_version,
// and emits an evidence_invalidated assessment event.
func (d *DB) InvalidateObligationsOnChange(in InvalidateObligationsInput) (*InvalidateObligationsResult, error) {
	if d == nil || in.TaskID <= 0 || in.RoundID <= 0 {
		return nil, errors.New("task_id and round_id are required")
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		return nil, fmt.Errorf("%w: invalidation reason is required", ErrObligationEvidenceMissing)
	}
	if err := rejectSecretInProfileText(reason, in.ChangeKind, in.NewCodebaseVersion, in.NewEnvVersion); err != nil {
		return nil, err
	}

	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	var roundStatus string
	var profileVer int
	err = tx.QueryRow(`SELECT status, profile_version FROM task_assessment_rounds WHERE id=$1 AND task_id=$2 FOR UPDATE`,
		in.RoundID, in.TaskID).Scan(&roundStatus, &profileVer)
	if err == sql.ErrNoRows {
		return nil, ErrObligationOwnershipMismatch
	}
	if err != nil {
		return nil, err
	}
	if roundStatus != "open" {
		return nil, fmt.Errorf("%w: round %d is %s", ErrAttemptStaleOrSuperseded, in.RoundID, roundStatus)
	}

	type obRow struct {
		ID             int64
		Dimension      string
		TargetEntityID *int64
		Status         string
		Deps           []int64
		ActiveAttempt  *int64
	}
	rows, err := tx.Query(`
SELECT id, dimension, target_entity_id, status, COALESCE(to_jsonb(dependency_ids), '[]'::jsonb), active_attempt_id
FROM task_coverage_obligations
WHERE task_id=$1 AND round_id=$2 AND required
FOR UPDATE`, in.TaskID, in.RoundID)
	if err != nil {
		return nil, err
	}
	var all []obRow
	byID := map[int64]*obRow{}
	for rows.Next() {
		var r obRow
		var targetID, activeAtt sql.NullInt64
		var depsRaw []byte
		if err := rows.Scan(&r.ID, &r.Dimension, &targetID, &r.Status, &depsRaw, &activeAtt); err != nil {
			rows.Close()
			return nil, err
		}
		if targetID.Valid {
			v := targetID.Int64
			r.TargetEntityID = &v
		}
		if activeAtt.Valid {
			v := activeAtt.Int64
			r.ActiveAttempt = &v
		}
		if len(depsRaw) > 0 {
			_ = json.Unmarshal(depsRaw, &r.Deps)
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	for i := range all {
		byID[all[i].ID] = &all[i]
	}

	explicitIDs := map[int64]bool{}
	for _, id := range normalizePositiveIDs(in.ObligationIDs) {
		explicitIDs[id] = true
	}
	dimFilter := map[string]bool{}
	for _, dm := range in.Dimensions {
		if trimmed := strings.TrimSpace(dm); trimmed != "" {
			dimFilter[trimmed] = true
		}
	}
	entityFilter := map[int64]bool{}
	for _, eid := range normalizePositiveIDs(in.TargetEntityIDs) {
		entityFilter[eid] = true
	}
	hasAnyFilter := len(explicitIDs) > 0 || len(dimFilter) > 0 || len(entityFilter) > 0

	matchesFilter := func(r obRow) bool {
		if !hasAnyFilter {
			return true
		}
		if len(explicitIDs) > 0 && !explicitIDs[r.ID] {
			return false
		}
		if len(dimFilter) > 0 && !dimFilter[r.Dimension] {
			return false
		}
		if len(entityFilter) > 0 && (r.TargetEntityID == nil || !entityFilter[*r.TargetEntityID]) {
			return false
		}
		return true
	}

	invalidated := map[int64]bool{}
	for _, r := range all {
		if (r.Status == ObligationSatisfied || r.Status == ObligationRunning) && matchesFilter(r) {
			invalidated[r.ID] = true
		}
	}

	if in.IncludeTransitive && len(invalidated) > 0 {
		changed := true
		for changed {
			changed = false
			for _, r := range all {
				if invalidated[r.ID] || (r.Status != ObligationSatisfied && r.Status != ObligationRunning) {
					continue
				}
				for _, dep := range r.Deps {
					if invalidated[dep] {
						invalidated[r.ID] = true
						changed = true
						break
					}
				}
			}
		}
	}

	var invIDs, cancelledAttempts, stoppedIntents []int64
	for _, r := range all {
		if invalidated[r.ID] {
			invIDs = append(invIDs, r.ID)
		}
	}
	sort.Slice(invIDs, func(i, j int) bool { return invIDs[i] < invIDs[j] })

	for _, id := range invIDs {
		r := byID[id]
		if r.ActiveAttempt != nil && *r.ActiveAttempt > 0 {
			attID := *r.ActiveAttempt
			var intentID sql.NullInt64
			err := tx.QueryRow(`
UPDATE task_test_attempts
SET status='cancelled',
    output = COALESCE(output, '{}'::jsonb) || jsonb_build_object('invalidated_reason', $2::text),
    completed_at = COALESCE(completed_at, now())
WHERE id=$1 AND task_id=$3 AND status IN ('dispatched','running')
RETURNING intent_node_id`, attID, reason, in.TaskID).Scan(&intentID)
			if err == nil {
				cancelledAttempts = append(cancelledAttempts, attID)
				if intentID.Valid && intentID.Int64 > 0 {
					res, sErr := tx.Exec(`UPDATE exploration_nodes SET state='stopped' WHERE id=$1 AND kind='intent' AND state IN ('open','running')`, intentID.Int64)
					if sErr == nil {
						if aff, _ := res.RowsAffected(); aff > 0 {
							stoppedIntents = append(stoppedIntents, intentID.Int64)
						}
					}
				}
			}
		}
		if _, err := tx.Exec(`
UPDATE task_coverage_obligations
SET status='stale',
    stale_reason=$2,
    active_attempt_id=NULL,
    updated_at=now()
WHERE id=$1 AND task_id=$3`, id, reason, in.TaskID); err != nil {
			return nil, err
		}
	}

	// Mark any ready obligation whose upstream dependency turned stale back to pending.
	if len(invIDs) > 0 {
		for _, r := range all {
			if r.Status != ObligationReady || invalidated[r.ID] || len(r.Deps) == 0 {
				continue
			}
			for _, dep := range r.Deps {
				if invalidated[dep] {
					if _, err := tx.Exec(`UPDATE task_coverage_obligations SET status='pending', updated_at=now() WHERE id=$1`, r.ID); err != nil {
						return nil, err
					}
					break
				}
			}
		}
	}

	newVer := profileVer
	if in.BumpProfileVersion || len(invIDs) > 0 || strings.TrimSpace(in.NewCodebaseVersion) != "" || strings.TrimSpace(in.NewEnvVersion) != "" {
		err = tx.QueryRow(`
UPDATE task_assessment_rounds
SET profile_version = profile_version + 1,
    codebase_version = CASE WHEN btrim($2) <> '' THEN btrim($2) ELSE codebase_version END,
    environment_version = CASE WHEN btrim($3) <> '' THEN btrim($3) ELSE environment_version END
WHERE id=$1
RETURNING profile_version`, in.RoundID, strings.TrimSpace(in.NewCodebaseVersion), strings.TrimSpace(in.NewEnvVersion)).Scan(&newVer)
		if err != nil {
			return nil, err
		}
	}

	var eventID int64
	if len(invIDs) > 0 || in.BumpProfileVersion {
		evPayload, _ := json.Marshal(map[string]any{
			"change_kind":         firstNonEmptyStr(in.ChangeKind, "manual"),
			"reason":              reason,
			"invalidated_ids":     invIDs,
			"cancelled_attempts":  cancelledAttempts,
			"new_profile_version": newVer,
			"codebase_version":    strings.TrimSpace(in.NewCodebaseVersion),
			"environment_version": strings.TrimSpace(in.NewEnvVersion),
		})
		if err := tx.QueryRow(`
INSERT INTO task_assessment_events(task_id, round_id, event_type, payload)
VALUES ($1, $2, 'evidence_invalidated', $3::jsonb) RETURNING id`, in.TaskID, in.RoundID, string(evPayload)).Scan(&eventID); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &InvalidateObligationsResult{
		RoundID:             in.RoundID,
		NewProfileVersion:   newVer,
		InvalidatedIDs:      invIDs,
		CancelledAttemptIDs: cancelledAttempts,
		StoppedIntentIDs:    stoppedIntents,
		EventID:             eventID,
	}, nil
}

// ReopenStaleObligations moves stale obligations in roundID back to pending/ready
// at the current profile_version and clears their stale_reason so they re-enter execution.
func (d *DB) ReopenStaleObligations(taskID, roundID int64, obligationIDs []int64, reason string) (*ReopenStaleResult, error) {
	if d == nil || taskID <= 0 || roundID <= 0 {
		return nil, errors.New("task_id and round_id are required")
	}
	reason = strings.TrimSpace(reason)
	if err := rejectSecretInProfileText(reason); err != nil {
		return nil, err
	}

	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	var roundStatus string
	var profileVer int
	err = tx.QueryRow(`SELECT status, profile_version FROM task_assessment_rounds WHERE id=$1 AND task_id=$2 FOR UPDATE`,
		roundID, taskID).Scan(&roundStatus, &profileVer)
	if err == sql.ErrNoRows {
		return nil, ErrObligationOwnershipMismatch
	}
	if err != nil {
		return nil, err
	}
	if roundStatus != "open" {
		return nil, fmt.Errorf("%w: round %d is %s", ErrAttemptStaleOrSuperseded, roundID, roundStatus)
	}

	ids := normalizePositiveIDs(obligationIDs)
	var rows *sql.Rows
	if len(ids) > 0 {
		rows, err = tx.Query(`
UPDATE task_coverage_obligations
SET status='pending',
    stale_reason='',
    evidence_ref_id=NULL,
    active_attempt_id=NULL,
    profile_version=$4,
    acceptance_rule = CASE WHEN btrim($5) <> '' THEN COALESCE(acceptance_rule, '{}'::jsonb) || jsonb_build_object('reopen_reason', btrim($5)) ELSE acceptance_rule END,
    updated_at=now()
WHERE task_id=$1 AND round_id=$2 AND status='stale' AND id = ANY($3::bigint[])
RETURNING id`, taskID, roundID, formatBigIntArray(ids), profileVer, reason)
	} else {
		rows, err = tx.Query(`
UPDATE task_coverage_obligations
SET status='pending',
    stale_reason='',
    evidence_ref_id=NULL,
    active_attempt_id=NULL,
    profile_version=$3,
    acceptance_rule = CASE WHEN btrim($4) <> '' THEN COALESCE(acceptance_rule, '{}'::jsonb) || jsonb_build_object('reopen_reason', btrim($4)) ELSE acceptance_rule END,
    updated_at=now()
WHERE task_id=$1 AND round_id=$2 AND status='stale'
RETURNING id`, taskID, roundID, profileVer, reason)
	}
	if err != nil {
		return nil, err
	}
	var reopened []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		reopened = append(reopened, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	readyCnt := 0
	if len(reopened) > 0 {
		readyCnt, _, _ = d.ReconcileObligationReadiness(taskID, roundID)
	}
	sort.Slice(reopened, func(i, j int) bool { return reopened[i] < reopened[j] })
	return &ReopenStaleResult{
		RoundID:     roundID,
		ReopenedIDs: reopened,
		ReadyCount:  readyCnt,
	}, nil
}

// hypothesisMergeKey derives a conservative canonical deduplication key for
// open hypothesis obligations so equivalent findings/candidates/targets merge cleanly.
func hypothesisMergeKey(ob CoverageObligation) string {
	var snap map[string]any
	if len(ob.ContextSnapshot) > 0 {
		_ = json.Unmarshal(ob.ContextSnapshot, &snap)
	}
	if snap != nil {
		if fid, ok := snap["finding_id"].(float64); ok && fid > 0 {
			return fmt.Sprintf("%s|finding:%d", ob.ExecutionMode, int64(fid))
		}
		if ck, ok := snap["candidate_key"].(string); ok && strings.TrimSpace(ck) != "" {
			return fmt.Sprintf("%s|cand:%s", ob.ExecutionMode, strings.ToLower(strings.TrimSpace(ck)))
		}
		if srcOb, ok := snap["source_obligation_id"].(float64); ok && srcOb > 0 {
			return fmt.Sprintf("%s|srcob:%d", ob.ExecutionMode, int64(srcOb))
		}
	}
	var targetID int64
	if ob.TargetEntityID != nil {
		targetID = *ob.TargetEntityID
	}
	normPurpose := strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(ob.Purpose))), " ")
	if targetID == 0 || normPurpose == "" {
		return ""
	}
	return fmt.Sprintf("%s|t:%d|p:%s", ob.ExecutionMode, targetID, normPurpose)
}

// MergeDuplicateHypothesisObligations consolidates duplicate non-terminal
// hypothesis obligations within roundID, preserving dependency lineage and marking
// duplicates not_applicable with an explicit auditable reference to the survivor.
func (d *DB) MergeDuplicateHypothesisObligations(taskID, roundID int64) (*MergeHypothesesResult, error) {
	if d == nil || taskID <= 0 || roundID <= 0 {
		return nil, errors.New("task_id and round_id are required")
	}
	obs, err := d.ListCoverageObligations(CoverageObligationFilter{
		TaskID:    taskID,
		RoundID:   roundID,
		Dimension: DimensionHypothesis,
		Limit:     500,
	})
	if err != nil {
		return nil, err
	}
	groups := map[string][]CoverageObligation{}
	var order []string
	for _, ob := range obs {
		switch ob.Status {
		case ObligationPending, ObligationReady, ObligationBlocked, ObligationStale, ObligationRunning:
		default:
			continue
		}
		key := hypothesisMergeKey(ob)
		if key == "" {
			continue
		}
		if _, exists := groups[key]; !exists {
			order = append(order, key)
		}
		groups[key] = append(groups[key], ob)
	}
	sort.Strings(order)

	res := &MergeHypothesesResult{RoundID: roundID}
	for _, key := range order {
		grp := groups[key]
		if len(grp) < 2 {
			continue
		}
		sort.SliceStable(grp, func(i, j int) bool {
			rank := func(o CoverageObligation) int {
				switch o.Status {
				case ObligationRunning:
					return 5
				case ObligationReady:
					return 4
				case ObligationPending:
					return 3
				case ObligationStale:
					return 2
				default:
					return 1
				}
			}
			ri, rj := rank(grp[i]), rank(grp[j])
			if ri != rj {
				return ri > rj
			}
			if grp[i].Priority != grp[j].Priority {
				return grp[i].Priority > grp[j].Priority
			}
			return grp[i].ID < grp[j].ID
		})
		primary := grp[0]
		var dupIDs []int64
		for _, dup := range grp[1:] {
			if dup.Status == ObligationRunning || dup.ActiveAttemptID != nil {
				continue
			}
			dupIDs = append(dupIDs, dup.ID)
		}
		if len(dupIDs) == 0 {
			continue
		}
		part, mErr := d.MergeHypothesisObligations(taskID, roundID, primary.ID, dupIDs, "同源静态/动态假设语义重复自动去重")
		if mErr != nil {
			return nil, mErr
		}
		res.MergedPairs += part.MergedPairs
		res.PrimaryIDs = append(res.PrimaryIDs, part.PrimaryIDs...)
		res.MergedIDs = append(res.MergedIDs, part.MergedIDs...)
	}
	return res, nil
}

// MergeHypothesisObligations explicitly merges duplicateIDs into primaryID within roundID,
// preserving merged lineage and giving every duplicate an auditable not_applicable_reason.
func (d *DB) MergeHypothesisObligations(taskID, roundID, primaryID int64, duplicateIDs []int64, reason string) (*MergeHypothesesResult, error) {
	if d == nil || taskID <= 0 || roundID <= 0 || primaryID <= 0 {
		return nil, errors.New("task_id, round_id, and primary_id are required")
	}
	cleanDups := normalizePositiveIDs(duplicateIDs)
	filtered := make([]int64, 0, len(cleanDups))
	for _, id := range cleanDups {
		if id != primaryID {
			filtered = append(filtered, id)
		}
	}
	if len(filtered) == 0 {
		return &MergeHypothesesResult{RoundID: roundID}, nil
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "等效假设合并"
	}
	if err := rejectSecretInProfileText(reason); err != nil {
		return nil, err
	}

	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	var roundStatus string
	if err := tx.QueryRow(`SELECT status FROM task_assessment_rounds WHERE id=$1 AND task_id=$2 FOR UPDATE`,
		roundID, taskID).Scan(&roundStatus); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrObligationOwnershipMismatch
		}
		return nil, err
	}
	if roundStatus != "open" {
		return nil, fmt.Errorf("%w: round %d is %s", ErrAttemptStaleOrSuperseded, roundID, roundStatus)
	}

	var pDim, pStatus string
	var pPriority int
	var pDepsRaw, pSnapRaw []byte
	err = tx.QueryRow(`
SELECT dimension, status, priority, COALESCE(to_jsonb(dependency_ids),'[]'::jsonb), COALESCE(context_snapshot,'{}'::jsonb)
FROM task_coverage_obligations
WHERE id=$1 AND task_id=$2 AND round_id=$3
FOR UPDATE`, primaryID, taskID, roundID).Scan(&pDim, &pStatus, &pPriority, &pDepsRaw, &pSnapRaw)
	if err == sql.ErrNoRows {
		return nil, ErrObligationOwnershipMismatch
	}
	if err != nil {
		return nil, err
	}
	if pDim != DimensionHypothesis {
		return nil, fmt.Errorf("%w: primary obligation %d must be dimension hypothesis, got %s", ErrObligationDimensionInvalid, primaryID, pDim)
	}
	if pStatus == ObligationNotApplicable {
		return nil, fmt.Errorf("%w: primary obligation %d is already not_applicable", ErrObligationAlreadyTerminal, primaryID)
	}

	var mergedDeps []int64
	_ = json.Unmarshal(pDepsRaw, &mergedDeps)
	snap := map[string]any{}
	if len(pSnapRaw) > 0 {
		_ = json.Unmarshal(pSnapRaw, &snap)
	}
	var mergedFrom []int64
	if rawArr, ok := snap["merged_from_ids"].([]any); ok {
		for _, v := range rawArr {
			if f, ok := v.(float64); ok && f > 0 {
				mergedFrom = append(mergedFrom, int64(f))
			}
		}
	}

	maxPrio := pPriority
	var mergedIDs []int64
	for _, dupID := range filtered {
		var dDim, dStatus, dDedupe string
		var dPriority int
		var dActive sql.NullInt64
		var dDepsRaw []byte
		err := tx.QueryRow(`
SELECT dimension, status, priority, dedupe_key, active_attempt_id, COALESCE(to_jsonb(dependency_ids),'[]'::jsonb)
FROM task_coverage_obligations
WHERE id=$1 AND task_id=$2 AND round_id=$3
FOR UPDATE`, dupID, taskID, roundID).Scan(&dDim, &dStatus, &dPriority, &dDedupe, &dActive, &dDepsRaw)
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w: duplicate obligation %d not found in round", ErrObligationOwnershipMismatch, dupID)
		}
		if err != nil {
			return nil, err
		}
		if dDim != DimensionHypothesis {
			return nil, fmt.Errorf("%w: only hypothesis obligations can be merged, got %s", ErrObligationDimensionInvalid, dDim)
		}
		if dStatus == ObligationSatisfied || dStatus == ObligationRunning || dActive.Valid {
			continue
		}
		if dStatus == ObligationNotApplicable {
			continue
		}
		var dupDeps []int64
		_ = json.Unmarshal(dDepsRaw, &dupDeps)
		mergedDeps = append(mergedDeps, dupDeps...)
		if dPriority > maxPrio {
			maxPrio = dPriority
		}
		mergedFrom = append(mergedFrom, dupID)
		auditReason := fmt.Sprintf("已合并至等价假设义务 #%d：%s", primaryID, reason)
		if _, err := tx.Exec(`
UPDATE task_coverage_obligations
SET status='not_applicable',
    not_applicable_reason=$2,
    active_attempt_id=NULL,
    updated_at=now()
WHERE id=$1`, dupID, auditReason); err != nil {
			return nil, err
		}
		mergedIDs = append(mergedIDs, dupID)
	}

	if len(mergedIDs) == 0 {
		return &MergeHypothesesResult{RoundID: roundID}, nil
	}

	// Filter self/duplicate dependencies from primary before saving.
	mergedSet := map[int64]bool{primaryID: true}
	for _, id := range mergedIDs {
		mergedSet[id] = true
	}
	var cleanDeps []int64
	for _, dep := range normalizePositiveIDs(mergedDeps) {
		if !mergedSet[dep] {
			cleanDeps = append(cleanDeps, dep)
		}
	}
	snap["merged_from_ids"] = normalizePositiveIDs(mergedFrom)
	snap["merge_note"] = reason
	snapBytes, _ := json.Marshal(snap)

	if _, err := tx.Exec(`
UPDATE task_coverage_obligations
SET priority=$2,
    dependency_ids=$3::bigint[],
    context_snapshot=$4::jsonb,
    updated_at=now()
WHERE id=$1`, primaryID, maxPrio, formatBigIntArray(cleanDeps), string(snapBytes)); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	_, _, _ = d.ReconcileObligationReadiness(taskID, roundID)
	return &MergeHypothesesResult{
		RoundID:     roundID,
		MergedPairs: len(mergedIDs),
		PrimaryIDs:  []int64{primaryID},
		MergedIDs:   mergedIDs,
	}, nil
}

// ReopenAssessmentForNextRound closes any currently open round, creates RoundNo+1
// preserving all prior round records intact (§6.4), reopens terminal done/timeout/failed
// tasks back to running + profiling, and emits an initial change event on the new round.
func (d *DB) ReopenAssessmentForNextRound(taskID int64, reason, codebaseVersion, envVersion string) (*ReopenRoundResult, error) {
	if d == nil || taskID <= 0 {
		return nil, errors.New("task_id is required")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "代码、环境或范围变更开启新一轮评估"
	}
	if err := rejectSecretInProfileText(reason, codebaseVersion, envVersion); err != nil {
		return nil, err
	}

	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	var taskStatus string
	var assessmentMode bool
	var expID int64
	if err := tx.QueryRow(`SELECT status, assessment_mode, exploration_id FROM tasks WHERE id=$1 FOR UPDATE`, taskID).
		Scan(&taskStatus, &assessmentMode, &expID); err != nil {
		return nil, err
	}
	if !assessmentMode {
		return nil, ErrTaskNotAssessmentMode
	}

	var prevRoundID int64
	var prevStdVer, prevScopeVer, prevCodeVer, prevEnvVer string
	err = tx.QueryRow(`
SELECT id, standard_version, scope_version, codebase_version, environment_version
FROM task_assessment_rounds
WHERE task_id=$1
ORDER BY (status='open') DESC, round_no DESC LIMIT 1
FOR UPDATE`, taskID).Scan(&prevRoundID, &prevStdVer, &prevScopeVer, &prevCodeVer, &prevEnvVer)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if prevRoundID > 0 {
		supReport, _ := json.Marshal(map[string]any{
			"superseded": true,
			"reason":     reason,
		})
		if _, err := tx.Exec(`
UPDATE task_assessment_rounds
SET status='completed',
    completion_report = CASE WHEN completion_report = '{}'::jsonb THEN $2::jsonb ELSE completion_report END,
    completed_at = COALESCE(completed_at, now())
WHERE id=$1 AND status='open'`, prevRoundID, string(supReport)); err != nil {
			return nil, err
		}
	}

	codeVer := firstNonEmptyStr(codebaseVersion, prevCodeVer)
	envVer := firstNonEmptyStr(envVersion, prevEnvVer)
	stdVer := firstNonEmptyStr(prevStdVer, AssessmentStandardDynamic)

	newRound, err := scanAssessmentRound(tx.QueryRow(`
INSERT INTO task_assessment_rounds(task_id, round_no, codebase_version, environment_version, scope_version, standard_version)
VALUES ($1, COALESCE((SELECT max(round_no) FROM task_assessment_rounds WHERE task_id=$1), 0) + 1, $2, $3, $4, $5)
RETURNING `+assessmentRoundCols, taskID, codeVer, envVer, prevScopeVer, stdVer))
	if err != nil {
		return nil, err
	}

	if _, err := tx.Exec(`
UPDATE tasks
SET status='running',
    draft=false,
    assessment_phase=$2,
    pause_reason='',
    stop_reason='',
    completed_at=NULL,
    first_run_at=NULL,
    deadline_at=NULL,
    no_result_checked_at=NULL,
    run_segment_started_at=COALESCE(run_segment_started_at, now())
WHERE id=$1`, taskID, AssessmentPhaseProfiling); err != nil {
		return nil, err
	}

	evType := "profile_change"
	if strings.TrimSpace(codebaseVersion) != "" {
		evType = "code_version_change"
	}
	evPayload, _ := json.Marshal(map[string]any{
		"previous_round_id":   prevRoundID,
		"new_round_id":        newRound.ID,
		"new_round_no":        newRound.RoundNo,
		"reason":              reason,
		"codebase_version":    codeVer,
		"environment_version": envVer,
		"reopened_from":       taskStatus,
	})
	var evID int64
	if err := tx.QueryRow(`
INSERT INTO task_assessment_events(task_id, round_id, event_type, payload)
VALUES ($1, $2, $3, $4::jsonb) RETURNING id`, taskID, newRound.ID, evType, string(evPayload)).Scan(&evID); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &ReopenRoundResult{
		PreviousRoundID: prevRoundID,
		NewRound:        newRound,
		EventID:         evID,
	}, nil
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return strings.TrimSpace(b)
}
