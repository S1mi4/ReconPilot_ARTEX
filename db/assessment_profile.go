package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// 画像断言确认状态（§4.2）。
const (
	ClaimStatusUnverified = "unverified"
	ClaimStatusConfirmed  = "confirmed"
	ClaimStatusConflicted = "conflicted"
	ClaimStatusUnknown    = "unknown"
)

var claimSourceTypes = map[string]struct{}{
	ClaimSourceUserDeclared:       {},
	ClaimSourceStaticExtraction:   {},
	ClaimSourceRuntimeObservation: {},
	ClaimSourceModelInference:     {},
}

var claimConfirmationStatuses = map[string]struct{}{
	ClaimStatusUnverified: {},
	ClaimStatusConfirmed:  {},
	ClaimStatusConflicted: {},
	ClaimStatusUnknown:    {},
}

var validTargetEntityTypes = map[string]struct{}{
	"service":             {},
	"module":              {},
	"shared_library":      {},
	"entry":               {},
	"config":              {},
	"instance":            {},
	"identity":            {},
	"business_object":     {},
	"protocol":            {},
	"external_dependency": {},
	"runtime_asset":       {},
}

var (
	ErrClaimSourceInvalid            = errors.New("invalid profile claim source_type")
	ErrClaimStatusInvalid            = errors.New("invalid profile claim confirmation_status")
	ErrInferenceCannotClaimConfirmed = errors.New("model_inference claims cannot be marked confirmed without independent verification")
	ErrRuntimeClaimEvidenceRequired  = errors.New("confirmed runtime_observation requires traffic, execution_output, or config evidence")
	ErrTargetEntityTypeInvalid       = errors.New("invalid target entity_type")
)

// IsValidClaimSourceType reports whether s is an allowed claim source_type.
func IsValidClaimSourceType(s string) bool {
	_, ok := claimSourceTypes[s]
	return ok
}

// IsValidClaimConfirmationStatus reports whether s is an allowed confirmation_status.
func IsValidClaimConfirmationStatus(s string) bool {
	_, ok := claimConfirmationStatuses[s]
	return ok
}

// IsValidTargetEntityType reports whether t matches the task_target_entities CHECK constraint.
func IsValidTargetEntityType(t string) bool {
	_, ok := validTargetEntityTypes[t]
	return ok
}

// EvidenceRef is one verifiable reference stored in task_evidence_refs (§9).
type EvidenceRef struct {
	ID        int64           `json:"id"`
	TaskID    int64           `json:"task_id"`
	Kind      string          `json:"kind"`
	Reference string          `json:"reference"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// ProfileClaim is one subject-relation-object assertion with provenance and
// confirmation/conflict state (§4.2).
type ProfileClaim struct {
	ID                 int64        `json:"id"`
	TaskID             int64        `json:"task_id"`
	RoundID            *int64       `json:"round_id,omitempty"`
	Subject            string       `json:"subject"`
	Relation           string       `json:"relation"`
	ObjectValue        string       `json:"object_value"`
	SourceType         string       `json:"source_type"`
	EvidenceRefID      *int64       `json:"evidence_ref_id,omitempty"`
	EvidenceRef        *EvidenceRef `json:"evidence_ref,omitempty"`
	ValidCodeVersion   string       `json:"valid_code_version"`
	Environment        string       `json:"environment"`
	ValidConfig        string       `json:"valid_config"`
	ConfirmationStatus string       `json:"confirmation_status"`
	ConflictNote       string       `json:"conflict_note"`
	ExecutionRef       string       `json:"execution_ref,omitempty"`
	CreatedAt          time.Time    `json:"created_at"`
}

// CreateProfileClaimInput creates a structured profile assertion in an open round.
type CreateProfileClaimInput struct {
	TaskID             int64
	RoundID            *int64
	Subject            string
	Relation           string
	ObjectValue        string
	SourceType         string
	EvidenceRefID      *int64
	ValidCodeVersion   string
	Environment        string
	ValidConfig        string
	ConfirmationStatus string
	ConflictNote       string
	ExecutionRef       string
}

// TargetEntityFilter filters target entities for a task/round.
type TargetEntityFilter struct {
	TaskID     int64
	RoundID    int64
	EntityType string
	CodebaseID string
	GapOnly    bool
	Limit      int
	Offset     int
}

// ProfileClaimFilter filters profile claims for a task/round.
type ProfileClaimFilter struct {
	TaskID             int64
	RoundID            int64
	Subject            string
	Relation           string
	SourceType         string
	ConfirmationStatus string
	ValidCodeVersion   string
	Environment        string
	Limit              int
	Offset             int
}

// AssessmentProfileSummary summarizes the round's target inventory and profile claims.
type AssessmentProfileSummary struct {
	RoundID             int64          `json:"round_id"`
	RoundNo             int            `json:"round_no"`
	ProfileVersion      int            `json:"profile_version"`
	ProfileBuiltAt      *time.Time     `json:"profile_built_at,omitempty"`
	InitialProfileReady bool           `json:"initial_profile_ready"`
	TotalEntities       int            `json:"total_entities"`
	EntityCounts        map[string]int `json:"entity_counts"`
	GapCount            int            `json:"gap_count"`
	UnresolvedGapCount  int            `json:"unresolved_gap_count"`
	TotalClaims         int            `json:"total_claims"`
	ClaimSourceCounts   map[string]int `json:"claim_source_counts"`
	ClaimStatusCounts   map[string]int `json:"claim_status_counts"`
	ConflictCount       int            `json:"conflict_count"`
	UnknownCount        int            `json:"unknown_count"`
	Languages           []string       `json:"languages"`
}

// ProfileContextSlice is a bounded, version-stamped profile slice for targeted
// downstream consumption (§9: 一次执行不应接收整个知识库).
type ProfileContextSlice struct {
	RoundID        int64          `json:"round_id"`
	RoundNo        int            `json:"round_no"`
	ProfileVersion int            `json:"profile_version"`
	Entities       []TargetEntity `json:"entities"`
	Claims         []ProfileClaim `json:"claims"`
	Conflicts      []ProfileClaim `json:"conflicts"`
	Unknowns       []ProfileClaim `json:"unknowns"`
	UnresolvedGaps []TargetEntity `json:"unresolved_gaps"`
}

var (
	jwtPattern            = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	secretAssignPattern   = regexp.MustCompile(`(?i)\b(password|passwd|secret|api_key|apikey|access_key|private_key|client_secret|jwt_secret)\b\s*[:=]\s*["']?([^\s"',;}{]{4,})["']?`)
	redactedTokenSentinel = regexp.MustCompile(`(?i)^(<redacted>|redacted|\*+|\$\{[^}]+\}|vault://.*|env:.*|secret://.*|kms://.*|ref://.*|true|false|null|none|required|optional)$`)
)

// rejectSecretInProfileText enforces §4.2: plaintext passwords, private keys,
// JWTs, and session tokens never enter ordinary profile text or entity rows.
func rejectSecretInProfileText(fields ...string) error {
	for _, s := range fields {
		if strings.TrimSpace(s) == "" {
			continue
		}
		if containsSecretMaterial(s) || jwtPattern.MatchString(s) {
			return ErrAssessmentSecretRejected
		}
		for _, m := range secretAssignPattern.FindAllStringSubmatch(s, -1) {
			if len(m) < 3 {
				continue
			}
			val := strings.TrimSpace(m[2])
			if val == "" || redactedTokenSentinel.MatchString(val) {
				continue
			}
			return ErrAssessmentSecretRejected
		}
	}
	return nil
}

// ValidateAssessmentTextSafe rejects plaintext passwords, tokens, JWTs, or
// private keys in free-form assessment text.
func ValidateAssessmentTextSafe(fields ...string) error {
	return rejectSecretInProfileText(fields...)
}

// GetOrCreateEvidenceRef returns an existing evidence ref with matching task,
// kind, reference, and payload, or creates a new one.
func (d *DB) GetOrCreateEvidenceRef(taskID int64, kind EvidenceRefKind, reference string, payload json.RawMessage) (int64, error) {
	ref := strings.TrimSpace(reference)
	if ref == "" {
		return 0, errors.New("evidence reference cannot be empty")
	}
	switch kind {
	case EvidenceCodeRange, EvidenceDecompiled, EvidenceTraffic,
		EvidenceExecution, EvidenceConfig, EvidenceManual:
	default:
		return 0, fmt.Errorf("invalid evidence kind %q", kind)
	}
	body := "{}"
	if len(payload) > 0 {
		body = string(payload)
	}
	var existingID int64
	err := d.QueryRow(`
SELECT id FROM task_evidence_refs
WHERE task_id=$1 AND kind=$2 AND reference=$3 AND payload=$4::jsonb
ORDER BY id DESC LIMIT 1`, taskID, string(kind), ref, body).Scan(&existingID)
	if err == nil && existingID > 0 {
		return existingID, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	return d.CreateEvidenceRef(taskID, kind, ref, json.RawMessage(body))
}

// ListEvidenceRefs returns evidence references for taskID, optionally filtered
// by explicit IDs or kind.
func (d *DB) ListEvidenceRefs(taskID int64, ids []int64, kind string) ([]EvidenceRef, error) {
	query := `SELECT id, task_id, kind, reference, payload, created_at FROM task_evidence_refs WHERE task_id=$1`
	args := []any{taskID}
	if kind != "" {
		args = append(args, kind)
		query += fmt.Sprintf(" AND kind=$%d", len(args))
	}
	if len(ids) > 0 {
		args = append(args, ids)
		query += fmt.Sprintf(" AND id = ANY($%d)", len(args))
	}
	query += ` ORDER BY id ASC LIMIT 500`

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]EvidenceRef, 0)
	for rows.Next() {
		var r EvidenceRef
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Kind, &r.Reference, scanJSONRaw(&r.Payload), &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertTargetEntity inserts a target entity or merges attributes on an existing
// identical entity in the same round. Existing gap=true flags are never silently cleared.
func (d *DB) UpsertTargetEntity(in CreateTargetEntityInput) (*TargetEntity, bool, error) {
	in.EntityType = strings.TrimSpace(in.EntityType)
	in.Name = strings.TrimSpace(in.Name)
	in.CodebaseID = strings.TrimSpace(in.CodebaseID)
	in.VersionID = strings.TrimSpace(in.VersionID)
	in.GapReason = strings.TrimSpace(in.GapReason)

	if in.RoundID == nil {
		return nil, false, errors.New("target entity must be bound to an assessment round")
	}
	if !IsValidTargetEntityType(in.EntityType) {
		return nil, false, fmt.Errorf("%w: %q", ErrTargetEntityTypeInvalid, in.EntityType)
	}
	if in.Name == "" {
		return nil, false, errors.New("target entity name cannot be empty")
	}
	if in.Gap && in.GapReason == "" {
		return nil, false, errors.New("target entity gap requires a reason")
	}
	attrs := "{}"
	if len(in.Attributes) > 0 {
		attrs = string(in.Attributes)
	}
	if err := rejectSecretInProfileText(in.Name, in.GapReason, attrs); err != nil {
		return nil, false, err
	}

	tx, err := d.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Serialize entity writes within the round so concurrent profiling/rebuild
	// calls cannot insert duplicate identical entities.
	var lockedRoundID int64
	if err := tx.QueryRow(`SELECT id FROM task_assessment_rounds WHERE id=$1 AND task_id=$2 FOR UPDATE`,
		*in.RoundID, in.TaskID).Scan(&lockedRoundID); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, ErrObligationOwnershipMismatch
		}
		return nil, false, err
	}

	var e TargetEntity
	err = tx.QueryRow(`
SELECT id, task_id, round_id, entity_type, name, asset_id, codebase_id, version_id,
       attributes, gap, gap_reason, resolved
FROM task_target_entities
WHERE task_id=$1 AND round_id=$2 AND entity_type=$3 AND name=$4
  AND codebase_id=$5 AND version_id=$6 AND gap=$7
ORDER BY id ASC LIMIT 1
FOR UPDATE`,
		in.TaskID, *in.RoundID, in.EntityType, in.Name, in.CodebaseID, in.VersionID, in.Gap).
		Scan(&e.ID, &e.TaskID, &e.RoundID, &e.EntityType, &e.Name, &e.AssetID, &e.CodebaseID,
			&e.VersionID, scanJSONRaw(&e.Attributes), &e.Gap, &e.GapReason, &e.Resolved)
	if err == nil {
		if err := tx.QueryRow(`
UPDATE task_target_entities
SET attributes = COALESCE(attributes, '{}'::jsonb) || $2::jsonb,
    asset_id   = COALESCE($3, asset_id)
WHERE id=$1
RETURNING id, task_id, round_id, entity_type, name, asset_id, codebase_id, version_id,
          attributes, gap, gap_reason, resolved`,
			e.ID, attrs, in.AssetID).
			Scan(&e.ID, &e.TaskID, &e.RoundID, &e.EntityType, &e.Name, &e.AssetID, &e.CodebaseID,
				&e.VersionID, scanJSONRaw(&e.Attributes), &e.Gap, &e.GapReason, &e.Resolved); err != nil {
			return nil, false, err
		}
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		return &e, false, nil
	}
	if err != sql.ErrNoRows {
		return nil, false, err
	}

	err = tx.QueryRow(`
INSERT INTO task_target_entities(task_id, round_id, entity_type, name, asset_id,
                                 codebase_id, version_id, attributes, gap, gap_reason, resolved)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11)
RETURNING id, task_id, round_id, entity_type, name, asset_id, codebase_id, version_id,
          attributes, gap, gap_reason, resolved`,
		in.TaskID, *in.RoundID, in.EntityType, in.Name, in.AssetID, in.CodebaseID, in.VersionID,
		attrs, in.Gap, in.GapReason, in.Resolved).
		Scan(&e.ID, &e.TaskID, &e.RoundID, &e.EntityType, &e.Name, &e.AssetID, &e.CodebaseID,
			&e.VersionID, scanJSONRaw(&e.Attributes), &e.Gap, &e.GapReason, &e.Resolved)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return &e, true, nil
}

// ListTargetEntities returns target entities matching the given filter.
func (d *DB) ListTargetEntities(f TargetEntityFilter) ([]TargetEntity, error) {
	query := `
SELECT id, task_id, round_id, entity_type, name, asset_id, codebase_id, version_id,
       attributes, gap, gap_reason, resolved
FROM task_target_entities
WHERE task_id=$1`
	args := []any{f.TaskID}
	if f.RoundID > 0 {
		args = append(args, f.RoundID)
		query += fmt.Sprintf(" AND round_id=$%d", len(args))
	}
	if f.EntityType != "" {
		args = append(args, f.EntityType)
		query += fmt.Sprintf(" AND entity_type=$%d", len(args))
	}
	if f.CodebaseID != "" {
		args = append(args, f.CodebaseID)
		query += fmt.Sprintf(" AND codebase_id=$%d", len(args))
	}
	if f.GapOnly {
		query += " AND gap"
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	offset := max(f.Offset, 0)
	args = append(args, limit, offset)
	query += fmt.Sprintf(" ORDER BY gap DESC, entity_type ASC, id ASC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]TargetEntity, 0)
	for rows.Next() {
		var e TargetEntity
		if err := rows.Scan(&e.ID, &e.TaskID, &e.RoundID, &e.EntityType, &e.Name, &e.AssetID,
			&e.CodebaseID, &e.VersionID, scanJSONRaw(&e.Attributes), &e.Gap, &e.GapReason, &e.Resolved); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ResolveTargetEntityGap marks a material/inventory gap entity as resolved with an explicit note.
func (d *DB) ResolveTargetEntityGap(taskID, entityID int64, resolutionNote string) error {
	note := strings.TrimSpace(resolutionNote)
	if note == "" {
		return errors.New("gap resolution requires a non-empty note")
	}
	if err := rejectSecretInProfileText(note); err != nil {
		return err
	}
	patch, _ := json.Marshal(map[string]any{"resolution_note": note, "resolved_at": time.Now().UTC()})
	res, err := d.Exec(`
UPDATE task_target_entities
SET resolved=true,
    attributes=COALESCE(attributes, '{}'::jsonb) || $3::jsonb
WHERE id=$1 AND task_id=$2 AND gap`, entityID, taskID, string(patch))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// isConflictCheckedRelation marks single-valued / policy / config relations where
// disagreeing assertions across sources or config files must be preserved as
// conflicted rather than overwriting each other (§4.2).
func isConflictCheckedRelation(relation string) bool {
	rel := strings.ToLower(strings.TrimSpace(relation))
	if strings.HasPrefix(rel, "config_value:") {
		return true
	}
	switch rel {
	case "auth_mechanism", "auth_required", "auth_enforcement",
		"server_port", "context_path", "tls_enabled", "cors_policy",
		"csrf_protection", "debug_mode", "database_engine", "session_store",
		"framework", "deployment_binding", "code_version_match":
		return true
	default:
		return false
	}
}

// CreateProfileClaim validates and persists one profile assertion. When an
// opposing non-unknown assertion already exists for a conflict-checked relation
// in the same round/environment scope, BOTH claims are preserved and marked
// conflicted, and a knowledge_conflict event is recorded in the same transaction.
func (d *DB) CreateProfileClaim(in CreateProfileClaimInput) (*ProfileClaim, bool, error) {
	in.Subject = strings.TrimSpace(in.Subject)
	in.Relation = strings.TrimSpace(in.Relation)
	in.ObjectValue = strings.TrimSpace(in.ObjectValue)
	in.SourceType = strings.TrimSpace(in.SourceType)
	in.ValidCodeVersion = strings.TrimSpace(in.ValidCodeVersion)
	in.Environment = strings.TrimSpace(in.Environment)
	in.ValidConfig = strings.TrimSpace(in.ValidConfig)
	in.ConfirmationStatus = strings.TrimSpace(in.ConfirmationStatus)
	in.ConflictNote = strings.TrimSpace(in.ConflictNote)
	in.ExecutionRef = strings.TrimSpace(in.ExecutionRef)

	if in.RoundID == nil {
		return nil, false, errors.New("profile claim must be bound to an assessment round")
	}
	if in.Subject == "" || in.Relation == "" {
		return nil, false, errors.New("profile claim subject and relation are required")
	}
	if !IsValidClaimSourceType(in.SourceType) {
		return nil, false, fmt.Errorf("%w: %q", ErrClaimSourceInvalid, in.SourceType)
	}
	if in.ConfirmationStatus == "" {
		if in.ObjectValue == "" {
			in.ConfirmationStatus = ClaimStatusUnknown
		} else {
			in.ConfirmationStatus = ClaimStatusUnverified
		}
	}
	if !IsValidClaimConfirmationStatus(in.ConfirmationStatus) {
		return nil, false, fmt.Errorf("%w: %q", ErrClaimStatusInvalid, in.ConfirmationStatus)
	}
	// 推断不冒充运行事实：model_inference 绝不能直接标为 confirmed。
	if in.SourceType == ClaimSourceModelInference && in.ConfirmationStatus == ClaimStatusConfirmed {
		return nil, false, ErrInferenceCannotClaimConfirmed
	}
	if err := rejectSecretInProfileText(in.Subject, in.ObjectValue, in.ConflictNote, in.ValidConfig); err != nil {
		return nil, false, err
	}

	tx, err := d.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Serialize claim writes within the round so concurrent profiling/rebuild
	// calls cannot duplicate identical claims or miss mutual conflict updates.
	var lockedRoundID int64
	if err := tx.QueryRow(`SELECT id FROM task_assessment_rounds WHERE id=$1 AND task_id=$2 FOR UPDATE`,
		*in.RoundID, in.TaskID).Scan(&lockedRoundID); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, ErrObligationOwnershipMismatch
		}
		return nil, false, err
	}

	var evidence *EvidenceRef
	if in.EvidenceRefID != nil {
		var ref EvidenceRef
		err := tx.QueryRow(`
SELECT id, task_id, kind, reference, payload, created_at
FROM task_evidence_refs WHERE id=$1`, *in.EvidenceRefID).
			Scan(&ref.ID, &ref.TaskID, &ref.Kind, &ref.Reference, scanJSONRaw(&ref.Payload), &ref.CreatedAt)
		if err == sql.ErrNoRows || (err == nil && ref.TaskID != in.TaskID) {
			return nil, false, ErrObligationOwnershipMismatch
		}
		if err != nil {
			return nil, false, err
		}
		evidence = &ref
	}
	if in.SourceType == ClaimSourceRuntimeObservation && in.ConfirmationStatus == ClaimStatusConfirmed {
		if evidence == nil {
			return nil, false, ErrRuntimeClaimEvidenceRequired
		}
		switch EvidenceRefKind(evidence.Kind) {
		case EvidenceTraffic, EvidenceExecution, EvidenceConfig:
		default:
			return nil, false, ErrRuntimeClaimEvidenceRequired
		}
	}

	// Idempotent check for identical claim within the round.
	var existing ProfileClaim
	err = tx.QueryRow(`
SELECT id, task_id, round_id, subject, relation, object_value, source_type, evidence_ref_id,
       valid_code_version, environment, valid_config, confirmation_status, conflict_note, execution_ref, created_at
FROM task_profile_claims
WHERE task_id=$1 AND round_id=$2 AND subject=$3 AND relation=$4 AND object_value=$5
  AND source_type=$6 AND valid_code_version=$7 AND environment=$8 AND valid_config=$9
ORDER BY id ASC LIMIT 1`,
		in.TaskID, *in.RoundID, in.Subject, in.Relation, in.ObjectValue, in.SourceType,
		in.ValidCodeVersion, in.Environment, in.ValidConfig).
		Scan(&existing.ID, &existing.TaskID, &existing.RoundID, &existing.Subject, &existing.Relation,
			&existing.ObjectValue, &existing.SourceType, &existing.EvidenceRefID,
			&existing.ValidCodeVersion, &existing.Environment, &existing.ValidConfig,
			&existing.ConfirmationStatus, &existing.ConflictNote, &existing.ExecutionRef, &existing.CreatedAt)
	if err == nil {
		if existing.EvidenceRefID != nil {
			existing.EvidenceRef = loadEvidenceRefTx(tx, *existing.EvidenceRefID)
		}
		return &existing, false, nil
	}
	if err != sql.ErrNoRows {
		return nil, false, err
	}

	type opposingRow struct {
		ID           int64
		ObjectValue  string
		SourceType   string
		Environment  string
		ValidConfig  string
		ConflictNote string
	}
	var opposing []opposingRow
	if isConflictCheckedRelation(in.Relation) && in.ConfirmationStatus != ClaimStatusUnknown && in.ObjectValue != "" {
		rows, qErr := tx.Query(`
SELECT id, object_value, source_type, environment, valid_config, conflict_note
FROM task_profile_claims
WHERE task_id=$1 AND round_id=$2 AND subject=$3 AND relation=$4
  AND confirmation_status <> 'unknown'
  AND btrim(object_value) <> ''
  AND lower(btrim(object_value)) <> lower(btrim($5))
  AND (environment = '' OR $6 = '' OR environment = $6)
ORDER BY id ASC
FOR UPDATE`, in.TaskID, *in.RoundID, in.Subject, in.Relation, in.ObjectValue, in.Environment)
		if qErr != nil {
			return nil, false, qErr
		}
		for rows.Next() {
			var r opposingRow
			if sErr := rows.Scan(&r.ID, &r.ObjectValue, &r.SourceType, &r.Environment, &r.ValidConfig, &r.ConflictNote); sErr != nil {
				rows.Close()
				return nil, false, sErr
			}
			opposing = append(opposing, r)
		}
		if rErr := rows.Err(); rErr != nil {
			rows.Close()
			return nil, false, rErr
		}
		rows.Close()
	}

	status := in.ConfirmationStatus
	conflictNote := in.ConflictNote
	if len(opposing) > 0 {
		status = ClaimStatusConflicted
		var parts []string
		for _, op := range opposing {
			desc := fmt.Sprintf("#%d=%q(%s", op.ID, op.ObjectValue, op.SourceType)
			if op.ValidConfig != "" {
				desc += ":" + op.ValidConfig
			} else if op.Environment != "" {
				desc += "@" + op.Environment
			}
			desc += ")"
			parts = append(parts, desc)
		}
		autoNote := fmt.Sprintf("与已有断言冲突：%s", strings.Join(parts, "，"))
		if conflictNote == "" {
			conflictNote = autoNote
		} else {
			conflictNote = conflictNote + "；" + autoNote
		}
	}

	var created ProfileClaim
	err = tx.QueryRow(`
INSERT INTO task_profile_claims(task_id, round_id, subject, relation, object_value, source_type,
                                evidence_ref_id, valid_code_version, environment, valid_config,
                                confirmation_status, conflict_note, execution_ref)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
RETURNING id, task_id, round_id, subject, relation, object_value, source_type, evidence_ref_id,
          valid_code_version, environment, valid_config, confirmation_status, conflict_note, execution_ref, created_at`,
		in.TaskID, *in.RoundID, in.Subject, in.Relation, in.ObjectValue, in.SourceType,
		in.EvidenceRefID, in.ValidCodeVersion, in.Environment, in.ValidConfig,
		status, conflictNote, in.ExecutionRef).
		Scan(&created.ID, &created.TaskID, &created.RoundID, &created.Subject, &created.Relation,
			&created.ObjectValue, &created.SourceType, &created.EvidenceRefID,
			&created.ValidCodeVersion, &created.Environment, &created.ValidConfig,
			&created.ConfirmationStatus, &created.ConflictNote, &created.ExecutionRef, &created.CreatedAt)
	if err != nil {
		return nil, false, err
	}
	created.EvidenceRef = evidence

	if len(opposing) > 0 {
		newDesc := fmt.Sprintf("#%d=%q(%s", created.ID, created.ObjectValue, created.SourceType)
		if created.ValidConfig != "" {
			newDesc += ":" + created.ValidConfig
		} else if created.Environment != "" {
			newDesc += "@" + created.Environment
		}
		newDesc += ")"
		claimIDs := make([]int64, 0, len(opposing)+1)
		values := []string{created.ObjectValue}
		sources := []string{created.SourceType}
		for _, op := range opposing {
			claimIDs = append(claimIDs, op.ID)
			values = append(values, op.ObjectValue)
			sources = append(sources, op.SourceType)
			nextNote := strings.TrimSpace(op.ConflictNote)
			msg := "与断言冲突：" + newDesc
			if nextNote == "" {
				nextNote = msg
			} else if !strings.Contains(nextNote, fmt.Sprintf("#%d=", created.ID)) {
				nextNote = nextNote + "；" + msg
			}
			if _, uErr := tx.Exec(`
UPDATE task_profile_claims SET confirmation_status='conflicted', conflict_note=$2 WHERE id=$1`,
				op.ID, nextNote); uErr != nil {
				return nil, false, uErr
			}
		}
		claimIDs = append(claimIDs, created.ID)
		payload, _ := json.Marshal(map[string]any{
			"subject":   created.Subject,
			"relation":  created.Relation,
			"claim_ids": claimIDs,
			"values":    values,
			"sources":   sources,
		})
		if _, eErr := tx.Exec(`
INSERT INTO task_assessment_events(task_id, round_id, event_type, payload)
VALUES ($1,$2,'knowledge_conflict',$3::jsonb)`, in.TaskID, *in.RoundID, string(payload)); eErr != nil {
			return nil, false, eErr
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return &created, true, nil
}

func loadEvidenceRefTx(tx *sql.Tx, id int64) *EvidenceRef {
	var r EvidenceRef
	if err := tx.QueryRow(`SELECT id, task_id, kind, reference, payload, created_at FROM task_evidence_refs WHERE id=$1`, id).
		Scan(&r.ID, &r.TaskID, &r.Kind, &r.Reference, scanJSONRaw(&r.Payload), &r.CreatedAt); err != nil {
		return nil
	}
	return &r
}

// ListProfileClaims returns claims with hydrated EvidenceRef matching the filter.
func (d *DB) ListProfileClaims(f ProfileClaimFilter) ([]ProfileClaim, error) {
	query := `
SELECT c.id, c.task_id, c.round_id, c.subject, c.relation, c.object_value, c.source_type,
       c.evidence_ref_id, c.valid_code_version, c.environment, c.valid_config,
       c.confirmation_status, c.conflict_note, c.execution_ref, c.created_at,
       e.id, e.task_id, e.kind, e.reference, e.payload, e.created_at
FROM task_profile_claims c
LEFT JOIN task_evidence_refs e ON e.id = c.evidence_ref_id
WHERE c.task_id=$1`
	args := []any{f.TaskID}
	if f.RoundID > 0 {
		args = append(args, f.RoundID)
		query += fmt.Sprintf(" AND c.round_id=$%d", len(args))
	}
	if f.Subject != "" {
		args = append(args, f.Subject)
		query += fmt.Sprintf(" AND c.subject=$%d", len(args))
	}
	if f.Relation != "" {
		args = append(args, f.Relation)
		query += fmt.Sprintf(" AND c.relation=$%d", len(args))
	}
	if f.SourceType != "" {
		args = append(args, f.SourceType)
		query += fmt.Sprintf(" AND c.source_type=$%d", len(args))
	}
	if f.ConfirmationStatus != "" {
		args = append(args, f.ConfirmationStatus)
		query += fmt.Sprintf(" AND c.confirmation_status=$%d", len(args))
	}
	if f.ValidCodeVersion != "" {
		args = append(args, f.ValidCodeVersion)
		query += fmt.Sprintf(" AND c.valid_code_version=$%d", len(args))
	}
	if f.Environment != "" {
		args = append(args, f.Environment)
		query += fmt.Sprintf(" AND c.environment=$%d", len(args))
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	offset := max(f.Offset, 0)
	args = append(args, limit, offset)
	query += fmt.Sprintf(`
ORDER BY CASE c.confirmation_status
             WHEN 'conflicted' THEN 0
             WHEN 'unknown' THEN 1
             WHEN 'unverified' THEN 2
             ELSE 3
         END ASC,
         c.id ASC
LIMIT $%d OFFSET $%d`, len(args)-1, len(args))

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ProfileClaim, 0)
	for rows.Next() {
		var c ProfileClaim
		var (
			evID      sql.NullInt64
			evTaskID  sql.NullInt64
			evKind    sql.NullString
			evRef     sql.NullString
			evPayload []byte
			evCreated sql.NullTime
		)
		if err := rows.Scan(&c.ID, &c.TaskID, &c.RoundID, &c.Subject, &c.Relation, &c.ObjectValue, &c.SourceType,
			&c.EvidenceRefID, &c.ValidCodeVersion, &c.Environment, &c.ValidConfig,
			&c.ConfirmationStatus, &c.ConflictNote, &c.ExecutionRef, &c.CreatedAt,
			&evID, &evTaskID, &evKind, &evRef, &evPayload, &evCreated); err != nil {
			return nil, err
		}
		if evID.Valid {
			ref := &EvidenceRef{
				ID:        evID.Int64,
				TaskID:    evTaskID.Int64,
				Kind:      evKind.String,
				Reference: evRef.String,
			}
			if len(evPayload) > 0 {
				ref.Payload = json.RawMessage(evPayload)
			}
			if evCreated.Valid {
				ref.CreatedAt = evCreated.Time
			}
			c.EvidenceRef = ref
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// BumpAssessmentProfileVersion increments profile_version on the round and
// stamps profile_built_at when first built.
func (d *DB) BumpAssessmentProfileVersion(taskID, roundID int64) (int, error) {
	var ver int
	err := d.QueryRow(`
UPDATE task_assessment_rounds
SET profile_version = profile_version + 1,
    profile_built_at = COALESCE(profile_built_at, now())
WHERE id=$2 AND task_id=$1
RETURNING profile_version`, taskID, roundID).Scan(&ver)
	return ver, err
}

// GetAssessmentProfileSummary computes structured counts and detected languages
// for the given task and round.
func (d *DB) GetAssessmentProfileSummary(taskID, roundID int64) (*AssessmentProfileSummary, error) {
	round, err := scanAssessmentRound(d.QueryRow(`
SELECT `+assessmentRoundCols+` FROM task_assessment_rounds WHERE id=$1 AND task_id=$2`, roundID, taskID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	summary := &AssessmentProfileSummary{
		RoundID:           round.ID,
		RoundNo:           round.RoundNo,
		ProfileVersion:    round.ProfileVersion,
		ProfileBuiltAt:    round.ProfileBuiltAt,
		EntityCounts:      map[string]int{},
		ClaimSourceCounts: map[string]int{},
		ClaimStatusCounts: map[string]int{},
		Languages:         []string{},
	}

	eRows, err := d.Query(`
SELECT entity_type, gap, resolved, count(*)
FROM task_target_entities
WHERE task_id=$1 AND round_id=$2
GROUP BY entity_type, gap, resolved`, taskID, roundID)
	if err != nil {
		return nil, err
	}
	defer eRows.Close()
	for eRows.Next() {
		var etype string
		var gap, resolved bool
		var cnt int
		if err := eRows.Scan(&etype, &gap, &resolved, &cnt); err != nil {
			return nil, err
		}
		if gap {
			summary.GapCount += cnt
			if !resolved {
				summary.UnresolvedGapCount += cnt
			}
		} else {
			summary.TotalEntities += cnt
			summary.EntityCounts[etype] += cnt
		}
	}
	if err := eRows.Err(); err != nil {
		return nil, err
	}

	cRows, err := d.Query(`
SELECT source_type, confirmation_status, count(*)
FROM task_profile_claims
WHERE task_id=$1 AND round_id=$2
GROUP BY source_type, confirmation_status`, taskID, roundID)
	if err != nil {
		return nil, err
	}
	defer cRows.Close()
	for cRows.Next() {
		var src, st string
		var cnt int
		if err := cRows.Scan(&src, &st, &cnt); err != nil {
			return nil, err
		}
		summary.TotalClaims += cnt
		summary.ClaimSourceCounts[src] += cnt
		summary.ClaimStatusCounts[st] += cnt
		if st == ClaimStatusConflicted {
			summary.ConflictCount += cnt
		}
		if st == ClaimStatusUnknown {
			summary.UnknownCount += cnt
		}
	}
	if err := cRows.Err(); err != nil {
		return nil, err
	}

	langSet := map[string]bool{}
	lRows, err := d.Query(`
SELECT DISTINCT lower(btrim(lang))
FROM task_target_entities e,
     jsonb_array_elements_text(COALESCE(e.attributes->'languages', '[]'::jsonb)) AS lang
WHERE e.task_id=$1 AND e.round_id=$2 AND NOT e.gap`, taskID, roundID)
	if err != nil {
		return nil, err
	}
	defer lRows.Close()
	for lRows.Next() {
		var lang string
		if err := lRows.Scan(&lang); err != nil {
			return nil, err
		}
		if lang != "" && lang != "unknown" {
			langSet[lang] = true
		}
	}
	if err := lRows.Err(); err != nil {
		return nil, err
	}
	lcRows, err := d.Query(`
SELECT DISTINCT lower(btrim(object_value))
FROM task_profile_claims
WHERE task_id=$1 AND round_id=$2 AND relation='uses_language' AND btrim(object_value) <> ''`,
		taskID, roundID)
	if err != nil {
		return nil, err
	}
	defer lcRows.Close()
	for lcRows.Next() {
		var lang string
		if err := lcRows.Scan(&lang); err != nil {
			return nil, err
		}
		if lang != "" && lang != "unknown" {
			langSet[lang] = true
		}
	}
	if err := lcRows.Err(); err != nil {
		return nil, err
	}

	for lang := range langSet {
		summary.Languages = append(summary.Languages, lang)
	}
	sort.Strings(summary.Languages)
	summary.InitialProfileReady = summary.ProfileVersion > 0 && summary.TotalEntities > 0
	return summary, nil
}

// QueryProfileContext returns a bounded, targeted profile slice bound to the
// current round's profile_version so downstream agents never ingest the entire
// knowledge base on every execution (§9).
func (d *DB) QueryProfileContext(taskID, roundID int64, subjects []string, limit int) (*ProfileContextSlice, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	round, err := scanAssessmentRound(d.QueryRow(`
SELECT `+assessmentRoundCols+` FROM task_assessment_rounds WHERE id=$1 AND task_id=$2`, roundID, taskID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	slice := &ProfileContextSlice{
		RoundID:        round.ID,
		RoundNo:        round.RoundNo,
		ProfileVersion: round.ProfileVersion,
		Entities:       []TargetEntity{},
		Claims:         []ProfileClaim{},
		Conflicts:      []ProfileClaim{},
		Unknowns:       []ProfileClaim{},
		UnresolvedGaps: []TargetEntity{},
	}

	allEntities, err := d.ListTargetEntities(TargetEntityFilter{TaskID: taskID, RoundID: roundID, Limit: 500})
	if err != nil {
		return nil, err
	}
	cleanSubs := make([]string, 0, len(subjects))
	subSet := map[string]bool{}
	for _, s := range subjects {
		s = strings.TrimSpace(s)
		if s == "" || subSet[s] {
			continue
		}
		subSet[s] = true
		cleanSubs = append(cleanSubs, s)
	}

	for _, e := range allEntities {
		if e.Gap && !e.Resolved {
			if len(slice.UnresolvedGaps) < limit {
				slice.UnresolvedGaps = append(slice.UnresolvedGaps, e)
			}
			continue
		}
		if len(slice.Entities) >= limit {
			continue
		}
		if len(cleanSubs) == 0 || matchesAnySubject(e.Name, cleanSubs) ||
			e.EntityType == "instance" || e.EntityType == "identity" ||
			e.EntityType == "service" || e.EntityType == "shared_library" {
			slice.Entities = append(slice.Entities, e)
		}
	}

	conflicts, err := d.ListProfileClaims(ProfileClaimFilter{
		TaskID: taskID, RoundID: roundID, ConfirmationStatus: ClaimStatusConflicted, Limit: limit,
	})
	if err != nil {
		return nil, err
	}
	slice.Conflicts = conflicts

	unknowns, err := d.ListProfileClaims(ProfileClaimFilter{
		TaskID: taskID, RoundID: roundID, ConfirmationStatus: ClaimStatusUnknown, Limit: limit,
	})
	if err != nil {
		return nil, err
	}
	slice.Unknowns = unknowns

	allClaims, err := d.ListProfileClaims(ProfileClaimFilter{TaskID: taskID, RoundID: roundID, Limit: 500})
	if err != nil {
		return nil, err
	}
	for _, c := range allClaims {
		if len(slice.Claims) >= limit {
			break
		}
		if len(cleanSubs) == 0 || subSet[c.Subject] || c.Subject == "task" || matchesAnySubject(c.Subject, cleanSubs) {
			slice.Claims = append(slice.Claims, c)
		}
	}
	return slice, nil
}

func matchesAnySubject(candidate string, subjects []string) bool {
	lowerCand := strings.ToLower(strings.TrimSpace(candidate))
	for _, sub := range subjects {
		lowerSub := strings.ToLower(sub)
		if lowerCand == lowerSub || strings.Contains(lowerSub, lowerCand) || strings.Contains(lowerCand, lowerSub) {
			return true
		}
	}
	return false
}
