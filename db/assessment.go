package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 白盒驱动测试转型的领域定义与程序完成判定契约。
// 设计文档：docs/whitebox-driven-assessment-design.md（§3.3 阶段、§5 覆盖义务、
// §6 状态/覆盖计算/完成判定、§9 数据模型）。
//
// 本文件只定义领域词汇、存储操作和"任务能否被判为全覆盖完成"的程序判定。
// 契约对 assessment_mode=true 的任务由引擎在结束路径上调用；传统任务
// （assessment_mode=false）不经过本契约，行为保持不变。

// ---------- 评估阶段（§3.3；与运行状态分离） ----------

const (
	// AssessmentPhaseNone 表示未启用评估阶段（传统模式任务或未启动的新模式任务）。
	AssessmentPhaseNone = ""
	// 1. 材料检查：启动前确认文件可读、可解包、清单可建立、存在有效审计对象。
	AssessmentPhaseMaterialCheck = "material_check"
	// 2. 画像构建：确定性清点 + 结构提取 + Agent 关联 + 环境核实，形成初始版本。
	AssessmentPhaseProfiling = "profiling"
	// 3. 覆盖规划：从清单与画像生成本轮覆盖义务与前置依赖。
	AssessmentPhaseCoveragePlanning = "coverage_planning"
	// 4. 执行与探索：白盒审计与动态测试按计划推进，持续补充画像。
	AssessmentPhaseExecuting = "executing"
	// 5. 收尾对账：跨模块收尾检查、证据对账、完成判定。
	AssessmentPhaseReconciliation = "reconciliation"
	// 6. 完成：全部必需义务满足且完成判定通过。
	AssessmentPhaseCompleted = "completed"
)

var assessmentPhases = map[string]struct{}{
	AssessmentPhaseNone:             {},
	AssessmentPhaseMaterialCheck:    {},
	AssessmentPhaseProfiling:        {},
	AssessmentPhaseCoveragePlanning: {},
	AssessmentPhaseExecuting:        {},
	AssessmentPhaseReconciliation:   {},
	AssessmentPhaseCompleted:        {},
}

// IsValidAssessmentPhase reports whether phase is a known assessment phase.
func IsValidAssessmentPhase(phase string) bool {
	_, ok := assessmentPhases[phase]
	return ok
}

// ---------- 覆盖义务状态（§6.1） ----------

const (
	// ObligationPending：尚未就绪（前置依赖未满足或计划刚生成）。
	ObligationPending = "pending"
	// ObligationReady：前置依赖已满足，可派发执行。
	ObligationReady = "ready"
	// ObligationRunning：正在执行。
	ObligationRunning = "running"
	// ObligationSatisfied：完成规定检查；可以发现漏洞，也可以没有发现问题。
	ObligationSatisfied = "satisfied"
	// ObligationBlocked：前提缺失、环境不可达等；不计入已覆盖。
	ObligationBlocked = "blocked"
	// ObligationStale：材料、环境或关键画像变化，原有证据不再适用。
	ObligationStale = "stale"
	// ObligationNotApplicable：有可审计的不适用依据；不能由 Agent 为提高覆盖率任意设置。
	ObligationNotApplicable = "not_applicable"
)

var obligationStatuses = map[string]struct{}{
	ObligationPending: {}, ObligationReady: {}, ObligationRunning: {},
	ObligationSatisfied: {}, ObligationBlocked: {}, ObligationStale: {},
	ObligationNotApplicable: {},
}

// IsValidObligationStatus reports whether status is a known obligation status.
func IsValidObligationStatus(status string) bool {
	_, ok := obligationStatuses[status]
	return ok
}

// obligationStatusNeedsReason 列出必须携带 reason 的终态：不适用要有可审计依据，
// 阻塞/失效要能解释为什么证据不再适用（§6.1）。
func obligationStatusNeedsReason(status string) bool {
	return status == ObligationNotApplicable || status == ObligationBlocked || status == ObligationStale
}

// ---------- 覆盖维度（§5.3 第一版） ----------

const (
	DimensionCodeAudit        = "code_audit"        // 自研模块、生产文件、Java 应用类
	DimensionConfigAudit      = "config_audit"      // 安全配置、部署配置、协议映射
	DimensionEntryTest        = "entry_test"        // HTTP、RPC、消息消费者、任务入口
	DimensionIdentityResource = "identity_resource" // 角色、租户、对象归属、业务状态
	DimensionCrossModule      = "cross_module"      // 服务调用、回调、消息、协议转换
	DimensionRuntimeAsset     = "runtime_asset"     // 范围内网关、实例、数据库等
	DimensionHypothesis       = "hypothesis"        // 静态候选、动态异常、配置冲突
)

var coverageDimensions = map[string]struct{}{
	DimensionCodeAudit: {}, DimensionConfigAudit: {}, DimensionEntryTest: {},
	DimensionIdentityResource: {}, DimensionCrossModule: {}, DimensionRuntimeAsset: {},
	DimensionHypothesis: {},
}

// IsValidCoverageDimension reports whether dimension is a known coverage dimension.
func IsValidCoverageDimension(dimension string) bool {
	_, ok := coverageDimensions[dimension]
	return ok
}

// executionDimensions 列出必须通过实际执行（而非纯静态证据）才能满足的维度：
// 入口测试、身份与资源关系、跨模块链路需要可执行的运行证据（§5.3）。
var executionDimensions = map[string]struct{}{
	DimensionEntryTest: {}, DimensionIdentityResource: {}, DimensionCrossModule: {},
}

// ---------- 尝试结果分类（§7.2） ----------

const (
	AttemptSupported         = "supported"          // 支持假设
	AttemptDisproved         = "disproved"          // 反证
	AttemptUnreproduced      = "unreproduced"       // 未复现（不等于漏洞不存在/已修复）
	AttemptEnvMismatch       = "env_mismatch"       // 环境不匹配
	AttemptDependencyMissing = "dependency_missing" // 依赖缺失
	AttemptFailed            = "failed"             // 执行失败
)

var attemptOutcomes = map[string]struct{}{
	AttemptSupported: {}, AttemptDisproved: {}, AttemptUnreproduced: {},
	AttemptEnvMismatch: {}, AttemptDependencyMissing: {}, AttemptFailed: {},
}

// IsValidAttemptOutcome reports whether outcome is a known attempt outcome.
func IsValidAttemptOutcome(outcome string) bool {
	_, ok := attemptOutcomes[outcome]
	return ok
}

// effectiveAttemptOutcomes 是"有依据的处置"：可以支撑义务满足的尝试结果。
// env_mismatch/dependency_missing/failed 是执行失败类，不等于已覆盖（§6.1/§7.2）。
var effectiveAttemptOutcomes = map[string]struct{}{
	AttemptSupported: {}, AttemptDisproved: {}, AttemptUnreproduced: {},
}

// ---------- 画像断言来源（§4.2） ----------

const (
	ClaimSourceUserDeclared       = "user_declared"
	ClaimSourceStaticExtraction   = "static_extraction"
	ClaimSourceRuntimeObservation = "runtime_observation"
	ClaimSourceModelInference     = "model_inference"
)

// ---------- 错误 ----------

var (
	ErrAssessmentPhaseInvalid     = errors.New("invalid assessment phase")
	ErrObligationStatusInvalid    = errors.New("invalid obligation status")
	ErrObligationDimensionInvalid = errors.New("invalid coverage dimension")
	ErrAttemptOutcomeInvalid      = errors.New("invalid attempt outcome")
	// ErrObligationStateConflict 表示 CAS 状态推进落空（状态已被并发修改）。
	ErrObligationStateConflict = errors.New("obligation state conflict")
	// ErrObligationEvidenceMissing 表示不满足"证据要求"的终态推进被拒绝。
	ErrObligationEvidenceMissing = errors.New("obligation terminal state requires evidence or reason")
	// ErrObligationCredentialsMissing 表示需要凭证的义务未绑定凭证引用。
	ErrObligationCredentialsMissing = errors.New("obligation requires credentials but none is bound")
	// ErrObligationOwnershipMismatch 表示证据/尝试引用了不属于本任务（或本项目）的记录。
	ErrObligationOwnershipMismatch = errors.New("referenced record does not belong to this task")
)

// ---------- 评估轮次 ----------

// AssessmentRound is one assessment round of a task (§6.4/§9).
type AssessmentRound struct {
	ID                 int64           `json:"id"`
	TaskID             int64           `json:"task_id"`
	RoundNo            int             `json:"round_no"`
	CodebaseVersion    string          `json:"codebase_version"`
	EnvironmentVersion string          `json:"environment_version"`
	ScopeVersion       string          `json:"scope_version"`
	StandardVersion    string          `json:"standard_version"`
	Status             string          `json:"status"`
	ProfileVersion     int             `json:"profile_version"`
	ProfileBuiltAt     *time.Time      `json:"profile_built_at,omitempty"`
	CompletionReport   json.RawMessage `json:"completion_report,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	CompletedAt        *time.Time      `json:"completed_at,omitempty"`
}

const assessmentRoundCols = `id, task_id, round_no, codebase_version, environment_version, scope_version,
       standard_version, status, profile_version, profile_built_at, completion_report, created_at, completed_at`

// CreateAssessmentRound opens round_no = max(existing)+1 for the task.
func (d *DB) CreateAssessmentRound(taskID int64) (*AssessmentRound, error) {
	round, err := scanAssessmentRound(d.QueryRow(`
INSERT INTO task_assessment_rounds(task_id, round_no)
VALUES ($1, COALESCE((SELECT max(round_no) FROM task_assessment_rounds WHERE task_id=$1), 0) + 1)
RETURNING `+assessmentRoundCols, taskID))
	if err != nil {
		return nil, err
	}
	return round, nil
}

// OpenAssessmentRound returns the task's current open round (nil if none).
// 完成判定、义务生成、尝试写入都以当前 open 轮次为界；历史轮次保持原有范围和结果。
func (d *DB) OpenAssessmentRound(taskID int64) (*AssessmentRound, error) {
	round, err := scanAssessmentRound(d.QueryRow(`
SELECT `+assessmentRoundCols+`
FROM task_assessment_rounds
WHERE task_id=$1 AND status='open'
ORDER BY round_no DESC LIMIT 1`, taskID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return round, nil
}

// LatestAssessmentRound returns the current open round if any, otherwise the
// most recent round (e.g. for viewing completed or archived tasks).
func (d *DB) LatestAssessmentRound(taskID int64) (*AssessmentRound, error) {
	round, err := scanAssessmentRound(d.QueryRow(`
SELECT `+assessmentRoundCols+`
FROM task_assessment_rounds
WHERE task_id=$1
ORDER BY (status='open') DESC, round_no DESC LIMIT 1`, taskID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return round, nil
}

// CompleteAssessmentRound closes an open round with the program-generated
// completion report (version/scope/standard snapshot of this round, §6.3-7).
func (d *DB) CompleteAssessmentRound(taskID, roundID int64, report json.RawMessage) error {
	result, err := d.Exec(`
UPDATE task_assessment_rounds
SET status='completed', completion_report=$3, completed_at=now()
WHERE id=$2 AND task_id=$1 AND status='open'`, taskID, roundID, string(report))
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrObligationStateConflict
	}
	return nil
}

func scanAssessmentRound(sc interface{ Scan(...any) error }) (*AssessmentRound, error) {
	var r AssessmentRound
	var report []byte
	if err := sc.Scan(&r.ID, &r.TaskID, &r.RoundNo, &r.CodebaseVersion, &r.EnvironmentVersion,
		&r.ScopeVersion, &r.StandardVersion, &r.Status, &r.ProfileVersion, &r.ProfileBuiltAt,
		&report, &r.CreatedAt, &r.CompletedAt); err != nil {
		return nil, err
	}
	if len(report) > 0 {
		r.CompletionReport = json.RawMessage(report)
	}
	return &r, nil
}

// ---------- 阶段写入 ----------

// SetAssessmentPhase persists the task's assessment phase. It refuses unknown
// phases (values are fixed by the design document, §3.3).
func (d *DB) SetAssessmentPhase(taskID int64, phase string) error {
	if !IsValidAssessmentPhase(phase) {
		return fmt.Errorf("%w: %q", ErrAssessmentPhaseInvalid, phase)
	}
	_, err := d.Exec(`UPDATE tasks SET assessment_phase=$2 WHERE id=$1`, taskID, phase)
	return err
}

// ---------- 证据引用 ----------

// CreateEvidenceRef records one evidence reference (code range, decompiled
// source, traffic, execution output, config, manual note) and returns its id.
// 画像断言、覆盖义务与测试尝试都只存这里的引用；正文进 payload。
type EvidenceRefKind string

const (
	EvidenceCodeRange  EvidenceRefKind = "code_range"
	EvidenceDecompiled EvidenceRefKind = "decompiled"
	EvidenceTraffic    EvidenceRefKind = "traffic"
	EvidenceExecution  EvidenceRefKind = "execution_output"
	EvidenceConfig     EvidenceRefKind = "config"
	EvidenceManual     EvidenceRefKind = "manual"
)

func (d *DB) CreateEvidenceRef(taskID int64, kind EvidenceRefKind, reference string, payload json.RawMessage) (int64, error) {
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
	var id int64
	if err := d.QueryRow(`
INSERT INTO task_evidence_refs(task_id, kind, reference, payload)
VALUES ($1,$2,$3,$4::jsonb) RETURNING id`, taskID, string(kind), reference, body).
		Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// ---------- 目标实体与清单缺口 ----------

// TargetEntity is an auditable object of the current round (module, service,
// shared library, entry, identity, ...). It reuses the existing asset id when
// one exists — the asset graph stays the single source for runtime objects.
type TargetEntity struct {
	ID         int64           `json:"id"`
	TaskID     int64           `json:"task_id"`
	RoundID    *int64          `json:"round_id,omitempty"`
	EntityType string          `json:"entity_type"`
	Name       string          `json:"name"`
	AssetID    *int64          `json:"asset_id,omitempty"`
	CodebaseID string          `json:"codebase_id"`
	VersionID  string          `json:"version_id"`
	Attributes json.RawMessage `json:"attributes,omitempty"`
	Gap        bool            `json:"gap"`
	GapReason  string          `json:"gap_reason"`
	Resolved   bool            `json:"gap_resolved"`
}

// CreateTargetEntityInput creates one target entity. gap=true registers a
// material-inventory gap (unreadable/unclassifiable object) — gaps never
// silently vanish from the denominator (§5.4).
type CreateTargetEntityInput struct {
	TaskID     int64
	RoundID    *int64
	EntityType string
	Name       string
	AssetID    *int64
	CodebaseID string
	VersionID  string
	Attributes json.RawMessage
	Gap        bool
	GapReason  string
	Resolved   bool
}

func (d *DB) CreateTargetEntity(in CreateTargetEntityInput) (*TargetEntity, error) {
	if in.Gap && in.GapReason == "" {
		return nil, errors.New("target entity gap requires a reason")
	}
	// 目标实体必须在写入时绑定所属轮次（§6.4）：读取侧按 round_id 严格匹配，
	// 未绑定的记录不计入任何轮次，不能靠"留空混进每一轮"。
	if in.RoundID == nil {
		return nil, errors.New("target entity must be bound to an assessment round")
	}
	attributes := "{}"
	if len(in.Attributes) > 0 {
		attributes = string(in.Attributes)
	}
	var e TargetEntity
	err := d.QueryRow(`
INSERT INTO task_target_entities(task_id, round_id, entity_type, name, asset_id,
                                codebase_id, version_id, attributes, gap, gap_reason, resolved)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11)
RETURNING id, task_id, round_id, entity_type, name, asset_id, codebase_id, version_id,
          attributes, gap, gap_reason, resolved`,
		in.TaskID, in.RoundID, in.EntityType, in.Name, in.AssetID, in.CodebaseID, in.VersionID,
		attributes, in.Gap, in.GapReason, in.Resolved).Scan(
		&e.ID, &e.TaskID, &e.RoundID, &e.EntityType, &e.Name, &e.AssetID, &e.CodebaseID,
		&e.VersionID, scanJSONRaw(&e.Attributes), &e.Gap, &e.GapReason, &e.Resolved)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// ---------- 覆盖义务 ----------

// CoverageObligation is one concrete unit of test work required to claim an
// object has been tested to this round's standard (§5.2).
type CoverageObligation struct {
	ID                  int64           `json:"id"`
	TaskID              int64           `json:"task_id"`
	RoundID             *int64          `json:"round_id,omitempty"`
	Dimension           string          `json:"dimension"`
	TargetEntityID      *int64          `json:"target_entity_id,omitempty"`
	Purpose             string          `json:"purpose"`
	Required            bool            `json:"required"`
	Status              string          `json:"status"`
	DedupeKey           string          `json:"dedupe_key,omitempty"`
	RequiresCredentials bool            `json:"requires_credentials"`
	CredentialRef       string          `json:"credential_ref,omitempty"`
	BlockedReason       string          `json:"blocked_reason,omitempty"`
	StaleReason         string          `json:"stale_reason,omitempty"`
	NotApplicableReason string          `json:"not_applicable_reason,omitempty"`
	EvidenceRefID       *int64          `json:"evidence_ref_id,omitempty"`
	AcceptanceRule      json.RawMessage `json:"acceptance_rule,omitempty"`
}

// CreateCoverageObligationInput creates an obligation. dedupeKey provides
// idempotency: re-planning must not duplicate dispatches (§10 step 4).
type CreateCoverageObligationInput struct {
	TaskID              int64
	RoundID             *int64
	Dimension           string
	TargetEntityID      *int64
	Purpose             string
	Required            bool
	DedupeKey           string
	RequiresCredentials bool
	AcceptanceRule      json.RawMessage
}

// CreateCoverageObligation inserts an obligation; when dedupeKey already exists
// in the same round it returns the existing row unchanged (idempotent replan).
// 去重作用域是 (task, round)（§6.4）：新一轮次可以用相同 key 为同一对象重建
// 义务，而不会命中历史轮次的记录。
func (d *DB) CreateCoverageObligation(in CreateCoverageObligationInput) (*CoverageObligation, error) {
	if !IsValidCoverageDimension(in.Dimension) {
		return nil, fmt.Errorf("%w: %q", ErrObligationDimensionInvalid, in.Dimension)
	}
	if !in.Required {
		// 非必需义务没有完成语义，第一版不允许创建，避免“降级成展示项”。
		return nil, errors.New("coverage obligation must be required (non-required obligations are not supported yet)")
	}
	if in.DedupeKey == "" {
		return nil, errors.New("coverage obligation requires a dedupe key")
	}
	// 覆盖义务必须在写入时绑定所属轮次（§6.4）：读取侧按 round_id 严格匹配，
	// 未绑定的记录不计入任何轮次的完成判定。
	if in.RoundID == nil {
		return nil, errors.New("coverage obligation must be bound to an assessment round")
	}
	rule := "{}"
	if len(in.AcceptanceRule) > 0 {
		rule = string(in.AcceptanceRule)
	}
	obligation, err := scanCoverageObligation(d.QueryRow(`
INSERT INTO task_coverage_obligations(task_id, round_id, dimension, target_entity_id,
                                      purpose, required, dedupe_key, requires_credentials, acceptance_rule)
VALUES ($1,$2,$3,$4,$5,true,$6,$7,$8::jsonb)
ON CONFLICT (task_id, COALESCE(round_id, 0), dedupe_key) WHERE dedupe_key <> '' DO UPDATE SET updated_at=now()
RETURNING id, task_id, round_id, dimension, target_entity_id, purpose, required, status,
          dedupe_key, requires_credentials, credential_ref, blocked_reason, stale_reason,
          not_applicable_reason, evidence_ref_id, acceptance_rule`,
		in.TaskID, in.RoundID, in.Dimension, in.TargetEntityID, in.Purpose, in.DedupeKey,
		in.RequiresCredentials, rule))
	if err != nil {
		return nil, err
	}
	return obligation, nil
}

func scanCoverageObligation(sc interface{ Scan(...any) error }) (*CoverageObligation, error) {
	var o CoverageObligation
	var rule []byte
	if err := sc.Scan(&o.ID, &o.TaskID, &o.RoundID, &o.Dimension, &o.TargetEntityID, &o.Purpose,
		&o.Required, &o.Status, &o.DedupeKey, &o.RequiresCredentials, &o.CredentialRef,
		&o.BlockedReason, &o.StaleReason, &o.NotApplicableReason, &o.EvidenceRefID, &rule); err != nil {
		return nil, err
	}
	if len(rule) > 0 {
		o.AcceptanceRule = json.RawMessage(rule)
	}
	return &o, nil
}

// TransitionObligationStatus atomically moves an obligation between states
// (compare-and-set on expected). Terminal states carry evidence requirements
// so coverage cannot advance without a basis (§6.1/§6.3):
//
//   - satisfied：必须有证据引用（evidenceRefID 非空），证据必须属于本任务，
//     需要凭证的义务必须已绑定凭证引用（credential_ref 非空），且执行类维度
//     必须有可执行的尝试依据；证据要求不满足时返回 ErrObligationEvidenceMissing，
//     覆盖不推进。
//   - not_applicable / blocked / stale：必须携带非空白 reason。
//
// Planner/Worker 只能经由本方法提交结论建议；满足与否由这里的程序规则裁定。
type TransitionObligationOptions struct {
	Reason        string // blocked/stale/not_applicable 的依据说明
	EvidenceRefID *int64 // satisfied 的证据引用
}

// effectiveAttemptCondition 是"有依据的处置"尝试的 SQL 条件：结果属于
// supported/disproved/unreproduced，且尝试自带可验证的执行关联——意图节点
// 须属于本任务的探索图、白盒运行须属于本任务、执行输出证据须属于本任务。
// 关联列没有外键，只查 ID 非空会让已删除/不存在/他人的记录蒙混过关；
// 只有结果枚举、没有任何执行关联的"裸尝试"不算已执行（§5.3）。
const effectiveAttemptCondition = `outcome IN ('supported','disproved','unreproduced')
  AND (
       (intent_node_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM exploration_nodes n
            WHERE n.id = attempt.intent_node_id
              AND n.exploration_id = (SELECT t.exploration_id FROM tasks t
                                       WHERE t.id = attempt.task_id)))
    OR (code_audit_run_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM task_code_audit_runs r
            WHERE r.id = attempt.code_audit_run_id AND r.task_id = attempt.task_id))
    OR EXISTS (SELECT 1 FROM task_evidence_refs e
               WHERE e.id = attempt.evidence_ref_id AND e.task_id = attempt.task_id
                 AND e.kind = 'execution_output'))`

func (d *DB) TransitionObligationStatus(obligationID int64, expected, next string, opts TransitionObligationOptions) (bool, error) {
	if !IsValidObligationStatus(next) {
		return false, fmt.Errorf("%w: %q", ErrObligationStatusInvalid, next)
	}
	if obligationStatusNeedsReason(next) && strings.TrimSpace(opts.Reason) == "" {
		return false, fmt.Errorf("%w: status %s requires a non-blank reason", ErrObligationEvidenceMissing, next)
	}
	if next == ObligationSatisfied {
		if opts.EvidenceRefID == nil {
			return false, fmt.Errorf("%w: satisfied requires an evidence reference", ErrObligationEvidenceMissing)
		}
		// 一次性核验：证据归属本任务、凭证已绑定、执行类维度有可执行尝试依据。
		var taskID int64
		var dimension, credentialRef string
		var requiresCredentials bool
		var evidenceTask sql.NullInt64
		var effectiveAttempts int64
		err := d.QueryRow(`
SELECT o.task_id, o.dimension, o.requires_credentials, o.credential_ref,
       (SELECT task_id FROM task_evidence_refs WHERE id=$2),
       (SELECT count(*) FROM task_test_attempts attempt
         WHERE attempt.obligation_id=o.id AND `+effectiveAttemptCondition+`)
FROM task_coverage_obligations o WHERE o.id=$1`, obligationID, *opts.EvidenceRefID).
			Scan(&taskID, &dimension, &requiresCredentials, &credentialRef,
				&evidenceTask, &effectiveAttempts)
		if err != nil {
			return false, err
		}
		if !evidenceTask.Valid {
			return false, fmt.Errorf("%w: evidence reference %d not found", ErrObligationOwnershipMismatch, *opts.EvidenceRefID)
		}
		if evidenceTask.Int64 != taskID {
			return false, fmt.Errorf("%w: evidence %d belongs to task %d, not %d",
				ErrObligationOwnershipMismatch, *opts.EvidenceRefID, evidenceTask.Int64, taskID)
		}
		if requiresCredentials && strings.TrimSpace(credentialRef) == "" {
			return false, fmt.Errorf("%w: bind credential_ref before satisfying obligation %d",
				ErrObligationCredentialsMissing, obligationID)
		}
		// 执行类维度（入口测试/身份资源/跨模块）必须有可执行的尝试依据；
		// 静态阅读不算动态验证（§1.1/§5.3）。
		if _, needsExecution := executionDimensions[dimension]; needsExecution && effectiveAttempts == 0 {
			return false, fmt.Errorf("%w: dimension %s requires an effective execution attempt", ErrObligationEvidenceMissing, dimension)
		}
	}
	result, err := d.Exec(`
UPDATE task_coverage_obligations
SET status=$3,
    updated_at=now(),
    satisfied_at=CASE WHEN $3='satisfied' THEN now() ELSE satisfied_at END,
    blocked_reason=CASE WHEN $3='blocked' THEN $4 ELSE blocked_reason END,
    stale_reason=CASE WHEN $3='stale' THEN $4 ELSE stale_reason END,
    not_applicable_reason=CASE WHEN $3='not_applicable' THEN $4 ELSE not_applicable_reason END,
    evidence_ref_id=CASE WHEN $3='satisfied' THEN $5 ELSE evidence_ref_id END
WHERE id=$1 AND status=$2`, obligationID, expected, next, opts.Reason, opts.EvidenceRefID)
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// ---------- 测试尝试 ----------

// RecordTestAttemptInput appends one execution attempt for an obligation.
// attempt_no 在义务内自增：编号分配在义务行锁（FOR UPDATE）下串行，
// 并发登记不会读到同一个 max 而撞唯一约束。重复登记同一尝试由调用侧
// 幂等键（后续步骤的 attempt 标识）保证，本方法只保证编号唯一。
type RecordTestAttemptInput struct {
	TaskID         int64
	ObligationID   int64
	IntentNodeID   *int64
	CodeAuditRunID *int64
	Outcome        string
	EvidenceRefID  *int64
	Output         json.RawMessage
}

func (d *DB) RecordTestAttempt(in RecordTestAttemptInput) (int64, error) {
	if !IsValidAttemptOutcome(in.Outcome) {
		return 0, fmt.Errorf("%w: %q", ErrAttemptOutcomeInvalid, in.Outcome)
	}
	output := "{}"
	if len(in.Output) > 0 {
		output = string(in.Output)
	}
	tx, err := d.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	// 串行化编号分配：锁住义务行，两个并发的登记事务在此排队，
	// 后到的事务提交前必能看到先到者写入的 attempt_no。
	var obligationTask int64
	if err := tx.QueryRow(`SELECT task_id FROM task_coverage_obligations WHERE id=$1 FOR UPDATE`,
		in.ObligationID).Scan(&obligationTask); err != nil {
		return 0, err
	}
	if obligationTask != in.TaskID {
		return 0, fmt.Errorf("%w: obligation %d belongs to task %d, not %d",
			ErrObligationOwnershipMismatch, in.ObligationID, obligationTask, in.TaskID)
	}
	if in.EvidenceRefID != nil {
		var evidenceTask int64
		err := tx.QueryRow(`SELECT task_id FROM task_evidence_refs WHERE id=$1`, *in.EvidenceRefID).
			Scan(&evidenceTask)
		if err == sql.ErrNoRows || (err == nil && evidenceTask != in.TaskID) {
			return 0, fmt.Errorf("%w: evidence %d does not belong to task %d",
				ErrObligationOwnershipMismatch, *in.EvidenceRefID, in.TaskID)
		}
		if err != nil {
			return 0, err
		}
	}
	// 有依据处置（supported/disproved/unreproduced）的尝试必须自带可验证的
	// 执行关联：意图节点、白盒运行或执行输出证据。关联列没有外键，只查
	// ID 非空会让已删除/不存在/他人的记录蒙混过关——这里连同归属一并核验
	//（§5.3：静态阅读不等于动态验证）。
	if _, effective := effectiveAttemptOutcomes[in.Outcome]; effective {
		linked := false
		if in.IntentNodeID != nil {
			var n int64
			if err := tx.QueryRow(`SELECT count(*) FROM exploration_nodes n
JOIN tasks t ON t.exploration_id=n.exploration_id
WHERE n.id=$1 AND t.id=$2`, *in.IntentNodeID, in.TaskID).Scan(&n); err != nil {
				return 0, err
			}
			linked = n > 0
			if !linked {
				return 0, fmt.Errorf("%w: intent node %d does not belong to task %d",
					ErrObligationOwnershipMismatch, *in.IntentNodeID, in.TaskID)
			}
		}
		if in.CodeAuditRunID != nil {
			var n int64
			if err := tx.QueryRow(`SELECT count(*) FROM task_code_audit_runs
WHERE id=$1 AND task_id=$2`, *in.CodeAuditRunID, in.TaskID).Scan(&n); err != nil {
				return 0, err
			}
			if n > 0 {
				linked = true
			} else {
				return 0, fmt.Errorf("%w: code audit run %d does not belong to task %d",
					ErrObligationOwnershipMismatch, *in.CodeAuditRunID, in.TaskID)
			}
		}
		if !linked && in.EvidenceRefID != nil {
			var kind string
			if err := tx.QueryRow(`SELECT kind FROM task_evidence_refs WHERE id=$1`, *in.EvidenceRefID).
				Scan(&kind); err == nil {
				linked = kind == string(EvidenceExecution)
			} else if err != sql.ErrNoRows {
				return 0, err
			}
		}
		if !linked {
			return 0, fmt.Errorf("%w: effective attempts require an execution association (intent node / code-audit run / execution-output evidence)",
				ErrObligationEvidenceMissing)
		}
	}
	var id int64
	err = tx.QueryRow(`
INSERT INTO task_test_attempts(task_id, obligation_id, attempt_no, intent_node_id,
                                code_audit_run_id, outcome, evidence_ref_id, output)
VALUES ($1,$2,
        (SELECT COALESCE(max(attempt_no),0)+1 FROM task_test_attempts WHERE obligation_id=$2),
        $3,$4,$5,$6,$7::jsonb)
RETURNING id`, in.TaskID, in.ObligationID, in.IntentNodeID, in.CodeAuditRunID,
		in.Outcome, in.EvidenceRefID, output).Scan(&id)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// ---------- 评估事件 ----------

// RecordAssessmentEvent registers a reliable assessment event (new asset, new
// entry, profile change, invalidated evidence, ...). Unprocessed events block
// the completion contract: 收尾时新发现不会丢失（§6.3-6/§10 第 7 步）。
func (d *DB) RecordAssessmentEvent(taskID int64, eventType string, payload json.RawMessage) (int64, error) {
	switch eventType {
	case "new_asset", "new_entry", "profile_change", "evidence_invalidated",
		"knowledge_conflict", "code_version_change":
	default:
		return 0, fmt.Errorf("invalid assessment event type %q", eventType)
	}
	body := "{}"
	if len(payload) > 0 {
		body = string(payload)
	}
	var id int64
	if err := d.QueryRow(`
INSERT INTO task_assessment_events(task_id, event_type, payload)
VALUES ($1,$2,$3::jsonb) RETURNING id`, taskID, eventType, body).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// MarkAssessmentEventsProcessed marks events processed up to (and including) id.
func (d *DB) MarkAssessmentEventsProcessed(taskID int64, upToID int64) (int64, error) {
	result, err := d.Exec(`
UPDATE task_assessment_events
SET processed=true, processed_at=now()
WHERE task_id=$1 AND id<=$2 AND NOT processed`, taskID, upToID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ---------- 程序完成判定契约（§6.3） ----------

// AssessmentCompletionReport is the machine-judged answer to "能否把该任务判为
// 全覆盖完成"。CanComplete=false 时 Reasons 逐条列出未满足的必要条件。
// 各状态计数仅针对当前 open 轮次的必需义务；无适用义务的维度显示"不适用"，
// 不显示 100%（§6.2），由前端基于 RequiredTotal=0 判断。
type AssessmentCompletionReport struct {
	TaskID      int64    `json:"task_id"`
	RoundID     int64    `json:"round_id"`
	RoundNo     int      `json:"round_no"`
	CanComplete bool     `json:"can_complete"`
	Reasons     []string `json:"reasons,omitempty"`

	// 必需义务按状态计数（当前 open 轮次）。
	Obligations struct {
		Satisfied     int `json:"satisfied"`
		NotApplicable int `json:"not_applicable"`
		Pending       int `json:"pending"`
		Ready         int `json:"ready"`
		Running       int `json:"running"`
		Blocked       int `json:"blocked"`
		Stale         int `json:"stale"`
		// MissingCredentials 统计 requires_credentials 且未解析出凭证引用的必需义务
		//（缺凭证按未满足计，§6.3）。
		MissingCredentials int `json:"missing_credentials"`
		// EvidenceBackedSatisfied 统计带证据引用的 satisfied 义务（应为全部）。
		EvidenceBackedSatisfied int `json:"evidence_backed_satisfied"`
		// NotApplicableWithoutReason 统计没有可审计理由的 not_applicable 记录
		//（正常写入已被拦截；历史/脏数据在此兜底阻断契约）。
		NotApplicableWithoutReason int `json:"not_applicable_without_reason"`
	} `json:"obligations"`

	TargetCount    int `json:"target_count"`
	UnresolvedGaps int `json:"unresolved_gaps"`
	// RoundID 空缺的升级前遗留记录：不属于任何轮次，但未了结的缺口/必需
	// 义务在对账（迁移绑轮或补录）前阻断完成判定（§6.3）。
	UnboundLegacyGaps        int `json:"unbound_legacy_gaps"`
	UnboundLegacyObligations int `json:"unbound_legacy_obligations"`
	UnprocessedEvents        int `json:"unprocessed_events"`
	ActiveWhiteboxRuns       int `json:"active_whitebox_runs"`
	ActiveIntents            int `json:"active_intents"`
	OpenGoals                int `json:"open_goals"`
	TotalAttempts            int `json:"total_attempts"`
	EffectiveAttempts        int `json:"effective_attempts"`
	FailedAttempts           int `json:"failed_attempts"`
}

// AssessmentCompletionCheck evaluates the program completion contract for the
// task's current open assessment round. It is the single judge of "全覆盖完成"
// (§6.3): Planner 和 Worker 只能提交工作、证据和结论建议，不能直接把任务标为
// 全覆盖完成。
//
// 必要条件（全部满足才返回 CanComplete=true）：
//  1. 存在进行中的评估轮次；
//  2. 材料清单没有未对账缺口（读取/解析/分类失败不静默消失）；
//  3. 范围内至少存在一个目标对象（零资产不能判完成）；
//  4. 当前轮次全部必需义务 satisfied 或有依据的 not_applicable；
//     pending/ready/running/blocked/stale 均视为未完成；缺同样阻断；
//  5. satisfied 必须带证据引用；执行类维度必须有可执行的尝试依据；
//     只有失败尝试不能判完成（执行失败≠已覆盖）；
//  6. 存在尝试时，至少一条尝试属于有依据的处置（supported/disproved/unreproduced）；
//  7. 任务没有任何 open/running 意图与 open goal（队列为空不能自动等于完成，
//     但仍有活动工作时绝不能完成）；
//  8. 白盒审计队列没有 queued/running 的运行（独立白盒队列不落下的义务）；
//  9. 没有未处理的评估事件（新发现/失效事件驱动增量调度，不丢弃）。
func (d *DB) AssessmentCompletionCheck(taskID int64) (*AssessmentCompletionReport, error) {
	report := &AssessmentCompletionReport{TaskID: taskID}
	addReason := func(format string, args ...any) {
		report.Reasons = append(report.Reasons, fmt.Sprintf(format, args...))
	}

	round, err := d.OpenAssessmentRound(taskID)
	if err != nil {
		return nil, err
	}
	if round == nil {
		addReason("没有进行中的评估轮次，无法进行完成判定")
		return report, nil
	}
	report.RoundID, report.RoundNo = round.ID, round.RoundNo

	// 必需义务统计 + 证据/凭证核验。缺凭证检查覆盖全部适用义务（含已标
	// satisfied 的）——satisfied 不能凭空免除凭证要求；仅不适用义务除外
	//（没有对应工作，自然不需要凭证）。空白判定与写入侧一致用 btrim：
	// 纯空白凭证引用/理由同样视为缺失（§6.1）。
	err = d.QueryRow(`
SELECT
  count(*) FILTER (WHERE status='satisfied'),
  count(*) FILTER (WHERE status='not_applicable'),
  count(*) FILTER (WHERE status='pending'),
  count(*) FILTER (WHERE status='ready'),
  count(*) FILTER (WHERE status='running'),
  count(*) FILTER (WHERE status='blocked'),
  count(*) FILTER (WHERE status='stale'),
  count(*) FILTER (WHERE requires_credentials AND btrim(credential_ref)='' AND status <> 'not_applicable'),
  count(*) FILTER (WHERE status='satisfied' AND evidence_ref_id IS NOT NULL),
  count(*) FILTER (WHERE status='not_applicable' AND btrim(not_applicable_reason)='')
FROM task_coverage_obligations
WHERE task_id=$1 AND required AND round_id=$2`, taskID, round.ID).Scan(
		&report.Obligations.Satisfied, &report.Obligations.NotApplicable,
		&report.Obligations.Pending, &report.Obligations.Ready, &report.Obligations.Running,
		&report.Obligations.Blocked, &report.Obligations.Stale,
		&report.Obligations.MissingCredentials,
		&report.Obligations.EvidenceBackedSatisfied,
		&report.Obligations.NotApplicableWithoutReason)
	if err != nil {
		return nil, err
	}
	incomplete := report.Obligations.Pending + report.Obligations.Ready + report.Obligations.Running
	// 只有 fact 的空图不能判完成：评估没有产生任何覆盖工作时（零义务），完成
	// 判定无从谈起；无适用义务的维度显示“不适用”而非 100%（§6.2）。
	if report.Obligations.Satisfied+report.Obligations.NotApplicable == 0 {
		addReason("当前轮次没有任何已满足或有依据不适用的必需覆盖义务（评估尚未产生覆盖工作，不能判为完成）")
	}
	if incomplete > 0 {
		addReason("仍有 %d 条必需义务未完成（pending=%d ready=%d running=%d）",
			incomplete, report.Obligations.Pending, report.Obligations.Ready, report.Obligations.Running)
	}
	if report.Obligations.Blocked > 0 {
		addReason("%d 条必需义务处于 blocked（前提缺失/环境不可达），不计入已覆盖", report.Obligations.Blocked)
	}
	if report.Obligations.Stale > 0 {
		addReason("%d 条必需义务处于 stale（材料/环境/画像变化，原有证据不再适用）", report.Obligations.Stale)
	}
	if report.Obligations.MissingCredentials > 0 {
		addReason("%d 条必需义务缺少凭证解析（requires_credentials 未绑定凭证引用）", report.Obligations.MissingCredentials)
	}
	if report.Obligations.EvidenceBackedSatisfied != report.Obligations.Satisfied {
		addReason("%d 条 satisfied 义务缺少证据引用", report.Obligations.Satisfied-report.Obligations.EvidenceBackedSatisfied)
	}
	if report.Obligations.NotApplicableWithoutReason > 0 {
		addReason("%d 条 not_applicable 义务缺少可审计的不适用理由", report.Obligations.NotApplicableWithoutReason)
	}

	// 执行类维度的 satisfied 必须有可执行的尝试依据（带执行关联的有效处置）；
	// 只有失败尝试或裸结果枚举不能推进覆盖。
	var satisfiedNoEffectiveAttempt int64
	if err := d.QueryRow(`
SELECT count(*)
FROM task_coverage_obligations o
WHERE o.task_id=$1 AND o.required AND o.round_id=$2
  AND o.status='satisfied'
  AND o.dimension IN ('entry_test','identity_resource','cross_module')
  AND NOT EXISTS (
      SELECT 1 FROM task_test_attempts attempt
      WHERE attempt.obligation_id=o.id AND `+effectiveAttemptCondition+`)`,
		taskID, round.ID).Scan(&satisfiedNoEffectiveAttempt); err != nil {
		return nil, err
	}
	if satisfiedNoEffectiveAttempt > 0 {
		addReason("%d 条已满足的执行类义务缺少可执行尝试依据（静态阅读不等于动态验证）", satisfiedNoEffectiveAttempt)
	}

	// 目标对象与清单缺口按当前轮次统计（历史轮次的目标不进入本轮分母）；
	// 零资产/零目标不能判完成，缺口不能静默消失。
	err = d.QueryRow(`
SELECT
  (SELECT count(*) FROM task_target_entities WHERE task_id=$1 AND NOT gap AND round_id=$2),
  (SELECT count(*) FROM task_target_entities WHERE task_id=$1 AND gap AND NOT resolved AND round_id=$2)`,
		taskID, round.ID).Scan(&report.TargetCount, &report.UnresolvedGaps)
	if err != nil {
		return nil, err
	}
	if report.TargetCount == 0 {
		addReason("范围内没有任何目标对象（零资产/零目标不能判为完成）")
	}
	if report.UnresolvedGaps > 0 {
		addReason("材料清单存在 %d 个未对账缺口（读取/解析/分类失败不能静默消失）", report.UnresolvedGaps)
	}

	// 升级前的遗留记录（round_id 为空）不属于任何轮次：归属明确的由迁移
	// 绑定轮次，其余未了结的缺口/必需义务不能因为"不计入本轮"就静默消失
	// ——对账完成前阻止完成判定（§6.3）。
	err = d.QueryRow(`
SELECT
  (SELECT count(*) FROM task_target_entities
    WHERE task_id=$1 AND round_id IS NULL AND gap AND NOT resolved),
  (SELECT count(*) FROM task_coverage_obligations
    WHERE task_id=$1 AND round_id IS NULL AND required
      AND status NOT IN ('satisfied','not_applicable'))`,
		taskID).Scan(&report.UnboundLegacyGaps, &report.UnboundLegacyObligations)
	if err != nil {
		return nil, err
	}
	if report.UnboundLegacyGaps > 0 {
		addReason("存在 %d 个未绑定轮次的遗留缺口未对账（迁移或补录所属轮次前不能判为完成）", report.UnboundLegacyGaps)
	}
	if report.UnboundLegacyObligations > 0 {
		addReason("存在 %d 条未绑定轮次的遗留必需义务未了结（迁移或补录所属轮次前不能判为完成）", report.UnboundLegacyObligations)
	}

	// 尝试统计按当前轮次：历史轮次的尝试不参与本轮"只有失败尝试"判定。
	err = d.QueryRow(`
SELECT
  count(*),
  count(*) FILTER (WHERE `+effectiveAttemptCondition+`),
  count(*) FILTER (WHERE attempt.outcome IN ('env_mismatch','dependency_missing','failed'))
FROM task_test_attempts attempt
JOIN task_coverage_obligations o ON o.id=attempt.obligation_id
WHERE attempt.task_id=$1 AND o.required AND o.round_id=$2`, taskID, round.ID).Scan(
		&report.TotalAttempts, &report.EffectiveAttempts, &report.FailedAttempts)
	if err != nil {
		return nil, err
	}
	if report.TotalAttempts > 0 && report.EffectiveAttempts == 0 {
		addReason("全部 %d 条测试尝试均为失败/未成处置（执行失败不等于已覆盖）", report.TotalAttempts)
	}

	// 活动意图与开放目标：仍有执行/等待派发的必需工作不能完成。
	var explorationID int64
	if err := d.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, taskID).
		Scan(&explorationID); err != nil {
		return nil, err
	}
	err = d.QueryRow(`
SELECT
  (SELECT count(*) FROM exploration_nodes
    WHERE exploration_id=$1 AND kind='intent' AND state IN ('open','running')),
  (SELECT count(*) FROM exploration_nodes
    WHERE exploration_id=$1 AND kind='goal' AND state='open')`,
		explorationID).Scan(&report.ActiveIntents, &report.OpenGoals)
	if err != nil {
		return nil, err
	}
	if report.ActiveIntents > 0 {
		addReason("仍有 %d 条 open/running 意图在执行或等待派发", report.ActiveIntents)
	}
	if report.OpenGoals > 0 {
		addReason("仍有 %d 个开放目标未了结", report.OpenGoals)
	}

	// 白盒队列：父任务不能忽略未结束的白盒工作（§2.3/§10 第 5 步）。
	if err := d.QueryRow(`
SELECT count(*) FROM task_code_audit_runs
WHERE task_id=$1 AND status IN ('queued','running')`, taskID).
		Scan(&report.ActiveWhiteboxRuns); err != nil {
		return nil, err
	}
	if report.ActiveWhiteboxRuns > 0 {
		addReason("白盒审计队列仍有 %d 个 queued/running 运行未结束", report.ActiveWhiteboxRuns)
	}

	// 未处理评估事件：新资产/新入口/证据失效必须先被消化（§6.3-6）。
	if err := d.QueryRow(`
SELECT count(*) FROM task_assessment_events
WHERE task_id=$1 AND NOT processed`, taskID).Scan(&report.UnprocessedEvents); err != nil {
		return nil, err
	}
	if report.UnprocessedEvents > 0 {
		addReason("存在 %d 条未处理的评估事件（新发现/画像变化/证据失效）", report.UnprocessedEvents)
	}

	report.CanComplete = len(report.Reasons) == 0
	return report, nil
}

// FinalizeAssessmentCompletion 在单个事务里原子完成评估收尾（§6.3/§6.4）：
//
//  1. 锁定任务行并复核白盒队列没有 queued/running 运行——与
//     CreateTaskCodeAudit 的任务行锁互斥，消除"完成检查之后、done 提交之前
//     并发入队"的窗口；
//  2. guarded 终态写入 done（与常规 done/timeout 路径 CAS，首写者胜出）；
//  3. 关闭当前 open 轮次并落完成报告；
//  4. 阶段推进到 completed。
//
// 任一步失败整体回滚，不会留下"任务 done 但轮次未关/报告缺失"的中间状态
// （此前三步分开提交时，中途失败无法重试——终态守卫会拒绝一切后续写入）。
// 队列在锁下仍非空时返回 won=false（非错误），调用方让任务继续运行。
func (d *DB) FinalizeAssessmentCompletion(taskID, roundID int64, report json.RawMessage) (active int64, started *time.Time, won bool, err error) {
	tx, err := d.Begin()
	if err != nil {
		return 0, nil, false, err
	}
	defer tx.Rollback() //nolint:errcheck

	// 锁任务行：串行化与评估模式下白盒入队（CreateTaskCodeAudit 对
	// assessment_mode 任务行 FOR UPDATE）的并发。
	var status string
	if err := tx.QueryRow(`SELECT status FROM tasks WHERE id=$1 FOR UPDATE`, taskID).Scan(&status); err != nil {
		return 0, nil, false, err
	}
	if status == "done" || status == "failed" || status == "timeout" {
		return 0, nil, false, nil
	}
	// 复核白盒队列：契约检查与终态提交之间不允许出现新的 queued/running 工作。
	var queuedRuns int64
	if err := tx.QueryRow(`SELECT count(*) FROM task_code_audit_runs
WHERE task_id=$1 AND status IN ('queued','running')`, taskID).Scan(&queuedRuns); err != nil {
		return 0, nil, false, err
	}
	if queuedRuns > 0 {
		return 0, nil, false, nil
	}
	// Guarded 终态：与常规路径的 done/timeout 竞态由首写者胜出解决。
	err = tx.QueryRow(`
UPDATE tasks
   SET status='done', pause_reason='', stop_reason='',
       completed_at=COALESCE(completed_at, now()),
       active_run_seconds = active_run_seconds + CASE WHEN run_segment_started_at IS NOT NULL
           THEN GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (now() - run_segment_started_at)))::bigint) ELSE 0 END,
       run_segment_started_at = NULL
 WHERE id=$1 AND status NOT IN ('done','failed','timeout')
 RETURNING active_run_seconds, run_segment_started_at`, taskID).Scan(&active, &started)
	if err == sql.ErrNoRows {
		return 0, nil, false, nil
	}
	if err != nil {
		return 0, nil, false, err
	}
	// 关闭当前轮次并落完成报告：轮次已被并发关闭时整体回滚（不覆盖历史）。
	result, err := tx.Exec(`
UPDATE task_assessment_rounds
   SET status='completed', completion_report=$3, completed_at=now()
 WHERE id=$2 AND task_id=$1 AND status='open'`, taskID, roundID, string(report))
	if err != nil {
		return 0, nil, false, err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return 0, nil, false, ErrObligationStateConflict
	}
	// 阶段推进到 completed。
	if _, err := tx.Exec(`UPDATE tasks SET assessment_phase=$2 WHERE id=$1`,
		taskID, AssessmentPhaseCompleted); err != nil {
		return 0, nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, nil, false, err
	}
	return active, started, true, nil
}

// scanJSONRaw scans a nullable JSONB column into a RawMessage target.
func scanJSONRaw(target *json.RawMessage) *[]byte {
	return (*[]byte)(target)
}
