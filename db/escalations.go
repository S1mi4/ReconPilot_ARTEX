package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 利用扩展提案：agent 在探索中识别到「必须扩大影响才能继续判断」时，只登记提案，
// 不执行。审批是人的动作（status/decided_by 只由 API 写），审批后也由人按步骤执行，
// 再通过 API 回填结果。把"写提案"和"批准"分开，是为了让 agent 永远不能批准自己。

// EscalationStatus 是提案的状态机取值。approved 之后只有取消/执行两种去向；
// 人工路径从 approved 直接回填 executed/failed；running 保留给未来的受控执行器。
const (
	EscalationProposed       = "proposed"
	EscalationApproved       = "approved"
	EscalationRejected       = "rejected"
	EscalationRunning        = "running"
	EscalationExecuted       = "executed"
	EscalationFailed         = "failed"
	EscalationCancelled      = "cancelled"
	EscalationExpired        = "expired"
	MaxEscalationApprovalTTL = 24 * time.Hour
)

var ErrEscalationApprovalTTLTooLong = errors.New("批准有效期不能超过 24 小时")

// ValidEscalationLevel 限定提案等级。L1 不需要提案（只改自建对象），L4 永远禁止。
func ValidEscalationLevel(s string) bool { return s == "L2" || s == "L3" }

// FindingEscalation 是一条"理论操作"提案及其审批结论。
type FindingEscalation struct {
	ID             int64      `json:"id,string"`
	ProjectID      int64      `json:"project_id,string"`
	FindingID      int64      `json:"finding_id,string"`
	TaskID         *int64     `json:"task_id,string,omitempty"`
	Level          string     `json:"level"`
	Title          string     `json:"title"`
	Objective      string     `json:"objective"`
	Preconditions  []string   `json:"preconditions"`
	Steps          string     `json:"steps"`
	ExpectedImpact string     `json:"expected_impact"`
	BlastRadius    string     `json:"blast_radius"`
	StopConditions []string   `json:"stop_conditions"`
	RollbackPlan   string     `json:"rollback_plan"`
	Alternative    string     `json:"alternative"`
	ProposedBy     string     `json:"proposed_by"`
	Status         string     `json:"status"`
	DecidedBy      string     `json:"decided_by"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	DecisionNote   string     `json:"decision_note"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	RunID          *int64     `json:"run_id,string,omitempty"`
	// ImpactObserved records verified, actual effects only. The proposal's
	// expected_impact is theoretical and must not be copied into this field.
	ImpactObserved string    `json:"impact_observed"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// EscalationInput 是 agent 提交提案时的完整载荷。必填项在 CreateEscalation 里校验：
// 一份说不清"做什么、为什么、最坏影响、怎么回滚"的提案没有审核价值，不该进库。
type EscalationInput struct {
	ProjectID      int64
	FindingID      int64
	TaskID         int64
	Level          string
	Title          string
	Objective      string
	Preconditions  []string
	Steps          string
	ExpectedImpact string
	BlastRadius    string
	StopConditions []string
	RollbackPlan   string
	Alternative    string
	ProposedBy     string
}

// Validate 检查提案是否够格被审核。
func (in EscalationInput) Validate() error {
	if in.FindingID <= 0 {
		return errors.New("提案必须绑定到一个已上报的漏洞（finding_id）")
	}
	if !ValidEscalationLevel(in.Level) {
		return errors.New("等级只能是 L2（受限读取）或 L3（写目标/命令执行/持久化/提权横向）：L1 无需提案，L4 永远禁止")
	}
	if strings.TrimSpace(in.Title) == "" {
		return errors.New("提案必须有标题")
	}
	if strings.TrimSpace(in.Steps) == "" {
		return errors.New("提案必须写出理论操作步骤（steps）")
	}
	if strings.TrimSpace(in.ExpectedImpact) == "" {
		return errors.New("提案必须说明预期影响（expected_impact）")
	}
	if strings.TrimSpace(in.RollbackPlan) == "" {
		return errors.New("提案必须给出回滚/止损方式（rollback_plan）")
	}
	if len(nonEmpty(in.StopConditions)) == 0 {
		return errors.New("提案必须至少给出一条停止条件（stop_conditions）")
	}
	return nil
}

func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// 数组列走 array_to_json：与 assets 的读法保持一致（TEXT[] 直接扫进 []string 会依赖
// 驱动的文本解析，转成 JSON 再解更稳）。
const escalationCols = `id, project_id, finding_id, task_id, level, title, objective,
	COALESCE(array_to_json(preconditions)::text,'[]'),
	steps, expected_impact, blast_radius,
	COALESCE(array_to_json(stop_conditions)::text,'[]'),
	rollback_plan, alternative,
	proposed_by, status, decided_by, decided_at, decision_note, expires_at, run_id,
	impact_observed, created_at, updated_at`

func scanEscalation(sc interface{ Scan(...any) error }) (*FindingEscalation, error) {
	e := &FindingEscalation{}
	var taskID, runID sql.NullInt64
	var decidedAt, expiresAt sql.NullTime
	var preconditions, stopConditions string
	if err := sc.Scan(&e.ID, &e.ProjectID, &e.FindingID, &taskID, &e.Level, &e.Title, &e.Objective,
		&preconditions, &e.Steps, &e.ExpectedImpact, &e.BlastRadius,
		&stopConditions, &e.RollbackPlan, &e.Alternative, &e.ProposedBy, &e.Status,
		&e.DecidedBy, &decidedAt, &e.DecisionNote, &expiresAt, &runID, &e.ImpactObserved,
		&e.CreatedAt, &e.UpdatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(preconditions), &e.Preconditions)
	_ = json.Unmarshal([]byte(stopConditions), &e.StopConditions)
	if taskID.Valid {
		v := taskID.Int64
		e.TaskID = &v
	}
	if runID.Valid {
		v := runID.Int64
		e.RunID = &v
	}
	if decidedAt.Valid {
		v := decidedAt.Time
		e.DecidedAt = &v
	}
	if expiresAt.Valid {
		v := expiresAt.Time
		e.ExpiresAt = &v
	}
	return e, nil
}

// CreateEscalation 登记一条提案。同一漏洞同一等级的待审提案只保留一条：agent 反复
// 提同一件事时更新原提案而不是刷屏（唯一索引兜底，这里做 upsert）。
func (d *DB) CreateEscalation(ctx context.Context, in EscalationInput) (*FindingEscalation, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	// 项目必须与漏洞所属项目一致：提案是项目内的审批对象，不能跨项目挂靠。
	var projectID int64
	if err := d.QueryRowContext(ctx, `SELECT COALESCE(project_id,0) FROM findings WHERE id=$1`, in.FindingID).Scan(&projectID); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("漏洞 %d 不存在", in.FindingID)
		}
		return nil, err
	}
	if projectID == 0 {
		return nil, errors.New("漏洞缺少所属项目，无法登记提案")
	}
	if in.ProjectID > 0 && in.ProjectID != projectID {
		return nil, errors.New("漏洞不属于当前项目")
	}
	var taskID any
	if in.TaskID > 0 {
		taskID = in.TaskID
	}
	row := d.QueryRowContext(ctx, `
INSERT INTO finding_escalations(project_id, finding_id, task_id, level, title, objective, preconditions,
	steps, expected_impact, blast_radius, stop_conditions, rollback_plan, alternative, proposed_by)
VALUES($1,$2,$3,$4,$5,$6,$7::text[],$8,$9,$10,$11::text[],$12,$13,$14)
ON CONFLICT (finding_id, level) WHERE status = 'proposed' DO UPDATE SET
	title=EXCLUDED.title, objective=EXCLUDED.objective, preconditions=EXCLUDED.preconditions,
	steps=EXCLUDED.steps, expected_impact=EXCLUDED.expected_impact, blast_radius=EXCLUDED.blast_radius,
	stop_conditions=EXCLUDED.stop_conditions, rollback_plan=EXCLUDED.rollback_plan,
	alternative=EXCLUDED.alternative, proposed_by=EXCLUDED.proposed_by, updated_at=now()
RETURNING `+escalationCols,
		projectID, in.FindingID, taskID, in.Level, in.Title, in.Objective, marshalStringArray(nonEmpty(in.Preconditions)),
		in.Steps, in.ExpectedImpact, in.BlastRadius, marshalStringArray(nonEmpty(in.StopConditions)), in.RollbackPlan,
		in.Alternative, in.ProposedBy)
	return scanEscalation(row)
}

// ListEscalations 返回一条漏洞的全部提案（最新在前），供详情页渲染。
func (d *DB) ListEscalations(ctx context.Context, findingID int64) ([]*FindingEscalation, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+escalationCols+` FROM finding_escalations
WHERE finding_id=$1 ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*FindingEscalation
	for rows.Next() {
		e, err := scanEscalation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetEscalation 按 id 取一条提案。
func (d *DB) GetEscalation(ctx context.Context, id int64) (*FindingEscalation, error) {
	row := d.QueryRowContext(ctx, `SELECT `+escalationCols+` FROM finding_escalations WHERE id=$1`, id)
	e, err := scanEscalation(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return e, err
}

// DecideEscalation 记录人工审批结论。只允许从 proposed 迁移：重复点击、并发点击都不会
// 把已拒绝的提案改成批准。approve=false 时写 rejected（"仅保留理论"也走这条）。
func (d *DB) DecideEscalation(ctx context.Context, id int64, approve bool, by, note string, ttl time.Duration) (*FindingEscalation, error) {
	if strings.TrimSpace(by) == "" {
		return nil, errors.New("审批人不能为空")
	}
	status := EscalationRejected
	var expires any
	if approve {
		if ttl <= 0 {
			ttl = MaxEscalationApprovalTTL
		}
		if ttl > MaxEscalationApprovalTTL {
			return nil, ErrEscalationApprovalTTLTooLong
		}
		status = EscalationApproved
		expires = time.Now().Add(ttl)
	}
	row := d.QueryRowContext(ctx, `
UPDATE finding_escalations
SET status=$2, decided_by=$3, decided_at=now(), decision_note=$4, expires_at=$5, updated_at=now()
WHERE id=$1 AND status='proposed'
RETURNING `+escalationCols, id, status, by, note, expires)
	e, err := scanEscalation(row)
	if err == sql.ErrNoRows {
		// 已决策或不存在：区分开，让调用方能给出"已被处理"而不是"不存在"。
		cur, getErr := d.GetEscalation(ctx, id)
		if getErr != nil {
			return nil, getErr
		}
		if cur == nil {
			return nil, fmt.Errorf("提案 %d 不存在", id)
		}
		return nil, fmt.Errorf("提案已处于 %s 状态，不能再审批", cur.Status)
	}
	return e, err
}

// CancelEscalation 让已批准的提案作废（人在执行前反悔）。已执行/已失败的不能取消。
func (d *DB) CancelEscalation(ctx context.Context, id int64, by, note string) (*FindingEscalation, error) {
	// 参数都显式 ::text：$2 只出现在 CASE 里，不标注类型时 PG 无法推断占位符类型。
	row := d.QueryRowContext(ctx, `
UPDATE finding_escalations
SET status='cancelled',
	decided_by    = CASE WHEN $2::text='' THEN decided_by ELSE $2::text END,
	decision_note = CASE WHEN $3::text='' THEN decision_note ELSE $3::text END,
	updated_at=now()
WHERE id=$1 AND status IN ('approved','running')
RETURNING `+escalationCols, id, by, note)
	e, err := scanEscalation(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("提案 %d 当前状态不允许取消", id)
	}
	return e, err
}

// ExpireStaleApprovals 把过了执行窗口、还没开始跑的批准标成 expired。启动和定时任务
// 都会调用，避免"批准的窗口早就过了，页面上还显示可以执行"。
func (d *DB) ExpireStaleApprovals(ctx context.Context) (int64, error) {
	res, err := d.ExecContext(ctx, `
UPDATE finding_escalations SET status='expired', updated_at=now()
WHERE status='approved' AND (expires_at IS NULL OR expires_at <= now())`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// MarkEscalationRunning / MarkEscalationFinished 由受控执行器（P2）调用。分开写是
// 为了让执行器不必碰其它列，也方便测试状态机。
func (d *DB) MarkEscalationRunning(ctx context.Context, id, runID int64) (*FindingEscalation, error) {
	row := d.QueryRowContext(ctx, `
UPDATE finding_escalations SET status='running', run_id=$2, updated_at=now()
WHERE id=$1 AND status='approved' AND expires_at IS NOT NULL AND expires_at > now()
RETURNING `+escalationCols, id, runID)
	e, err := scanEscalation(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("提案 %d 不是已批准状态，无法开始执行", id)
	}
	return e, err
}

// RecordEscalationOutcome 是人工执行路径的结案入口：人按批准的理论步骤执行之后，
// 把结果与真实影响回填。它也接受 running，供未来受控执行器完成运行中的提案。
func (d *DB) RecordEscalationOutcome(ctx context.Context, id int64, status, impact, note string) (*FindingEscalation, error) {
	if status != EscalationExecuted && status != EscalationFailed {
		return nil, fmt.Errorf("结案状态只能是 executed 或 failed")
	}
	if !validImpactObserved[impact] {
		return nil, fmt.Errorf("非法的影响取值 %q", impact)
	}
	row := d.QueryRowContext(ctx, `
UPDATE finding_escalations
SET status=$2, impact_observed=$3,
	decision_note = CASE WHEN $4::text='' THEN decision_note ELSE $4::text END,
	updated_at=now()
WHERE id=$1 AND (status='running' OR
    (status='approved' AND expires_at IS NOT NULL AND expires_at > now()))
RETURNING `+escalationCols, id, status, impact, note)
	e, err := scanEscalation(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("提案 %d 不在已批准/执行中状态，无法回填结果", id)
	}
	return e, err
}

// MarkEscalationFinished 落最终状态并记录实际观察到的影晌。
func (d *DB) MarkEscalationFinished(ctx context.Context, id int64, status, impact string) (*FindingEscalation, error) {
	if status != EscalationExecuted && status != EscalationFailed && status != EscalationCancelled {
		return nil, fmt.Errorf("非法的结束状态 %q", status)
	}
	row := d.QueryRowContext(ctx, `
UPDATE finding_escalations SET status=$2, impact_observed=$3, updated_at=now()
WHERE id=$1 AND status='running' RETURNING `+escalationCols, id, status, impact)
	e, err := scanEscalation(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("提案 %d 不在执行中，无法结案", id)
	}
	return e, err
}
