package server

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 白盒驱动测试转型第 1 步（server 侧）验收：Manager.CompleteAssessment 是任务
// 全覆盖完成的唯一程序判定入口。契约未通过时任务不得进入 done；契约通过时
// 一次性完成 终态落库 → 关闭评估轮次 → 阶段推进（completed），且与常规终态
// 写入互斥（首写者胜出）。

// newAssessmentManagerTask 建立一个 assessment_mode 任务的运行时句柄。
func newAssessmentManagerTask(t *testing.T) (*Manager, *Task) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	created, err := m.CreateTask(testProjectID(t, m), "assessment completion", "contract", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	created.AssessmentMode = true
	return m, created
}

func TestManagerCompleteAssessmentRefusesWhenContractFails(t *testing.T) {
	m, task := newAssessmentManagerTask(t)
	// 场景一：没有任何评估数据（零轮次/零义务/零资产）→ 不能完成。
	completed, report, err := m.CompleteAssessment(task)
	if err != nil {
		t.Fatal(err)
	}
	if completed {
		t.Fatal("空评估场景不应判为完成")
	}
	if report == nil || report.CanComplete {
		t.Fatalf("空评估场景应返回未通过的报告：%+v", report)
	}
	if !strings.Contains(strings.Join(report.Reasons, "；"), "评估轮次") {
		t.Fatalf("空评估场景原因应指出缺少评估轮次：%v", report.Reasons)
	}
	// 任务不得进入终态。
	if status := m.TaskStatus(task.ID); isTerminalStatus(status) {
		t.Fatalf("契约未通过却进入终态 %q", status)
	}
}

func TestManagerCompleteAssessmentBlockedScenarios(t *testing.T) {
	m, task := newAssessmentManagerTask(t)
	// 用确认不存在的任务 ID 验证外键拒绝：projects.id 与 tasks.id 来自独立
	// 序列，任何取自其它表/对象的 ID（如项目 ID）都可能恰好等于某个已存在
	// 的任务 ID；max(id)+1 也会在 db/server 测试共享同一 PostgreSQL 时被并发
	// 建出的任务占用。此处用 nextval 保留一个序列值但不插入行——该 ID 永不
	// 会有对应任务，外键拒绝是确定的。
	var reservedTaskID int64
	if err := m.pg.QueryRow(`SELECT nextval(pg_get_serial_sequence('tasks','id'))`).Scan(&reservedTaskID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.CreateAssessmentRound(reservedTaskID); err == nil {
		t.Fatalf("对不存在的任务 ID 建轮次不应成功")
	}
	round, err := m.pg.CreateAssessmentRound(assessmentTaskID(t, task))
	if err != nil {
		t.Fatal(err)
	}
	// 建齐目标与义务但全部只有失败尝试 → 契约必须拒绝。
	target, err := m.pg.CreateTargetEntity(db.CreateTargetEntityInput{
		TaskID: assessmentTaskID(t, task), RoundID: &round.ID, EntityType: "entry", Name: "GET /api/users",
	})
	if err != nil {
		t.Fatal(err)
	}
	obligation, err := m.pg.CreateCoverageObligation(db.CreateCoverageObligationInput{
		TaskID: assessmentTaskID(t, task), RoundID: &round.ID, Dimension: db.DimensionEntryTest,
		TargetEntityID: &target.ID, Purpose: "入口动态测试", Required: true, DedupeKey: "entry:users",
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := m.pg.CreateEvidenceRef(assessmentTaskID(t, task), db.EvidenceTraffic, "traffic/req-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.RecordTestAttempt(db.RecordTestAttemptInput{
		TaskID: assessmentTaskID(t, task), ObligationID: obligation.ID,
		Outcome: db.AttemptFailed, EvidenceRefID: &evidence,
	}); err != nil {
		t.Fatal(err)
	}
	completed, report, err := m.CompleteAssessment(task)
	if err != nil {
		t.Fatal(err)
	}
	if completed || report == nil || report.CanComplete {
		t.Fatalf("只有失败尝试不能判完成: completed=%v report=%+v", completed, report)
	}
	for _, want := range []string{"均为失败/未成处置", "未完成"} {
		if !strings.Contains(strings.Join(report.Reasons, "；"), want) {
			t.Fatalf("原因缺少 %q：%v", want, report.Reasons)
		}
	}
	if isTerminalStatus(m.TaskStatus(task.ID)) {
		t.Fatal("只有失败尝试的任务不应进入终态")
	}
}

func TestManagerCompleteAssessmentHappyPathCommitsOnce(t *testing.T) {
	m, task := newAssessmentManagerTask(t)
	taskID := assessmentTaskID(t, task)
	round, err := m.pg.CreateAssessmentRound(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.CreateTargetEntity(db.CreateTargetEntityInput{
		TaskID: taskID, RoundID: &round.ID, EntityType: "service", Name: "user-service",
	}); err != nil {
		t.Fatal(err)
	}
	staticEvidence, err := m.pg.CreateEvidenceRef(taskID, db.EvidenceCodeRange, "src/Auth.java", nil)
	if err != nil {
		t.Fatal(err)
	}
	static, err := m.pg.CreateCoverageObligation(db.CreateCoverageObligationInput{
		TaskID: taskID, RoundID: &round.ID, Dimension: db.DimensionCodeAudit,
		Purpose: "自研模块审计", Required: true, DedupeKey: "code:auth",
	})
	if err != nil {
		t.Fatal(err)
	}
	if won, err := m.pg.TransitionObligationStatus(static.ID, db.ObligationPending, db.ObligationSatisfied,
		db.TransitionObligationOptions{EvidenceRefID: &staticEvidence}); err != nil || !won {
		t.Fatalf("静态义务满足失败: won=%v err=%v", won, err)
	}
	// 第二条义务：有依据的不适用例外。
	na, err := m.pg.CreateCoverageObligation(db.CreateCoverageObligationInput{
		TaskID: taskID, RoundID: &round.ID, Dimension: db.DimensionRuntimeAsset,
		Purpose: "运行资产检查", Required: true, DedupeKey: "runtime:none",
	})
	if err != nil {
		t.Fatal(err)
	}
	if won, err := m.pg.TransitionObligationStatus(na.ID, db.ObligationPending, db.ObligationNotApplicable,
		db.TransitionObligationOptions{Reason: "纯静态评估轮次，无运行资产"}); err != nil || !won {
		t.Fatalf("不适用义务失败: won=%v err=%v", won, err)
	}

	completed, report, err := m.CompleteAssessment(task)
	if err != nil {
		t.Fatal(err)
	}
	if !completed || report == nil || !report.CanComplete {
		t.Fatalf("满足契约却未完成: completed=%v report=%+v err=%v", completed, report, err)
	}
	// 终态/轮次/阶段三处都已落库。
	if status := m.TaskStatus(task.ID); status != "done" {
		t.Fatalf("完成后状态=%q want done", status)
	}
	closed, err := m.pg.OpenAssessmentRound(taskID)
	if err != nil || closed != nil {
		t.Fatalf("完成后评估轮次应已关闭: %+v err=%v", closed, err)
	}
	latest, err := m.pg.GetTask(taskID)
	if err != nil || latest == nil {
		t.Fatalf("读取任务失败: %v", err)
	}
	if latest.Status != "done" || latest.AssessmentPhase != db.AssessmentPhaseCompleted {
		t.Fatalf("落库状态=%q 阶段=%q want done/completed", latest.Status, latest.AssessmentPhase)
	}
	var persisted struct {
		CompletionReport json.RawMessage `json:"completion_report"`
	}
	if err := m.pg.QueryRow(`SELECT completion_report FROM task_assessment_rounds WHERE id=$1`, round.ID).
		Scan(&persisted.CompletionReport); err != nil {
		t.Fatal(err)
	}
	if len(persisted.CompletionReport) == 0 {
		t.Fatal("关闭的评估轮次缺少完成报告")
	}
	// 重复调用不得改写已完成历史（guarded；won=false 且不改轮次）。
	againCompleted, _, err := m.CompleteAssessment(task)
	if err != nil {
		t.Fatal(err)
	}
	if againCompleted {
		t.Fatal("已完成任务的重复完成判定应落空")
	}
	var roundStatus string
	if err := m.pg.QueryRow(`SELECT status FROM task_assessment_rounds WHERE id=$1`, round.ID).Scan(&roundStatus); err != nil {
		t.Fatal(err)
	}
	if roundStatus != "completed" {
		t.Fatalf("历史轮次被改写: %q", roundStatus)
	}
}

// TestManagerCompleteAssessmentLegacyTaskUntouched 确认契约不触碰传统任务的行为
// 语义：非 assessment_mode 任务不经过该路径（这里只验证调用侧不产生副作用——
// 传统路径的 done 由既有 engine 测试覆盖）。
func TestManagerCompleteAssessmentLegacyTaskUntouched(t *testing.T) {
	m, task := newAssessmentManagerTask(t)
	task.AssessmentMode = false
	// 即使误调用，传统任务也不应被该方法直接终态化以外地破坏：契约返回未通过
	//（无评估数据），任务状态保持非终态。
	completed, _, err := m.CompleteAssessment(task)
	if err != nil {
		t.Fatal(err)
	}
	if completed {
		t.Fatal("无评估数据的调用不应完成任务")
	}
	if isTerminalStatus(m.TaskStatus(task.ID)) {
		t.Fatal("任务不应被误终态化")
	}
}

func assessmentTaskID(t *testing.T, task *Task) int64 {
	t.Helper()
	id, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatalf("非法任务 id %q: %v", task.ID, err)
	}
	return id
}
