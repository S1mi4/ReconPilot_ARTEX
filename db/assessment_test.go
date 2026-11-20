package db

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// 白盒驱动测试转型第 1 步验收（docs/whitebox-driven-assessment-design.md §11.1）：
// 零资产、只有 fact、只有失败尝试、缺凭证或白盒队列仍运行的任务都不能被判为
// 全覆盖完成；全部必需义务满足且证据对账通过时才允许完成。

// assessmentFixture 是一个最小可判定的评估场景：任务 + 当前 open 轮次。
func assessmentFixture(t *testing.T) (*DB, *Task, *AssessmentRound) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask(testProjectID(t, d), "whitebox assessment contract", "contract fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	round, err := d.CreateAssessmentRound(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	return d, task, round
}

func assessmentReasons(report *AssessmentCompletionReport) string {
	if report == nil {
		return ""
	}
	return strings.Join(report.Reasons, "；")
}

func assertCannotComplete(t *testing.T, report *AssessmentCompletionReport, wantSubstr ...string) {
	t.Helper()
	if report.CanComplete {
		t.Fatalf("预期不能完成，但契约判定可完成；报告=%+v", report)
	}
	for _, want := range wantSubstr {
		if !strings.Contains(assessmentReasons(report), want) {
			t.Fatalf("判定原因缺少 %q；实际原因：%s", want, assessmentReasons(report))
		}
	}
}

// mustEvidence 写入一条证据引用并返回其 id。
func mustEvidence(t *testing.T, d *DB, taskID int64, reference string) int64 {
	t.Helper()
	id, err := d.CreateEvidenceRef(taskID, EvidenceCodeRange, reference, json.RawMessage(`{"path":"`+reference+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// buildSatisfiableObligation 建立一条带证据的必需义务（不做终态推进）。
func buildSatisfiableObligation(t *testing.T, d *DB, task *Task, round *AssessmentRound, dimension, dedupe string) *CoverageObligation {
	t.Helper()
	obligation, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: dimension, Required: true,
		Purpose: "验收测试 " + dedupe, DedupeKey: dedupe,
	})
	if err != nil {
		t.Fatal(err)
	}
	return obligation
}

func TestAssessmentRoundLifecycle(t *testing.T) {
	d, task, round := assessmentFixture(t)
	if round.RoundNo != 1 {
		t.Fatalf("首轮 round_no=%d want 1", round.RoundNo)
	}
	second, err := d.CreateAssessmentRound(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second.RoundNo != 2 {
		t.Fatalf("次轮 round_no=%d want 2", second.RoundNo)
	}
	open, err := d.OpenAssessmentRound(task.ID)
	if err != nil || open == nil || open.ID != second.ID {
		t.Fatalf("当前 open 轮次=%+v err=%v", open, err)
	}
	if err := d.CompleteAssessmentRound(task.ID, second.ID, json.RawMessage(`{"can_complete":true}`)); err != nil {
		t.Fatal(err)
	}
	open, err = d.OpenAssessmentRound(task.ID)
	if err != nil || open == nil || open.ID != round.ID {
		t.Fatalf("关闭后应回落到第一轮 open：%+v err=%v", open, err)
	}
	// 重复关闭已完成的轮次必须失败，历史轮次结果不被覆盖。
	if err := d.CompleteAssessmentRound(task.ID, second.ID, nil); err == nil {
		t.Fatal("重复关闭已完成轮次应报错")
	}
	// 阶段校验：未知阶段拒绝。
	if err := d.SetAssessmentPhase(task.ID, "not_a_phase"); err == nil {
		t.Fatal("未知评估阶段应被拒绝")
	}
	if err := d.SetAssessmentPhase(task.ID, AssessmentPhaseReconciliation); err != nil {
		t.Fatal(err)
	}
}

func TestAssessmentObligationDedupeIsIdempotent(t *testing.T) {
	d, task, round := assessmentFixture(t)
	in := CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionCodeAudit, Required: true,
		Purpose: "共享库审计", DedupeKey: "code:shared:auth-lib",
	}
	first, err := d.CreateCoverageObligation(in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.CreateCoverageObligation(in)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("重复规划产生重复义务：%d != %d", first.ID, second.ID)
	}
}

// 终态证据契约：satisfied 必须有证据引用；执行类维度必须有可执行尝试依据；
// not_applicable/blocked/stale 必须有理由。只有失败尝试不能推进覆盖。
func TestObligationTerminalEvidenceContract(t *testing.T) {
	d, task, round := assessmentFixture(t)
	static := buildSatisfiableObligation(t, d, task, round, DimensionCodeAudit, "code:static")
	dynamic := buildSatisfiableObligation(t, d, task, round, DimensionEntryTest, "entry:api")

	// satisfied 没有证据 → 拒绝。
	if _, err := d.TransitionObligationStatus(static.ID, ObligationPending, ObligationSatisfied,
		TransitionObligationOptions{}); err == nil {
		t.Fatal("无证据的 satisfied 应被拒绝")
	}
	// 执行类维度：有证据但没有有效尝试 → 仍拒绝（静态阅读不等于动态验证）。
	evidenceID := mustEvidence(t, d, task.ID, "src/main.go:10-88")
	if _, err := d.TransitionObligationStatus(dynamic.ID, ObligationPending, ObligationSatisfied,
		TransitionObligationOptions{EvidenceRefID: &evidenceID}); err == nil {
		t.Fatal("执行类维度无有效尝试的 satisfied 应被拒绝")
	}
	// 只有失败尝试仍不足：尝试 outcome=failed 不算有依据的处置。
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: dynamic.ID, Outcome: AttemptFailed, EvidenceRefID: &evidenceID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.TransitionObligationStatus(dynamic.ID, ObligationPending, ObligationSatisfied,
		TransitionObligationOptions{EvidenceRefID: &evidenceID}); err == nil {
		t.Fatal("只有失败尝试时 satisfied 应被拒绝")
	}
	// 有效尝试（supported）之后方可满足。
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: dynamic.ID, Outcome: AttemptSupported, EvidenceRefID: &evidenceID,
	}); err != nil {
		t.Fatal(err)
	}
	if won, err := d.TransitionObligationStatus(dynamic.ID, ObligationPending, ObligationSatisfied,
		TransitionObligationOptions{EvidenceRefID: &evidenceID}); err != nil || !won {
		t.Fatalf("有效尝试后 satisfied 失败: won=%v err=%v", won, err)
	}
	// 静态维度凭证据即可满足。
	if won, err := d.TransitionObligationStatus(static.ID, ObligationPending, ObligationSatisfied,
		TransitionObligationOptions{EvidenceRefID: &evidenceID}); err != nil || !won {
		t.Fatalf("静态维度凭证据 satisfied 失败: won=%v err=%v", won, err)
	}
	// not_applicable 无理由 → 拒绝；有理由 → 允许。
	na := buildSatisfiableObligation(t, d, task, round, DimensionRuntimeAsset, "runtime:db")
	if _, err := d.TransitionObligationStatus(na.ID, ObligationPending, ObligationNotApplicable,
		TransitionObligationOptions{}); err == nil {
		t.Fatal("无理由的 not_applicable 应被拒绝")
	}
	if won, err := d.TransitionObligationStatus(na.ID, ObligationPending, ObligationNotApplicable,
		TransitionObligationOptions{Reason: "范围内不存在运行数据库，环境输入已确认"}); err != nil || !won {
		t.Fatalf("有理由的 not_applicable 失败: won=%v err=%v", won, err)
	}
	// CAS：状态已不再是 pending → 推进落空，不报错也不生效。
	if won, _ := d.TransitionObligationStatus(dynamic.ID, ObligationPending, ObligationBlocked,
		TransitionObligationOptions{Reason: "环境不可达"}); won {
		t.Fatal("CAS 落空时不应视为成功")
	}
}

func TestAssessmentCompletionContractZeroObligationAndZeroTargets(t *testing.T) {
	d, task, round := assessmentFixture(t)
	_ = round
	// 零资产 + 零义务：只有 fact 的空任务不能判完成。
	report, err := d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCannotComplete(t, report, "没有任何已满足或有依据不适用的必需覆盖义务", "没有任何目标对象")

	// 只建目标不改义务：仍不能完成。
	if _, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, EntityType: "service", Name: "user-service",
	}); err != nil {
		t.Fatal(err)
	}
	report, err = d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCannotComplete(t, report, "没有任何已满足或有依据不适用的必需覆盖义务")
}

func TestAssessmentCompletionContractUnresolvedGap(t *testing.T) {
	d, task, round := assessmentFixture(t)
	if _, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, EntityType: "service", Name: "user-service",
	}); err != nil {
		t.Fatal(err)
	}
	// 清单缺口：无法解析的模块，不能静默从分母消失。
	if _, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "module", Name: "legacy-ear",
		Gap: true, GapReason: "解包失败：损坏的 class 文件",
	}); err != nil {
		t.Fatal(err)
	}
	report, err := d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCannotComplete(t, report, "未对账缺口")
}

func TestAssessmentCompletionContractMissingCredentials(t *testing.T) {
	d, task, round := assessmentFixture(t)
	if _, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, EntityType: "service", Name: "admin-console",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionIdentityResource, Required: true,
		Purpose: "管理员租户隔离验证", DedupeKey: "identity:admin", RequiresCredentials: true,
	}); err != nil {
		t.Fatal(err)
	}
	report, err := d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCannotComplete(t, report, "缺少凭证解析")
	if report.Obligations.MissingCredentials != 1 {
		t.Fatalf("缺凭证义务计数=%d want 1", report.Obligations.MissingCredentials)
	}
}

func TestAssessmentCompletionContractFailedOnlyAttempts(t *testing.T) {
	d, task, round := assessmentFixture(t)
	if _, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, EntityType: "entry", Name: "POST /api/login",
	}); err != nil {
		t.Fatal(err)
	}
	obligation := buildSatisfiableObligation(t, d, task, round, DimensionEntryTest, "entry:login")
	evidenceID := mustEvidence(t, d, task.ID, "controller/Login.java")
	// 两条尝试均为失败处置 → 只有失败尝试，不能完成。
	for _, outcome := range []string{AttemptFailed, AttemptEnvMismatch} {
		if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
			TaskID: task.ID, ObligationID: obligation.ID, Outcome: outcome, EvidenceRefID: &evidenceID,
		}); err != nil {
			t.Fatal(err)
		}
	}
	report, err := d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCannotComplete(t, report, "均为失败/未成处置")
	if report.TotalAttempts != 2 || report.EffectiveAttempts != 0 {
		t.Fatalf("尝试统计 total=%d effective=%d want 2/0", report.TotalAttempts, report.EffectiveAttempts)
	}
}

func TestAssessmentCompletionContractWhiteboxQueueRunning(t *testing.T) {
	d, task, round := assessmentFixture(t)
	_ = round
	// 建立一条 queued 白盒审计运行：父任务不能在白盒队列未结束前判完成。
	codebaseID := "wbq-" + strconv.FormatInt(task.ID, 10)
	var serviceID int64
	if err := d.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,latest_present)
VALUES($1,$2,'service','service','confirmed','manual',true) RETURNING id`,
		task.ID, codebaseID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO task_code_audit_runs(task_id,code_service_id,codebase_id,version_id,status)
VALUES($1,$2,$3,'v1','queued')`, task.ID, serviceID, codebaseID); err != nil {
		t.Fatal(err)
	}
	report, err := d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCannotComplete(t, report, "白盒审计队列")
	if report.ActiveWhiteboxRuns != 1 {
		t.Fatalf("白盒在跑计数=%d want 1", report.ActiveWhiteboxRuns)
	}
}

func TestAssessmentCompletionContractActiveIntentsAndEvents(t *testing.T) {
	d, task, round := assessmentFixture(t)
	if _, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, EntityType: "service", Name: "user-service",
	}); err != nil {
		t.Fatal(err)
	}
	// open 意图仍在执行/等待派发 → 不能完成。
	if _, err := d.Exec(`INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
VALUES($1,'intent','{}'::jsonb,0,'open','test')`, task.ExplorationID); err != nil {
		t.Fatal(err)
	}
	report, err := d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCannotComplete(t, report, "open/running 意图")
	// 处理掉意图后，挂一条未处理评估事件 → 仍不能完成。
	if _, err := d.Exec(`UPDATE exploration_nodes SET state='done' WHERE exploration_id=$1 AND kind='intent'`, task.ExplorationID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RecordAssessmentEvent(task.ID, "new_asset", json.RawMessage(`{"asset":"gateway-2"}`)); err != nil {
		t.Fatal(err)
	}
	report, err = d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCannotComplete(t, report, "未处理的评估事件")
	// 事件全部处理 → 该条件放行。
	if n, err := d.MarkAssessmentEventsProcessed(task.ID, 1<<40); err != nil || n != 1 {
		t.Fatalf("事件处理 n=%d err=%v", n, err)
	}
	report, err = d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCannotComplete(t, report) // 仍因零义务不能完成，但不应再提事件/意图
	joined := assessmentReasons(report)
	if strings.Contains(joined, "评估事件") || strings.Contains(joined, "意图") {
		t.Fatalf("已处置的条件仍出现在原因中：%s", joined)
	}
	_ = round
}

func TestAssessmentCompletionContractHappyPath(t *testing.T) {
	d, task, round := assessmentFixture(t)
	if _, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "service", Name: "user-service",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "entry", Name: "GET /api/users",
	}); err != nil {
		t.Fatal(err)
	}
	evidenceStatic := mustEvidence(t, d, task.ID, "src/UserService.java")
	evidenceDyn := mustEvidence(t, d, task.ID, "traffic/req-42")

	// 静态代码审计义务：凭证据满足。
	static := buildSatisfiableObligation(t, d, task, round, DimensionCodeAudit, "code:users")
	if won, err := d.TransitionObligationStatus(static.ID, ObligationPending, ObligationSatisfied,
		TransitionObligationOptions{EvidenceRefID: &evidenceStatic}); err != nil || !won {
		t.Fatalf("静态义务满足失败: won=%v err=%v", won, err)
	}
	// 入口测试义务：有效尝试 + 证据 → 满足。
	entry := buildSatisfiableObligation(t, d, task, round, DimensionEntryTest, "entry:users")
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: entry.ID, Outcome: AttemptSupported, EvidenceRefID: &evidenceDyn,
	}); err != nil {
		t.Fatal(err)
	}
	if won, err := d.TransitionObligationStatus(entry.ID, ObligationPending, ObligationSatisfied,
		TransitionObligationOptions{EvidenceRefID: &evidenceDyn}); err != nil || !won {
		t.Fatalf("入口义务满足失败: won=%v err=%v", won, err)
	}
	// 不适用义务：有依据的例外。
	na := buildSatisfiableObligation(t, d, task, round, DimensionRuntimeAsset, "runtime:none")
	if won, err := d.TransitionObligationStatus(na.ID, ObligationPending, ObligationNotApplicable,
		TransitionObligationOptions{Reason: "本轮为纯静态离线评估，环境输入为空"}); err != nil || !won {
		t.Fatalf("不适用义务失败: won=%v err=%v", won, err)
	}

	report, err := d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !report.CanComplete {
		t.Fatalf("预期可完成但契约未通过：%s", assessmentReasons(report))
	}
	if report.Obligations.Satisfied != 2 || report.Obligations.NotApplicable != 1 {
		t.Fatalf("义务统计 satisfied=%d not_applicable=%d want 2/1",
			report.Obligations.Satisfied, report.Obligations.NotApplicable)
	}
}
