package db

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"
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

// mustExecutionEvidence 写入一条执行输出类证据：它是尝试自带执行关联的
// 合法载体之一（静态 code_range 证据不算执行关联）。
func mustExecutionEvidence(t *testing.T, d *DB, taskID int64, reference string) int64 {
	t.Helper()
	id, err := d.CreateEvidenceRef(taskID, EvidenceExecution, reference, json.RawMessage(`{"stdout":"`+reference+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// mustIntentNode 写入一个意图节点并返回其 id，作为尝试的执行关联。
func mustIntentNode(t *testing.T, d *DB, task *Task) int64 {
	t.Helper()
	var id int64
	if err := d.QueryRow(`INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
VALUES($1,'intent','{}'::jsonb,0,'done','test') RETURNING id`, task.ExplorationID).Scan(&id); err != nil {
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
	// 有效尝试（supported，带执行关联）之后方可满足。
	intentNode := mustIntentNode(t, d, task)
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: dynamic.ID, Outcome: AttemptSupported, EvidenceRefID: &evidenceID,
		IntentNodeID: &intentNode,
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
	// 入口测试义务：带执行关联的有效尝试 + 证据 → 满足。
	entry := buildSatisfiableObligation(t, d, task, round, DimensionEntryTest, "entry:users")
	execEvidence := mustExecutionEvidence(t, d, task.ID, "exec/users-42")
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: entry.ID, Outcome: AttemptSupported, EvidenceRefID: &execEvidence,
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

// ---------- Review 整改回归测试 ----------

// TestObligationSatisfiedRequiresBoundCredentials（P1）：
// requires_credentials 的义务未绑定凭证引用时不能被置为 satisfied，
// 完成判定的缺凭证统计也必须覆盖已 satisfied 的义务。
func TestObligationSatisfiedRequiresBoundCredentials(t *testing.T) {
	d, task, round := assessmentFixture(t)
	if _, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "entry", Name: "POST /api/login",
	}); err != nil {
		t.Fatal(err)
	}
	obligation, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionEntryTest, Required: true,
		Purpose: "管理员登录验证", DedupeKey: "entry:admin", RequiresCredentials: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence := mustEvidence(t, d, task.ID, "controller/AdminLogin.java")
	intentNode := mustIntentNode(t, d, task)
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: obligation.ID, Outcome: AttemptSupported,
		EvidenceRefID: &evidence, IntentNodeID: &intentNode,
	}); err != nil {
		t.Fatal(err)
	}
	// 证据、尝试齐备但凭证未绑定 → satisfied 拒绝。
	if _, err := d.TransitionObligationStatus(obligation.ID, ObligationPending, ObligationSatisfied,
		TransitionObligationOptions{EvidenceRefID: &evidence}); err == nil {
		t.Fatal("缺凭证的义务不应能置为 satisfied")
	}
	// 即使历史数据里已经存在缺凭证的 satisfied 记录（绕过转移），完成判定的
	// 缺凭证统计也必须拦截它——satisfied 不豁免凭证要求。
	if _, err := d.Exec(`UPDATE task_coverage_obligations SET status='satisfied', evidence_ref_id=$2 WHERE id=$1`,
		obligation.ID, evidence); err != nil {
		t.Fatal(err)
	}
	report, err := d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCannotComplete(t, report, "缺少凭证解析")
	if report.Obligations.MissingCredentials != 1 {
		t.Fatalf("缺凭证计数=%d want 1", report.Obligations.MissingCredentials)
	}
}

// TestObligationDedupeScopesToRounds（P2）：同一 dedupe_key 在新一轮次必须
// 建出新义务（旧轮次记录不能吞掉新轮次的派工），同轮次内仍幂等。
func TestObligationDedupeScopesToRounds(t *testing.T) {
	d, task, round := assessmentFixture(t)
	in := CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionCodeAudit, Required: true,
		Purpose: "共享库审计", DedupeKey: "code:shared:auth-lib",
	}
	first, err := d.CreateCoverageObligation(in)
	if err != nil {
		t.Fatal(err)
	}
	again, err := d.CreateCoverageObligation(in)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != again.ID {
		t.Fatalf("同轮次重复规划产生重复义务：%d != %d", first.ID, again.ID)
	}
	// 开新一轮次：同 key 必须得到新义务，而不是旧轮次的历史记录。
	if err := d.CompleteAssessmentRound(task.ID, round.ID, json.RawMessage(`{"superseded":true}`)); err != nil {
		t.Fatal(err)
	}
	second, err := d.CreateAssessmentRound(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	in.RoundID = &second.ID
	reborn, err := d.CreateCoverageObligation(in)
	if err != nil {
		t.Fatal(err)
	}
	if reborn.ID == first.ID || reborn.RoundID == nil || *reborn.RoundID != second.ID {
		t.Fatalf("新轮次同 key 未建新义务: got id=%d round=%v want new id round=%d", reborn.ID, reborn.RoundID, second.ID)
	}
}

// TestAssessmentCompletionScopesToCurrentRound（P2）：目标/缺口/尝试按当前
// 轮次统计——历史轮次的目标与成功尝试不能让新一轮次的空图/纯失败判定通过。
func TestAssessmentCompletionScopesToCurrentRound(t *testing.T) {
	d, task, round := assessmentFixture(t)
	// 旧轮次：齐备的目标 + 成功尝试 + satisfied 义务。
	if _, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "service", Name: "legacy-service",
	}); err != nil {
		t.Fatal(err)
	}
	obligation := buildSatisfiableObligation(t, d, task, round, DimensionEntryTest, "entry:legacy")
	evidence := mustExecutionEvidence(t, d, task.ID, "exec/legacy-1")
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: obligation.ID, Outcome: AttemptSupported, EvidenceRefID: &evidence,
	}); err != nil {
		t.Fatal(err)
	}
	if won, err := d.TransitionObligationStatus(obligation.ID, ObligationPending, ObligationSatisfied,
		TransitionObligationOptions{EvidenceRefID: &evidence}); err != nil || !won {
		t.Fatalf("旧轮次义务满足失败: won=%v err=%v", won, err)
	}
	if err := d.CompleteAssessmentRound(task.ID, round.ID, json.RawMessage(`{"can_complete":true}`)); err != nil {
		t.Fatal(err)
	}
	newRound, err := d.CreateAssessmentRound(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	// 新轮次：没有任何目标/义务/尝试——历史轮次的记录一律不得计入。
	report, err := d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCannotComplete(t, report,
		"没有任何已满足或有依据不适用的必需覆盖义务", "没有任何目标对象")
	if report.TargetCount != 0 || report.TotalAttempts != 0 || report.Obligations.Satisfied != 0 {
		t.Fatalf("历史轮次数据泄漏到新轮次统计: targets=%d attempts=%d satisfied=%d",
			report.TargetCount, report.TotalAttempts, report.Obligations.Satisfied)
	}
	if report.RoundID != newRound.ID {
		t.Fatalf("判定轮次=%d want %d", report.RoundID, newRound.ID)
	}
}

// TestRecordTestAttemptValidatesOwnership（P2）：尝试与证据必须归属本任务，
// 跨任务/跨项目引用直接拒绝，防止他人记录被计入本任务覆盖率。
func TestRecordTestAttemptValidatesOwnership(t *testing.T) {
	d, task, round := assessmentFixture(t)
	otherDB, otherTask, otherRound := assessmentFixture(t)
	obligation := buildSatisfiableObligation(t, d, task, round, DimensionEntryTest, "entry:mine")
	foreignObligation := buildSatisfiableObligation(t, otherDB, otherTask, otherRound, DimensionEntryTest, "entry:theirs")
	foreignEvidence := mustEvidence(t, d, otherTask.ID, "controller/Theirs.java")

	// 尝试写到不属于本任务的义务上 → 拒绝。
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: foreignObligation.ID, Outcome: AttemptSupported,
	}); err == nil {
		t.Fatal("跨任务的义务登记尝试不应成功")
	}
	// 本任务义务 + 他任务证据 → 拒绝。
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: obligation.ID, Outcome: AttemptFailed,
		EvidenceRefID: &foreignEvidence,
	}); err == nil {
		t.Fatal("他任务证据不应能挂到本任务尝试上")
	}
	// 转移终态时引用他任务证据 → 拒绝。
	if _, err := d.TransitionObligationStatus(obligation.ID, ObligationPending, ObligationSatisfied,
		TransitionObligationOptions{EvidenceRefID: &foreignEvidence}); err == nil {
		t.Fatal("他任务证据不应能支撑本任务义务 satisfy")
	}
	// 合法路径仍可用。
	intentNode := mustIntentNode(t, d, task)
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: obligation.ID, Outcome: AttemptSupported,
		IntentNodeID: &intentNode,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestEffectiveAttemptRequiresExecutionLinkage（P2）：只有 supported 标记、
// 没有任何执行关联（意图节点/白盒运行/执行输出证据）的尝试不算已执行；
// 静态 code_range 证据同样不能充当执行关联。
func TestEffectiveAttemptRequiresExecutionLinkage(t *testing.T) {
	d, task, round := assessmentFixture(t)
	obligation := buildSatisfiableObligation(t, d, task, round, DimensionEntryTest, "entry:linkage")
	staticEvidence := mustEvidence(t, d, task.ID, "controller/Legacy.java")
	// 裸 supported 尝试 → 拒绝。
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: obligation.ID, Outcome: AttemptSupported,
	}); err == nil {
		t.Fatal("无执行关联的有效处置尝试不应被登记")
	}
	// supported + 静态证据 → 仍拒绝。
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: obligation.ID, Outcome: AttemptSupported,
		EvidenceRefID: &staticEvidence,
	}); err == nil {
		t.Fatal("静态证据不应充当执行关联")
	}
	// satisfied 依据执行关联缺失的尝试 → 拒绝。
	if _, err := d.TransitionObligationStatus(obligation.ID, ObligationPending, ObligationSatisfied,
		TransitionObligationOptions{EvidenceRefID: &staticEvidence}); err == nil {
		t.Fatal("执行类维度凭静态证据与裸尝试不应满足")
	}
	// 失败类尝试无执行关联仍可登记（失败处置本身不需要"已执行"依据链）。
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: obligation.ID, Outcome: AttemptFailed,
	}); err != nil {
		t.Fatal(err)
	}
	// 执行输出证据的 supported 尝试 → 通过。
	execEvidence := mustExecutionEvidence(t, d, task.ID, "exec/linkage-9")
	if _, err := d.RecordTestAttempt(RecordTestAttemptInput{
		TaskID: task.ID, ObligationID: obligation.ID, Outcome: AttemptSupported,
		EvidenceRefID: &execEvidence,
	}); err != nil {
		t.Fatal(err)
	}
	if won, err := d.TransitionObligationStatus(obligation.ID, ObligationPending, ObligationSatisfied,
		TransitionObligationOptions{EvidenceRefID: &staticEvidence}); err != nil || !won {
		t.Fatalf("带执行关联的有效尝试后应可满足: won=%v err=%v", won, err)
	}
}

// TestTransitionRejectsBlankReason（P3）：纯空白 reason 不能把义务置为
// not_applicable/blocked/stale；完成检查也要拦截已存在的无理由例外记录。
func TestTransitionRejectsBlankReason(t *testing.T) {
	d, task, round := assessmentFixture(t)
	na := buildSatisfiableObligation(t, d, task, round, DimensionRuntimeAsset, "runtime:blank")
	if _, err := d.TransitionObligationStatus(na.ID, ObligationPending, ObligationNotApplicable,
		TransitionObligationOptions{Reason: "   "}); err == nil {
		t.Fatal("空白 reason 的 not_applicable 应被拒绝")
	}
	// 历史脏数据：无理由的 not_applicable（绕过转移直接落库）→ 完成检查拦截。
	if _, err := d.Exec(`UPDATE task_coverage_obligations SET status='not_applicable', not_applicable_reason='' WHERE id=$1`,
		na.ID); err != nil {
		t.Fatal(err)
	}
	report, err := d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCannotComplete(t, report, "缺少可审计的不适用理由")
}

// TestRecordTestAttemptConcurrentNumbering（P2）：并发登记同一义务的尝试时，
// 行锁串行化编号分配——全部登记成功且 attempt_no 无重复。
func TestRecordTestAttemptConcurrentNumbering(t *testing.T) {
	d, task, round := assessmentFixture(t)
	obligation := buildSatisfiableObligation(t, d, task, round, DimensionEntryTest, "entry:concurrent")
	execEvidence := mustExecutionEvidence(t, d, task.ID, "exec/concurrent")
	const n = 5
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = d.RecordTestAttempt(RecordTestAttemptInput{
				TaskID: task.ID, ObligationID: obligation.ID,
				Outcome:       []string{AttemptSupported, AttemptDisproved, AttemptUnreproduced}[i%3],
				EvidenceRefID: &execEvidence,
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("并发登记 %d 失败: %v", i, err)
		}
	}
	var distinct, max int64
	if err := d.QueryRow(`SELECT count(DISTINCT attempt_no), max(attempt_no) FROM task_test_attempts WHERE obligation_id=$1`,
		obligation.ID).Scan(&distinct, &max); err != nil {
		t.Fatal(err)
	}
	if distinct != n || max != n {
		t.Fatalf("编号分配 distinct=%d max=%d want %d/%d", distinct, max, n, n)
	}
}

// TestFinalizeAssessmentCompletion Atomicity（P1）：
// 白盒队列在锁下非空时收尾放弃（won=false，任务保持运行、轮次保持 open）；
// 收尾成功时终态/轮次/阶段一次落库；任务已是终态时 won=false 不改历史。
func TestFinalizeAssessmentCompletionAtomicity(t *testing.T) {
	d, task, round := assessmentFixture(t)
	if _, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "service", Name: "user-service",
	}); err != nil {
		t.Fatal(err)
	}
	evidence := mustEvidence(t, d, task.ID, "src/UserService.java")
	obligation := buildSatisfiableObligation(t, d, task, round, DimensionCodeAudit, "code:users")
	if won, err := d.TransitionObligationStatus(obligation.ID, ObligationPending, ObligationSatisfied,
		TransitionObligationOptions{EvidenceRefID: &evidence}); err != nil || !won {
		t.Fatalf("义务满足失败: won=%v err=%v", won, err)
	}
	report, err := d.AssessmentCompletionCheck(task.ID)
	if err != nil || !report.CanComplete {
		t.Fatalf("前置场景应可完成: report=%+v err=%v", report, err)
	}
	reportJSON, _ := json.Marshal(report)

	// 并发入队使队列非空 → 收尾放弃，任务不落终态、轮次保持 open。
	codebaseID := "fin-" + strconv.FormatInt(task.ID, 10)
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
	if _, err := d.Exec(`UPDATE tasks SET assessment_mode=true WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	_, _, won, err := d.FinalizeAssessmentCompletion(task.ID, report.RoundID, reportJSON)
	if err != nil {
		t.Fatal(err)
	}
	if won {
		t.Fatal("白盒队列非空时不应完成收尾")
	}
	var status, roundStatus, phase string
	if err := d.QueryRow(`SELECT status FROM tasks WHERE id=$1`, task.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT status FROM task_assessment_rounds WHERE id=$1`, round.ID).Scan(&roundStatus); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT assessment_phase FROM tasks WHERE id=$1`, task.ID).Scan(&phase); err != nil {
		t.Fatal(err)
	}
	if status == "done" || roundStatus != "open" || phase == AssessmentPhaseCompleted {
		t.Fatalf("被放弃的收尾不应留下任何写入: status=%q round=%q phase=%q", status, roundStatus, phase)
	}

	// 队列清空后收尾成功：终态/轮次/阶段一次落库。
	if _, err := d.Exec(`UPDATE task_code_audit_runs SET status='completed' WHERE task_id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	_, _, won, err = d.FinalizeAssessmentCompletion(task.ID, report.RoundID, reportJSON)
	if err != nil || !won {
		t.Fatalf("队列清空后收尾应成功: won=%v err=%v", won, err)
	}
	if err := d.QueryRow(`SELECT status, assessment_phase FROM tasks WHERE id=$1`, task.ID).Scan(&status, &phase); err != nil {
		t.Fatal(err)
	}
	if status != "done" || phase != AssessmentPhaseCompleted {
		t.Fatalf("收尾后 status=%q phase=%q want done/completed", status, phase)
	}
	var persisted []byte
	if err := d.QueryRow(`SELECT completion_report FROM task_assessment_rounds WHERE id=$1`, round.ID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted) == 0 {
		t.Fatal("收尾后轮次缺少完成报告")
	}
	// 任务已终态 → 再次收尾 won=false，不覆盖历史。
	_, _, won, err = d.FinalizeAssessmentCompletion(task.ID, report.RoundID, reportJSON)
	if err != nil || won {
		t.Fatalf("终态重复收尾应落空: won=%v err=%v", won, err)
	}
}

// TestCreateTaskCodeAuditRejectsTerminalAssessmentTask（P1）：
// 终态后的评估模式任务不能再入队白盒审计；非评估任务不受影响。
func TestCreateTaskCodeAuditRejectsTerminalAssessmentTask(t *testing.T) {
	d, task, _ := assessmentFixture(t)
	codebaseID := "audit-" + strconv.FormatInt(task.ID, 10)
	var serviceID int64
	if err := d.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,latest_present,latest_version_id)
VALUES($1,$2,'service','service','confirmed','manual',true,'v1') RETURNING id`,
		task.ID, codebaseID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	// 传统/非终态任务可入队。
	if _, err := d.CreateTaskCodeAudit(CreateTaskCodeAudit{
		TaskID: task.ID, CodeServiceID: serviceID, CodebaseID: codebaseID, VersionID: "v1",
	}); err != nil {
		t.Fatalf("非终态任务入队失败: %v", err)
	}
	// 评估模式 + 终态 → 拒绝。
	if _, err := d.Exec(`UPDATE tasks SET assessment_mode=true, status='done' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateTaskCodeAudit(CreateTaskCodeAudit{
		TaskID: task.ID, CodeServiceID: serviceID, CodebaseID: codebaseID, VersionID: "v1",
	}); err == nil {
		t.Fatal("终态评估任务入队应被拒绝")
	}
	// 评估模式非终态 → 允许。
	if _, err := d.Exec(`UPDATE tasks SET status='running' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateTaskCodeAudit(CreateTaskCodeAudit{
		TaskID: task.ID, CodeServiceID: serviceID, CodebaseID: codebaseID, VersionID: "v1",
	}); err != nil {
		t.Fatalf("非终态评估任务入队失败: %v", err)
	}
}
