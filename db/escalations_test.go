package db

import (
	"context"
	"strings"
	"testing"
	"time"
)

// 提案状态机：只有人能批，只有 proposed 能批，批准有窗口，同一漏洞同等级不重复堆积。
func TestEscalationLifecycle(t *testing.T) {
	d := openProjectTestDB(t)
	ctx := context.Background()
	task, err := d.CreateTask(testProjectID(t, d), "escalation "+time.Now().Format("150405.000000"), "g", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteFindingsByTask(task.ID); d.DeleteTask(task.ID) })
	findingID, err := d.AddFinding(task.ID, 0, "SQLi", "布尔差异", "high", "s", "e", "w", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM finding_escalations WHERE finding_id=$1`, findingID) })

	base := EscalationInput{
		FindingID: findingID, Level: "L3", Title: "读取应用配置确认凭据泄露面",
		Objective: "评估 RCE 的实际危害", Steps: "1. cat /app/config.yml",
		ExpectedImpact: "可能读到数据库凭据", RollbackPlan: "只读，无残留",
		StopConditions: []string{"看到凭据即停"}, ProposedBy: "worker",
	}
	// 必填项缺失要被拒，避免空壳提案进审核列表。
	bad := base
	bad.Steps = "  "
	if _, err := d.CreateEscalation(ctx, bad); err == nil {
		t.Fatal("empty steps must be rejected")
	}
	bad = base
	bad.Level = "L4"
	if _, err := d.CreateEscalation(ctx, bad); err == nil {
		t.Fatal("L4 must be rejected")
	}

	e, err := d.CreateEscalation(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != EscalationProposed || e.ProjectID != testProjectID(t, d) {
		t.Fatalf("created = %+v", e)
	}
	// agent 反复提同一件事 → 更新原提案，不新增行。
	upd := base
	upd.Steps = "1. cat /app/config.yml\n2. 记录返回内容"
	again, err := d.CreateEscalation(ctx, upd)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != e.ID {
		t.Fatalf("duplicate pending proposal created a new row: %d vs %d", again.ID, e.ID)
	}
	if !strings.Contains(again.Steps, "记录返回内容") {
		t.Fatal("proposal content was not refreshed")
	}

	approved, err := d.DecideEscalation(ctx, e.ID, true, "admin@test", "同意，注意别读业务表", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != EscalationApproved || approved.ExpiresAt == nil {
		t.Fatalf("approved = %+v", approved)
	}
	// 不能重复审批：已决策的提案再点一次不该改变结论。
	if _, err := d.DecideEscalation(ctx, e.ID, false, "admin@test", "反悔", 0); err == nil {
		t.Fatal("deciding twice must fail")
	}

	running, err := d.MarkEscalationRunning(ctx, e.ID, 77)
	if err != nil {
		t.Fatal(err)
	}
	if running.Status != EscalationRunning || running.RunID == nil || *running.RunID != 77 {
		t.Fatalf("running = %+v", running)
	}
	done, err := d.MarkEscalationFinished(ctx, e.ID, EscalationExecuted, "read")
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != EscalationExecuted || done.ImpactObserved != "read" {
		t.Fatalf("finished = %+v", done)
	}

	list, err := d.ListEscalations(ctx, findingID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v %v", list, err)
	}
	// 执行完的提案不再占待审位：同等级可以再提一条新的。
	if _, err := d.CreateEscalation(ctx, base); err != nil {
		t.Fatalf("new proposal after execution: %v", err)
	}
	n, err := d.ExpireStaleApprovals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = n
}

// 过期的批准必须自己失效，否则页面上会一直显示"可以执行"。
func TestEscalationApprovalExpires(t *testing.T) {
	d := openProjectTestDB(t)
	ctx := context.Background()
	task, err := d.CreateTask(testProjectID(t, d), "escalation ttl "+time.Now().Format("150405.000000"), "g", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteFindingsByTask(task.ID); d.DeleteTask(task.ID) })
	findingID, err := d.AddFinding(task.ID, 0, "RCE", "命令执行", "critical", "s", "e", "w", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM finding_escalations WHERE finding_id=$1`, findingID) })
	e, err := d.CreateEscalation(ctx, EscalationInput{
		FindingID: findingID, Level: "L2", Title: "读取一条他人订单", Steps: "1. GET /api/order/2",
		ExpectedImpact: "读到 1 条他人数据", RollbackPlan: "只读", StopConditions: []string{"超时即停"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DecideEscalation(ctx, e.ID, true, "admin", "", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := d.ExpireStaleApprovals(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetEscalation(ctx, e.ID)
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if got.Status != EscalationExpired {
		t.Fatalf("status = %s, want expired", got.Status)
	}
	if _, err := d.MarkEscalationRunning(ctx, e.ID, 1); err == nil {
		t.Fatal("expired approval must not start a run")
	}
}
