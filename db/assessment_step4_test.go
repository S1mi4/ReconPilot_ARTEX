package db

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

func TestStep4IdempotentObligationCreationAndRoundScoping(t *testing.T) {
	d, task, round := assessmentFixture(t)

	ent, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "service", Name: "order-svc",
	})
	if err != nil {
		t.Fatal(err)
	}
	evID := mustEvidence(t, d, task.ID, "order-svc/Controller.java:10")

	ob1, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID:         task.ID,
		RoundID:        &round.ID,
		Dimension:      DimensionCodeAudit,
		TargetEntityID: &ent.ID,
		Purpose:        "白盒审计 order-svc",
		Required:       true,
		DedupeKey:      "code_audit:service:-:order-svc",
		InitialStatus:  ObligationReady,
		ExecutionMode:  ExecModeCodeAuditBatch,
		Origin:         ObligationOriginProgram,
		Priority:       8,
		ProfileVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	ok, err := d.TransitionObligationStatus(ob1.ID, ObligationReady, ObligationSatisfied, TransitionObligationOptions{
		EvidenceRefID: &evID,
	})
	if err != nil || !ok {
		t.Fatalf("satisfy obligation failed: ok=%v err=%v", ok, err)
	}

	// Re-planning in the same round with the same dedupe_key must return existing row
	// without resetting status='satisfied' or evidence_ref_id.
	ob1Again, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID:         task.ID,
		RoundID:        &round.ID,
		Dimension:      DimensionCodeAudit,
		TargetEntityID: &ent.ID,
		Purpose:        "重复生成白盒审计 order-svc",
		Required:       true,
		DedupeKey:      "code_audit:service:-:order-svc",
		InitialStatus:  ObligationPending,
		ExecutionMode:  ExecModeCodeAuditBatch,
		Origin:         ObligationOriginProgram,
		Priority:       3,
		ProfileVersion: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ob1Again.ID != ob1.ID {
		t.Fatalf("expected idempotent obligation ID %d, got %d", ob1.ID, ob1Again.ID)
	}
	if ob1Again.Status != ObligationSatisfied || ob1Again.EvidenceRefID == nil || *ob1Again.EvidenceRefID != evID {
		t.Fatalf("replan clobbered satisfied obligation: %+v", ob1Again)
	}

	// Completing round 1 and opening round 2 allows recreating the same dedupe_key in round 2.
	if err := d.CompleteAssessmentRound(task.ID, round.ID, json.RawMessage(`{"can_complete":true}`)); err != nil {
		t.Fatal(err)
	}
	round2, err := d.CreateAssessmentRound(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	ent2, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round2.ID, EntityType: "service", Name: "order-svc",
	})
	if err != nil {
		t.Fatal(err)
	}
	ob2, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID:         task.ID,
		RoundID:        &round2.ID,
		Dimension:      DimensionCodeAudit,
		TargetEntityID: &ent2.ID,
		Purpose:        "第 2 轮白盒审计 order-svc",
		Required:       true,
		DedupeKey:      "code_audit:service:-:order-svc",
		ExecutionMode:  ExecModeCodeAuditBatch,
		Origin:         ObligationOriginProgram,
		ProfileVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ob2.ID == ob1.ID || ob2.RoundID == nil || *ob2.RoundID != round2.ID || ob2.Status != ObligationPending {
		t.Fatalf("expected fresh round-2 obligation, got %+v", ob2)
	}
}

func TestStep4DependencyReadinessCycleAndEdgeIsolation(t *testing.T) {
	d, task, round := assessmentFixture(t)
	es := d.Exploration(task.ExplorationID)

	entRT, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "instance", Name: "staging-api",
	})
	if err != nil {
		t.Fatal(err)
	}
	entEntry, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "entry", Name: "GET /api/orders",
	})
	if err != nil {
		t.Fatal(err)
	}
	entCode, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "service", Name: "order-svc",
	})
	if err != nil {
		t.Fatal(err)
	}

	obRT, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionRuntimeAsset, TargetEntityID: &entRT.ID,
		Purpose: "核实实例 staging-api", Required: true, DedupeKey: "runtime_asset:staging",
		ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram, Priority: 9,
	})
	if err != nil {
		t.Fatal(err)
	}
	obEntry, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionEntryTest, TargetEntityID: &entEntry.ID,
		Purpose: "测试入口 GET /api/orders", Required: true, DedupeKey: "entry:orders",
		ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram, Priority: 7,
		DependencyIDs: []int64{obRT.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	obCred, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionIdentityResource,
		Purpose: "验证管理员身份边界", Required: true, DedupeKey: "identity:admin",
		RequiresCredentials: true, CredentialRef: "",
		ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram, Priority: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	obCode, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionCodeAudit, TargetEntityID: &entCode.ID,
		Purpose: "白盒审计 order-svc", Required: true, DedupeKey: "code_audit:order-svc",
		ExecutionMode: ExecModeCodeAuditBatch, Origin: ObligationOriginProgram, Priority: 8,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Add an incomplete open exploration intent and derived_from edges to prove
	// exploration_edges never acts as an execution dependency for obligations.
	openFactID, err := es.AddNode(KindFact, map[string]any{"summary": "runtime probe pending"}, 5, "confirmed", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	openIntentID, err := es.AddIntent(map[string]any{"summary": "unrelated open intent"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	_ = es.Link(openIntentID, RelDerivedFrom, openFactID)

	readyCnt, blockedCnt, err := d.ReconcileObligationReadiness(task.ID, round.ID)
	if err != nil {
		t.Fatal(err)
	}
	if readyCnt != 2 || blockedCnt != 1 {
		t.Fatalf("reconcile expected ready=2 (obRT+obCode) blocked=1 (obCred), got ready=%d blocked=%d", readyCnt, blockedCnt)
	}

	gotEntry, err := d.GetCoverageObligation(task.ID, obEntry.ID)
	if err != nil || gotEntry == nil {
		t.Fatalf("get obEntry failed: %v", err)
	}
	if gotEntry.Status != ObligationPending || len(gotEntry.UnmetDependencyIDs) != 1 || gotEntry.UnmetDependencyIDs[0] != obRT.ID {
		t.Fatalf("expected obEntry pending waiting on %d, got %+v", obRT.ID, gotEntry)
	}

	// Self-dependency / cyclic dependency_ids must be rejected with ErrObligationDependencyCycle.
	if _, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionRuntimeAsset,
		Purpose: "cycle self", Required: true, DedupeKey: "runtime_asset:staging",
		DependencyIDs: []int64{obRT.ID},
	}); !errors.Is(err, ErrObligationDependencyCycle) {
		t.Fatalf("expected ErrObligationDependencyCycle on self-dep, got %v", err)
	}
	if _, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionRuntimeAsset,
		Purpose: "cycle mutual", Required: true, DedupeKey: "runtime_asset:staging",
		DependencyIDs: []int64{obEntry.ID},
	}); !errors.Is(err, ErrObligationDependencyCycle) {
		t.Fatalf("expected ErrObligationDependencyCycle on mutual cycle, got %v", err)
	}

	// Providing credential_ref and reopening blocked obligation transitions it to ready on reconcile.
	if _, err := d.Exec(`UPDATE task_coverage_obligations SET credential_ref='vault://staging/admin', status='pending', blocked_reason='' WHERE id=$1`, obCred.ID); err != nil {
		t.Fatal(err)
	}
	readyCnt2, _, err := d.ReconcileObligationReadiness(task.ID, round.ID)
	if err != nil || readyCnt2 != 1 {
		t.Fatalf("expected obCred to reconcile to ready, readyCnt=%d err=%v", readyCnt2, err)
	}
	_ = obCode
}

func TestStep4IdempotentAndConcurrentDispatchAndRejection(t *testing.T) {
	d, task, round := assessmentFixture(t)

	obRT, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionRuntimeAsset,
		Purpose: "核实实例", Required: true, DedupeKey: "rt:1", InitialStatus: ObligationReady,
		ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram, Priority: 9,
	})
	if err != nil {
		t.Fatal(err)
	}
	obEntry, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionEntryTest,
		Purpose: "入口测试", Required: true, DedupeKey: "entry:1",
		ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram, Priority: 7,
		DependencyIDs: []int64{obRT.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	obCred, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionIdentityResource,
		Purpose: "身份越权测试", Required: true, DedupeKey: "id:admin",
		RequiresCredentials: true, CredentialRef: "", InitialStatus: ObligationReady,
		ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Unmet dependency dispatch rejection.
	if _, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obEntry.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "未就绪入口测试",
	}); !errors.Is(err, ErrObligationDependencyUnmet) {
		t.Fatalf("expected ErrObligationDependencyUnmet, got %v", err)
	}

	// 2. Missing credentials rejection.
	if _, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obCred.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "缺凭证身份测试",
	}); !errors.Is(err, ErrObligationCredentialsMissing) {
		t.Fatalf("expected ErrObligationCredentialsMissing, got %v", err)
	}

	// 3. Invalid (dimension, execution_mode) combinations.
	if _, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obRT.ID,
		ExecutionMode: ExecModeCodeAuditBatch, Summary: "错误模式",
	}); !errors.Is(err, ErrExecutionModeInvalid) {
		t.Fatalf("expected ErrExecutionModeInvalid, got %v", err)
	}
	if err := ValidateObligationExecutionMode(DimensionRuntimeAsset, ExecModeDynamicVerify, AssessmentExecOffline); !errors.Is(err, ErrExecutionModeInvalid) {
		t.Fatalf("expected ErrExecutionModeInvalid for offline dynamic_verify, got %v", err)
	}

	// 4. Concurrent dispatch on obRT must produce exactly 1 open intent and 1 attempt.
	const n = 8
	results := make([]*DispatchAssessmentIntentResult, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			results[i], errs[i] = d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
				TaskID: task.ID, RoundID: round.ID, ObligationID: obRT.ID,
				ExecutionMode: ExecModeDynamicVerify, Summary: "核实运行环境",
			})
		}()
	}
	wg.Wait()

	freshCount := 0
	var intentID, attemptID int64
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d failed: %v", i, errs[i])
		}
		if results[i] == nil || results[i].IntentID <= 0 || results[i].AttemptID <= 0 {
			t.Fatalf("goroutine %d invalid result: %+v", i, results[i])
		}
		if !results[i].AlreadyActive {
			freshCount++
		}
		if intentID == 0 {
			intentID = results[i].IntentID
			attemptID = results[i].AttemptID
		} else if results[i].IntentID != intentID || results[i].AttemptID != attemptID {
			t.Fatalf("concurrent dispatch produced multiple intents/attempts: (%d,%d) vs (%d,%d)",
				results[i].IntentID, results[i].AttemptID, intentID, attemptID)
		}
	}
	if freshCount != 1 {
		t.Fatalf("expected exactly 1 fresh dispatch, got %d", freshCount)
	}

	// Sequential re-dispatch also returns AlreadyActive=true.
	again, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obRT.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "再次核实运行环境",
	})
	if err != nil || !again.AlreadyActive || again.IntentID != intentID || again.AttemptID != attemptID {
		t.Fatalf("expected idempotent re-dispatch, got %+v err=%v", again, err)
	}

	attempts, err := d.ListTestAttempts(task.ID, round.ID, obRT.ID, 10)
	if err != nil || len(attempts) != 1 {
		t.Fatalf("expected 1 attempt row, got %+v err=%v", attempts, err)
	}
}

func TestStep4EvidenceAndAntiDowngradeGuardrails(t *testing.T) {
	d, task, round := assessmentFixture(t)

	evExec, err := d.CreateEvidenceRef(task.ID, EvidenceExecution, "exec/runtime-probe-1", json.RawMessage(`{"status":200}`))
	if err != nil {
		t.Fatal(err)
	}
	evCode, err := d.CreateEvidenceRef(task.ID, EvidenceCodeRange, "src/OrderController.java:18", nil)
	if err != nil {
		t.Fatal(err)
	}

	obRT, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionRuntimeAsset,
		Purpose: "核实实例", Required: true, DedupeKey: "rt:ev", InitialStatus: ObligationReady,
		ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}
	obEntry, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionEntryTest,
		Purpose: "测试入口 POST /orders", Required: true, DedupeKey: "entry:ev",
		ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
		DependencyIDs: []int64{obRT.ID},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Dispatch obRT, try to satisfy without EvidenceRefID -> must NOT advance.
	d1, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obRT.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "无证据核实实例",
	})
	if err != nil {
		t.Fatal(err)
	}
	f1, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: obRT.ID, AttemptID: d1.AttemptID,
		Outcome: AttemptSupported, EvidenceRefID: nil, SatisfyObligation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !f1.InsufficientEvidence || f1.ObligationAdvanced || f1.NewObligationStatus != ObligationReady {
		t.Fatalf("expected insufficient evidence non-advancement, got %+v", f1)
	}
	obRTCheck, err := d.GetCoverageObligation(task.ID, obRT.ID)
	if err != nil || obRTCheck.Status != ObligationReady || obRTCheck.ActiveAttemptID != nil {
		t.Fatalf("expected obRT back in ready with nil active attempt, got %+v err=%v", obRTCheck, err)
	}

	// Mark intent done so next dispatch creates a fresh attempt.
	if err := d.Exploration(task.ExplorationID).SetIntentState(d1.IntentID, "done"); err != nil {
		t.Fatal(err)
	}

	// 2. Dispatch obRT again, satisfy with valid evExec -> promotes obRT to satisfied & unlocks obEntry!
	d2, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obRT.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "带证据核实实例",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.MarkObligationAttemptRunning(task.ID, obRT.ID, d2.AttemptID); err != nil || !ok {
		t.Fatalf("mark running failed: ok=%v err=%v", ok, err)
	}
	f2, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: obRT.ID, AttemptID: d2.AttemptID,
		Outcome: AttemptSupported, EvidenceRefID: &evExec, SatisfyObligation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !f2.ObligationAdvanced || f2.NewObligationStatus != ObligationSatisfied || f2.UnlockedCount != 1 {
		t.Fatalf("expected obRT satisfied & 1 unlocked dep, got %+v", f2)
	}
	_ = d.Exploration(task.ExplorationID).SetIntentState(d2.IntentID, "done")

	gotEntry, err := d.GetCoverageObligation(task.ID, obEntry.ID)
	if err != nil || gotEntry.Status != ObligationReady || len(gotEntry.UnmetDependencyIDs) != 0 {
		t.Fatalf("expected obEntry unlocked to ready, got %+v err=%v", gotEntry, err)
	}

	// 3. Anti-downgrade: static read-only code_investigate CANNOT satisfy entry_test.
	d3, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obEntry.ID,
		ExecutionMode: ExecModeCodeInvestigate, Summary: "只读代码路径调查",
	})
	if err != nil {
		t.Fatal(err)
	}
	f3, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: obEntry.ID, AttemptID: d3.AttemptID,
		Outcome: AttemptUnreproduced, EvidenceRefID: &evCode, SatisfyObligation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !f3.InsufficientEvidence || f3.ObligationAdvanced || f3.NewObligationStatus != ObligationReady {
		t.Fatalf("expected anti-downgrade rejection for code_investigate on entry_test, got %+v", f3)
	}
}

func TestStep4LateWriteAttemptProtection(t *testing.T) {
	d, task, round := assessmentFixture(t)
	evExec, err := d.CreateEvidenceRef(task.ID, EvidenceExecution, "exec/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	ob, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionRuntimeAsset,
		Purpose: "迟到保护", Required: true, DedupeKey: "rt:late", InitialStatus: ObligationReady,
		ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}

	d1, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: ob.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "attempt 1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CancelObligationAttempt(task.ID, ob.ID, d1.AttemptID, "cancelled"); err != nil {
		t.Fatal(err)
	}
	_ = d.Exploration(task.ExplorationID).SetIntentState(d1.IntentID, "stopped")

	// Late write on cancelled attempt 1 when active_attempt_id is nil must fail.
	if _, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: ob.ID, AttemptID: d1.AttemptID,
		Outcome: AttemptSupported, EvidenceRefID: &evExec, SatisfyObligation: true,
	}); !errors.Is(err, ErrAttemptStaleOrSuperseded) {
		t.Fatalf("expected ErrAttemptStaleOrSuperseded for cancelled attempt, got %v", err)
	}

	// Even after attempt 2 is dispatched, finalizing attempt 1 must be rejected without hurting attempt 2.
	d2, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: ob.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "attempt 2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: ob.ID, AttemptID: d1.AttemptID,
		Outcome: AttemptSupported, EvidenceRefID: &evExec, SatisfyObligation: true,
	}); !errors.Is(err, ErrAttemptStaleOrSuperseded) {
		t.Fatalf("expected ErrAttemptStaleOrSuperseded when attempt 2 is active, got %v", err)
	}
	got, err := d.GetCoverageObligation(task.ID, ob.ID)
	if err != nil || got.ActiveAttemptID == nil || *got.ActiveAttemptID != d2.AttemptID || got.Status != ObligationReady {
		t.Fatalf("attempt 2 binding damaged by late write: %+v err=%v", got, err)
	}
}

func TestStep4PauseResumeAttemptLifecycle(t *testing.T) {
	d, task, round := assessmentFixture(t)
	ob, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionRuntimeAsset,
		Purpose: "暂停恢复测试", Required: true, DedupeKey: "rt:pause", InitialStatus: ObligationReady,
		ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}
	disp, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: ob.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "rungable check",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason, err := d.IsObligationExecutable(task.ID, ob.ID, round.ID, disp.AttemptID); err != nil || !ok {
		t.Fatalf("expected executable before claim: ok=%v reason=%s err=%v", ok, reason, err)
	}
	if ok, err := d.MarkObligationAttemptRunning(task.ID, ob.ID, disp.AttemptID); err != nil || !ok {
		t.Fatalf("mark running failed: ok=%v err=%v", ok, err)
	}
	if ok, _, err := d.IsObligationExecutable(task.ID, ob.ID, round.ID, disp.AttemptID); err != nil || ok {
		t.Fatalf("expected not executable while running")
	}

	if err := d.PauseObligationAttempt(task.ID, ob.ID, disp.AttemptID); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetCoverageObligation(task.ID, ob.ID)
	if err != nil || got.Status != ObligationReady || got.ActiveAttemptID == nil || *got.ActiveAttemptID != disp.AttemptID {
		t.Fatalf("expected pause to restore ready status keeping active attempt %d, got %+v err=%v", disp.AttemptID, got, err)
	}
	if ok, reason, err := d.IsObligationExecutable(task.ID, ob.ID, round.ID, disp.AttemptID); err != nil || !ok {
		t.Fatalf("expected executable after pause so resume succeeds cleanly: ok=%v reason=%s err=%v", ok, reason, err)
	}
	if ok, err := d.MarkObligationAttemptRunning(task.ID, ob.ID, disp.AttemptID); err != nil || !ok {
		t.Fatalf("mark running on resume failed: ok=%v err=%v", ok, err)
	}
}

func TestStep4ProgramOriginActorGuardrails(t *testing.T) {
	d, task, round := assessmentFixture(t)
	ob, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionCodeAudit,
		Purpose: "必需代码审计", Required: true, DedupeKey: "code_audit:protected", InitialStatus: ObligationReady,
		ExecutionMode: ExecModeCodeAuditBatch, Origin: ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, actor := range []string{ObligationOriginPlanner, "worker"} {
		if _, err := d.TransitionObligationStatusByActor(task.ID, ob.ID, actor, ObligationReady, ObligationNotApplicable, TransitionObligationOptions{
			Reason: "attempt skip",
		}); !errors.Is(err, ErrObligationProtectedByProgram) {
			t.Fatalf("actor %s not_applicable: expected ErrObligationProtectedByProgram, got %v", actor, err)
		}
		if _, err := d.TransitionObligationStatusByActor(task.ID, ob.ID, actor, ObligationReady, ObligationSatisfied, TransitionObligationOptions{}); !errors.Is(err, ErrObligationEvidenceMissing) {
			t.Fatalf("actor %s satisfy without evidence: expected ErrObligationEvidenceMissing, got %v", actor, err)
		}
		if err := d.DeleteCoverageObligationByActor(task.ID, ob.ID, actor); !errors.Is(err, ErrObligationProtectedByProgram) {
			t.Fatalf("actor %s delete: expected ErrObligationProtectedByProgram, got %v", actor, err)
		}
	}
	if err := d.DeleteCoverageObligationByActor(task.ID, ob.ID, ObligationOriginProgram); !errors.Is(err, ErrObligationProtectedByProgram) {
		t.Fatalf("expected required program obligation deletion blocked, got %v", err)
	}
}

func TestStep4CompletionCheckIgnoresNonCompletedAttempts(t *testing.T) {
	d, task, round := assessmentFixture(t)
	if _, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "instance", Name: "staging",
	}); err != nil {
		t.Fatal(err)
	}
	evExec, err := d.CreateEvidenceRef(task.ID, EvidenceExecution, "exec/ok", nil)
	if err != nil {
		t.Fatal(err)
	}
	ob, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionRuntimeAsset,
		Purpose: "测试环境检查", Required: true, DedupeKey: "rt:comp", InitialStatus: ObligationReady,
		ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Dispatch and cancel one attempt (non-completed attempt must NOT be treated as completed failure).
	d1, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: ob.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "cancelled probe",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CancelObligationAttempt(task.ID, ob.ID, d1.AttemptID, "stopped"); err != nil {
		t.Fatal(err)
	}
	_ = d.Exploration(task.ExplorationID).SetIntentState(d1.IntentID, "stopped")

	// Completing the obligation cleanly with a fresh attempt -> AssessmentCompletionCheck must pass
	// and TotalAttempts/FailedAttempts must NOT count the cancelled attempt.
	d2, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: ob.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "valid probe",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: ob.ID, AttemptID: d2.AttemptID,
		Outcome: AttemptSupported, EvidenceRefID: &evExec, SatisfyObligation: true,
	}); err != nil {
		t.Fatal(err)
	}
	_ = d.Exploration(task.ExplorationID).SetIntentState(d2.IntentID, "done")

	// Also insert an unrelated dispatched attempt row on ob to verify non-completed rows are filtered.
	if _, err := d.Exec(`
INSERT INTO task_test_attempts(task_id, round_id, obligation_id, attempt_no, execution_mode, attempt_uid, status, outcome, output)
VALUES ($1,$2,$3,99,'dynamic_verify','stale-dispatched','dispatched','','{}'::jsonb)`,
		task.ID, round.ID, ob.ID); err != nil {
		t.Fatal(err)
	}

	report, err := d.AssessmentCompletionCheck(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !report.CanComplete {
		t.Fatalf("expected CanComplete=true when only cancelled/dispatched extra attempts exist, got reasons=%v report=%+v",
			report.Reasons, report)
	}
	if report.TotalAttempts != 1 || report.EffectiveAttempts != 1 || report.FailedAttempts != 0 {
		t.Fatalf("unexpected attempt counts (dispatched/cancelled should be excluded): %+v", report)
	}
}
