package db

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestStep7InvalidateTransitiveLateWriteAndReopen(t *testing.T) {
	d, task, round := assessmentFixture(t)

	// Root runtime obligation -> satisfied.
	rtEnt, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "instance", Name: "qa-staging",
		Attributes: json.RawMessage(`{"url":"http://127.0.0.1:18080"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	obRT, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionRuntimeAsset, TargetEntityID: &rtEnt.ID,
		Purpose: "核实测试环境 qa-staging", Required: true, DedupeKey: "s7-rt",
		InitialStatus: ObligationReady, ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
		Priority: 9, ProfileVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	dRT, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obRT.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "check rt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.MarkObligationAttemptRunning(task.ID, obRT.ID, dRT.AttemptID); err != nil || !ok {
		t.Fatalf("MarkObligationAttemptRunning rt failed: ok=%v err=%v", ok, err)
	}
	evRT, err := d.CreateEvidenceRef(task.ID, EvidenceExecution, "exec:rt-ok", json.RawMessage(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: obRT.ID, AttemptID: dRT.AttemptID,
		Outcome: AttemptSupported, EvidenceRefID: &evRT, SatisfyObligation: true,
	}); err != nil {
		t.Fatal(err)
	}
	_ = d.Exploration(task.ExplorationID).SetIntentState(dRT.IntentID, "done")

	// Downstream entry obligation (depends on obRT) -> satisfied.
	obEntry, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionEntryTest, TargetEntityID: &rtEnt.ID,
		Purpose: "入口动态测试", Required: true, DedupeKey: "s7-entry",
		InitialStatus: ObligationReady, ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
		Priority: 7, ProfileVersion: 1, DependencyIDs: []int64{obRT.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	dEntry, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obEntry.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "check entry",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.MarkObligationAttemptRunning(task.ID, obEntry.ID, dEntry.AttemptID); err != nil || !ok {
		t.Fatalf("MarkObligationAttemptRunning entry failed: ok=%v err=%v", ok, err)
	}
	if _, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: obEntry.ID, AttemptID: dEntry.AttemptID,
		Outcome: AttemptSupported, EvidenceRefID: &evRT, SatisfyObligation: true,
	}); err != nil {
		t.Fatal(err)
	}
	_ = d.Exploration(task.ExplorationID).SetIntentState(dEntry.IntentID, "done")

	// Transitive grandchild obligation (depends on obEntry) -> currently in-flight running.
	obChild, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionCrossModule, TargetEntityID: &rtEnt.ID,
		Purpose: "跨模块动态闭环", Required: true, DedupeKey: "s7-cross",
		InitialStatus: ObligationReady, ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
		Priority: 7, ProfileVersion: 1, DependencyIDs: []int64{obEntry.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	dChild, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obChild.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "in-flight cross",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.MarkObligationAttemptRunning(task.ID, obChild.ID, dChild.AttemptID); err != nil || !ok {
		t.Fatalf("MarkObligationAttemptRunning child failed: ok=%v err=%v", ok, err)
	}

	// Ready downstream sibling of obRT (not yet dispatched) -> should return to pending on invalidation.
	obReadySibling, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionIdentityResource, TargetEntityID: &rtEnt.ID,
		Purpose: "身份边界检查", Required: true, DedupeKey: "s7-id",
		InitialStatus: ObligationReady, ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
		Priority: 7, ProfileVersion: 1, DependencyIDs: []int64{obRT.ID},
	})
	if err != nil {
		t.Fatal(err)
	}

	inv, err := d.InvalidateObligationsOnChange(InvalidateObligationsInput{
		TaskID:             task.ID,
		RoundID:            round.ID,
		ChangeKind:         "code_version_change",
		Reason:             "环境重新部署版本 v2，相关动态验证结论失效",
		ObligationIDs:      []int64{obRT.ID},
		IncludeTransitive:  true,
		BumpProfileVersion: true,
		NewCodebaseVersion: "code-v2",
		NewEnvVersion:      "env-v2",
	})
	if err != nil {
		t.Fatalf("InvalidateObligationsOnChange failed: %v", err)
	}
	if inv.NewProfileVersion != round.ProfileVersion+1 || len(inv.InvalidatedIDs) != 3 || inv.EventID <= 0 {
		t.Fatalf("unexpected invalidation result: %+v (initVer=%d)", inv, round.ProfileVersion)
	}
	if len(inv.CancelledAttemptIDs) != 1 || inv.CancelledAttemptIDs[0] != dChild.AttemptID {
		t.Fatalf("expected active in-flight attempt %d cancelled, got %+v", dChild.AttemptID, inv.CancelledAttemptIDs)
	}
	if len(inv.StoppedIntentIDs) != 1 || inv.StoppedIntentIDs[0] != dChild.IntentID {
		t.Fatalf("expected intent %d stopped, got %+v", dChild.IntentID, inv.StoppedIntentIDs)
	}

	// Verify statuses + late write protection on stale attempt.
	for _, id := range []int64{obRT.ID, obEntry.ID, obChild.ID} {
		got, gErr := d.GetCoverageObligation(task.ID, id)
		if gErr != nil || got.Status != ObligationStale || !strings.Contains(got.StaleReason, "v2") {
			t.Fatalf("obligation #%d expected stale with reason, got %+v err=%v", id, got, gErr)
		}
	}
	sibGot, _ := d.GetCoverageObligation(task.ID, obReadySibling.ID)
	if sibGot.Status != ObligationPending {
		t.Fatalf("ready dependent sibling expected reverted to pending, got %s", sibGot.Status)
	}

	// Late write from cancelled attempt must fail with ErrAttemptStaleOrSuperseded.
	if _, lateErr := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: obChild.ID, AttemptID: dChild.AttemptID,
		Outcome: AttemptSupported, EvidenceRefID: &evRT, SatisfyObligation: true,
	}); !errors.Is(lateErr, ErrAttemptStaleOrSuperseded) {
		t.Fatalf("expected ErrAttemptStaleOrSuperseded on stale late write, got %v", lateErr)
	}

	// Reopen stale obligations: obRT becomes ready, dependents become pending until obRT is satisfied again.
	reopenRes, err := d.ReopenStaleObligations(task.ID, round.ID, nil, "版本 v2 已对齐，重开失效义务")
	if err != nil {
		t.Fatalf("ReopenStaleObligations failed: %v", err)
	}
	if len(reopenRes.ReopenedIDs) != 3 || reopenRes.ReadyCount != 1 {
		t.Fatalf("unexpected reopen result: %+v", reopenRes)
	}
	gotRT, _ := d.GetCoverageObligation(task.ID, obRT.ID)
	gotEntry, _ := d.GetCoverageObligation(task.ID, obEntry.ID)
	if gotRT.Status != ObligationReady || gotEntry.Status != ObligationPending {
		t.Fatalf("expected rt=ready entry=pending after reopen, got rt=%s entry=%s", gotRT.Status, gotEntry.Status)
	}

	// Re-satisfy obRT -> readiness reconciler unblocks obEntry and obReadySibling.
	dRT2, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obRT.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "reverify rt v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.MarkObligationAttemptRunning(task.ID, obRT.ID, dRT2.AttemptID); err != nil || !ok {
		t.Fatalf("MarkObligationAttemptRunning rt2 failed: ok=%v err=%v", ok, err)
	}
	if _, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: obRT.ID, AttemptID: dRT2.AttemptID,
		Outcome: AttemptSupported, EvidenceRefID: &evRT, SatisfyObligation: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.ReconcileObligationReadiness(task.ID, round.ID); err != nil {
		t.Fatal(err)
	}
	gotEntry, _ = d.GetCoverageObligation(task.ID, obEntry.ID)
	sibGot, _ = d.GetCoverageObligation(task.ID, obReadySibling.ID)
	if gotEntry.Status != ObligationReady || sibGot.Status != ObligationReady {
		t.Fatalf("expected downstream entry & sibling ready after rt v2 satisfied, got entry=%s sib=%s", gotEntry.Status, sibGot.Status)
	}
}

func TestStep7MergeDuplicateHypothesesAndRejectBaseline(t *testing.T) {
	d, task, round := assessmentFixture(t)

	// Baseline required entry_test obligation must never be merged/dismissed.
	obBase, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionEntryTest,
		Purpose: "必需入口测试", Required: true, DedupeKey: "s7-base-entry",
		InitialStatus: ObligationReady, ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}
	obH1, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionHypothesis,
		Purpose: "静态候选 #1 动态复现", Required: true, DedupeKey: "s7-h1", Priority: 8,
		InitialStatus: ObligationReady, ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
		ContextSnapshot: json.RawMessage(`{"candidate_key":"cand:export-idor"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	obH2, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionHypothesis,
		Purpose: "静态候选 #1 重复派生", Required: true, DedupeKey: "s7-h2", Priority: 5,
		InitialStatus: ObligationReady, ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginPlanner,
		ContextSnapshot: json.RawMessage(`{"candidate_key":"cand:export-idor"}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := d.MergeHypothesisObligations(task.ID, round.ID, obBase.ID, []int64{obH2.ID}, "invalid baseline merge"); !errors.Is(err, ErrObligationDimensionInvalid) {
		t.Fatalf("expected ErrObligationDimensionInvalid merging non-hypothesis obligation, got %v", err)
	}

	mRes, err := d.MergeDuplicateHypothesisObligations(task.ID, round.ID)
	if err != nil {
		t.Fatalf("MergeDuplicateHypothesisObligations failed: %v", err)
	}
	if mRes.MergedPairs != 1 || len(mRes.PrimaryIDs) != 1 || mRes.PrimaryIDs[0] != obH1.ID || len(mRes.MergedIDs) != 1 || mRes.MergedIDs[0] != obH2.ID {
		t.Fatalf("unexpected merge result: %+v", mRes)
	}

	gotH2, _ := d.GetCoverageObligation(task.ID, obH2.ID)
	if gotH2.Status != ObligationNotApplicable || !strings.Contains(gotH2.NotApplicableReason, "已合并至等价假设义务") {
		t.Fatalf("expected duplicate hypothesis not_applicable with merge reason, got %+v", gotH2)
	}
	gotH1, _ := d.GetCoverageObligation(task.ID, obH1.ID)
	if gotH1.Status != ObligationReady || !strings.Contains(string(gotH1.ContextSnapshot), "merged_from_ids") {
		t.Fatalf("expected primary hypothesis ready with merged_from_ids, got %+v", gotH1)
	}
}

func TestStep7AtomicCompletionVersionFenceAndReopenNextRound(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	projID := testProjectID(t, d)
	legacyTask, err := d.CreateTask(projID, "legacy task", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(legacyTask.ID) })
	if _, err := d.ReopenAssessmentForNextRound(legacyTask.ID, "should reject legacy", "", ""); !errors.Is(err, ErrTaskNotAssessmentMode) {
		t.Fatalf("expected ErrTaskNotAssessmentMode for legacy task, got %v", err)
	}

	task, err := d.CreateTaskWithOptions("step7 atomic round", "assess", TaskCreateOptions{
		ProjectID:      projID,
		AssessmentMode: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	round, err := d.CreateAssessmentRound(task.ID)
	if err != nil {
		t.Fatal(err)
	}

	ob, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionCodeAudit,
		Purpose: "代码审计", Required: true, DedupeKey: "s7-ca",
		InitialStatus: ObligationReady, ExecutionMode: ExecModeCodeAuditBatch, Origin: ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}
	dCA, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: ob.ID,
		ExecutionMode: ExecModeCodeAuditBatch, Summary: "audit",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.MarkObligationAttemptRunning(task.ID, ob.ID, dCA.AttemptID); err != nil || !ok {
		t.Fatalf("MarkObligationAttemptRunning failed: ok=%v err=%v", ok, err)
	}
	evCA, err := d.CreateEvidenceRef(task.ID, EvidenceCodeRange, "Main.go:1-10", json.RawMessage(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: ob.ID, AttemptID: dCA.AttemptID,
		Outcome: AttemptSupported, EvidenceRefID: &evCA, SatisfyObligation: true,
	}); err != nil {
		t.Fatal(err)
	}
	_ = d.Exploration(task.ExplorationID).SetIntentState(dCA.IntentID, "done")

	// Unprocessed event blocks atomic completion.
	evID, err := d.RecordAssessmentRoundEvent(task.ID, round.ID, "new_asset", json.RawMessage(`{"url":"http://127.0.0.1/new"}`))
	if err != nil {
		t.Fatal(err)
	}
	reportJSON := json.RawMessage(`{"can_complete":true}`)
	_, _, won, err := d.FinalizeAssessmentCompletionAtVersion(task.ID, round.ID, round.ProfileVersion, reportJSON)
	if err != nil || won {
		t.Fatalf("expected atomic completion blocked by unprocessed event, won=%v err=%v", won, err)
	}
	if err := d.MarkAssessmentEventIDsProcessed(task.ID, []int64{evID}); err != nil {
		t.Fatal(err)
	}

	// Wrong expectedProfileVersion blocks atomic completion.
	_, _, wonStaleVer, err := d.FinalizeAssessmentCompletionAtVersion(task.ID, round.ID, round.ProfileVersion+1, reportJSON)
	if err != nil || wonStaleVer {
		t.Fatalf("expected atomic completion rejected on profile_version mismatch, won=%v err=%v", wonStaleVer, err)
	}

	// Matching version and clean state commits done atomically.
	_, _, wonOK, err := d.FinalizeAssessmentCompletionAtVersion(task.ID, round.ID, round.ProfileVersion, reportJSON)
	if err != nil || !wonOK {
		t.Fatalf("expected atomic completion to win at version %d, won=%v err=%v", round.ProfileVersion, wonOK, err)
	}

	// Open Round 2 after completion; Round 1 history/report stays intact.
	reopenRes, err := d.ReopenAssessmentForNextRound(task.ID, "发布版本 v2 重新评估", "ver-2", "env-2")
	if err != nil {
		t.Fatalf("ReopenAssessmentForNextRound failed: %v", err)
	}
	if reopenRes.PreviousRoundID != round.ID || reopenRes.NewRound == nil || reopenRes.NewRound.RoundNo != 2 || reopenRes.NewRound.Status != "open" {
		t.Fatalf("unexpected ReopenAssessmentForNextRound result: %+v", reopenRes)
	}
	var r1Status string
	var r1Report json.RawMessage
	if err := d.QueryRow(`SELECT status, completion_report FROM task_assessment_rounds WHERE id=$1`, round.ID).Scan(&r1Status, &r1Report); err != nil {
		t.Fatal(err)
	}
	if r1Status != "completed" || len(r1Report) == 0 {
		t.Fatalf("expected round 1 intact as completed with report, got status=%s report=%s", r1Status, string(r1Report))
	}
	reloaded, err := d.GetTask(task.ID)
	if err != nil || reloaded.Status != "running" || reloaded.AssessmentPhase != AssessmentPhaseProfiling {
		t.Fatalf("expected reopened task running/profiling, got %+v err=%v", reloaded, err)
	}
	if cnt, err := d.CountUnprocessedAssessmentEvents(task.ID); err != nil || cnt == 0 {
		t.Fatalf("expected new round event queued for round 2, got cnt=%d err=%v", cnt, err)
	}
}
