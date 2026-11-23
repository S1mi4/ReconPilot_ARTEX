package agent

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func TestStep7InsertAssetsCapturesSummaryWithoutSecrets(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("step7 insert assets", "assess", db.TaskCreateOptions{
		ProjectID:      testProjectID(t, d),
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

	tsx := NewToolSet(d.Exploration(task.ExplorationID), "work#1")
	as := d.Assets(task.ProjectID)
	tsx.SetAssetStore(as, as.Companies())
	tsx.SetTaskID(task.ID)

	var execCount atomic.Int64
	var outcome DynamicVerifyOutcome
	dc := DynamicVerifyContext{
		PG:               d,
		TaskID:           task.ID,
		RoundID:          round.ID,
		RoundNo:          round.RoundNo,
		ProfileVersion:   round.ProfileVersion,
		ObligationID:     1,
		AttemptID:        1,
		Dimension:        db.DimensionEntryTest,
		ExecutionCounter: &execCount,
	}
	tools := tsx.DynamicVerifyTools(dc, &outcome)
	var insertTool actool.CoreTool
	for _, tl := range tools {
		if tl.Name() == "insert_assets" {
			insertTool = tl
			break
		}
	}
	if insertTool == nil {
		t.Fatal("insert_assets missing from DynamicVerifyTools")
	}

	args, _ := json.Marshal(map[string]any{
		"assets": []map[string]any{
			{
				"type":   "endpoint",
				"url":    "http://127.0.0.1:18080/api/v2/export",
				"method": "POST",
			},
			{
				"type":       "service",
				"url":        "http://127.0.0.1:19090",
				"service_ip": "127.0.0.1",
				"auth":       []map[string]any{{"type": "bearer", "password": "secret-should-not-copy"}},
			},
		},
	})
	res, err := insertTool.Call(t.Context(), args, nil)
	if err != nil {
		t.Fatalf("insert_assets execute err=%v", err)
	}
	if res.IsError {
		t.Fatalf("insert_assets returned error: %+v", res.Content)
	}

	inserted := tsx.InsertedAssets()
	if len(inserted) != 2 {
		t.Fatalf("expected 2 InsertedAssets summaries, got %+v", inserted)
	}
	if inserted[0].ID <= 0 || inserted[0].Type != "endpoint" || inserted[0].URL != "http://127.0.0.1:18080/api/v2/export" || inserted[0].Method != "POST" {
		t.Fatalf("unexpected first InsertedAssetSummary: %+v", inserted[0])
	}
	if inserted[1].ID <= 0 || inserted[1].Type != "service" || inserted[1].IP != "127.0.0.1" {
		t.Fatalf("unexpected second InsertedAssetSummary: %+v", inserted[1])
	}
	rawJSON, _ := json.Marshal(inserted)
	if strings.Contains(string(rawJSON), "secret-should-not-copy") {
		t.Fatalf("InsertedAssetSummary must stay secret-free, got %s", string(rawJSON))
	}
}

func TestStep7PlannerReopenStaleAndMergeHypothesesTools(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("step7 planner tools", "assess", db.TaskCreateOptions{
		ProjectID:      testProjectID(t, d),
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

	obBase, err := d.CreateCoverageObligation(db.CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: db.DimensionEntryTest,
		Purpose: "必需入口", Required: true, DedupeKey: "s7p-entry",
		InitialStatus: db.ObligationReady, ExecutionMode: db.ExecModeDynamicVerify, Origin: db.ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}
	obStale, err := d.CreateCoverageObligation(db.CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: db.DimensionCodeAudit,
		Purpose: "待重开代码审计", Required: true, DedupeKey: "s7p-stale",
		InitialStatus: db.ObligationReady, ExecutionMode: db.ExecModeCodeAuditBatch, Origin: db.ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}
	dStale, err := d.DispatchAssessmentIntent(db.DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obStale.ID,
		ExecutionMode: db.ExecModeCodeAuditBatch, Summary: "initial code audit",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = d.MarkObligationAttemptRunning(task.ID, obStale.ID, dStale.AttemptID)
	evCA, err := d.CreateEvidenceRef(task.ID, db.EvidenceCodeRange, "Main.go:1-5", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.FinalizeObligationAttempt(db.FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: obStale.ID, AttemptID: dStale.AttemptID,
		Outcome: db.AttemptSupported, EvidenceRefID: &evCA, SatisfyObligation: true,
	}); err != nil {
		t.Fatal(err)
	}
	_ = d.Exploration(task.ExplorationID).SetIntentState(dStale.IntentID, "done")
	if _, err := d.InvalidateObligationsOnChange(db.InvalidateObligationsInput{
		TaskID: task.ID, RoundID: round.ID, ChangeKind: "code_version_change",
		Reason: "新代码上传待重测", ObligationIDs: []int64{obStale.ID}, BumpProfileVersion: true,
	}); err != nil {
		t.Fatal(err)
	}
	obH1, err := d.CreateCoverageObligation(db.CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: db.DimensionHypothesis,
		Purpose: "假设 #1", Required: true, DedupeKey: "s7p-h1", Priority: 9,
		InitialStatus: db.ObligationReady, ExecutionMode: db.ExecModeDynamicVerify, Origin: db.ObligationOriginProgram,
		ContextSnapshot: json.RawMessage(`{"candidate_key":"cand:dup"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	obH2, err := d.CreateCoverageObligation(db.CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: db.DimensionHypothesis,
		Purpose: "假设 #1 duplicate", Required: true, DedupeKey: "s7p-h2", Priority: 4,
		InitialStatus: db.ObligationReady, ExecutionMode: db.ExecModeDynamicVerify, Origin: db.ObligationOriginProgram,
		ContextSnapshot: json.RawMessage(`{"candidate_key":"cand:dup"}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	tsx := NewToolSet(d.Exploration(task.ExplorationID), "planner")
	tsx.SetTaskID(task.ID)
	tsx.SetAssessmentContext(&AssessmentPlannerContext{
		PG:            d,
		TaskID:        task.ID,
		RoundID:       round.ID,
		RoundNo:       round.RoundNo,
		ExecutionMode: db.AssessmentExecDynamic,
	})

	byName := map[string]actool.CoreTool{}
	for _, tl := range tsx.AssessmentPlannerTools() {
		byName[tl.Name()] = tl
	}
	reopenTool := byName["reopen_stale_obligations"]
	mergeTool := byName["merge_hypothesis_obligations"]
	if reopenTool == nil || mergeTool == nil {
		t.Fatalf("missing step 7 planner tools: reopen=%v merge=%v", reopenTool != nil, mergeTool != nil)
	}

	// Merge duplicate hypotheses with empty input -> auto-deduplicate.
	resMerge, err := mergeTool.Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil || resMerge.IsError {
		t.Fatalf("merge_hypothesis_obligations failed: res=%+v err=%v", resMerge, err)
	}
	gotH2, _ := d.GetCoverageObligation(task.ID, obH2.ID)
	if gotH2.Status != db.ObligationNotApplicable {
		t.Fatalf("expected duplicate hypothesis %d marked not_applicable, got %s", obH2.ID, gotH2.Status)
	}
	gotH1, _ := d.GetCoverageObligation(task.ID, obH1.ID)
	if gotH1.Status != db.ObligationReady {
		t.Fatalf("expected surviving hypothesis %d ready, got %s", obH1.ID, gotH1.Status)
	}

	// Trying to merge required baseline entry_test must fail cleanly.
	badMergeArgs, _ := json.Marshal(map[string]any{
		"primary_id":    obBase.ID,
		"duplicate_ids": []int64{obH1.ID},
		"reason":        "must reject baseline",
	})
	resBadMerge, err := mergeTool.Call(context.Background(), badMergeArgs, nil)
	if err != nil || !resBadMerge.IsError {
		t.Fatalf("expected merge_hypothesis_obligations to reject baseline dimension, got %+v err=%v", resBadMerge, err)
	}

	// Reopen stale obligation.
	reopenArgs, _ := json.Marshal(map[string]any{"reason": "代码重传后重新测试"})
	resReopen, err := reopenTool.Call(context.Background(), reopenArgs, nil)
	if err != nil || resReopen.IsError {
		t.Fatalf("reopen_stale_obligations failed: res=%+v err=%v", resReopen, err)
	}
	gotStale, _ := d.GetCoverageObligation(task.ID, obStale.ID)
	if gotStale.Status != db.ObligationReady {
		t.Fatalf("expected reopened stale obligation ready, got %s", gotStale.Status)
	}
}
