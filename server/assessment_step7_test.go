package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

func satisfyStep7ObligationWithEvidence(t *testing.T, pg *pgdb.DB, task *Task, taskNum, roundID int64, ob pgdb.CoverageObligation, evKind pgdb.EvidenceRefKind, evRef string) {
	t.Helper()
	d, err := pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
		TaskID: taskNum, RoundID: roundID, ObligationID: ob.ID,
		ExecutionMode: ob.ExecutionMode, Summary: ob.Purpose,
	})
	if err != nil {
		t.Fatalf("dispatch ob #%d failed: %v", ob.ID, err)
	}
	if ok, err := pg.MarkObligationAttemptRunning(taskNum, ob.ID, d.AttemptID); err != nil || !ok {
		t.Fatalf("MarkObligationAttemptRunning ob #%d failed: ok=%v err=%v", ob.ID, ok, err)
	}
	evID, err := pg.CreateEvidenceRef(taskNum, evKind, evRef, json.RawMessage(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.FinalizeObligationAttempt(pgdb.FinalizeObligationAttemptInput{
		TaskID: taskNum, ObligationID: ob.ID, AttemptID: d.AttemptID,
		Outcome: pgdb.AttemptSupported, EvidenceRefID: &evID, SatisfyObligation: true,
	}); err != nil {
		t.Fatalf("FinalizeObligationAttempt ob #%d failed: %v", ob.ID, err)
	}
	_ = task.Store.SetIntentState(d.IntentID, "done")
}

func TestStep7IncrementalDiscoveryInvalidationReopenAndMultiRound(t *testing.T) {
	s, projectID, token := step2TestServer(t)
	h := s.Handler()

	task, round := createStartedAssessmentTask(t, s.m, projectID, "step7-incremental-and-rounds", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecDynamic,
		ScopeNotes:    "授权测试范围仅限 127.0.0.1:18080",
		Environments: []pgdb.AssessmentEnvironmentInput{
			{Name: "qa", URL: "http://127.0.0.1:18080", IsDefault: true},
		},
	}, 2)
	taskNum, _ := strconv.ParseInt(task.ID, 10, 64)

	v1 := uploadTestCodebaseOnDraft(t, s, token, task.ID, []codebaseTestFile{
		{path: "order-svc/pom.xml", data: []byte(`<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>order-svc</artifactId><version>1.0.0</version></project>`)},
		{path: "order-svc/src/main/java/com/example/App.java", data: []byte("package com.example;\npublic class App { public void run() {} }\n")},
		{path: "order-svc/application.yml", data: []byte("server:\n  port: 8080\n")},
	})
	if _, _, err := s.BuildAssessmentInitialProfile(t.Context(), task.ID, BuildProfileOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.BuildAssessmentCoveragePlan(t.Context(), task.ID); err != nil {
		t.Fatal(err)
	}

	// Satisfy runtime_asset ("qa") and baseline code_audit obligations first.
	obsR1, err := s.m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{TaskID: taskNum, RoundID: round.ID, Limit: 100})
	if err != nil || len(obsR1) < 2 {
		t.Fatalf("expected baseline obligations in round 1, got len=%d err=%v", len(obsR1), err)
	}
	if _, _, err := s.m.pg.ReconcileObligationReadiness(taskNum, round.ID); err != nil {
		t.Fatal(err)
	}
	obsR1, _ = s.m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{TaskID: taskNum, RoundID: round.ID, Limit: 100})
	var rtOb, caOb pgdb.CoverageObligation
	for _, ob := range obsR1 {
		switch ob.Dimension {
		case pgdb.DimensionRuntimeAsset:
			rtOb = ob
			satisfyStep7ObligationWithEvidence(t, s.m.pg, task, taskNum, round.ID, ob, pgdb.EvidenceExecution, "exec:qa-reachable")
		case pgdb.DimensionCodeAudit:
			caOb = ob
			satisfyStep7ObligationWithEvidence(t, s.m.pg, task, taskNum, round.ID, ob, pgdb.EvidenceCodeRange, "order-svc/main.go:1-2")
		}
	}
	if rtOb.ID == 0 || caOb.ID == 0 {
		t.Fatalf("expected both runtime_asset and code_audit obligations, got rt=%d ca=%d", rtOb.ID, caOb.ID)
	}

	// Add an out-of-scope block intercept rule to verify incremental asset gating.
	if _, err := s.m.assetsForTask(task).CreateTaskInterceptRule(taskNum, "block", "fuzzy_domain", "evil.external", "out of scope", true); err != nil {
		t.Fatal(err)
	}

	// 1. Dynamic feedback records new_entry via InsertedAssets (plus an out-of-scope blocked entry).
	newEntryPayload, _ := json.Marshal(map[string]any{
		"obligation_id":  rtOb.ID,
		"assets_written": 2,
		"inserted_assets": []agent.InsertedAssetSummary{
			{ID: 101, Type: "endpoint", URL: "http://127.0.0.1:18080/api/v2/shadow-export", Method: "POST"},
			{ID: 102, Type: "endpoint", URL: "https://evil.external/secret", Method: "GET"},
		},
	})
	if _, err := s.m.pg.RecordAssessmentRoundEvent(taskNum, round.ID, "new_entry", newEntryPayload); err != nil {
		t.Fatal(err)
	}
	incTriggers, matIDs, err := s.reconcileIncrementalAssessmentState(t.Context(), task.ID, round.ID)
	if err != nil {
		t.Fatalf("reconcileIncrementalAssessmentState failed: %v", err)
	}
	if len(incTriggers) == 0 || len(matIDs) != 1 {
		t.Fatalf("expected incremental new_entry trigger & processed id, triggers=%+v mat=%v", incTriggers, matIDs)
	}

	// Only the allowed in-scope endpoint should produce an entry_test obligation, already ready because rtOb is satisfied.
	obsAfterNew, _ := s.m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{TaskID: taskNum, RoundID: round.ID, Dimension: pgdb.DimensionEntryTest, Limit: 50})
	var shadowOb pgdb.CoverageObligation
	for _, ob := range obsAfterNew {
		if strings.Contains(ob.Purpose, "shadow-export") {
			shadowOb = ob
		}
		if strings.Contains(ob.Purpose, "evil.external") {
			t.Fatalf("blocked out-of-scope endpoint leaked into obligations: %+v", ob)
		}
	}
	if shadowOb.ID == 0 || shadowOb.Status != pgdb.ObligationReady {
		t.Fatalf("expected incremental entry_test ready for shadow-export, got %+v", shadowOb)
	}
	satisfyStep7ObligationWithEvidence(t, s.m.pg, task, taskNum, round.ID, shadowOb, pgdb.EvidenceExecution, "exec:shadow-export-ok")

	// 2. Dispatch an in-flight attempt on an obligation, then trigger conflicting profile claim -> stale + late write blocked.
	obsHyp, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionIdentityResource,
		Purpose: "验证订单导出权限边界", Required: true, DedupeKey: "s7-id-border",
		InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeDynamicVerify,
		Origin: pgdb.ObligationOriginProgram, ProfileVersion: round.ProfileVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	inFlightDisp, err := s.m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
		TaskID: taskNum, RoundID: round.ID, ObligationID: obsHyp.ID,
		ExecutionMode: pgdb.ExecModeDynamicVerify, Summary: "check identity boundary",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.m.pg.MarkObligationAttemptRunning(taskNum, obsHyp.ID, inFlightDisp.AttemptID); err != nil || !ok {
		t.Fatalf("MarkObligationAttemptRunning failed: ok=%v err=%v", ok, err)
	}

	// First claim sets auth_required=false; second conflicting claim sets auth_required=true -> invalidates obsHyp, shadowOb!
	evCfgID, _ := s.m.pg.CreateEvidenceRef(taskNum, pgdb.EvidenceConfig, "gateway.yml:12", nil)
	if _, _, err := s.m.pg.CreateProfileClaim(pgdb.CreateProfileClaimInput{
		TaskID: taskNum, RoundID: &round.ID, Subject: "entry:HTTP POST /api/v2/shadow-export",
		Relation: "auth_required", ObjectValue: "false", SourceType: pgdb.ClaimSourceStaticExtraction,
		EvidenceRefID: &evCfgID, ConfirmationStatus: pgdb.ClaimStatusConfirmed,
	}); err != nil {
		t.Fatal(err)
	}
	conflictResp := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+task.ID+"/profile/claims", map[string]any{
		"subject":             "entry:HTTP POST /api/v2/shadow-export",
		"relation":            "auth_required",
		"object_value":        "true",
		"source_type":         pgdb.ClaimSourceRuntimeObservation,
		"confirmation_status": pgdb.ClaimStatusConfirmed,
		"evidence":            map[string]any{"kind": string(pgdb.EvidenceExecution), "reference": "exec:401-unauthorized"},
	})
	if conflictResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 for conflicting claim, got %d %s", conflictResp.Code, conflictResp.Body.String())
	}
	var conflictBody map[string]any
	_ = json.Unmarshal(conflictResp.Body.Bytes(), &conflictBody)
	if conf, _ := conflictBody["conflicted"].(bool); !conf {
		t.Fatalf("expected conflicted=true in response, got %s", conflictResp.Body.String())
	}
	// Late write on cancelled in-flight attempt must fail with ErrAttemptStaleOrSuperseded.
	lateEvID, _ := s.m.pg.CreateEvidenceRef(taskNum, pgdb.EvidenceExecution, "exec:stale-late", nil)
	if _, lateErr := s.m.pg.FinalizeObligationAttempt(pgdb.FinalizeObligationAttemptInput{
		TaskID: taskNum, ObligationID: obsHyp.ID, AttemptID: inFlightDisp.AttemptID,
		Outcome: pgdb.AttemptSupported, EvidenceRefID: &lateEvID, SatisfyObligation: true,
	}); !errors.Is(lateErr, pgdb.ErrAttemptStaleOrSuperseded) {
		t.Fatalf("expected late write error ErrAttemptStaleOrSuperseded, got %v", lateErr)
	}

	// 3. Live codebase upload on active task invalidates code_audit & bumps version.
	_ = v1
	s.onTaskCodebaseUploaded(task.ID, taskCodebaseVersion{
		ID:         "ver-live-2",
		CodebaseID: v1.CodebaseID,
		Name:       "order-svc-v2.zip",
	})
	caGot, _ := s.m.pg.GetCoverageObligation(taskNum, caOb.ID)
	if caGot == nil || caGot.Status != pgdb.ObligationStale {
		t.Fatalf("expected code_audit obligation stale after live codebase upload, got %+v", caGot)
	}

	// 4. Reconcile HTTP endpoint reopens stale obligations and prepares them for execution.
	recResp := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+task.ID+"/coverage-plan/reconcile", map[string]any{
		"reopen_stale":  true,
		"reopen_reason": "重新核实新版代码与认证策略",
	})
	if recResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from reconcile endpoint, got %d %s", recResp.Code, recResp.Body.String())
	}

	// Drain any remaining events and satisfy all unfinished required obligations to complete Round 1.
	if evs, err := s.m.pg.ListUnprocessedAssessmentEventsByType(taskNum, "knowledge_conflict", 50); err == nil {
		var ids []int64
		for _, ev := range evs {
			ids = append(ids, ev.ID)
		}
		_ = s.m.pg.MarkAssessmentEventIDsProcessed(taskNum, ids)
	}
	for _, evType := range []string{"evidence_invalidated", "code_version_change"} {
		if evs, err := s.m.pg.ListUnprocessedAssessmentEventsByType(taskNum, evType, 50); err == nil {
			var ids []int64
			for _, ev := range evs {
				ids = append(ids, ev.ID)
			}
			_ = s.m.pg.MarkAssessmentEventIDsProcessed(taskNum, ids)
		}
	}
	_, _, _ = s.m.pg.ReconcileObligationReadiness(taskNum, round.ID)
	obsAll, _ := s.m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{TaskID: taskNum, RoundID: round.ID, ExcludeTerminal: true, Limit: 100})
	for _, ob := range obsAll {
		evKind := pgdb.EvidenceExecution
		switch ob.ExecutionMode {
		case pgdb.ExecModeCodeAuditBatch:
			evKind = pgdb.EvidenceCodeRange
		case pgdb.ExecModeCodeInvestigate:
			evKind = pgdb.EvidenceConfig
		}
		satisfyStep7ObligationWithEvidence(t, s.m.pg, task, taskNum, round.ID, ob, evKind, fmt.Sprintf("exec:ok-%d", ob.ID))
	}

	completed, report, err := s.m.CompleteAssessment(task)
	if err != nil || !completed {
		t.Fatalf("expected Round 1 completion, completed=%v report=%+v err=%v", completed, report, err)
	}
	if s.m.TaskStatus(task.ID) != "done" {
		t.Fatalf("expected task done after Round 1 completion, got %q", s.m.TaskStatus(task.ID))
	}

	// 5. Post-completion codebase upload opens Round 2 while keeping Round 1 completion_report intact.
	s.onTaskCodebaseUploaded(task.ID, taskCodebaseVersion{
		ID:         "ver-post-complete-3",
		CodebaseID: v1.CodebaseID,
		Name:       "order-svc-v3.zip",
	})
	r2, err := s.m.pg.OpenAssessmentRound(taskNum)
	if err != nil || r2 == nil || r2.RoundNo != 2 {
		t.Fatalf("expected Round 2 open after post-completion codebase upload, got %+v err=%v", r2, err)
	}
	if s.m.TaskStatus(task.ID) != "running" {
		t.Fatalf("expected task revived to running for Round 2, got %q", s.m.TaskStatus(task.ID))
	}
	var r1Status string
	var r1Report json.RawMessage
	if err := s.m.pg.QueryRow(`SELECT status, completion_report FROM task_assessment_rounds WHERE id=$1`, round.ID).Scan(&r1Status, &r1Report); err != nil {
		t.Fatal(err)
	}
	if r1Status != "completed" || len(r1Report) == 0 {
		t.Fatalf("Round 1 must remain completed with report, got status=%s len=%d", r1Status, len(r1Report))
	}

	// 6. Explicit HTTP POST /api/tasks/{id}/assessment-rounds opens Round 3 cleanly.
	roundResp := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+task.ID+"/assessment-rounds", map[string]any{
		"reason":              "生产配置变更手动开启 Round 3",
		"environment_version": "env-v3",
	})
	if roundResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 from POST assessment-rounds, got %d %s", roundResp.Code, roundResp.Body.String())
	}
	r3, _ := s.m.pg.OpenAssessmentRound(taskNum)
	if r3 == nil || r3.RoundNo != 3 {
		t.Fatalf("expected Round 3 open, got %+v", r3)
	}
}

func TestStep7TimeoutSettlesAtomicallyThroughCompleteAssessment(t *testing.T) {
	s, projectID, _ := step2TestServer(t)

	// Task A: all obligations satisfied & 0 unprocessed events -> timeout settle commits done atomically.
	taskA, roundA := createStartedAssessmentTask(t, s.m, projectID, "step7-timeout-done", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecOffline,
	}, 1)
	numA, _ := strconv.ParseInt(taskA.ID, 10, 64)
	svcA, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: numA, RoundID: &roundA.ID, EntityType: "service", Name: "svc-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	obA, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: numA, RoundID: &roundA.ID, Dimension: pgdb.DimensionCodeAudit, TargetEntityID: &svcA.ID,
		Purpose: "audit A", Required: true, DedupeKey: "s7t-a",
		InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeCodeAuditBatch, Origin: pgdb.ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}
	satisfyStep7ObligationWithEvidence(t, s.m.pg, taskA, numA, roundA.ID, *obA, pgdb.EvidenceCodeRange, "Main.go:1")
	s.engine.settleTask(t.Context(), taskA, "")
	if got := s.m.TaskStatus(taskA.ID); got != "done" {
		t.Fatalf("expected satisfied assessment task timeout settle -> done, got %q", got)
	}
	if lc := taskA.lifecycleSnapshot(); lc.AssessmentPhase != pgdb.AssessmentPhaseCompleted {
		t.Fatalf("expected completed phase after timeout settle, got %q", lc.AssessmentPhase)
	}

	// Task B: unprocessed event prevents atomic completion -> timeout settle marks timeout (not fake done).
	taskB, roundB := createStartedAssessmentTask(t, s.m, projectID, "step7-timeout-fail", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecOffline,
	}, 1)
	numB, _ := strconv.ParseInt(taskB.ID, 10, 64)
	svcB, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: numB, RoundID: &roundB.ID, EntityType: "service", Name: "svc-b",
	})
	if err != nil {
		t.Fatal(err)
	}
	obB, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: numB, RoundID: &roundB.ID, Dimension: pgdb.DimensionCodeAudit, TargetEntityID: &svcB.ID,
		Purpose: "audit B", Required: true, DedupeKey: "s7t-b",
		InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeCodeAuditBatch, Origin: pgdb.ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}
	satisfyStep7ObligationWithEvidence(t, s.m.pg, taskB, numB, roundB.ID, *obB, pgdb.EvidenceCodeRange, "Main.go:1")
	if _, err := s.m.pg.RecordAssessmentRoundEvent(numB, roundB.ID, "profile_change", json.RawMessage(`{"reason":"pending event"}`)); err != nil {
		t.Fatal(err)
	}
	s.engine.settleTask(t.Context(), taskB, pgdb.StopReasonNoResult)
	if got := s.m.TaskStatus(taskB.ID); got != "timeout" {
		t.Fatalf("expected task with unprocessed event to settle as timeout, got %q", got)
	}

	// Task C: legacy assessment_mode=false remains unaffected by Assessment completion contract.
	legacy, err := s.m.CreateTask(projectID, "step7-legacy-timeout", "normal goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(legacy.ID, DeleteTaskOptions{}) })
	s.engine.settleTask(t.Context(), legacy, "")
	if got := s.m.TaskStatus(legacy.ID); got != "timeout" {
		t.Fatalf("expected legacy task timeout status untouched, got %q", got)
	}
}

func TestStep7PlannerIncrementalWakeupAndAtomicCompletionGate(t *testing.T) {
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"path":"` + r.URL.Path + `"}`))
	}))
	defer targetSrv.Close()

	s, projectID, _ := step2TestServer(t)
	task, round := createStartedAssessmentTask(t, s.m, projectID, "step7-planner-e2e", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecDynamic,
		ScopeNotes:    targetSrv.URL,
		Environments: []pgdb.AssessmentEnvironmentInput{
			{Name: "qa", URL: targetSrv.URL, IsDefault: true},
		},
	}, 2)
	taskNum, _ := strconv.ParseInt(task.ID, 10, 64)

	// Seed a satisfied runtime_asset obligation + a new_entry event whose payload came from insert_assets.
	rtEnt, _ := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: taskNum, RoundID: &round.ID, EntityType: "instance", Name: "qa",
		Attributes: json.RawMessage(`{"url":"` + targetSrv.URL + `"}`),
	})
	obRT, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionRuntimeAsset, TargetEntityID: &rtEnt.ID,
		Purpose: "核实测试环境 qa", Required: true, DedupeKey: "s7e2e-rt",
		InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeDynamicVerify, Origin: pgdb.ObligationOriginProgram,
		Priority: 9, ProfileVersion: round.ProfileVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	satisfyStep7ObligationWithEvidence(t, s.m.pg, task, taskNum, round.ID, *obRT, pgdb.EvidenceExecution, "exec:qa-ok")

	evPayload, _ := json.Marshal(map[string]any{
		"obligation_id":  obRT.ID,
		"assets_written": 1,
		"inserted_assets": []agent.InsertedAssetSummary{
			{ID: 777, Type: "endpoint", URL: targetSrv.URL + "/api/v2/export-new", Method: "GET"},
		},
	})
	if _, err := s.m.pg.RecordAssessmentRoundEvent(taskNum, round.ID, "new_entry", evPayload); err != nil {
		t.Fatal(err)
	}

	prov := &step4ScriptedProvider{
		turns: func(_ int, req llm.CompletionRequest) (llm.Message, string, error) {
			if !step6ReqMatches(req, targetSrv.URL) && !step6ReqMatches(req, "export-new") {
				return llm.Message{}, "", context.Canceled
			}
			turn := step6AssistantTurns(req.Messages) + 1
			switch {
			case step6ReqHasTool(req, "submit_dynamic_verification"):
				switch turn {
				case 1:
					b, _ := json.Marshal(map[string]any{"command": "curl -sS " + targetSrv.URL + "/api/v2/export-new"})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "s7d1", Name: "Bash", Input: b},
					}}, "tool_use", nil
				case 2:
					b, _ := json.Marshal(map[string]any{
						"verdict":          pgdb.AttemptSupported,
						"summary":          "已完成新增入口 /api/v2/export-new 动态覆盖",
						"observed_url":     targetSrv.URL + "/api/v2/export-new",
						"command_evidence": []string{"curl 200 ok"},
					})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "s7d2", Name: "submit_dynamic_verification", Input: b},
					}}, "tool_use", nil
				default:
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						llm.TextBlock("done"),
					}}, "end_turn", nil
				}
			case step6ReqHasTool(req, "request_assessment_completion"):
				if step6ReqMatches(req, "export-new") && step6ReqMatches(req, `"status":"ready"`) {
					// Dispatch incremental ready entry_test obligation on turn 1.
					if turn == 1 {
						obs, _ := s.m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{
							TaskID: taskNum, RoundID: round.ID, Status: pgdb.ObligationReady, Dimension: pgdb.DimensionEntryTest, Limit: 5,
						})
						if len(obs) > 0 {
							b, _ := json.Marshal(map[string]any{
								"obligation_id":  obs[0].ID,
								"execution_mode": pgdb.ExecModeDynamicVerify,
								"summary":        "动态验证增量入口 /api/v2/export-new",
								"work_order": map[string]any{
									"environment": map[string]any{"name": "qa", "url": targetSrv.URL},
									"question":    "测试新增入口 " + targetSrv.URL + "/api/v2/export-new",
								},
							})
							return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
								{Type: llm.BlockToolUse, ID: "s7p1", Name: "dispatch_assessment_intent", Input: b},
							}}, "tool_use", nil
						}
					}
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						llm.TextBlock("已派发增量入口测试"),
					}}, "end_turn", nil
				}
				// Round 2: all obligations satisfied -> call request_assessment_completion.
				if turn == 1 {
					b, _ := json.Marshal(map[string]any{"reason": "全部必需与增量义务均已满足"})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "s7p2", Name: "request_assessment_completion", Input: b},
					}}, "tool_use", nil
				}
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					llm.TextBlock("已完成收敛"),
				}}, "end_turn", nil
			default:
				return llm.Message{}, "", context.Canceled
			}
		},
	}
	installMockGlobalLLM(s, prov)

	// Round 1 of Planner reconciles new_entry -> creates ready entry_test -> Planner dispatches it.
	b := s.agentsForTask(task)
	s.engine.runAssessmentPlannerRound(t.Context(), task, b.pl, nil)

	incObs, _ := s.m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{
		TaskID: taskNum, RoundID: round.ID, Dimension: pgdb.DimensionEntryTest, Limit: 20,
	})
	var exportNewOb *pgdb.CoverageObligation
	for i := range incObs {
		if strings.Contains(incObs[i].Purpose, "export-new") {
			exportNewOb = &incObs[i]
			break
		}
	}
	if exportNewOb == nil || exportNewOb.ActiveAttemptID == nil || *exportNewOb.ActiveAttemptID <= 0 {
		t.Fatalf("expected Planner Round 1 to materialize & dispatch entry_test for export-new, got %+v (all=%+v)", exportNewOb, incObs)
	}

	// Drive dynamic_verify worker on the newly dispatched entry_test intent.
	_ = s.engine.runWorkerStep(t.Context(), task, "work#1", nil)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		cur, _ := s.m.pg.GetCoverageObligation(taskNum, exportNewOb.ID)
		if cur != nil && cur.Status == pgdb.ObligationSatisfied {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if cur, _ := s.m.pg.GetCoverageObligation(taskNum, exportNewOb.ID); cur == nil || cur.Status != pgdb.ObligationSatisfied {
		t.Fatalf("expected export-new entry_test satisfied by dynamic_verify, got %+v", cur)
	}

	// Round 2 of Planner calls request_assessment_completion -> task finishes done cleanly.
	s.engine.runAssessmentPlannerRound(t.Context(), task, b.pl, nil)
	if got := s.m.TaskStatus(task.ID); got != "done" {
		t.Fatalf("expected task status done after Planner request_assessment_completion, got %q", got)
	}
}
