package agent

import (
	"context"
	"encoding/json"
	"iter"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

type scriptedAssessmentProvider struct {
	mu    sync.Mutex
	calls int
	turns func(call int, req llm.CompletionRequest) (llm.Message, string, error)
}

func (p *scriptedAssessmentProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.mu.Lock()
	p.calls++
	c := p.calls
	fn := p.turns
	p.mu.Unlock()
	if fn == nil {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("done")}}, "end_turn", llm.Usage{}, nil
	}
	msg, stop, err := fn(c, req)
	return msg, stop, llm.Usage{InputTokens: 10, OutputTokens: 10}, err
}

func (p *scriptedAssessmentProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) {
		msg, stop, _, err := p.Complete(ctx, req)
		if err != nil {
			y(llm.StreamEvent{}, err)
			return
		}
		for _, b := range msg.Content {
			if b.Type == llm.BlockToolUse {
				if !y(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: b.ID, ToolName: b.Name}, nil) {
					return
				}
				if !y(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(b.Input)}, nil) {
					return
				}
			} else if !y(llm.StreamEvent{Type: llm.SETextDelta, Text: b.Text}, nil) {
				return
			}
		}
		if !y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stop}, nil) {
			return
		}
		y(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func toolUseBlock(id, name string, payload any) llm.ContentBlock {
	raw, _ := json.Marshal(payload)
	return llm.ContentBlock{
		Type:  llm.BlockToolUse,
		ID:    id,
		Name:  name,
		Input: raw,
	}
}

func TestStep4AssessmentPlannerToolAllowlistAndGuardrails(t *testing.T) {
	tsx := NewToolSet(nil, "planner")
	tsx.SetAssessmentContext(&AssessmentPlannerContext{
		TaskID:  1,
		RoundID: 1,
	})
	tools := tsx.AssessmentPlannerTools()
	got := map[string]bool{}
	for _, tl := range tools {
		got[tl.Name()] = true
	}

	required := []string{
		"get_assessment_overview",
		"list_coverage_obligations",
		"query_profile_slice",
		"list_code_audit_coverage",
		"list_findings",
		"list_facts",
		"node_detail",
		"get_worker_output",
		"get_worker_trace",
		"list_assets",
		"dispatch_assessment_intent",
		"add_exploration_obligation",
		"update_obligation_priority",
		"record_profile_claim",
		"steer_work",
		"kill_work",
		"request_assessment_completion",
	}
	for _, name := range required {
		if !got[name] {
			t.Fatalf("missing expected assessment planner tool %q", name)
		}
	}

	forbidden := []string{
		"prove_goal",
		"goal_met",
		"add_intent",
		"Bash",
		"Write",
		"Edit",
		"Read",
		"Glob",
		"Grep",
		"WebFetch",
		"WebSearch",
		"delete_obligation",
		"mark_not_applicable",
		"skip_obligation",
		"satisfy_obligation",
	}
	for _, name := range forbidden {
		if got[name] {
			t.Fatalf("forbidden tool %q exposed in AssessmentPlannerTools", name)
		}
	}
}

func TestStep4PlannerPlanAssessmentOrchestrationAndGuardrails(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("step4 planner orchestration", "assess service", db.TaskCreateOptions{
		ProjectID:      testProjectID(t, d),
		AssessmentMode: true,
		AssessmentConfig: db.AssessmentConfig{
			ExecutionMode:    db.AssessmentExecDynamic,
			BusinessOverview: "订单平台",
			BusinessFocus:    []string{"权限越权", "支付回调"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	round, err := d.CreateAssessmentRound(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	entSvc, err := d.CreateTargetEntity(db.CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "service", Name: "order-svc",
	})
	if err != nil {
		t.Fatal(err)
	}
	entRT, err := d.CreateTargetEntity(db.CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "instance", Name: "staging-api",
	})
	if err != nil {
		t.Fatal(err)
	}
	entEntry, err := d.CreateTargetEntity(db.CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "entry", Name: "GET /orders",
	})
	if err != nil {
		t.Fatal(err)
	}

	evCode, err := d.CreateEvidenceRef(task.ID, db.EvidenceCodeRange, "src/OrderController.java:15", nil)
	if err != nil {
		t.Fatal(err)
	}
	evExec, err := d.CreateEvidenceRef(task.ID, db.EvidenceExecution, "exec/probe-ok", json.RawMessage(`{"status":200}`))
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := d.CreateProfileClaim(db.CreateProfileClaimInput{
		TaskID: task.ID, RoundID: &round.ID, Subject: "service:order-svc",
		Relation: "framework", ObjectValue: "Spring Boot", SourceType: db.ClaimSourceStaticExtraction,
		EvidenceRefID: &evCode,
	}); err != nil {
		t.Fatal(err)
	}

	obRT, err := d.CreateCoverageObligation(db.CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: db.DimensionRuntimeAsset,
		TargetEntityID: &entRT.ID, Purpose: "核实运行实例 staging-api",
		Required: true, DedupeKey: "rt:staging", InitialStatus: db.ObligationReady,
		ExecutionMode: db.ExecModeDynamicVerify, Origin: db.ObligationOriginProgram, Priority: 9,
	})
	if err != nil {
		t.Fatal(err)
	}
	obCode, err := d.CreateCoverageObligation(db.CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: db.DimensionCodeAudit,
		TargetEntityID: &entSvc.ID, Purpose: "白盒审计 order-svc",
		Required: true, DedupeKey: "code:order-svc", InitialStatus: db.ObligationReady,
		ExecutionMode: db.ExecModeCodeAuditBatch, Origin: db.ObligationOriginProgram, Priority: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	obEntry, err := d.CreateCoverageObligation(db.CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: db.DimensionEntryTest,
		TargetEntityID: &entEntry.ID, Purpose: "测试入口 GET /orders",
		Required: true, DedupeKey: "entry:orders",
		ExecutionMode: db.ExecModeDynamicVerify, Origin: db.ObligationOriginProgram, Priority: 7,
		DependencyIDs: []int64{obRT.ID},
	})
	if err != nil {
		t.Fatal(err)
	}

	completeFn := func(reason string) (bool, *db.AssessmentCompletionReport, error) {
		report, err := d.AssessmentCompletionCheck(task.ID)
		if err != nil {
			return false, nil, err
		}
		if !report.CanComplete {
			return false, report, nil
		}
		reportBytes, _ := json.Marshal(report)
		_, _, won, err := d.FinalizeAssessmentCompletion(task.ID, report.RoundID, reportBytes)
		if err != nil {
			return false, report, err
		}
		return won, report, nil
	}

	prov1 := &scriptedAssessmentProvider{
		turns: func(call int, req llm.CompletionRequest) (llm.Message, string, error) {
			switch call {
			case 1:
				return llm.Message{
					Role: llm.RoleAssistant,
					Content: []llm.ContentBlock{
						toolUseBlock("c-slice", "query_profile_slice", map[string]any{
							"subjects": []string{"service:order-svc"},
						}),
						toolUseBlock("c-obs", "list_coverage_obligations", map[string]any{
							"exclude_terminal": true,
						}),
						toolUseBlock("c-disp-1", "dispatch_assessment_intent", map[string]any{
							"obligation_id":  obRT.ID,
							"execution_mode": db.ExecModeDynamicVerify,
							"summary":        "核实 staging-api 版本与可达性",
							"work_order": map[string]any{
								"hypothesis": "实例可达且与代码版本一致",
							},
						}),
					},
				}, "tool_use", nil
			case 2:
				return llm.Message{
					Role: llm.RoleAssistant,
					Content: []llm.ContentBlock{
						toolUseBlock("c-disp-dup", "dispatch_assessment_intent", map[string]any{
							"obligation_id":  obRT.ID,
							"execution_mode": db.ExecModeDynamicVerify,
							"summary":        "重复派发同一义务",
						}),
						toolUseBlock("c-disp-unmet", "dispatch_assessment_intent", map[string]any{
							"obligation_id":  obEntry.ID,
							"execution_mode": db.ExecModeDynamicVerify,
							"summary":        "前置未满足不应派发",
						}),
						toolUseBlock("c-claim-bad-conf", "record_profile_claim", map[string]any{
							"subject":             "service:order-svc",
							"relation":            "auth_enabled",
							"object_value":        "true",
							"confirmation_status": "confirmed",
						}),
						toolUseBlock("c-claim-secret", "record_profile_claim", map[string]any{
							"subject":             "service:order-svc",
							"relation":            "db_note",
							"object_value":        "password=SuperSecretValue123",
							"confirmation_status": "unverified",
						}),
						toolUseBlock("c-claim-ok", "record_profile_claim", map[string]any{
							"subject":             "service:order-svc",
							"relation":            "suspected_bypass",
							"object_value":        "missing_tenant_filter",
							"confirmation_status": "unverified",
							"evidence_kind":       "code_range",
							"evidence_reference":  "src/OrderController.java:15",
						}),
						toolUseBlock("c-add-hyp", "add_exploration_obligation", map[string]any{
							"dimension":      db.DimensionHypothesis,
							"purpose":        "排查租户过滤缺失越权风险",
							"execution_mode": db.ExecModeDynamicVerify,
							"dedupe_key":     "hyp:tenant-filter",
							"evidence_note":  "OrderController.java:15 缺少 tenant_id 校验",
						}),
						toolUseBlock("c-prio", "update_obligation_priority", map[string]any{
							"obligation_id": obCode.ID,
							"priority":      10,
						}),
						toolUseBlock("c-comp-early", "request_assessment_completion", map[string]any{
							"reason": "提前尝试收尾",
						}),
					},
				}, "tool_use", nil
			default:
				return llm.Message{
					Role:    llm.RoleAssistant,
					Content: []llm.ContentBlock{llm.TextBlock("已派发就绪运行实例检查，等待结果唤醒。")},
				}, "end_turn", nil
			}
		},
	}

	tsStore := d.Exploration(task.ExplorationID)
	txStore := transcript.NewStore(t.TempDir())
	planner := NewPlanner(prov1, "mock-model", t.TempDir(), txStore, 100000, 10)
	planner.SetNonStreaming(func() bool { return true })

	ac := AssessmentPlannerContext{
		PG:                d,
		TaskID:            task.ID,
		RoundID:           round.ID,
		RoundNo:           round.RoundNo,
		ProfileVersion:    round.ProfileVersion,
		ExecutionMode:     db.AssessmentExecDynamic,
		AssessmentPhase:   db.AssessmentPhaseExecuting,
		BusinessOverview:  "订单平台",
		BusinessFocus:     []string{"权限越权"},
		WorkerSlots:       2,
		RequestCompletion: completeFn,
	}

	var acts1 []db.Activity
	completed, _, err := planner.PlanAssessment(t.Context(), ac, d.Assets(testProjectID(t, d)), tsStore, nil, func(a db.Activity) {
		acts1 = append(acts1, a)
	})
	if err != nil {
		t.Fatalf("PlanAssessment round 1 failed: %v", err)
	}
	if completed {
		t.Fatal("expected completed=false when obligations remain unsatisfied")
	}

	resultsByID := map[string]db.Activity{}
	for _, a := range acts1 {
		if a.Kind == "tool_result" && a.ToolUseID != "" {
			resultsByID[a.ToolUseID] = a
		}
	}

	if r, ok := resultsByID["c-disp-1"]; !ok || r.IsError || !strings.Contains(r.Detail, `"already_active":false`) {
		t.Fatalf("c-disp-1 unexpected: %+v", r)
	}
	if r, ok := resultsByID["c-disp-dup"]; !ok || r.IsError || !strings.Contains(r.Detail, `"already_active":true`) {
		t.Fatalf("expected c-disp-dup already_active=true, got %+v", r)
	}
	if r, ok := resultsByID["c-disp-unmet"]; !ok || !r.IsError || !strings.Contains(r.Detail, db.ErrObligationDependencyUnmet.Error()) {
		t.Fatalf("expected c-disp-unmet dependency error, got %+v", r)
	}
	if r, ok := resultsByID["c-claim-bad-conf"]; !ok || !r.IsError {
		t.Fatalf("expected c-claim-bad-conf rejected, got %+v", r)
	}
	if r, ok := resultsByID["c-claim-secret"]; !ok || !r.IsError || !strings.Contains(r.Detail, db.ErrAssessmentSecretRejected.Error()) {
		t.Fatalf("expected c-claim-secret rejected for secret, got %+v", r)
	}
	if r, ok := resultsByID["c-claim-ok"]; !ok || r.IsError {
		t.Fatalf("expected c-claim-ok success, got %+v", r)
	}
	if r, ok := resultsByID["c-add-hyp"]; !ok || r.IsError {
		t.Fatalf("expected c-add-hyp success, got %+v", r)
	}
	if r, ok := resultsByID["c-prio"]; !ok || r.IsError {
		t.Fatalf("expected c-prio success, got %+v", r)
	}
	if r, ok := resultsByID["c-comp-early"]; !ok || r.IsError || !strings.Contains(r.Detail, `"can_complete":false`) {
		t.Fatalf("expected premature completion can_complete=false, got %+v", r)
	}

	// Verify DB side-effects match: 1 active intent for obRT, 0 for obEntry, obCode prio updated, planner hypothesis created.
	activeIntents, err := tsStore.ListActiveIntents(20)
	if err != nil || len(activeIntents) != 1 {
		t.Fatalf("expected exactly 1 active intent after duplicate dispatch, got %d err=%v", len(activeIntents), err)
	}
	gotCode, err := d.GetCoverageObligation(task.ID, obCode.ID)
	if err != nil || gotCode.Priority != 10 {
		t.Fatalf("expected obCode priority=10, got %+v err=%v", gotCode, err)
	}

	// Satisfy all required obligations in DB and close active intent, then let Planner call request_assessment_completion.
	obRTState, err := d.GetCoverageObligation(task.ID, obRT.ID)
	if err != nil || obRTState.ActiveAttemptID == nil {
		t.Fatalf("expected obRT active attempt, got %+v err=%v", obRTState, err)
	}
	if _, err := d.FinalizeObligationAttempt(db.FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: obRT.ID, AttemptID: *obRTState.ActiveAttemptID,
		Outcome: db.AttemptSupported, EvidenceRefID: &evExec, SatisfyObligation: true,
	}); err != nil {
		t.Fatal(err)
	}
	_ = tsStore.SetIntentState(activeIntents[0].ID, "done")

	allObs, err := d.ListCoverageObligations(db.CoverageObligationFilter{
		TaskID: task.ID, RoundID: round.ID, ExcludeTerminal: true, Limit: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ob := range allObs {
		mode := ob.ExecutionMode
		if mode == "" {
			mode = db.ExecModeDynamicVerify
		}
		disp, err := d.DispatchAssessmentIntent(db.DispatchAssessmentIntentInput{
			TaskID: task.ID, RoundID: round.ID, ObligationID: ob.ID,
			ExecutionMode: mode, Summary: "finish " + ob.DedupeKey,
		})
		if err != nil {
			t.Fatalf("dispatch %s failed: %v", ob.DedupeKey, err)
		}
		evID := evExec
		if mode == db.ExecModeCodeAuditBatch {
			evID = evCode
		}
		res, err := d.FinalizeObligationAttempt(db.FinalizeObligationAttemptInput{
			TaskID: task.ID, ObligationID: ob.ID, AttemptID: disp.AttemptID,
			Outcome: db.AttemptSupported, EvidenceRefID: &evID, SatisfyObligation: true,
		})
		if err != nil || !res.ObligationAdvanced {
			t.Fatalf("finalize %s failed: res=%+v err=%v", ob.DedupeKey, res, err)
		}
		_ = tsStore.SetIntentState(disp.IntentID, "done")
	}

	prov2 := &scriptedAssessmentProvider{
		turns: func(call int, _ llm.CompletionRequest) (llm.Message, string, error) {
			if call == 1 {
				return llm.Message{
					Role: llm.RoleAssistant,
					Content: []llm.ContentBlock{
						toolUseBlock("c-comp-final", "request_assessment_completion", map[string]any{
							"reason": "全维度覆盖已满足且证据完整",
						}),
					},
				}, "tool_use", nil
			}
			return llm.Message{
				Role:    llm.RoleAssistant,
				Content: []llm.ContentBlock{llm.TextBlock("完成契约已通过，评估结束。")},
			}, "end_turn", nil
		},
	}
	planner2 := NewPlanner(prov2, "mock-model", t.TempDir(), txStore, 100000, 10)
	planner2.SetNonStreaming(func() bool { return true })

	completed2, reason2, err := planner2.PlanAssessment(t.Context(), ac, d.Assets(testProjectID(t, d)), tsStore, nil, nil)
	if err != nil {
		t.Fatalf("PlanAssessment round 2 failed: %v", err)
	}
	if !completed2 || reason2 == "" {
		t.Fatalf("expected completed=true after all obligations satisfied, got completed=%v reason=%q", completed2, reason2)
	}
	storedTask, err := d.GetTask(task.ID)
	if err != nil || storedTask.Status != "done" {
		t.Fatalf("expected DB task status=done, got %+v err=%v", storedTask, err)
	}
}
