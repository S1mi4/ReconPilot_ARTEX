package db

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestStep6DynamicFinalizeAntiDowngradeAndSecretGuard(t *testing.T) {
	d, task, round := assessmentFixture(t)

	// 1. DispatchAssessmentIntent must reject plaintext secrets in WorkOrder.
	rtEnt, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "instance", Name: "staging",
		Attributes: json.RawMessage(`{"url":"http://127.0.0.1:8080"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	obRT, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionRuntimeAsset, TargetEntityID: &rtEnt.ID,
		Purpose: "核实测试环境 staging 版本与可达性", Required: true, DedupeKey: "step6-rt-staging",
		InitialStatus: ObligationReady, ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
		Priority: 9, ProfileVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obRT.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "check staging",
		WorkOrder: json.RawMessage(`{"note":"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload123.sig456"}`),
	}); !errors.Is(err, ErrAssessmentSecretRejected) {
		t.Fatalf("expected ErrAssessmentSecretRejected for secret in WorkOrder, got %v", err)
	}

	// 2. Dynamic verify attempt CANNOT satisfy an obligation using static code_range evidence.
	d1, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obRT.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "check staging runtime",
		WorkOrder: json.RawMessage(`{"question":"verify staging runtime version"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.MarkObligationAttemptRunning(task.ID, obRT.ID, d1.AttemptID); err != nil || !ok {
		t.Fatalf("MarkObligationAttemptRunning failed: ok=%v err=%v", ok, err)
	}
	evCode, err := d.CreateEvidenceRef(task.ID, EvidenceCodeRange, "src/App.java:10", json.RawMessage(`{"line":10}`))
	if err != nil {
		t.Fatal(err)
	}
	resCode, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: obRT.ID, AttemptID: d1.AttemptID,
		Outcome: AttemptSupported, EvidenceRefID: &evCode, SatisfyObligation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resCode.ObligationAdvanced || !resCode.InsufficientEvidence || resCode.AttemptOutcome != AttemptFailed {
		t.Fatalf("expected anti-downgrade rejection for code_range on dynamic_verify, got %+v", resCode)
	}
	if err := d.Exploration(task.ExplorationID).SetIntentState(d1.IntentID, "blocked"); err != nil {
		t.Fatal(err)
	}

	// 3. Re-dispatch with env_mismatch blocks runtime_asset cleanly without advancing dependent obligations.
	entryEnt, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "entry", Name: "POST /api/orders",
	})
	if err != nil {
		t.Fatal(err)
	}
	obEntry, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionEntryTest, TargetEntityID: &entryEnt.ID,
		Purpose: "动态检查入口 POST /api/orders", Required: true, DedupeKey: "step6-entry-orders",
		InitialStatus: ObligationPending, ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
		Priority: 7, ProfileVersion: 1, DependencyIDs: []int64{obRT.ID},
	})
	if err != nil {
		t.Fatal(err)
	}

	d2, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obRT.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "recheck staging",
	})
	if err != nil {
		t.Fatal(err)
	}
	evExec, err := d.CreateEvidenceRef(task.ID, EvidenceExecution, "dynamic_verify:mismatch", json.RawMessage(`{"version":"v2"}`))
	if err != nil {
		t.Fatal(err)
	}
	resMismatch, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: obRT.ID, AttemptID: d2.AttemptID,
		Outcome: AttemptEnvMismatch, EvidenceRefID: &evExec, SatisfyObligation: false,
		BlockedReason: "环境运行 v2，代码快照为 v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resMismatch.ObligationAdvanced || resMismatch.NewObligationStatus != ObligationBlocked {
		t.Fatalf("expected env_mismatch to block obligation without advancing, got %+v", resMismatch)
	}
	if err := d.Exploration(task.ExplorationID).SetIntentState(d2.IntentID, "blocked"); err != nil {
		t.Fatal(err)
	}
	gotEntry, _ := d.GetCoverageObligation(task.ID, obEntry.ID)
	if gotEntry.Status != ObligationPending {
		t.Fatalf("expected dependent entry_test to stay pending on env_mismatch, got %s", gotEntry.Status)
	}

	// 4. Transition back to ready and settle with EvidenceTraffic -> satisfies runtime_asset and unlocks entry_test.
	if ok, err := d.TransitionObligationStatus(obRT.ID, ObligationBlocked, ObligationReady, TransitionObligationOptions{}); err != nil || !ok {
		t.Fatalf("reset runtime_asset blocked->ready failed: ok=%v err=%v", ok, err)
	}
	d3, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obRT.ID,
		ExecutionMode: ExecModeDynamicVerify, Summary: "verify matching staging",
	})
	if err != nil {
		t.Fatal(err)
	}
	evTraffic, err := d.CreateEvidenceRef(task.ID, EvidenceTraffic, "traffic:req-101", json.RawMessage(`{"traffic_ids":["req-101"]}`))
	if err != nil {
		t.Fatal(err)
	}
	resOK, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: obRT.ID, AttemptID: d3.AttemptID,
		Outcome: AttemptSupported, EvidenceRefID: &evTraffic, SatisfyObligation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resOK.ObligationAdvanced || resOK.NewObligationStatus != ObligationSatisfied || resOK.UnlockedCount != 1 {
		t.Fatalf("expected traffic-backed dynamic_verify to satisfy and unlock 1 dependent, got %+v", resOK)
	}
}

func TestStep6ListPublishedCodeAuditFindingsIncludesCandidatesAndTheoreticalFindings(t *testing.T) {
	d, task, round := assessmentFixture(t)

	ent, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "service", Name: "order-svc",
		CodebaseID: "cb-step6", VersionID: "v-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	run, _, err := d.CreateOrResumeEngineCodeAuditRun(CreateEngineCodeAuditInput{
		TaskID: task.ID, ObligationID: 0, TargetEntityID: &ent.ID, TargetName: "order-svc",
		TargetType: "service", CodebaseID: "cb-step6", VersionID: "v-1", RelativePath: "order-svc",
		ScopePath: ".", Languages: []string{"go"}, ProfileSource: "test", ProfileName: "p",
		ProfileFormat: "openai", Model: "m", Endpoint: "http://localhost", SourceAcknowledged: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Mark running and record one published candidate.
	candJSON := json.RawMessage(`{
		"title":"OrderController 缺少租户校验",
		"category":"BROKEN_OBJECT_LEVEL_AUTH",
		"severity":"high",
		"registration_tier":"A",
		"source":{"file":"order/handler.go","line":18,"symbol":"OrderID","description":"URL param"},
		"sink":{"file":"order/repo.go","line":42,"symbol":"FindByID","description":"Unscoped query"}
	}`)
	if _, err := d.Exec(`INSERT INTO task_code_audit_candidates(run_id,candidate_key,review_status,candidate,candidate_variants,verification_summary) VALUES($1,$2,'published',$3::jsonb,jsonb_build_array(jsonb_build_object('analysis_chunk','chunk-1','candidate',$3::jsonb)),'ready')`, run.ID, "cand-bola-1", string(candJSON)); err != nil {
		t.Fatal(err)
	}
	// Also record a standalone theoretical finding not bound to a candidate row.
	fRec, err := d.Exploration(task.ExplorationID).RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID,
		VulnClass: "SSRF", Name: "WebhookFetcher 未校验内网地址", Severity: "medium",
		Summary: "静态分析发现 URL 可控", Evidence: "webhook.go:25", Worker: "whitebox_audit",
		CodeAuditEvidence: json.RawMessage(`{"relative_path":"order-svc","locations":[{"file":"webhook.go","line":25}]}`),
		VerifyLevel:       "theoretical", ImpactObserved: "none",
	})
	if err != nil {
		t.Fatal(err)
	}

	items, err := d.ListPublishedCodeAuditFindings(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 published static summaries (1 candidate + 1 theoretical finding), got %d: %+v", len(items), items)
	}
	if items[0].CandidateKey != "cand-bola-1" || !strings.Contains(items[0].Title, "OrderController") {
		t.Fatalf("unexpected candidate summary[0]: %+v", items[0])
	}
	if items[1].FindingID == nil || *items[1].FindingID != fRec.FindingID {
		t.Fatalf("unexpected standalone theoretical finding summary[1]: %+v", items[1])
	}
}
