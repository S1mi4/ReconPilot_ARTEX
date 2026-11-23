package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
	"github.com/Autumn-27/norma/llm"
)

func TestStep6StaticToDynamicWorkOrderAndNoSecretLeak(t *testing.T) {
	s, projectID, token := step2TestServer(t)

	task, round := createStartedAssessmentTask(t, s.m, projectID, "step6-work-order", pgdb.AssessmentConfig{
		ExecutionMode:    pgdb.AssessmentExecDynamic,
		ScopeNotes:       "仅验证已授权隔离测试实例 http://127.0.0.1:18080",
		BusinessOverview: "订单结算服务，包含支付回调与只读查询",
		Environments: []pgdb.AssessmentEnvironmentInput{
			{Name: "qa-isolated", URL: "http://127.0.0.1:18080", Description: "隔离测试环境", IsDefault: true},
		},
		EnvAccess: &pgdb.AssessmentEnvAccessInput{
			Mode:  "direct",
			Notes: "局域网直连隔离测试环境",
		},
		Identities: []pgdb.AssessmentIdentityInput{
			{Role: "buyer", Username: "buyer01", AuthType: "bearer", CredentialRef: "vault:qa-buyer-token", Scope: "order:read"},
		},
	}, 2)
	taskNum, _ := strconv.ParseInt(task.ID, 10, 64)

	ver := uploadTestCodebaseOnDraft(t, s, token, task.ID, []codebaseTestFile{
		{path: "order-svc/main.go", data: []byte("package main\nfunc HandleOrder() {}\nfunc ExportOrder() {}\n")},
	})

	// StartAssessmentTask already creates instance "qa-isolated" and identity "buyer" from AssessmentConfig;
	// add codebase service, an entry without static candidates, deployment claim, and external out-of-scope dep.
	svcEnt, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: taskNum, RoundID: &round.ID, EntityType: "service", Name: "order-svc",
		CodebaseID: ver.CodebaseID, VersionID: ver.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	entryEnt, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: taskNum, RoundID: &round.ID, EntityType: "entry", Name: "GET /api/orders/ping",
		CodebaseID: ver.CodebaseID, VersionID: ver.ID,
		Attributes: json.RawMessage(`{"method":"GET","path":"/api/orders/ping","module":"order-svc"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.m.pg.CreateProfileClaim(pgdb.CreateProfileClaimInput{
		TaskID: taskNum, RoundID: &round.ID, Subject: "service:order-svc",
		Relation: "deployed_to_instance", ObjectValue: "instance:qa-isolated",
		SourceType: pgdb.ClaimSourceStaticExtraction, ConfirmationStatus: pgdb.ClaimStatusUnverified,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.m.pg.CreateProfileClaim(pgdb.CreateProfileClaimInput{
		TaskID: taskNum, RoundID: &round.ID, Subject: "service:order-svc",
		Relation: "depends_on", ObjectValue: "https://thirdparty-pay.example.net/notify",
		SourceType: pgdb.ClaimSourceStaticExtraction, ConfirmationStatus: pgdb.ClaimStatusUnverified,
	}); err != nil {
		t.Fatal(err)
	}

	// Publish a static candidate + theoretical finding (static != dynamic).
	run, _, err := s.m.pg.CreateOrResumeEngineCodeAuditRun(pgdb.CreateEngineCodeAuditInput{
		TaskID: taskNum, TargetEntityID: &svcEnt.ID, TargetName: "order-svc",
		TargetType: "service", CodebaseID: ver.CodebaseID, VersionID: ver.ID, RelativePath: ".",
		ScopePath: ".", Languages: []string{"go"}, ProfileSource: "test", ProfileName: "p",
		ProfileFormat: "openai", Model: "m", Endpoint: "http://localhost", SourceAcknowledged: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	candRaw := json.RawMessage(`{
		"title":"ExportOrder 参数未限制订单归属",
		"category":"IDOR",
		"severity":"high",
		"registration_tier":"A",
		"source":{"file":"order-svc/main.go","line":3,"symbol":"ExportOrder","description":"query param id"},
		"why_unobstructed":"未检查 buyer 所有权",
		"exploitability":"静态路径到达导出逻辑"
	}`)
	if _, err := s.m.pg.Exec(`INSERT INTO task_code_audit_candidates(run_id,candidate_key,review_status,candidate,candidate_variants,verification_summary) VALUES($1,$2,'published',$3::jsonb,jsonb_build_array(jsonb_build_object('analysis_chunk','chunk-1','candidate',$3::jsonb)),'static candidate')`, run.ID, "cand-export-idor", string(candRaw)); err != nil {
		t.Fatal(err)
	}
	fRec, err := task.Store.RecordFinding(t.Context(), pgdb.RecordFindingInput{
		TaskID: taskNum, ExplorationID: task.Store.ID(),
		VulnClass: "IDOR", Name: "ExportOrder 参数未限制订单归属", Severity: "high",
		Summary: "静态待验证", Evidence: "main.go:3", Worker: "whitebox_audit",
		CodeAuditEvidence: json.RawMessage(`{"candidate_key":"cand-export-idor","locations":[{"file":"order-svc/main.go","line":3,"symbol":"ExportOrder"}]}`),
		VerifyLevel:       "theoretical", ImpactObserved: "none",
	})
	if err != nil {
		t.Fatal(err)
	}

	plan, statusCode, err := s.BuildAssessmentCoveragePlan(t.Context(), task.ID)
	if err != nil || statusCode != http.StatusOK {
		t.Fatalf("BuildAssessmentCoveragePlan failed: code=%d err=%v", statusCode, err)
	}

	var obEntry, obID, obHyp *pgdb.CoverageObligation
	for i := range plan.Obligations {
		ob := &plan.Obligations[i]
		switch {
		case ob.Dimension == pgdb.DimensionEntryTest && ob.TargetEntityID != nil && *ob.TargetEntityID == entryEnt.ID:
			obEntry = ob
		case ob.Dimension == pgdb.DimensionIdentityResource && strings.Contains(ob.DedupeKey, "buyer"):
			obID = ob
		case ob.Dimension == pgdb.DimensionHypothesis && strings.Contains(ob.DedupeKey, "cand-export-idor"):
			obHyp = ob
		}
	}
	if obEntry == nil || obID == nil || obHyp == nil {
		t.Fatalf("expected entry_test, identity_resource, and static hypothesis obligations; got %+v", plan.Obligations)
	}
	if obHyp.ExecutionMode != pgdb.ExecModeDynamicVerify {
		t.Fatalf("expected hypothesis obligation ExecutionMode=dynamic_verify, got %s", obHyp.ExecutionMode)
	}

	// Build WorkOrder for static hypothesis & verify anchors, env, out-of-scope dep guard, no secret leakage.
	woHyp, envSummary := s.buildDynamicVerifyWorkOrder(taskNum, round.ID, obHyp, pgdb.IntentAssessmentMeta{}, task, nil)
	if woHyp.Environment == nil || woHyp.Environment.URL != "http://127.0.0.1:18080" || !strings.Contains(envSummary, "qa-isolated") {
		t.Fatalf("expected mapped qa-isolated environment in work order, got env=%+v summary=%q", woHyp.Environment, envSummary)
	}
	if woHyp.LinkedFindingID == nil || *woHyp.LinkedFindingID != fRec.FindingID || !woHyp.StaticOnly {
		t.Fatalf("expected LinkedFindingID=%d StaticOnly=true, got %+v", fRec.FindingID, woHyp)
	}
	if len(woHyp.CodeAnchors) == 0 || woHyp.CodeAnchors[0].Path != "order-svc/main.go" {
		t.Fatalf("expected bound code anchor on order-svc/main.go, got %+v", woHyp.CodeAnchors)
	}
	if len(woHyp.OutOfScopeDependencies) == 0 || !strings.Contains(woHyp.OutOfScopeDependencies[0], "thirdparty-pay.example.net") {
		t.Fatalf("expected external out-of-scope dependency flagged read-only, got %+v", woHyp.OutOfScopeDependencies)
	}

	// Build WorkOrder for identity_resource & verify credential_ref (ref only, never secret).
	woID, _ := s.buildDynamicVerifyWorkOrder(taskNum, round.ID, obID, pgdb.IntentAssessmentMeta{}, task, nil)
	if woID.Identity == nil || woID.Identity.CredentialRef != "vault:qa-buyer-token" || !woID.Identity.RequiresCredentials {
		t.Fatalf("expected credential_ref vault:qa-buyer-token in identity work order, got %+v", woID.Identity)
	}
	woBytes, _ := json.Marshal([]any{woHyp, woID})
	if err := pgdb.ValidateAssessmentTextSafe(string(woBytes)); err != nil {
		t.Fatalf("work order leaked unsafe secret text: %v", err)
	}

	// Entry without static candidate must STILL produce a concrete entry_test work order.
	woEntry, _ := s.buildDynamicVerifyWorkOrder(taskNum, round.ID, obEntry, pgdb.IntentAssessmentMeta{}, task, nil)
	if woEntry.EntryURL != "http://127.0.0.1:18080/api/orders/ping" || len(woEntry.EvidencePlan) == 0 {
		t.Fatalf("expected concrete entry_test work order for non-candidate entry, got %+v", woEntry)
	}
}

func TestStep6DynamicVerifyEnvMismatchUnreproducedAndMissingCredentials(t *testing.T) {
	var appVersion atomic.Value
	appVersion.Store("v2.0-mismatch")

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-App-Version", appVersion.Load().(string))
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "status=ok version=%s\n", appVersion.Load().(string))
			return
		}
		if r.URL.Path == "/api/orders/export" {
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = w.Write([]byte("missing batch job token"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer targetSrv.Close()

	s, projectID, _ := step2TestServer(t)
	task, round := createStartedAssessmentTask(t, s.m, projectID, "step6-env-mismatch-unreproduced", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecDynamic,
		ScopeNotes:    targetSrv.URL,
		Environments: []pgdb.AssessmentEnvironmentInput{
			{Name: "staging", URL: targetSrv.URL, IsDefault: true},
		},
		EnvAccess: &pgdb.AssessmentEnvAccessInput{Mode: "direct"},
	}, 2)
	taskNum, _ := strconv.ParseInt(task.ID, 10, 64)

	rtEnt, err := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: taskNum, RoundID: &round.ID, EntityType: "instance", Name: "staging",
		VersionID: "v1.0-expected", Attributes: json.RawMessage(fmt.Sprintf(`{"url":%q,"is_default":true}`, targetSrv.URL)),
	})
	if err != nil {
		t.Fatal(err)
	}
	obRT, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionRuntimeAsset, TargetEntityID: &rtEnt.ID,
		Purpose: "核实测试环境 staging 版本与可达性", Required: true, DedupeKey: "rt-staging",
		InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeDynamicVerify, Origin: pgdb.ObligationOriginProgram,
		Priority: 9, ProfileVersion: round.ProfileVersion,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Linked theoretical static finding + hypothesis obligation dependent on rt-staging.
	fRec, err := task.Store.RecordFinding(t.Context(), pgdb.RecordFindingInput{
		TaskID: taskNum, ExplorationID: task.Store.ID(),
		VulnClass: "IDOR", Name: "订单导出越权", Severity: "high",
		Summary: "静态未校验归属", Evidence: "export.go:12", Worker: "whitebox_audit",
		VerifyLevel: "theoretical", ImpactObserved: "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	hypSnap, _ := json.Marshal(map[string]any{
		"finding_id": fRec.FindingID, "static_only": true, "title": "订单导出越权",
	})
	obHyp, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionHypothesis,
		Purpose: "动态复现静态候选：订单导出越权", Required: true, DedupeKey: "hyp-export",
		InitialStatus: pgdb.ObligationPending, ExecutionMode: pgdb.ExecModeDynamicVerify,
		Origin: pgdb.ObligationOriginProgram, Priority: 8, ProfileVersion: round.ProfileVersion,
		DependencyIDs: []int64{obRT.ID}, ContextSnapshot: hypSnap,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Missing-credential identity_resource obligation.
	obNoCred, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionIdentityResource,
		Purpose: "验证 admin 身份权限边界", Required: true, DedupeKey: "id-admin-nocred",
		RequiresCredentials: true, CredentialRef: "",
		InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeDynamicVerify,
		Origin: dbOriginProgramCompat(), Priority: 7, ProfileVersion: round.ProfileVersion,
	})
	if err != nil {
		t.Fatal(err)
	}

	prov := &step4ScriptedProvider{
		turns: func(_ int, req llm.CompletionRequest) (llm.Message, string, error) {
			if !step6ReqHasTool(req, "submit_dynamic_verification") || !step6ReqMatches(req, targetSrv.URL) {
				return llm.Message{}, "", context.Canceled
			}
			turn := step6AssistantTurns(req.Messages) + 1
			switch {
			case step6ReqMatches(req, "reverify matching staging"):
				switch turn {
				case 1:
					b, _ := json.Marshal(map[string]any{"command": "curl -sS -i " + targetSrv.URL + "/health"})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "bash-match", Name: "Bash", Input: b},
					}}, "tool_use", nil
				case 2:
					b, _ := json.Marshal(map[string]any{
						"verdict":          "supported",
						"summary":          "环境已切换回 v1.0-expected 且 /health 可达",
						"observed_url":     targetSrv.URL,
						"observed_version": "v1.0-expected",
						"version_matched":  true,
						"command_evidence": []string{"curl /health -> 200 OK X-App-Version: v1.0-expected"},
					})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "sub-match", Name: "submit_dynamic_verification", Input: b},
					}}, "tool_use", nil
				default:
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						llm.TextBlock("已确认测试环境匹配。"),
					}}, "end_turn", nil
				}
			case step6ReqMatches(req, "订单导出越权"):
				switch turn {
				case 1:
					b, _ := json.Marshal(map[string]any{"command": "curl -sS -i " + targetSrv.URL + "/api/orders/export"})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "bash-unrep", Name: "Bash", Input: b},
					}}, "tool_use", nil
				case 2:
					b, _ := json.Marshal(map[string]any{
						"verdict":               "unreproduced",
						"summary":               "动态请求 /api/orders/export 返回 412，缺少批量任务前置令牌",
						"observed_url":          targetSrv.URL,
						"missing_preconditions": []string{"需要先行创建批量导出任务句柄"},
						"command_evidence":      []string{"curl /api/orders/export -> 412 missing batch job token"},
					})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "sub-unrep", Name: "submit_dynamic_verification", Input: b},
					}}, "tool_use", nil
				default:
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						llm.TextBlock("已完成动态探测并保留未复现前置缺口。"),
					}}, "end_turn", nil
				}
			default:
				switch turn {
				case 1:
					b, _ := json.Marshal(map[string]any{"command": "curl -sS -i " + targetSrv.URL + "/health"})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "bash-mismatch", Name: "Bash", Input: b},
					}}, "tool_use", nil
				case 2:
					b, _ := json.Marshal(map[string]any{
						"verdict":          "env_mismatch",
						"summary":          "实时环境返回 v2.0-mismatch，与预期代码版本 v1.0-expected 不一致",
						"blocked_reason":   "环境运行版本 v2.0-mismatch 与静态快照 v1.0-expected 不一致",
						"observed_url":     targetSrv.URL,
						"observed_version": "v2.0-mismatch",
						"version_matched":  false,
						"command_evidence": []string{"curl /health -> X-App-Version: v2.0-mismatch"},
					})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "sub-mismatch", Name: "submit_dynamic_verification", Input: b},
					}}, "tool_use", nil
				default:
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						llm.TextBlock("已报告环境版本差异。"),
					}}, "end_turn", nil
				}
			}
		},
	}
	installMockGlobalLLM(s, prov)

	waitObStatus := func(obID int64, wantStatus string) *pgdb.CoverageObligation {
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			if ob, err := s.m.pg.GetCoverageObligation(taskNum, obID); err == nil && ob != nil && ob.Status == wantStatus {
				return ob
			}
			time.Sleep(25 * time.Millisecond)
		}
		ob, _ := s.m.pg.GetCoverageObligation(taskNum, obID)
		return ob
	}

	// Subtest A: env_mismatch on runtime_asset
	if _, err := s.m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
		TaskID: taskNum, RoundID: round.ID, ObligationID: obRT.ID,
		ExecutionMode: pgdb.ExecModeDynamicVerify, Summary: obRT.Purpose,
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.engine.runWorkerStep(t.Context(), task, "work#1", nil)
	gotRT := waitObStatus(obRT.ID, pgdb.ObligationBlocked)
	if gotRT == nil || gotRT.Status != pgdb.ObligationBlocked || !strings.Contains(gotRT.BlockedReason, "v2.0-mismatch") {
		t.Fatalf("expected runtime_asset blocked with version mismatch reason, got %+v", gotRT)
	}
	claims, _ := s.m.pg.ListProfileClaims(pgdb.ProfileClaimFilter{TaskID: taskNum, RoundID: round.ID, Relation: "code_version_verified", Limit: 10})
	if len(claims) == 0 || claims[len(claims)-1].ConfirmationStatus != pgdb.ClaimStatusConflicted {
		t.Fatalf("expected conflicted code_version_verified profile claim, got %+v", claims)
	}
	evs, _ := s.m.pg.ListUnprocessedAssessmentEventsByType(taskNum, "code_version_change", 10)
	if len(evs) == 0 {
		t.Fatal("expected code_version_change assessment event on env_mismatch")
	}

	// Subtest B: Missing credentials on identity_resource is rejected at dispatch AND blocked in runAssessmentDynamicVerify.
	if _, err := s.m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
		TaskID: taskNum, RoundID: round.ID, ObligationID: obNoCred.ID,
		ExecutionMode: pgdb.ExecModeDynamicVerify, Summary: obNoCred.Purpose,
	}); err == nil || !strings.Contains(err.Error(), "credential_ref") {
		t.Fatalf("expected DispatchAssessmentIntent to reject empty credential_ref, got err=%v", err)
	}
	resNoCred, err := s.runAssessmentDynamicVerify(t.Context(), task, "work#1", nil, pgdb.IntentAssessmentMeta{
		ObligationID: obNoCred.ID, RoundID: round.ID, AttemptID: 999, ExecutionMode: pgdb.ExecModeDynamicVerify,
	}, nil)
	if err != nil || resNoCred.SatisfyObligation || resNoCred.Outcome != pgdb.AttemptDependencyMissing {
		t.Fatalf("expected runAssessmentDynamicVerify missing-credential dependency_missing block, got %+v err=%v", resNoCred, err)
	}

	// Subtest C: Resolve version mismatch -> satisfy runtime_asset -> run hypothesis -> unreproduced MUST preserve static theoretical finding.
	appVersion.Store("v1.0-expected")
	if _, err := s.m.pg.TransitionObligationStatus(obRT.ID, pgdb.ObligationBlocked, pgdb.ObligationReady, pgdb.TransitionObligationOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
		TaskID: taskNum, RoundID: round.ID, ObligationID: obRT.ID,
		ExecutionMode: pgdb.ExecModeDynamicVerify, Summary: "reverify matching staging",
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.engine.runWorkerStep(t.Context(), task, "work#1", nil)
	gotHyp := waitObStatus(obHyp.ID, pgdb.ObligationReady)
	if gotHyp == nil || gotHyp.Status != pgdb.ObligationReady {
		t.Fatalf("expected dependent hypothesis obligation unlocked to ready, got %+v", gotHyp)
	}

	if _, err := s.m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
		TaskID: taskNum, RoundID: round.ID, ObligationID: obHyp.ID,
		ExecutionMode: pgdb.ExecModeDynamicVerify, Summary: obHyp.Purpose,
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.engine.runWorkerStep(t.Context(), task, "work#1", nil)
	gotHypAfter := waitObStatus(obHyp.ID, pgdb.ObligationSatisfied)
	if gotHypAfter == nil || gotHypAfter.Status != pgdb.ObligationSatisfied || gotHypAfter.EvidenceRefID == nil {
		t.Fatalf("expected unreproduced dynamic attempt with real evidence to satisfy coverage check, got %+v", gotHypAfter)
	}
	gotFinding, err := s.m.pg.GetFinding(fRec.FindingID)
	if err != nil || gotFinding == nil {
		t.Fatalf("static finding vanished or error: %v", err)
	}
	if gotFinding.VerifyLevel != "theoretical" || gotFinding.Status == "dismissed" || gotFinding.Status == "fixed" {
		t.Fatalf("single unreproduced MUST NOT downgrade/close static finding, got verify_level=%s status=%s", gotFinding.VerifyLevel, gotFinding.Status)
	}
}

func TestStep6DynamicToWhiteboxBidirectionalFeedbackLoop(t *testing.T) {
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/orders" && r.Method == http.MethodPost {
			w.Header().Set("X-Custom-Sign-Required", "true")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("missing hmac signature header X-Order-Sign"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	s, projectID, token := step2TestServer(t)
	task, round := createStartedAssessmentTask(t, s.m, projectID, "step6-bidirectional-loop", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecDynamic,
		ScopeNotes:    targetSrv.URL,
		Environments: []pgdb.AssessmentEnvironmentInput{
			{Name: "qa", URL: targetSrv.URL, IsDefault: true},
		},
	}, 2)
	taskNum, _ := strconv.ParseInt(task.ID, 10, 64)

	ver := uploadTestCodebaseOnDraft(t, s, token, task.ID, []codebaseTestFile{
		{path: "app-gw/gateway/auth_guard.py", data: []byte("def verify_order_sign(h):\n    if h == \"bypass-debug\":\n        return True\n    return False\n")},
	})
	svcEnt, _ := s.m.pg.CreateTargetEntity(pgdb.CreateTargetEntityInput{
		TaskID: taskNum, RoundID: &round.ID, EntityType: "service", Name: "gateway",
		CodebaseID: ver.CodebaseID, VersionID: ver.ID,
	})
	obEntry, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID: taskNum, RoundID: &round.ID, Dimension: pgdb.DimensionEntryTest, TargetEntityID: &svcEnt.ID,
		Purpose: "动态验证入口 POST /api/orders（无前置静态候选）", Required: true, DedupeKey: "entry-post-orders",
		InitialStatus: pgdb.ObligationReady, ExecutionMode: pgdb.ExecModeDynamicVerify,
		Origin: pgdb.ObligationOriginProgram, Priority: 7, ProfileVersion: round.ProfileVersion,
	})
	if err != nil {
		t.Fatal(err)
	}

	prov := &step4ScriptedProvider{
		turns: func(_ int, req llm.CompletionRequest) (llm.Message, string, error) {
			if !step6ReqMatches(req, targetSrv.URL) && !step6ReqMatches(req, "hyp:rev:order-sign") && !step6ReqMatches(req, "X-Order-Sign") {
				return llm.Message{}, "", context.Canceled
			}
			turn := step6AssistantTurns(req.Messages) + 1
			switch {
			case step6ReqHasTool(req, "submit_dynamic_verification"):
				switch turn {
				case 1:
					b, _ := json.Marshal(map[string]any{"command": "curl -sS -X POST " + targetSrv.URL + "/api/orders"})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "dyn1", Name: "Bash", Input: b},
					}}, "tool_use", nil
				case 2:
					b, _ := json.Marshal(map[string]any{
						"subject":             "entry:POST /api/orders",
						"relation":            "auth_middleware",
						"object_value":        "requires-X-Order-Sign",
						"source_type":         "runtime_observation",
						"confirmation_status": "confirmed",
						"execution_summary":   "curl POST /api/orders returned 403 missing hmac signature header X-Order-Sign",
					})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "dyn2", Name: "record_profile_claim", Input: b},
					}}, "tool_use", nil
				case 3:
					b, _ := json.Marshal(map[string]any{
						"dimension":      "hypothesis",
						"purpose":        "反向白盒排查 X-Order-Sign 校验实现与绕过分支",
						"execution_mode": "code_investigate",
						"dedupe_key":     "hyp:rev:order-sign",
						"evidence_note":  "动态请求 POST /api/orders 返回 403 missing hmac signature header X-Order-Sign",
					})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "dyn3", Name: "add_exploration_obligation", Input: b},
					}}, "tool_use", nil
				case 4:
					b, _ := json.Marshal(map[string]any{
						"verdict":               "unreproduced",
						"summary":               "入口要求未知签名头 X-Order-Sign，已提交反向白盒排查义务确认签名算法与后门分支",
						"observed_url":          targetSrv.URL,
						"missing_preconditions": []string{"需白盒查明 X-Order-Sign 生成或校验规则"},
						"command_evidence":      []string{"POST /api/orders -> 403 missing hmac signature header X-Order-Sign"},
					})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "dyn4", Name: "submit_dynamic_verification", Input: b},
					}}, "tool_use", nil
				default:
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						llm.TextBlock("已完成动态探测并触发反向查码反馈。"),
					}}, "end_turn", nil
				}
			case step6ReqHasTool(req, "dispatch_assessment_intent"):
				if turn == 1 {
					obs, _ := s.m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{TaskID: taskNum, RoundID: round.ID, Limit: 20})
					var revID int64
					for _, item := range obs {
						if item.DedupeKey == "hyp:rev:order-sign" && item.Status == pgdb.ObligationReady {
							revID = item.ID
							break
						}
					}
					if revID > 0 {
						b, _ := json.Marshal(map[string]any{
							"obligation_id":  revID,
							"execution_mode": pgdb.ExecModeCodeInvestigate,
							"summary":        "定向读取网关签名逻辑确认 X-Order-Sign 绕过条件",
						})
						return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
							{Type: llm.BlockToolUse, ID: "pl1", Name: "dispatch_assessment_intent", Input: b},
						}}, "tool_use", nil
					}
				}
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					llm.TextBlock("本轮规划完成。"),
				}}, "end_turn", nil
			case step6ReqHasTool(req, "submit_investigation_result"):
				switch turn {
				case 1:
					b, _ := json.Marshal(map[string]any{"path": "gateway/auth_guard.py", "start_line": 1, "end_line": 10})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "ci1", Name: "read_file", Input: b},
					}}, "tool_use", nil
				case 2:
					b, _ := json.Marshal(map[string]any{
						"verdict":  "needs_dynamic_verify",
						"summary":  "verify_order_sign 在第 2 行硬编码旁路签名 bypass-debug，需动态验证头部绕过",
						"evidence": []map[string]any{{"path": "gateway/auth_guard.py", "line": 2, "excerpt": "bypass-debug"}},
					})
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "ci2", Name: "submit_investigation_result", Input: b},
					}}, "tool_use", nil
				default:
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
						llm.TextBlock("已完成反向查码确认旁路分支。"),
					}}, "end_turn", nil
				}
			default:
				return llm.Message{}, "", context.Canceled
			}
		},
	}
	installMockGlobalLLM(s, prov)

	// Step 1: Dispatch entry_test and drive dynamic worker (or observe background completion).
	if _, err := s.m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
		TaskID: taskNum, RoundID: round.ID, ObligationID: obEntry.ID,
		ExecutionMode: pgdb.ExecModeDynamicVerify, Summary: obEntry.Purpose,
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.engine.runWorkerStep(t.Context(), task, "work#1", nil)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := s.m.pg.GetCoverageObligation(taskNum, obEntry.ID)
		if got != nil && got.Status == pgdb.ObligationSatisfied {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got, _ := s.m.pg.GetCoverageObligation(taskNum, obEntry.ID); got == nil || got.Status != pgdb.ObligationSatisfied {
		t.Fatalf("expected entry_test dynamic_verify to satisfy, got %+v", got)
	}

	// Step 2: Planner round consumes knowledge_conflict and dispatches hyp:rev:order-sign (or idempotent check).
	b := s.agentsForTask(task)
	s.engine.runAssessmentPlannerRound(t.Context(), task, b.pl, nil)

	unproc, _ := s.m.pg.ListUnprocessedAssessmentEventsByType(taskNum, "knowledge_conflict", 10)
	if len(unproc) != 0 {
		t.Fatalf("expected knowledge_conflict event to be marked processed after planner round, remaining=%d", len(unproc))
	}

	// Step 3: Drive dispatched reverse code_investigate -> emits follow-up dynamic_verify hypothesis!
	_ = s.engine.runWorkerStep(t.Context(), task, "work#1", nil)
	deadline = time.Now().Add(4 * time.Second)
	var obs []pgdb.CoverageObligation
	foundWB2Dyn := false
	for time.Now().Before(deadline) {
		obs, _ = s.m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{TaskID: taskNum, RoundID: round.ID, Limit: 30})
		for _, ob := range obs {
			if strings.HasPrefix(ob.DedupeKey, "hypothesis:wb2dyn:") && ob.ExecutionMode == pgdb.ExecModeDynamicVerify {
				foundWB2Dyn = true
				break
			}
		}
		if foundWB2Dyn {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !foundWB2Dyn {
		t.Fatalf("expected whitebox needs_dynamic_verify to emit follow-up dynamic_verify hypothesis obligation, got %+v", obs)
	}
}

func step6ReqHasTool(req llm.CompletionRequest, name string) bool {
	for _, td := range req.Tools {
		if td.Name == name {
			return true
		}
	}
	return false
}

func step6ReqMatches(req llm.CompletionRequest, needle string) bool {
	if needle == "" {
		return true
	}
	if strings.Contains(fmt.Sprint(req.System), needle) {
		return true
	}
	for _, m := range req.Messages {
		if strings.Contains(m.Text(), needle) {
			return true
		}
	}
	return false
}

func step6AssistantTurns(msgs []llm.Message) int {
	n := 0
	for _, m := range msgs {
		if m.Role == llm.RoleAssistant {
			n++
		}
	}
	return n
}

func TestStep6RealTrafficVerificationAndLegacyIsolation(t *testing.T) {
	s, projectID, _ := step2TestServer(t)
	tr, err := traffic.Open(filepath.Join(s.m.dir, "traffic"), ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	s.m.traffic = tr

	// Seed 2 traffic rows: one in-scope for qa.local, one out-of-scope for other.external.
	if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES('tr-in-scope',1,'qa.local','GET','/ping','http://qa.local/ping',200,'text/plain',0,2,''),('tr-out-scope',1,'other.external','GET','/','http://other.external/',200,'text/plain',0,2,'')`); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,resp_head,req_body,resp_body) VALUES('tr-in-scope','GET /ping HTTP/1.1','HTTP/1.1 200 OK',X'',X'6f6b'),('tr-out-scope','GET / HTTP/1.1','HTTP/1.1 200 OK',X'',X'6f6b')`); err != nil {
		t.Fatal(err)
	}

	task, _ := createStartedAssessmentTask(t, s.m, projectID, "step6-traffic-verify", pgdb.AssessmentConfig{
		ExecutionMode: pgdb.AssessmentExecDynamic,
		Environments:  []pgdb.AssessmentEnvironmentInput{{Name: "qa", URL: "http://qa.local", IsDefault: true}},
	}, 1)

	verifier := s.buildDynamicTrafficVerifier(task, agent.DynamicWorkOrder{
		Environment: &agent.DynamicEnvironmentTarget{Name: "qa", URL: "http://qa.local"},
	})
	verified, err := verifier(t.Context(), []string{"tr-in-scope"})
	if err != nil || len(verified) != 1 || verified[0] != "tr-in-scope" {
		t.Fatalf("expected in-scope traffic ID verification to succeed, got verified=%v err=%v", verified, err)
	}
	if _, err := verifier(t.Context(), []string{"tr-nonexistent"}); err == nil {
		t.Fatal("expected nonexistent traffic ID to fail verification")
	}
	if _, err := verifier(t.Context(), []string{"tr-out-scope"}); err == nil || !strings.Contains(err.Error(), "不在当前任务的授权") {
		t.Fatalf("expected out-of-scope traffic ID rejection, got err=%v", err)
	}

	// Legacy assessment_mode=false task must bypass specialized dynamic_verify routing and run standard Worker.
	legacyTask, err := s.m.CreateTask(projectID, "step6-legacy-worker", "normal pentest", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(legacyTask.ID, DeleteTaskOptions{}) })
	intentID, err := legacyTask.Store.AddIntent(map[string]any{"summary": "test legacy worker", "execution_mode": pgdb.ExecModeDynamicVerify}, 7, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	prov := &step4ScriptedProvider{
		turns: func(_ int, req llm.CompletionRequest) (llm.Message, string, error) {
			if !step6ReqMatches(req, "test legacy worker") {
				return llm.Message{}, "", context.Canceled
			}
			for _, td := range req.Tools {
				if td.Name == "submit_dynamic_verification" {
					return llm.Message{}, "", fmt.Errorf("legacy worker received assessment-only tool %s", td.Name)
				}
			}
			if step6AssistantTurns(req.Messages) == 0 {
				b, _ := json.Marshal(map[string]any{"summary": "legacy fact recorded", "confidence": "observed", "evidence": "cmd ok", "intent_id": intentID})
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					{Type: llm.BlockToolUse, ID: "lf1", Name: "record_fact", Input: b},
				}}, "tool_use", nil
			}
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				llm.TextBlock("done"),
			}}, "end_turn", nil
		},
	}
	installMockGlobalLLM(s, prov)
	b := s.agentsForTask(legacyTask)
	if !s.engine.runWorkerStep(t.Context(), legacyTask, "work#1", b.wk) {
		t.Fatal("expected legacy worker runWorkerStep to execute")
	}
	node, _ := legacyTask.Store.GetNode(intentID)
	if node == nil || node.State != "done" {
		t.Fatalf("expected legacy worker intent done, got %+v", node)
	}
	_ = time.Now()
}

func dbOriginProgramCompat() string { return pgdb.ObligationOriginProgram }
