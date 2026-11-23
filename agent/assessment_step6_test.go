package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

func TestStep6DynamicVerifyToolGatesAndSecrets(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("step6 tool gates", "assess", db.TaskCreateOptions{
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

	ob, err := d.CreateCoverageObligation(db.CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: db.DimensionIdentityResource,
		Purpose: "验证 buyer 角色边界", Required: true, DedupeKey: "id-buyer",
		RequiresCredentials: true, CredentialRef: "qa:buyer",
		InitialStatus: db.ObligationReady, ExecutionMode: db.ExecModeDynamicVerify,
		Origin: db.ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}

	tsx := NewToolSet(d.Exploration(task.ExplorationID), "work#1")
	tsx.SetTaskID(task.ID)

	var execCount atomic.Int64
	var outcome DynamicVerifyOutcome
	dc := DynamicVerifyContext{
		PG:                  d,
		TaskID:              task.ID,
		RoundID:             round.ID,
		RoundNo:             round.RoundNo,
		ProfileVersion:      round.ProfileVersion,
		ObligationID:        ob.ID,
		AttemptID:           101,
		Dimension:           ob.Dimension,
		RequiresCredentials: true,
		CredentialRef:       ob.CredentialRef,
		ExecutionCounter:    &execCount,
		ReadCodeTools: []actool.CoreTool{
			dummyReadTool("list_code_slice"),
			dummyReadTool("read_code_slice"),
			dummyReadTool("Bash"), // duplicate/disallowed from ReadCodeTools
		},
		VerifyTrafficIDs: func(_ context.Context, ids []string) ([]string, error) {
			for _, id := range ids {
				if id != "real-tr-1" {
					return nil, fmt.Errorf("unknown traffic id %q", id)
				}
			}
			return ids, nil
		},
	}

	tools := tsx.DynamicVerifyTools(dc, &outcome)
	byName := map[string]actool.CoreTool{}
	for _, tl := range tools {
		byName[tl.Name()] = tl
	}

	for _, forbidden := range []string{"add_intent", "set_goals", "kill_work", "dispatch_assessment_intent", "request_assessment_completion"} {
		if byName[forbidden] != nil {
			t.Fatalf("forbidden control-plane tool %q exposed to dynamic_verify", forbidden)
		}
	}
	for _, want := range []string{
		"Bash", "report_finding", "record_fact", "insert_assets",
		"query_profile_slice", "list_coverage_obligations", "record_profile_claim",
		"add_exploration_obligation", "list_code_slice", "read_code_slice", "submit_dynamic_verification",
	} {
		if byName[want] == nil {
			t.Fatalf("expected tool %q in DynamicVerifyTools", want)
		}
	}

	submit := byName["submit_dynamic_verification"]

	// 1. Reject effective verdict when ExecutionCounter == 0 and no verified traffic_ids.
	res, err := submit.Call(context.Background(), json.RawMessage(`{
		"verdict":"supported",
		"summary":"未真正探测就宣称成功",
		"command_evidence":["simulated curl returned 200"]
	}`), nil)
	if err != nil || !res.IsError || outcome.Submitted {
		t.Fatalf("expected fabricated command_evidence rejection when ExecutionCounter=0, res=%+v err=%v", res, err)
	}

	// 2. Reject forged traffic_ids.
	res, err = submit.Call(context.Background(), json.RawMessage(`{
		"verdict":"supported",
		"summary":"伪造流量 ID 测试",
		"traffic_ids":["fake-tr-999"]
	}`), nil)
	if err != nil || !res.IsError || outcome.Submitted {
		t.Fatalf("expected forged traffic_id rejection, res=%+v err=%v", res, err)
	}

	// 3. Reject missing credentials when RequiresCredentials=true and CredentialRef="".
	dcNoCred := dc
	dcNoCred.CredentialRef = ""
	var outNoCred DynamicVerifyOutcome
	submitNoCred := tsx.submitDynamicVerificationTool(dcNoCred, &outNoCred)
	res, err = submitNoCred.Call(context.Background(), json.RawMessage(`{
		"verdict":"supported",
		"summary":"无凭证宣称测通",
		"traffic_ids":["real-tr-1"]
	}`), nil)
	if err != nil || !res.IsError || outNoCred.Submitted {
		t.Fatalf("expected missing credential_ref rejection for supported verdict, res=%+v", res)
	}

	// 4. Reject unreproduced without missing_preconditions.
	execCount.Store(1)
	res, err = submit.Call(context.Background(), json.RawMessage(`{
		"verdict":"unreproduced",
		"summary":"暂未复现漏洞",
		"command_evidence":["curl -i http://127.0.0.1:8080/api -> 403"]
	}`), nil)
	if err != nil || !res.IsError || outcome.Submitted {
		t.Fatalf("expected unreproduced without missing_preconditions rejection, res=%+v", res)
	}

	// 5. Reject plaintext secret anywhere in submission.
	res, err = submit.Call(context.Background(), json.RawMessage(`{
		"verdict":"supported",
		"summary":"验证通过 password=MyPlaintextSecret123",
		"traffic_ids":["real-tr-1"]
	}`), nil)
	if err != nil || !res.IsError || outcome.Submitted {
		t.Fatalf("expected plaintext secret rejection in submit_dynamic_verification, res=%+v", res)
	}

	// 6. Reject runtime_asset supported when version_matched=false.
	dcRT := dc
	dcRT.Dimension = db.DimensionRuntimeAsset
	dcRT.RequiresCredentials = false
	var outRT DynamicVerifyOutcome
	submitRT := tsx.submitDynamicVerificationTool(dcRT, &outRT)
	res, err = submitRT.Call(context.Background(), json.RawMessage(`{
		"verdict":"supported",
		"summary":"版本不一致却宣称 supported",
		"version_matched":false,
		"traffic_ids":["real-tr-1"]
	}`), nil)
	if err != nil || !res.IsError || outRT.Submitted {
		t.Fatalf("expected version_matched=false + supported rejection on runtime_asset, res=%+v", res)
	}

	// 7. Valid verified traffic submission succeeds and persists EvidenceTraffic.
	res, err = submit.Call(context.Background(), json.RawMessage(`{
		"verdict":"supported",
		"summary":"buyer 凭证仅可查看本人订单，越权请求均返回 403",
		"traffic_ids":["real-tr-1"]
	}`), nil)
	if err != nil || res.IsError || !outcome.Submitted || outcome.EvidenceRefID == nil || *outcome.EvidenceRefID <= 0 {
		t.Fatalf("expected verified traffic submission success, res=%+v err=%v outcome=%+v", res, err, outcome)
	}

	// 8. Check seeds, wrapup, and minimalExploitRoles registration.
	if strings.TrimSpace(BuiltinPromptSeeds()["dynamic_verify"]) == "" {
		t.Fatal("BuiltinPromptSeeds missing dynamic_verify")
	}
	if strings.TrimSpace(WrapupDefault("dynamic_verify")) == "" || strings.TrimSpace(TaskTimeoutWrapupDefault("dynamic_verify")) == "" {
		t.Fatal("dynamic_verify wrapup defaults missing")
	}
	if !minimalExploitRoles("dynamic_verify") {
		t.Fatal("minimalExploitRoles should include dynamic_verify")
	}

	// 9. record_profile_claim rejects unverified runtime_observation without execution/traffic evidence.
	claimTool := byName["record_profile_claim"]
	var execZero atomic.Int64
	dcZero := dc
	dcZero.ExecutionCounter = &execZero
	claimToolZero := tsx.recordDynamicProfileClaimTool(dcZero, &outcome)
	res, err = claimToolZero.Call(context.Background(), json.RawMessage(`{
		"subject":"instance:staging",
		"relation":"code_version_verified",
		"object_value":"v1",
		"source_type":"runtime_observation",
		"confirmation_status":"confirmed",
		"execution_summary":"fabricated check"
	}`), nil)
	if err != nil || !res.IsError {
		t.Fatalf("expected record_profile_claim to reject confirmed runtime_observation when ExecutionCounter=0, got %+v", res)
	}
	res, err = claimTool.Call(context.Background(), json.RawMessage(`{
		"subject":"instance:staging",
		"relation":"auth_middleware",
		"object_value":"requires-hmac-header",
		"source_type":"runtime_observation",
		"confirmation_status":"confirmed",
		"traffic_ids":["real-tr-1"]
	}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("expected verified traffic record_profile_claim to succeed, got res=%+v err=%v", res, err)
	}
	_ = errors.Is
}

func TestStep6WorkerExecuteDynamicVerifyBidirectional(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("step6 worker exec", "assess", db.TaskCreateOptions{
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
	ob, err := d.CreateCoverageObligation(db.CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: db.DimensionEntryTest,
		Purpose: "动态验证 /api/ping", Required: true, DedupeKey: "entry-ping",
		InitialStatus: db.ObligationReady, ExecutionMode: db.ExecModeDynamicVerify,
		Origin: db.ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}

	ts := d.Exploration(task.ExplorationID)
	intentID, err := ts.AddIntent(map[string]any{"summary": "动态核查 /api/ping"}, 7, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := ts.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}

	var codeRead atomic.Bool

	var callCount atomic.Int32
	prov := &scriptedAssessmentProvider{
		turns: func(_ int, req llm.CompletionRequest) (llm.Message, string, error) {
			switch callCount.Add(1) {
			case 1:
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					toolUseBlock("dv1", "read_code_slice", map[string]any{"path": "ping.go"}),
				}}, "tool_use", nil
			case 2:
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					toolUseBlock("dv2", "Bash", map[string]any{"command": "echo DYNAMIC_PROBE_OK"}),
				}}, "tool_use", nil
			case 3:
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					toolUseBlock("dv3", "submit_dynamic_verification", map[string]any{
						"verdict":          "supported",
						"summary":          "已通过 Bash 实测验证 /api/ping 行为，并登记反向查码义务排查中间件限流阈值",
						"command_evidence": []string{"echo DYNAMIC_PROBE_OK -> DYNAMIC_PROBE_OK"},
						"next_code_investigate": map[string]any{
							"purpose":       "排查 /api/ping 限流中间件源码",
							"evidence_note": "响应包含限流头需确认配置来源",
						},
					}),
				}}, "tool_use", nil
			default:
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					llm.TextBlock("已完成动态验证与反向查码反馈。"),
				}}, "end_turn", nil
			}
		},
	}

	txStore := transcript.NewStore(t.TempDir())
	wk := NewWorker(prov, "mock-model", t.TempDir(), txStore, 64000, 12)
	readSliceTool := actool.Build(actool.Spec{
		Name:        "read_code_slice",
		Description: "read code slice",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{"path": str("path")}},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: nil,
		Run: func(_ context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			codeRead.Store(true)
			return actool.Text("func Ping() string { return \"pong\" }"), nil
		},
	})

	execCounter := &atomic.Int64{}
	dc := DynamicVerifyContext{
		PG:               d,
		TaskID:           task.ID,
		RoundID:          round.ID,
		RoundNo:          round.RoundNo,
		ProfileVersion:   round.ProfileVersion,
		ObligationID:     ob.ID,
		AttemptID:        202,
		Dimension:        ob.Dimension,
		ReadCodeTools:    []actool.CoreTool{readSliceTool},
		ExecutionCounter: execCounter,
		WorkOrder: DynamicWorkOrder{
			ObligationID: ob.ID,
			Dimension:    ob.Dimension,
			Purpose:      ob.Purpose,
			Question:     "验证 /api/ping 响应与限流头",
		},
	}

	outcome, _, _, err := wk.ExecuteDynamicVerify(t.Context(), "work#1", dc, nil, ts, intent, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !codeRead.Load() {
		t.Fatal("expected read_code_slice tool to be called")
	}
	if !outcome.Submitted || outcome.Verdict != db.AttemptSupported || execCounter.Load() == 0 {
		t.Fatalf("unexpected ExecuteDynamicVerify outcome: %+v execCount=%d", outcome, execCounter.Load())
	}
	if outcome.FeedbackObligationsCreated != 1 || outcome.EvidenceRefID == nil {
		t.Fatalf("expected reverse code_investigate obligation & evidence ref, got %+v", outcome)
	}
	obs, err := d.ListCoverageObligations(db.CoverageObligationFilter{TaskID: task.ID, RoundID: round.ID, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	foundReverse := false
	for _, item := range obs {
		if item.ExecutionMode == db.ExecModeCodeInvestigate && strings.Contains(item.Purpose, "限流中间件") {
			foundReverse = true
		}
	}
	if !foundReverse {
		t.Fatalf("expected persisted reverse code_investigate obligation, got %+v", obs)
	}
}
