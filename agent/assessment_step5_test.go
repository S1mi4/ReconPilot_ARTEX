package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

func dummyReadTool(name string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        name,
		Description: "test dummy tool",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return actool.Text("ok"), nil
		},
	})
}

func TestStep5CodeInvestigateToolAllowlistAndGuards(t *testing.T) {
	tsx := NewToolSet(nil, "code_investigate")
	var outcome CodeInvestigateOutcome
	ic := CodeInvestigateContext{
		TaskID:  1,
		RoundID: 1,
		ReadTools: []actool.CoreTool{
			dummyReadTool("read_file"),
			dummyReadTool("list_files"),
			dummyReadTool("Bash"),
			dummyReadTool("Write"),
			dummyReadTool("Edit"),
			dummyReadTool("MultiEdit"),
			dummyReadTool("Sleep"),
			dummyReadTool("web_fetch"),
			dummyReadTool("web_search"),
			dummyReadTool("add_intent"),
			dummyReadTool("set_goals"),
			dummyReadTool("insert_assets"),
			dummyReadTool("report_finding"),
		},
	}
	tools := tsx.CodeInvestigateTools(ic, &outcome)
	got := map[string]bool{}
	for _, tl := range tools {
		got[tl.Name()] = true
	}

	required := []string{
		"read_file",
		"list_files",
		"query_profile_slice",
		"list_coverage_obligations",
		"list_code_audit_coverage",
		"list_findings",
		"list_facts",
		"node_detail",
		"record_fact",
		"record_profile_claim",
		"add_exploration_obligation",
		"submit_investigation_result",
	}
	for _, name := range required {
		if !got[name] {
			t.Fatalf("expected required tool %q in CodeInvestigateTools, got %v", name, got)
		}
	}

	forbidden := []string{
		"Bash", "Write", "Edit", "MultiEdit", "Sleep",
		"web_fetch", "WebFetch", "web_search", "WebSearch",
		"add_intent", "set_goals", "insert_assets", "report_finding",
		"dispatch_assessment_intent", "request_assessment_completion", "kill_work",
	}
	for _, name := range forbidden {
		if got[name] {
			t.Fatalf("forbidden tool %q leaked into CodeInvestigateTools", name)
		}
	}
}

func TestStep5SubmitInvestigationRealReadAndSecrets(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("step5 submit investigation", "assess auth", db.TaskCreateOptions{
		ProjectID:      testProjectID(t, d),
		AssessmentMode: true,
		AssessmentConfig: db.AssessmentConfig{
			ExecutionMode: db.AssessmentExecDynamic,
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
	ent, err := d.CreateTargetEntity(db.CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "module", Name: "auth-mod",
	})
	if err != nil {
		t.Fatal(err)
	}
	ob, err := d.CreateCoverageObligation(db.CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: db.DimensionConfigAudit, TargetEntityID: &ent.ID,
		Purpose: "核查签名校验", Required: true, DedupeKey: "cfg-auth",
		InitialStatus: db.ObligationReady, ExecutionMode: db.ExecModeCodeInvestigate, Origin: db.ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}

	readState := map[string]map[int]string{
		"src/Auth.java": {
			18: `if (sig.equals(expected)) { return true; }`,
		},
	}
	var outcome CodeInvestigateOutcome
	ic := CodeInvestigateContext{
		PG:             d,
		TaskID:         task.ID,
		RoundID:        round.ID,
		RoundNo:        round.RoundNo,
		ProfileVersion: round.ProfileVersion,
		ObligationID:   ob.ID,
		ReadTools:      []actool.CoreTool{dummyReadTool("read_file")},
		VerifyEvidenceRead: func(path string, line int, excerpt string) error {
			lines := readState[path]
			if lines == nil {
				return fmt.Errorf("file %s not read", path)
			}
			src, ok := lines[line]
			if !ok {
				return fmt.Errorf("line %d not read in %s", line, path)
			}
			if excerpt != "" && !strings.Contains(src, excerpt) {
				return fmt.Errorf("excerpt mismatch at %s:%d", path, line)
			}
			return nil
		},
	}
	tsx := NewToolSet(d.Exploration(task.ID), "code_investigate")
	tools := tsx.CodeInvestigateTools(ic, &outcome)
	var submitTool actool.CoreTool
	for _, tl := range tools {
		if tl.Name() == "submit_investigation_result" {
			submitTool = tl
			break
		}
	}
	if submitTool == nil {
		t.Fatal("missing submit_investigation_result")
	}

	// 1. Unread path rejected.
	res, err := submitTool.Call(context.Background(), json.RawMessage(`{
		"verdict":"needs_dynamic_verify",
		"summary":"签名可绕过",
		"evidence":[{"path":"src/Other.java","line":10,"excerpt":"sig"}]
	}`), nil)
	if err != nil || !res.IsError || outcome.Submitted {
		t.Fatalf("expected unread path rejection, res=%+v err=%v outcome=%+v", res, err, outcome)
	}

	// 2. Excerpt mismatch rejected.
	res, err = submitTool.Call(context.Background(), json.RawMessage(`{
		"verdict":"needs_dynamic_verify",
		"summary":"签名可绕过",
		"evidence":[{"path":"src/Auth.java","line":18,"excerpt":"fabricateCall()"}]
	}`), nil)
	if err != nil || !res.IsError || outcome.Submitted {
		t.Fatalf("expected excerpt mismatch rejection, res=%+v err=%v outcome=%+v", res, err, outcome)
	}

	// 3. Plaintext secret rejected even when path & line are valid.
	res, err = submitTool.Call(context.Background(), json.RawMessage(`{
		"verdict":"needs_dynamic_verify",
		"summary":"硬编码 password=SuperSecretPassword123",
		"evidence":[{"path":"src/Auth.java","line":18,"excerpt":"sig.equals"}]
	}`), nil)
	if err != nil || !res.IsError || outcome.Submitted {
		t.Fatalf("expected secret rejection, res=%+v err=%v outcome=%+v", res, err, outcome)
	}

	// 4. Valid real-read submission succeeds and persists EvidenceCodeRange.
	res, err = submitTool.Call(context.Background(), json.RawMessage(`{
		"verdict":"needs_dynamic_verify",
		"summary":"Auth.java 仅校验局部期望签名，需动态验证头部伪造路径",
		"evidence":[{"path":"src/Auth.java","line":18,"symbol":"sig.equals","excerpt":"sig.equals(expected)"}],
		"followups":["用不同签名头请求验证是否可绕过"]
	}`), nil)
	if err != nil || res.IsError || !outcome.Submitted || outcome.EvidenceRefID == nil || *outcome.EvidenceRefID <= 0 {
		t.Fatalf("expected valid submission to persist EvidenceCodeRange, res=%+v err=%v outcome=%+v", res, err, outcome)
	}
}

func TestStep5AssessmentMainToolsTriggersPromptsAndExecuteCodeInvestigate(t *testing.T) {
	// 1. AssessmentMainTools omits add_intent / set_goals while preserving steering tools.
	tsx := NewToolSet(nil, "human")
	mainTools := map[string]bool{}
	for _, tl := range tsx.AssessmentMainTools() {
		mainTools[tl.Name()] = true
	}
	if mainTools["add_intent"] || mainTools["set_goals"] {
		t.Fatalf("AssessmentMainTools must omit legacy add_intent/set_goals, got %v", mainTools)
	}
	for _, want := range []string{
		"steer_work", "set_constraints", "add_hint",
		"query_profile_slice", "list_coverage_obligations", "list_code_audit_coverage",
		"update_obligation_priority", "add_exploration_obligation",
	} {
		if !mainTools[want] {
			t.Fatalf("AssessmentMainTools missing %q", want)
		}
	}

	// 2. renderTriggers formats code_audit_chunk_completed distinctly.
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("step5 trigger & worker test", "assess", db.TaskCreateOptions{
		ProjectID:      testProjectID(t, d),
		AssessmentMode: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	rendered := renderTriggers(ts, []TriggerEvent{{
		Kind:     "code_audit_chunk_completed",
		IntentID: 99,
		Detail:   "run #3 分片 1/2 完成",
	}})
	if !strings.Contains(rendered, "白盒批量审计分片完成") || strings.Contains(rendered, "worker 结束") {
		t.Fatalf("unexpected chunk trigger rendering: %s", rendered)
	}

	// 3. De-biased whiteboxAuditDefaultTmpl and registered code_investigate seed/wrapup.
	for _, biased := range []string{"SQL_INJECTION", "AUTHORIZATION_BYPASS", "SSRF", "反序列化"} {
		if biased == "反序列化" {
			// Policy explicitly clarifies expression execution is not deserialization, so only check example lists.
			if strings.Contains(whiteboxAuditDefaultTmpl, "SSRF、反序列化") {
				t.Fatalf("whiteboxAuditDefaultTmpl still contains vuln enumeration list")
			}
			continue
		}
		if strings.Contains(whiteboxAuditDefaultTmpl, biased) {
			t.Fatalf("whiteboxAuditDefaultTmpl still contains biased example %q", biased)
		}
	}
	seeds := BuiltinPromptSeeds()
	if strings.TrimSpace(seeds["code_investigate"]) == "" {
		t.Fatal("BuiltinPromptSeeds missing code_investigate")
	}
	if strings.TrimSpace(WrapupDefault("code_investigate")) == "" || strings.TrimSpace(TaskTimeoutWrapupDefault("code_investigate")) == "" {
		t.Fatal("code_investigate wrapup defaults missing")
	}

	// 4. Worker.ExecuteCodeInvestigate end-to-end with scripted provider (strictly read-only tools, no Bash/WebFetch).
	round, err := d.CreateAssessmentRound(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	intentID, err := ts.AddIntent(map[string]any{"summary": "查证 Config.java"}, 8, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := ts.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}

	readCalled := false
	readTool := actool.Build(actool.Spec{
		Name:        "read_file",
		Description: "read code file",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{"path": str("path")}},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			readCalled = true
			return actool.Text("1: permitAll()\n"), nil
		},
	})

	prov := &scriptedAssessmentProvider{
		turns: func(call int, req llm.CompletionRequest) (llm.Message, string, error) {
			for _, td := range req.Tools {
				switch td.Name {
				case "Bash", "Write", "Edit", "MultiEdit", "web_fetch", "web_search", "report_finding":
					return llm.Message{}, "", fmt.Errorf("forbidden tool exposed to model: %s", td.Name)
				}
			}
			switch call {
			case 1:
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					toolUseBlock("c1", "read_file", map[string]any{"path": "Config.java"}),
				}}, "tool_use", nil
			case 2:
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					toolUseBlock("c2", "submit_investigation_result", map[string]any{
						"verdict":  "confirmed_static",
						"summary":  "Config.java 第 1 行放开了 permitAll",
						"evidence": []map[string]any{{"path": "Config.java", "line": 1, "excerpt": "permitAll()"}},
					}),
				}}, "tool_use", nil
			default:
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					llm.TextBlock("已核实 Config.java 第 1 行配置并提交结论。"),
				}}, "end_turn", nil
			}
		},
	}

	tx := transcript.NewStore(t.TempDir())
	wk := NewWorker(prov, "mock-model", t.TempDir(), tx, 0, 8)
	ic := CodeInvestigateContext{
		PG:             d,
		TaskID:         task.ID,
		RoundID:        round.ID,
		RoundNo:        round.RoundNo,
		ProfileVersion: round.ProfileVersion,
		ReadTools:      []actool.CoreTool{readTool},
		VerifyEvidenceRead: func(path string, line int, _ string) error {
			if !readCalled || path != "Config.java" || line != 1 {
				return fmt.Errorf("not read: %s:%d", path, line)
			}
			return nil
		},
		Objective: "检查安全过滤器配置",
	}
	outcome, _, err := wk.ExecuteCodeInvestigate(context.Background(), "work#1", ic, ts, intent, nil, nil)
	if err != nil {
		t.Fatalf("ExecuteCodeInvestigate failed: %v", err)
	}
	if !outcome.Submitted || outcome.Verdict != "confirmed_static" || outcome.EvidenceRefID == nil {
		t.Fatalf("unexpected ExecuteCodeInvestigate outcome: %+v", outcome)
	}
}
