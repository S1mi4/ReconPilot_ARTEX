package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// CodeInvestigateEvidenceItem records one code anchor verified by a real read
// during a code_investigate run.
type CodeInvestigateEvidenceItem struct {
	Path        string `json:"path"`
	Line        int    `json:"line"`
	EndLine     int    `json:"end_line,omitempty"`
	Symbol      string `json:"symbol,omitempty"`
	Excerpt     string `json:"excerpt,omitempty"`
	Description string `json:"description,omitempty"`
}

// CodeInvestigateContext binds a code_investigate run to an assessment round,
// obligation, and read-only code/JavaCodeDB snapshot tools.
type CodeInvestigateContext struct {
	PG                 *db.DB
	TaskID             int64
	RoundID            int64
	RoundNo            int
	ProfileVersion     int
	ObligationID       int64
	AttemptID          int64
	ScopeNotes         string
	ReadTools          []actool.CoreTool
	VerifyEvidenceRead func(path string, line int, excerpt string) error
	Objective          string
	ProfileSlice       string
}

// CodeInvestigateOutcome captures the structured conclusion returned via
// submit_investigation_result.
type CodeInvestigateOutcome struct {
	Submitted     bool                          `json:"submitted"`
	Verdict       string                        `json:"verdict"`
	Summary       string                        `json:"summary"`
	BlockedReason string                        `json:"blocked_reason,omitempty"`
	EvidenceRefID *int64                        `json:"evidence_ref_id,omitempty"`
	Evidence      []CodeInvestigateEvidenceItem `json:"evidence,omitempty"`
	Followups     []string                      `json:"followups,omitempty"`
}

var forbiddenCodeInvestigateTools = map[string]bool{
	"bash":                          true,
	"write":                         true,
	"edit":                          true,
	"multiedit":                     true,
	"sleep":                         true,
	"web_fetch":                     true,
	"webfetch":                      true,
	"web_search":                    true,
	"websearch":                     true,
	"add_intent":                    true,
	"set_goals":                     true,
	"insert_assets":                 true,
	"add_company_scope":             true,
	"add_task_scope":                true,
	"report_finding":                true,
	"propose_escalation":            true,
	"kill_work":                     true,
	"dispatch_assessment_intent":    true,
	"request_assessment_completion": true,
}

func appendAllowedCodeInvestigateTools(dst []actool.CoreTool, seen map[string]bool, tools ...actool.CoreTool) []actool.CoreTool {
	for _, tl := range tools {
		if tl == nil {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(tl.Name()))
		if key == "" || forbiddenCodeInvestigateTools[key] || seen[key] {
			continue
		}
		seen[key] = true
		dst = append(dst, tl)
	}
	return dst
}

// CodeInvestigateTools builds the strictly read-only whitebox investigation
// toolset plus real-read-verified evidence submission. Bash, file-mutation,
// network tools, and autonomous intent/finding tools are strictly excluded.
func (t *ToolSet) CodeInvestigateTools(ic CodeInvestigateContext, outcome *CodeInvestigateOutcome) []actool.CoreTool {
	if ic.PG != nil && ic.TaskID > 0 && ic.RoundID > 0 {
		ac := AssessmentPlannerContext{
			PG:             ic.PG,
			TaskID:         ic.TaskID,
			RoundID:        ic.RoundID,
			RoundNo:        ic.RoundNo,
			ProfileVersion: ic.ProfileVersion,
			ScopeNotes:     ic.ScopeNotes,
		}
		t.SetAssessmentContext(&ac)
	}
	seen := map[string]bool{}
	var out []actool.CoreTool
	out = appendAllowedCodeInvestigateTools(out, seen,
		t.queryProfileSliceTool(),
		t.listCoverageObligationsTool(),
		t.listCodeAuditCoverageTool(),
		t.listFindings(),
		t.listFacts(),
		t.nodeDetail(),
		t.recordFact(),
		t.recordProfileClaimTool(),
		t.addExplorationObligationTool(),
	)
	out = appendAllowedCodeInvestigateTools(out, seen, ic.ReadTools...)
	out = appendAllowedCodeInvestigateTools(out, seen, t.submitInvestigationResultTool(ic, outcome))
	return out
}

func (t *ToolSet) submitInvestigationResultTool(ic CodeInvestigateContext, outcome *CodeInvestigateOutcome) actool.CoreTool {
	return writeTool("submit_investigation_result",
		"提交本次定向只读白盒排查的结构化结论与经真实读取核实的源码证据锚点。若非 blocked，至少需要一条本次实际读取过的 code 位置证据。",
		obj(map[string]any{
			"verdict":        str("判定结论：confirmed_static | needs_dynamic_verify | cleared | blocked"),
			"summary":        str("清晰、简洁的排查结论与依据摘要（严禁将静态线索写成已动态利用成功，严禁包含明文密码/密钥/token）"),
			"blocked_reason": str("当 verdict=blocked 时必填：缺失前置/缺口说明"),
			"evidence": map[string]any{
				"type":        "array",
				"description": "本次通过只读工具实际读到的源码/反编译证据锚点列表",
				"items": obj(map[string]any{
					"path":        str("代码文件相对路径（或 JavaCodeDB 返回的类源码路径）"),
					"line":        intp("实际读到的起始行号（>=1）"),
					"end_line":    intp("可选：结束行号"),
					"symbol":      str("可选：该行附近真实出现的方法/变量符号"),
					"excerpt":     str("可选：该处逐字源码摘录，不得改写或编造"),
					"description": str("该锚点在调用链/检查逻辑中的作用"),
				}, "path", "line"),
			},
			"followups": map[string]any{
				"type":        "array",
				"description": "可选：建议后续动态验证或继续追查的前置条件与方向",
				"items":       map[string]any{"type": "string"},
			},
		}, "verdict", "summary"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Verdict       string                        `json:"verdict"`
				Summary       string                        `json:"summary"`
				BlockedReason string                        `json:"blocked_reason"`
				Evidence      []CodeInvestigateEvidenceItem `json:"evidence"`
				Followups     []string                      `json:"followups"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("参数 JSON 解析失败: %v", err)), nil
			}
			verdict := strings.TrimSpace(strings.ToLower(a.Verdict))
			switch verdict {
			case "confirmed_static", "needs_dynamic_verify", "cleared", "blocked":
			default:
				return actool.Errorf("verdict 必须为 confirmed_static | needs_dynamic_verify | cleared | blocked"), nil
			}
			summary := strings.TrimSpace(a.Summary)
			if summary == "" {
				return actool.Errorf("summary 必填"), nil
			}
			blockedReason := strings.TrimSpace(a.BlockedReason)
			if verdict == "blocked" && blockedReason == "" {
				return actool.Errorf("verdict=blocked 时必须填写 blocked_reason"), nil
			}
			if err := db.ValidateAssessmentTextSafe(summary, blockedReason); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			followups := make([]string, 0, len(a.Followups))
			for _, f := range a.Followups {
				trimmed := strings.TrimSpace(f)
				if trimmed == "" {
					continue
				}
				if err := db.ValidateAssessmentTextSafe(trimmed); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				followups = append(followups, trimmed)
			}
			if verdict != "blocked" && len(a.Evidence) == 0 {
				return actool.Errorf("非 blocked 结论必须至少提供一条经本次实际读取验证过的源码证据（evidence）"), nil
			}
			cleaned := make([]CodeInvestigateEvidenceItem, 0, len(a.Evidence))
			for i, item := range a.Evidence {
				item.Path = strings.TrimSpace(item.Path)
				item.Symbol = strings.TrimSpace(item.Symbol)
				item.Excerpt = strings.TrimSpace(item.Excerpt)
				item.Description = strings.TrimSpace(item.Description)
				if item.Path == "" || item.Line <= 0 {
					return actool.Errorf(fmt.Sprintf("evidence[%d] 缺少有效的 path 或 line（必须 >= 1）", i)), nil
				}
				if err := db.ValidateAssessmentTextSafe(item.Path, item.Symbol, item.Excerpt, item.Description); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if ic.VerifyEvidenceRead != nil {
					if err := ic.VerifyEvidenceRead(item.Path, item.Line, item.Excerpt); err != nil {
						return actool.Errorf(fmt.Sprintf("evidence[%d] 实读核验失败: %v", i, err)), nil
					}
				}
				cleaned = append(cleaned, item)
			}

			var evIDPtr *int64
			if len(cleaned) > 0 && ic.PG != nil && ic.TaskID > 0 {
				primaryRef := fmt.Sprintf("%s:%d", cleaned[0].Path, cleaned[0].Line)
				payload, _ := json.Marshal(map[string]any{
					"verdict":       verdict,
					"summary":       summary,
					"obligation_id": ic.ObligationID,
					"attempt_id":    ic.AttemptID,
					"evidence":      cleaned,
					"followups":     followups,
				})
				evID, err := ic.PG.GetOrCreateEvidenceRef(ic.TaskID, db.EvidenceCodeRange, primaryRef, payload)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("保存 code_range 证据引用失败: %v", err)), nil
				}
				evIDPtr = &evID
			}
			if outcome != nil {
				*outcome = CodeInvestigateOutcome{
					Submitted:     true,
					Verdict:       verdict,
					Summary:       summary,
					BlockedReason: blockedReason,
					EvidenceRefID: evIDPtr,
					Evidence:      cleaned,
					Followups:     followups,
				}
			}
			return jsonResult(map[string]any{
				"ok":              true,
				"verdict":         verdict,
				"evidence_ref_id": evIDPtr,
				"evidence_count":  len(cleaned),
			})
		})
}

func codeInvestigateSystem(ic CodeInvestigateContext, w *Worker, ts *db.ExplorationStore, intent *db.Node) string {
	dataDir := ""
	wantConstraints := true
	if w != nil {
		dataDir = w.workDir
		wantConstraints = w.wantConstraints()
	}
	vars := CodeInvestigateVars{
		RoundNo:        fmt.Sprint(ic.RoundNo),
		ProfileVersion: fmt.Sprint(ic.ProfileVersion),
		Scope:          strings.TrimSpace(ic.ScopeNotes),
		DataDir:        dataDir,
		Now:            nowStr(),
	}
	if vars.Scope == "" {
		vars.Scope = "遵循当前评估任务授权代码与画像范围。"
	}
	sys := renderSystem("code_investigate", codeInvestigateDefaultTmpl, vars)
	if wantConstraints && ts != nil {
		sys += constraintBlock(ts)
	}
	if intent != nil {
		sys += renderIntentTask(intent)
	}
	if strings.TrimSpace(ic.Objective) != "" {
		sys += "\n\n【本次定向查码具体目标与前置背景】\n" + strings.TrimSpace(ic.Objective)
	}
	if strings.TrimSpace(ic.ProfileSlice) != "" {
		sys += "\n\n【相关系统画像切片（只读线索，须读代码核实）】\n" + strings.TrimSpace(ic.ProfileSlice)
	}
	sys += "\n\n开始只读查码：先调用只读文件/JavaCodeDB 工具核实代码位置与调用链，再用 submit_investigation_result 落库结论与真实证据锚点。"
	return sys
}

// ExecuteCodeInvestigate runs a strictly read-only whitebox investigation turn
// for a bound obligation intent under workCtx. It never enables Bash, file
// writing, WebFetch, or WebSearch.
func (w *Worker) ExecuteCodeInvestigate(ctx context.Context, name string, ic CodeInvestigateContext, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity)) (CodeInvestigateOutcome, harness.TerminalReason, error) {
	var outcome CodeInvestigateOutcome
	if intent == nil {
		return outcome, "", fmt.Errorf("intent is required")
	}
	tsx := NewToolSet(ts, name)
	tsx.SetTaskID(ic.TaskID)
	tsx.SetOwnerNode(intent.ID)
	tools := tsx.CodeInvestigateTools(ic, &outcome)

	runDir := ensureRunDir(w.workDir, ic.TaskID, intent.ID)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: ic.TaskID, ExplorationID: explorationID(ts), IntentID: intent.ID})
	ctx = intercept.WithReviewContext(ctx, runDir, intercept.ReviewBackground{})

	tc := taskClockFrom(ctx)
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, w.runTimeout)
	settle := wrapupSettlement("code_investigate", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("code_investigate", nil, clamped)
	}

	opts := agentcore.Options{
		Provider:        w.prov,
		SystemPrompt:    []string{codeInvestigateSystem(ic, w, ts, intent)},
		Tools:           tools,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  false,
		EnableWebSearch: false,
		BashEnv:         nil,
		WorkingDir:      runDir,
		ToolOutputDir:   cmdOutDir(runDir),
		MaxTurns:        w.maxTurns,
		MaxDuration:     maxDur,
		Settlement:      settle,
		Compaction:      compactionConfig(w.compactionWindow()),
		Todos:           actool.NewTodoStore(),
		NonStreaming:    w.nonStreaming(),
		MaxTokens:       w.maxTokens(),
	}
	if hooks != nil {
		opts.Hooks = hooks
	}
	if w.tx != nil && ts != nil {
		opts.Transcript = w.tx
		opts.SessionID = WorkerSessionID(ts.ID(), intent.ID)
	}

	var noaSession string
	if ts != nil {
		noaSession = WorkerSessionID(ts.ID(), intent.ID)
		enableNoa(&opts, w.noaEnabledFn, w.workDir, noaSession, noaWarn(noaSession))
	}
	ctx = attachSideCapture(ctx, &opts)
	s := agentcore.NewSession(opts)
	defer s.Close()

	input := "请先使用只读代码或 JavaCodeDB 工具读取相关代码确认细节，随后调用 submit_investigation_result 提交经真实读取核实的证据与结论。"
	if w.tx != nil && opts.SessionID != "" {
		_ = s.Resume(opts.SessionID)
		if len(s.Messages()) > 0 {
			input = "继续完成尚未结束的定向只读代码排查；切记任何证据锚点必须来自真实只读读取，最后调用 submit_investigation_result 提交结果。"
		}
	}

	intentID := intent.ID
	emitWrap := func(r db.Activity) {
		if emit != nil {
			r.NodeID, r.Worker = &intentID, name
			emit(r)
		}
	}
	_, reason, err := captureRunSession(ctx, s, input, emitWrap)
	return outcome, reason, err
}
