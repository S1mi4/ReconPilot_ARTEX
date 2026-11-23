package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// DynamicEnvironmentTarget describes the authorized runtime environment bound
// to a dynamic_verify work order. Plaintext secrets never appear here.
type DynamicEnvironmentTarget struct {
	Name            string `json:"name"`
	URL             string `json:"url,omitempty"`
	Description     string `json:"description,omitempty"`
	AccessMode      string `json:"access_mode,omitempty"`
	AccessNotes     string `json:"access_notes,omitempty"`
	IsDefault       bool   `json:"is_default,omitempty"`
	VersionStatus   string `json:"version_status,omitempty"`
	ExpectedVersion string `json:"expected_version,omitempty"`
}

// DynamicIdentityRef describes the role equivalence group and non-secret
// credential reference assigned to a dynamic_verify work order.
type DynamicIdentityRef struct {
	Role                string `json:"role,omitempty"`
	Username            string `json:"username,omitempty"`
	AuthType            string `json:"auth_type,omitempty"`
	CredentialRef       string `json:"credential_ref,omitempty"`
	Scope               string `json:"scope,omitempty"`
	Notes               string `json:"notes,omitempty"`
	RequiresCredentials bool   `json:"requires_credentials"`
	Anonymous           bool   `json:"anonymous,omitempty"`
}

// DynamicCodeAnchor records one static file/line/symbol location attached to
// a dynamic work order for focused verification without full-repo dumping.
type DynamicCodeAnchor struct {
	Path        string `json:"path,omitempty"`
	Line        int    `json:"line,omitempty"`
	Symbol      string `json:"symbol,omitempty"`
	Excerpt     string `json:"excerpt,omitempty"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source,omitempty"`
}

// DynamicWorkOrder is the structured assignment envelope consumed by dynamic_verify.
type DynamicWorkOrder struct {
	ObligationID           int64                     `json:"obligation_id"`
	Dimension              string                    `json:"dimension"`
	Purpose                string                    `json:"purpose"`
	DedupeKey              string                    `json:"dedupe_key,omitempty"`
	Question               string                    `json:"question"`
	Hypothesis             string                    `json:"hypothesis,omitempty"`
	Environment            *DynamicEnvironmentTarget `json:"environment,omitempty"`
	Identity               *DynamicIdentityRef       `json:"identity,omitempty"`
	TargetAsset            string                    `json:"target_asset,omitempty"`
	Module                 string                    `json:"module,omitempty"`
	EntryMethod            string                    `json:"entry_method,omitempty"`
	EntryPath              string                    `json:"entry_path,omitempty"`
	EntryURL               string                    `json:"entry_url,omitempty"`
	CodeAnchors            []DynamicCodeAnchor       `json:"code_anchors,omitempty"`
	ExpectedBehavior       string                    `json:"expected_behavior,omitempty"`
	EvidencePlan           []string                  `json:"evidence_plan,omitempty"`
	StopCondition          string                    `json:"stop_condition,omitempty"`
	OutOfScopeDependencies []string                  `json:"out_of_scope_dependencies,omitempty"`
	LinkedFindingID        *int64                    `json:"linked_finding_id,omitempty"`
	StaticOnly             bool                      `json:"static_only,omitempty"`
	PlannerOverrides       map[string]any            `json:"planner_overrides,omitempty"`
}

// DynamicVerifyContext carries runtime metadata, read-only code slice tools,
// and verification callbacks for one dynamic_verify attempt.
type DynamicVerifyContext struct {
	PG                  *db.DB
	TaskID              int64
	RoundID             int64
	RoundNo             int
	ProfileVersion      int
	ExecutionMode       string
	ObligationID        int64
	AttemptID           int64
	Dimension           string
	ScopeNotes          string
	EnvironmentSummary  string
	WorkOrder           DynamicWorkOrder
	ProfileSlice        string
	RequiresCredentials bool
	CredentialRef       string
	ReadCodeTools       []actool.CoreTool
	VerifyTrafficIDs    func(ctx context.Context, ids []string) ([]string, error)
	ExecutionCounter    *atomic.Int64
}

// DynamicVerifyOutcome captures the structured verdict persisted via
// submit_dynamic_verification plus bidirectional feedback counters.
type DynamicVerifyOutcome struct {
	Submitted                  bool     `json:"submitted"`
	Verdict                    string   `json:"verdict"`
	Summary                    string   `json:"summary"`
	BlockedReason              string   `json:"blocked_reason,omitempty"`
	ObservedURL                string   `json:"observed_url,omitempty"`
	ObservedVersion            string   `json:"observed_version,omitempty"`
	VersionMatched             *bool    `json:"version_matched,omitempty"`
	TrafficIDs                 []string `json:"traffic_ids,omitempty"`
	CommandEvidence            []string `json:"command_evidence,omitempty"`
	MissingPreconditions       []string `json:"missing_preconditions,omitempty"`
	ReverseInvestigateSummary  string   `json:"reverse_investigate_summary,omitempty"`
	FeedbackClaimsCreated      int      `json:"feedback_claims_created,omitempty"`
	FeedbackObligationsCreated int      `json:"feedback_obligations_created,omitempty"`
	EvidenceRefID              *int64   `json:"evidence_ref_id,omitempty"`
}

var forbiddenDynamicVerifyTools = map[string]bool{
	"add_intent":                    true,
	"set_goals":                     true,
	"kill_work":                     true,
	"dispatch_assessment_intent":    true,
	"request_assessment_completion": true,
	"update_obligation_priority":    true,
	"dispatch_assessment_work":      true,
	"stop_code_audit":               true,
}

func appendAllowedDynamicTools(dst []actool.CoreTool, seen map[string]bool, tools ...actool.CoreTool) []actool.CoreTool {
	for _, tl := range tools {
		if tl == nil {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(tl.Name()))
		if key == "" || forbiddenDynamicVerifyTools[key] || seen[key] {
			continue
		}
		seen[key] = true
		dst = append(dst, tl)
	}
	return dst
}

// isDynamicRuntimeProbeTool returns true for live probe/interaction tools that
// constitute runtime execution rather than static/metadata lookups.
func isDynamicRuntimeProbeTool(name string) bool {
	key := strings.ToLower(strings.TrimSpace(name))
	switch key {
	case "bash", "web_fetch", "webfetch", "shell_open", "shell_exec", "execute_extra_tool":
		return true
	}
	return strings.HasPrefix(key, "browser_") || strings.HasPrefix(key, "playwright_")
}

// dynamicVerifyBaseTools builds the worker + read-only assessment/code-slice +
// feedback + structured verification toolset before AugmentTools resolves
// platform worker permissions, skills, custom tools, and MCP servers.
func (t *ToolSet) dynamicVerifyBaseTools(dc DynamicVerifyContext, outcome *DynamicVerifyOutcome, extra []actool.CoreTool) ([]actool.CoreTool, []actool.CoreTool) {
	execMode := strings.TrimSpace(dc.ExecutionMode)
	if execMode == "" {
		execMode = db.AssessmentExecDynamic
	}
	if dc.PG != nil && dc.TaskID > 0 && dc.RoundID > 0 {
		t.SetAssessmentContext(&AssessmentPlannerContext{
			PG:             dc.PG,
			TaskID:         dc.TaskID,
			RoundID:        dc.RoundID,
			RoundNo:        dc.RoundNo,
			ProfileVersion: dc.ProfileVersion,
			ExecutionMode:  execMode,
			ScopeNotes:     dc.ScopeNotes,
		})
	}
	if dc.ExecutionCounter == nil {
		dc.ExecutionCounter = &atomic.Int64{}
	}

	seen := map[string]bool{}
	workerBase := make([]actool.CoreTool, 0, len(t.WorkerTools())+len(extra)+10)
	workerBase = appendAllowedDynamicTools(workerBase, seen, t.WorkerTools()...)
	workerBase = appendAllowedDynamicTools(workerBase, seen, extra...)
	workerBase = appendAllowedDynamicTools(workerBase, seen, defaultToolsExcept("MultiEdit", "Glob", "Grep")...)

	// Assessment slice, bounded code-slice lookup, bidirectional feedback, and
	// structured conclusion tools have no DB catalog rows and stay intact across
	// worker ToolResolve filtering, with explicit outcome tracking wrappers.
	var assessmentTools []actool.CoreTool
	assessmentTools = appendAllowedDynamicTools(assessmentTools, seen,
		t.queryProfileSliceTool(),
		t.listCoverageObligationsTool(),
		t.listCodeAuditCoverageTool(),
		t.recordDynamicProfileClaimTool(dc, outcome),
		wrapDynamicObligationTool(t.addExplorationObligationTool(), outcome),
	)
	for _, rt := range dc.ReadCodeTools {
		if rt == nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(rt.Name())) {
		case "list_code_slice", "search_code_slice", "read_code_slice":
			assessmentTools = appendAllowedDynamicTools(assessmentTools, seen, rt)
		default:
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rt.Name())), "jcd_") {
				assessmentTools = appendAllowedDynamicTools(assessmentTools, seen, rt)
			}
		}
	}
	assessmentTools = appendAllowedDynamicTools(assessmentTools, seen, t.submitDynamicVerificationTool(dc, outcome))
	return workerBase, assessmentTools
}

// DynamicVerifyTools returns the full dynamic_verify toolset (worker + read-only
// profile/code slice + bidirectional feedback + structured verification) without
// platform DB filtering. Used primarily by unit tests and custom setups.
func (t *ToolSet) DynamicVerifyTools(dc DynamicVerifyContext, outcome *DynamicVerifyOutcome, extra ...actool.CoreTool) []actool.CoreTool {
	workerBase, assessmentTools := t.dynamicVerifyBaseTools(dc, outcome, extra)
	seen := map[string]bool{}
	out := appendAllowedDynamicTools(nil, seen, workerBase...)
	return appendAllowedDynamicTools(out, seen, assessmentTools...)
}

type wrappedDynamicTool struct {
	actool.CoreTool
	onSuccess func()
}

func (w *wrappedDynamicTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	res, err := w.CoreTool.Call(ctx, in, tc)
	if err == nil && !res.IsError && w.onSuccess != nil {
		w.onSuccess()
	}
	return res, err
}

func wrapDynamicObligationTool(tl actool.CoreTool, outcome *DynamicVerifyOutcome) actool.CoreTool {
	return &wrappedDynamicTool{
		CoreTool: tl,
		onSuccess: func() {
			if outcome != nil {
				outcome.FeedbackObligationsCreated++
			}
		},
	}
}

func (t *ToolSet) recordDynamicProfileClaimTool(dc DynamicVerifyContext, outcome *DynamicVerifyOutcome) actool.CoreTool {
	return writeTool("record_profile_claim",
		"向当前评估轮次画像写入动态运行观察（runtime_observation）或待核查推断（model_inference）。runtime_observation 设为 confirmed/conflicted 时必须提供核实的 traffic_ids 或真实命令执行摘要。",
		obj(map[string]any{
			"subject":             str("主体标识（如 instance:default / entry:POST /pay / service:order-svc）"),
			"relation":            str("关系或属性名（如 code_version_verified / exposed_entry / auth_behavior）"),
			"object_value":        str("关系客体或属性值"),
			"source_type":         str("来源类型：runtime_observation（默认）| model_inference"),
			"confirmation_status": str("状态：confirmed | conflicted | unverified | unknown（model_inference 不可自称 confirmed）"),
			"traffic_ids":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选：已录制的真实 HTTP 流量 ID"},
			"execution_summary":   str("可选：本次真实执行工具/命令观察到的简短输出依据（严禁写入明文密码/Token）"),
			"conflict_note":       str("可选：冲突或不确定说明"),
			"environment":         str("可选：适用测试环境名称"),
			"valid_code_version":  str("可选：适用代码版本 ID"),
		}, "subject", "relation", "object_value", "confirmation_status"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if dc.PG == nil || dc.TaskID <= 0 || dc.RoundID <= 0 {
				return actool.Errorf("评估画像上下文不可用"), nil
			}
			var a struct {
				Subject            string   `json:"subject"`
				Relation           string   `json:"relation"`
				ObjectValue        string   `json:"object_value"`
				SourceType         string   `json:"source_type"`
				ConfirmationStatus string   `json:"confirmation_status"`
				TrafficIDs         []string `json:"traffic_ids"`
				ExecutionSummary   string   `json:"execution_summary"`
				ConflictNote       string   `json:"conflict_note"`
				Environment        string   `json:"environment"`
				ValidCodeVersion   string   `json:"valid_code_version"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			src := strings.TrimSpace(a.SourceType)
			if src == "" {
				src = db.ClaimSourceRuntimeObservation
			}
			if src != db.ClaimSourceRuntimeObservation && src != db.ClaimSourceModelInference {
				return actool.Errorf(fmt.Sprintf("动态验证仅支持 runtime_observation 或 model_inference，不支持 %q", src)), nil
			}
			st := strings.TrimSpace(a.ConfirmationStatus)
			if err := db.ValidateAssessmentTextSafe(a.Subject, a.Relation, a.ObjectValue, a.ExecutionSummary, a.ConflictNote); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if src == db.ClaimSourceModelInference && st == db.ClaimStatusConfirmed {
				return actool.Errorf("model_inference 断言不允许设为 confirmed"), nil
			}

			var evPtr *int64
			trafficIDs := normalizeTrimmedStrings(a.TrafficIDs)
			execSummary := strings.TrimSpace(a.ExecutionSummary)
			if src == db.ClaimSourceRuntimeObservation && (st == db.ClaimStatusConfirmed || st == db.ClaimStatusConflicted) {
				if len(trafficIDs) == 0 && execSummary == "" {
					return actool.Errorf("runtime_observation 设为 confirmed/conflicted 时必须提供 traffic_ids 或 execution_summary"), nil
				}
				if len(trafficIDs) > 0 && dc.VerifyTrafficIDs != nil {
					verified, verr := dc.VerifyTrafficIDs(ctx, trafficIDs)
					if verr != nil {
						return actool.Errorf(fmt.Sprintf("核验 traffic_ids 失败: %v", verr)), nil
					}
					trafficIDs = verified
				}
				if len(trafficIDs) == 0 && execSummary != "" && dc.ExecutionCounter != nil && dc.ExecutionCounter.Load() == 0 {
					return actool.Errorf("尚未执行任何动态命令/HTTP/浏览器工具，不能仅凭文本断言 runtime_observation"), nil
				}
				kind := db.EvidenceExecution
				ref := fmt.Sprintf("dynamic_claim:o%d:a%d:%s", dc.ObligationID, dc.AttemptID, strings.TrimSpace(a.Relation))
				if len(trafficIDs) > 0 && execSummary == "" {
					kind = db.EvidenceTraffic
					ref = "traffic:" + strings.Join(trafficIDs, ",")
				}
				payload, _ := json.Marshal(map[string]any{
					"obligation_id":     dc.ObligationID,
					"attempt_id":        dc.AttemptID,
					"subject":           strings.TrimSpace(a.Subject),
					"relation":          strings.TrimSpace(a.Relation),
					"traffic_ids":       trafficIDs,
					"execution_summary": execSummary,
				})
				evID, err := dc.PG.GetOrCreateEvidenceRef(dc.TaskID, kind, ref, payload)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				evPtr = &evID
			}

			roundID := dc.RoundID
			claim, conflicted, err := dc.PG.CreateProfileClaim(db.CreateProfileClaimInput{
				TaskID:             dc.TaskID,
				RoundID:            &roundID,
				Subject:            strings.TrimSpace(a.Subject),
				Relation:           strings.TrimSpace(a.Relation),
				ObjectValue:        strings.TrimSpace(a.ObjectValue),
				SourceType:         src,
				EvidenceRefID:      evPtr,
				ValidCodeVersion:   strings.TrimSpace(a.ValidCodeVersion),
				Environment:        strings.TrimSpace(a.Environment),
				ConfirmationStatus: st,
				ConflictNote:       strings.TrimSpace(a.ConflictNote),
				ExecutionRef:       fmt.Sprintf("dynamic_verify:o%d:a%d", dc.ObligationID, dc.AttemptID),
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if outcome != nil {
				outcome.FeedbackClaimsCreated++
			}
			return jsonResult(map[string]any{"claim": claim, "conflicted": conflicted})
		})
}

func (t *ToolSet) submitDynamicVerificationTool(dc DynamicVerifyContext, outcome *DynamicVerifyOutcome) actool.CoreTool {
	return writeTool("submit_dynamic_verification",
		"提交本次动态验证（dynamic_verify）的结构化结果分类与可核验证据引用。所有非阻塞/非失败有效结论（supported/disproved/unreproduced）都必须附带真实运行输出或经核实的流量 ID，单次 unreproduced 绝不等于已修复或无漏洞。",
		obj(map[string]any{
			"verdict":               str("结果分类：supported | disproved | unreproduced | env_mismatch | dependency_missing | failed"),
			"summary":               str("简洁客观的动态验证结论（严禁包含明文密码/Token/私钥）"),
			"blocked_reason":        str("当 verdict 为 env_mismatch / dependency_missing / failed 时必填"),
			"observed_url":          str("实际测试到的环境 URL"),
			"observed_version":      str("实际观察到的版本/构建标识（runtime_asset 或 env_mismatch 时建议填写）"),
			"version_matched":       map[string]any{"type": "boolean", "description": "实际环境版本/配置是否与代码快照匹配"},
			"traffic_ids":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "已录制并经 traffic_search/traffic_get 核实的真实流量 ID 列表"},
			"command_evidence":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "真实执行的命令/请求与关键观察输出摘要（严禁写明文凭证）"},
			"missing_preconditions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "当 verdict=unreproduced 时必填：尚未满足的前置条件或不确定因素"},
			"next_code_investigate": obj(map[string]any{
				"purpose":       str("可选：需要动态→白盒反向查码的明确目标"),
				"evidence_note": str("触发反向查码的动态异常、响应差异或中间件拦截依据"),
				"dedupe_key":    str("可选：反向排查义务幂等键"),
			}),
		}, "verdict", "summary"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Verdict              string   `json:"verdict"`
				Summary              string   `json:"summary"`
				BlockedReason        string   `json:"blocked_reason"`
				ObservedURL          string   `json:"observed_url"`
				ObservedVersion      string   `json:"observed_version"`
				VersionMatched       *bool    `json:"version_matched"`
				TrafficIDs           []string `json:"traffic_ids"`
				CommandEvidence      []string `json:"command_evidence"`
				MissingPreconditions []string `json:"missing_preconditions"`
				NextCodeInvestigate  *struct {
					Purpose      string `json:"purpose"`
					EvidenceNote string `json:"evidence_note"`
					DedupeKey    string `json:"dedupe_key"`
				} `json:"next_code_investigate"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("参数 JSON 解析失败: %v", err)), nil
			}
			verdict := strings.TrimSpace(strings.ToLower(a.Verdict))
			if !db.IsValidAttemptOutcome(verdict) {
				return actool.Errorf("verdict 必须为 supported | disproved | unreproduced | env_mismatch | dependency_missing | failed"), nil
			}
			summary := strings.TrimSpace(a.Summary)
			if summary == "" {
				return actool.Errorf("summary 必填"), nil
			}
			blockedReason := strings.TrimSpace(a.BlockedReason)
			observedURL := strings.TrimSpace(a.ObservedURL)
			observedVersion := strings.TrimSpace(a.ObservedVersion)
			if err := db.ValidateAssessmentTextSafe(summary, blockedReason, observedURL, observedVersion); err != nil {
				return actool.Errorf(err.Error()), nil
			}

			cmdEvidence := normalizeTrimmedStrings(a.CommandEvidence)
			for _, item := range cmdEvidence {
				if err := db.ValidateAssessmentTextSafe(item); err != nil {
					return actool.Errorf(err.Error()), nil
				}
			}
			missingPreconds := normalizeTrimmedStrings(a.MissingPreconditions)
			for _, item := range missingPreconds {
				if err := db.ValidateAssessmentTextSafe(item); err != nil {
					return actool.Errorf(err.Error()), nil
				}
			}
			trafficIDs := normalizeTrimmedStrings(a.TrafficIDs)
			for _, item := range trafficIDs {
				if err := db.ValidateAssessmentTextSafe(item); err != nil {
					return actool.Errorf(err.Error()), nil
				}
			}

			if len(trafficIDs) > 0 && dc.VerifyTrafficIDs != nil {
				verified, verr := dc.VerifyTrafficIDs(ctx, trafficIDs)
				if verr != nil {
					return actool.Errorf(fmt.Sprintf("流量证据核验失败: %v", verr)), nil
				}
				trafficIDs = verified
			}

			switch verdict {
			case db.AttemptEnvMismatch:
				if blockedReason == "" {
					return actool.Errorf("verdict=env_mismatch 必须填写 blocked_reason 说明版本或配置差异"), nil
				}
				if observedVersion == "" && a.VersionMatched != nil && *a.VersionMatched {
					return actool.Errorf("verdict=env_mismatch 时 version_matched 不能为 true"), nil
				}
			case db.AttemptDependencyMissing, db.AttemptFailed:
				if blockedReason == "" {
					return actool.Errorf(fmt.Sprintf("verdict=%s 必须填写 blocked_reason", verdict)), nil
				}
			case db.AttemptSupported, db.AttemptDisproved, db.AttemptUnreproduced:
				if dc.RequiresCredentials && strings.TrimSpace(dc.CredentialRef) == "" {
					return actool.Errorf("当前义务要求绑定凭证（requires_credentials=true），在缺少 credential_ref 时只能提交 dependency_missing"), nil
				}
				if dc.Dimension == db.DimensionRuntimeAsset && verdict == db.AttemptSupported && a.VersionMatched != nil && !*a.VersionMatched {
					return actool.Errorf("version_matched=false 时不能判定 runtime_asset 为 supported，请改判 env_mismatch"), nil
				}
				if verdict == db.AttemptUnreproduced && len(missingPreconds) == 0 && blockedReason == "" {
					return actool.Errorf("verdict=unreproduced 必须提供至少一条 missing_preconditions（明确未能触发的前置缺口；单次未复现不等于已修复）"), nil
				}
				if len(trafficIDs) == 0 && len(cmdEvidence) == 0 {
					return actool.Errorf("有效动态结论必须至少提供一条已核实的 traffic_ids 或真实命令/请求执行证据（command_evidence）"), nil
				}
				if len(trafficIDs) == 0 && dc.ExecutionCounter != nil && dc.ExecutionCounter.Load() == 0 {
					return actool.Errorf("本次动态验证未检测到真实命令/HTTP/浏览器工具执行，也未提供已核实的 traffic_ids；禁止无实测提交有效结论"), nil
				}
			}

			var reverseSummary string
			reverseCount := 0
			if a.NextCodeInvestigate != nil && strings.TrimSpace(a.NextCodeInvestigate.Purpose) != "" {
				revPurpose := strings.TrimSpace(a.NextCodeInvestigate.Purpose)
				revNote := strings.TrimSpace(a.NextCodeInvestigate.EvidenceNote)
				if revNote == "" {
					revNote = summary
				}
				if err := db.ValidateAssessmentTextSafe(revPurpose, revNote); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				reverseSummary = revPurpose
				if dc.PG != nil && dc.TaskID > 0 && dc.RoundID > 0 {
					dedupe := strings.TrimSpace(a.NextCodeInvestigate.DedupeKey)
					if dedupe == "" {
						dedupe = fmt.Sprintf("hypothesis:dyn2wb:o%d:a%d", dc.ObligationID, dc.AttemptID)
					}
					ruleBytes, _ := json.Marshal(map[string]any{
						"evidence_note": revNote,
						"origin_source": "dynamic_verify",
					})
					roundID := dc.RoundID
					if _, err := dc.PG.CreateCoverageObligation(db.CreateCoverageObligationInput{
						TaskID:         dc.TaskID,
						RoundID:        &roundID,
						Dimension:      db.DimensionHypothesis,
						Purpose:        revPurpose,
						Required:       true,
						DedupeKey:      dedupe,
						AcceptanceRule: ruleBytes,
						ExecutionMode:  db.ExecModeCodeInvestigate,
						Origin:         db.ObligationOriginPlanner,
						Priority:       8,
						ProfileVersion: dc.ProfileVersion,
					}); err != nil {
						return actool.Errorf(fmt.Sprintf("创建动态→白盒反向排查义务失败: %v", err)), nil
					}
					_, _, _ = dc.PG.ReconcileObligationReadiness(dc.TaskID, roundID)
					reverseCount = 1
				}
			}

			var evIDPtr *int64
			if dc.PG != nil && dc.TaskID > 0 && (len(trafficIDs) > 0 || len(cmdEvidence) > 0 || verdict == db.AttemptEnvMismatch) {
				kind := db.EvidenceExecution
				ref := fmt.Sprintf("dynamic_verify:o%d:a%d", dc.ObligationID, dc.AttemptID)
				if len(trafficIDs) > 0 && len(cmdEvidence) == 0 {
					kind = db.EvidenceTraffic
					ref = "traffic:" + strings.Join(trafficIDs, ",")
				}
				payloadMap := map[string]any{
					"verdict":               verdict,
					"summary":               summary,
					"obligation_id":         dc.ObligationID,
					"attempt_id":            dc.AttemptID,
					"dimension":             dc.Dimension,
					"observed_url":          observedURL,
					"observed_version":      observedVersion,
					"version_matched":       a.VersionMatched,
					"traffic_ids":           trafficIDs,
					"command_evidence":      cmdEvidence,
					"missing_preconditions": missingPreconds,
					"blocked_reason":        blockedReason,
				}
				if verdict == db.AttemptUnreproduced {
					payloadMap["unreproduced_not_fixed"] = true
				}
				payloadBytes, _ := json.Marshal(payloadMap)
				evID, err := dc.PG.GetOrCreateEvidenceRef(dc.TaskID, kind, ref, payloadBytes)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("持久化动态验证证据引用失败: %v", err)), nil
				}
				evIDPtr = &evID
			}

			if outcome != nil {
				prevClaims := outcome.FeedbackClaimsCreated
				prevObs := outcome.FeedbackObligationsCreated
				*outcome = DynamicVerifyOutcome{
					Submitted:                  true,
					Verdict:                    verdict,
					Summary:                    summary,
					BlockedReason:              blockedReason,
					ObservedURL:                observedURL,
					ObservedVersion:            observedVersion,
					VersionMatched:             a.VersionMatched,
					TrafficIDs:                 trafficIDs,
					CommandEvidence:            cmdEvidence,
					MissingPreconditions:       missingPreconds,
					ReverseInvestigateSummary:  reverseSummary,
					FeedbackClaimsCreated:      prevClaims,
					FeedbackObligationsCreated: prevObs + reverseCount,
					EvidenceRefID:              evIDPtr,
				}
			}
			return jsonResult(map[string]any{
				"ok":                         true,
				"verdict":                    verdict,
				"evidence_ref_id":            evIDPtr,
				"verified_traffic_count":     len(trafficIDs),
				"command_evidence_count":     len(cmdEvidence),
				"reverse_investigate_queued": reverseCount > 0,
			})
		})
}

func normalizeTrimmedStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func dynamicVerifySystem(dc DynamicVerifyContext, proxyAddr, caCert, dataDir, runDir string, wantConstraints bool, ts *db.ExplorationStore, intent *db.Node, as *db.AssetStore, coverageEnabled bool) string {
	envSummary := strings.TrimSpace(dc.EnvironmentSummary)
	if envSummary == "" && dc.WorkOrder.Environment != nil {
		env := dc.WorkOrder.Environment
		envSummary = fmt.Sprintf("%s (%s, access=%s)", env.Name, env.URL, env.AccessMode)
	}
	if envSummary == "" {
		envSummary = "使用任务当前授权环境与范围资产"
	}
	scopeText := strings.TrimSpace(dc.ScopeNotes)
	if scopeText == "" {
		scopeText = "严格限定于已授权测试环境实例与范围资产，禁止主动探测外部依赖。"
	}
	body := renderSystem("dynamic_verify", dynamicVerifyDefaultTmpl, DynamicVerifyVars{
		RoundNo:            fmt.Sprint(max(dc.RoundNo, 1)),
		ProfileVersion:     fmt.Sprint(max(dc.ProfileVersion, 1)),
		EnvironmentSummary: envSummary,
		Scope:              scopeText,
		ProxyAddr:          proxyAddr,
		DataDir:            dataDir,
		Now:                nowStr(),
	})
	body += workerTrafficBlock(caCert != "") + workerArtifactSpec(runDir)
	if wantConstraints && ts != nil {
		body += constraintBlock(ts)
	}
	if intent != nil {
		body += renderIntentTask(intent)
	}
	if as != nil && intent != nil {
		if ids := intentAssetIDs(intent); len(ids) > 0 {
			if assets, err := as.GetByIDsInScope(dc.TaskID, ids); err == nil && len(assets) > 0 {
				if b, err := json.Marshal(assets); err == nil {
					body += "\n\n本意图 asset_ids 对应的范围资产：\n" + string(b)
				}
				if coverageEnabled {
					for _, a := range assets {
						_ = as.AddAutoScope(dc.TaskID, a.Type, a.Domain, a.URL, a.IP)
					}
				}
			}
		}
	}
	if b, err := json.Marshal(dc.WorkOrder); err == nil && len(b) > 0 {
		body += "\n\n【结构化动态验证工作单（work_order）】\n" + string(b)
	}
	if strings.TrimSpace(dc.ProfileSlice) != "" {
		body += "\n\n【相关画像切片与代码线索（只读背景，须动态核实）】\n" + strings.TrimSpace(dc.ProfileSlice)
	}
	body += "\n\n开始执行动态验证：先根据工作单对授权环境与目标入口/身份/假设做最小可行真实探测，再调用 submit_dynamic_verification 落库结果分类与可核验证据。"
	return body
}

// ExecuteDynamicVerify runs one bound dynamic_verify Intent against authorized
// runtime environments using Worker's proxy/Bash/HTTP/browser tools alongside
// read-only profile/code slices and structured evidence/verdict enforcement.
func (w *Worker) ExecuteDynamicVerify(
	ctx context.Context,
	name string,
	dc DynamicVerifyContext,
	as *db.AssetStore,
	ts *db.ExplorationStore,
	intent *db.Node,
	hooks harness.HookRunner,
	emit func(db.Activity),
	enr EnrichTrigger,
	notifyFinding func(int64, string),
) (DynamicVerifyOutcome, WriteCounts, harness.TerminalReason, error) {
	var outcome DynamicVerifyOutcome
	if intent == nil {
		return outcome, WriteCounts{}, "", fmt.Errorf("intent is required")
	}
	if dc.ExecutionCounter == nil {
		dc.ExecutionCounter = &atomic.Int64{}
	}

	tsx := NewToolSet(ts, name)
	tsx.SetFindingRecorder(w.findingRecorder)
	tsx.SetEscalationRecorder(w.escalations)
	tsx.SetTaskID(dc.TaskID)
	coverageEnabled := as == nil || as.CoverageEnabled(dc.TaskID)
	tsx.SetCoverageEnabled(coverageEnabled)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetOwnerNode(intent.ID)
	tsx.SetEnrich(enr)
	tsx.SetNotifyFinding(notifyFinding)

	workerBase, assessmentTools := tsx.dynamicVerifyBaseTools(dc, &outcome, w.extraTools)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: dc.TaskID, ExplorationID: explorationID(ts), IntentID: intent.ID})
	// Augment with "worker" DB bindings/skills/MCPs so existing browser MCPs,
	// traffic tools, and custom tools work identically without DB migration fragility,
	// while forbidden planner/batch tools remain filtered and assessmentTools stay intact.
	augmented, def, cleanup := AugmentTools(ctx, "worker", workerBase)
	defer cleanup()

	seen := map[string]bool{}
	tools := appendAllowedDynamicTools(nil, seen, augmented...)
	for i := range assessmentTools {
		assessmentTools[i] = guardPanic(assessmentTools[i])
	}
	tools = appendAllowedDynamicTools(tools, seen, assessmentTools...)
	tools = appendAllowedDynamicTools(tools, seen, deepSeekTools(w.webSearch)...)

	runDir := ensureRunDir(w.workDir, dc.TaskID, intent.ID)
	ctx = intercept.WithReviewContext(ctx, runDir, intercept.ReviewBackground{})

	proxyAddr := w.proxyAddr
	if w.proxyAddrFn != nil {
		proxyAddr = w.proxyAddrFn()
	}
	sysBody := dynamicVerifySystem(dc, proxyAddr, w.proxyCACert, w.workDir, runDir, w.wantConstraints(), ts, intent, as, coverageEnabled)
	system, boundary := deferredSystem(sysBody, def)

	tc := taskClockFrom(ctx)
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, w.runTimeout)
	settle := wrapupSettlement("dynamic_verify", []string{"Bash"})
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("dynamic_verify", []string{"Bash"}, clamped)
	}

	opts := agentcore.Options{
		Provider:           w.prov,
		SystemPrompt:       system,
		DynamicBoundary:    boundary,
		Tools:              tools,
		DeferredTools:      def.Deferred,
		UnlockSet:          def.Unlock,
		PermissionMode:     permission.ModeBypass,
		EnableWebFetch:     true,
		WebFetchProxy:      proxyAddr,
		WebFetchCACert:     w.proxyCACert,
		EnableWebSearch:    w.webSearch.Enabled && w.webSearch.Backend != "deepseek",
		WebSearchBackend:   w.webSearch.Backend,
		BraveSearchAPIKey:  w.webSearch.BraveKey,
		TavilySearchAPIKey: w.webSearch.TavilyKey,
		WebSearchProxy:     w.webSearch.Proxy,
		BashEnv:            proxyEnv(proxyAddr, w.proxyCACert),
		WorkingDir:         runDir,
		MaxTurns:           w.maxTurns,
		MaxDuration:        maxDur,
		Settlement:         settle,
		ToolOutputDir:      cmdOutDir(runDir),
		Compaction:         compactionConfig(w.compactionWindow()),
		Todos:              actool.NewTodoStore(),
		NonStreaming:       w.nonStreaming(),
		MaxTokens:          w.maxTokens(),
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

	input := renderWorkerGraphOverview(tsx.graphOverviewData())
	if strings.TrimSpace(input) == "" {
		input = "请按照工作单对目标环境/入口/身份/静态假设执行最小可行动态验证，并调用 submit_dynamic_verification 提交结构化结果与真实证据。"
	}
	if w.tx != nil && opts.SessionID != "" {
		_ = s.Resume(opts.SessionID)
		if len(s.Messages()) > 0 {
			seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
			input = "继续执行尚未完成的动态验证工作单，最后务必调用 submit_dynamic_verification 提交结构化结论与真实运行/流量证据。"
		}
	}

	intentID := intent.ID
	emitWrap := func(r db.Activity) {
		if r.Kind == "tool_use" && isDynamicRuntimeProbeTool(r.Tool) {
			dc.ExecutionCounter.Add(1)
		}
		if emit != nil {
			r.NodeID, r.Worker = &intentID, name
			emit(r)
		}
	}
	_, reason, err := captureRunSession(ctx, s, input, emitWrap)
	return outcome, tsx.Writes(), reason, err
}
