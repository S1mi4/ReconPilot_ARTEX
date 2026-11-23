package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// AssessmentPlannerContext carries the round-scoped dependencies and program
// completion gate for Assessment Planner rounds (§8.3).
type AssessmentPlannerContext struct {
	PG                *db.DB
	TaskID            int64
	RoundID           int64
	RoundNo           int
	ProfileVersion    int
	ExecutionMode     string // "dynamic" | "offline"
	AssessmentPhase   string
	BusinessOverview  string
	BusinessFocus     []string
	ScopeNotes        string
	WorkerSlots       int
	RequestCompletion func(reason string) (completed bool, report *db.AssessmentCompletionReport, err error)
}

type assessmentIntentDispatchItem struct {
	ObligationID   json.RawMessage   `json:"obligation_id"`
	ExecutionMode  string            `json:"execution_mode"`
	Summary        string            `json:"summary"`
	Priority       int               `json:"priority"`
	IdempotencyKey string            `json:"idempotency_key"`
	AssetIDs       []json.RawMessage `json:"asset_ids"`
	ParentIDs      []json.RawMessage `json:"parent_ids"`
	WorkOrder      json.RawMessage   `json:"work_order"`
}

func assessmentMaxBatchSlots(totalSlots int) int {
	if totalSlots >= 2 {
		return totalSlots - 1
	}
	return 1
}

// AssessmentPlannerTools returns the strict allowlisted toolset for the
// assessment-mode global Planner (§8.3). It deliberately excludes prove_goal,
// goal_met, add_intent, obligation delete/not_applicable tools, and Bash/FS tools.
func (t *ToolSet) AssessmentPlannerTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.getAssessmentOverviewTool(),
		t.listCoverageObligationsTool(),
		t.queryProfileSliceTool(),
		t.listCodeAuditCoverageTool(),
		t.listFindings(),
		t.listFacts(),
		t.nodeDetail(),
		t.getWorkerOutput(),
		t.getWorkerTrace(),
		t.listAssets(),
		t.dispatchAssessmentIntentTool(),
		t.addExplorationObligationTool(),
		t.updateObligationPriorityTool(),
		t.recordProfileClaimTool(),
		t.steerWorkTool(),
		t.killWorkTool(),
		t.requestAssessmentCompletionTool(),
	}
}

// AssessmentMainTools returns the assessment-mode MainAgent toolset (§8.3).
// It converges legacy whitebox audit queries/steering into MainAgent while
// omitting legacy add_intent / set_goals (which bypass obligation coverage).
func (t *ToolSet) AssessmentMainTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(),
		t.getAssessmentOverviewTool(),
		t.listCoverageObligationsTool(),
		t.queryProfileSliceTool(),
		t.listCodeAuditCoverageTool(),
		t.listFindings(),
		t.listFacts(),
		t.listAssets(),
		t.nodeDetail(),
		t.expandDigest(),
		t.getWorkerOutput(),
		t.getWorkerTrace(),
		t.searchAllWorkerTraces(),
		t.addHint(),
		t.steerWorkTool(),
		t.setConstraints(),
		t.updateObligationPriorityTool(),
		t.addExplorationObligationTool(),
		t.recordProfileClaimTool(),
		t.recordFact(),
		t.recordIntelligence(),
		t.proposeEscalation(),
	}
}

func (t *ToolSet) needAssessmentContext(name string, run func(context.Context, json.RawMessage) (actool.Result, error)) func(context.Context, json.RawMessage) (actool.Result, error) {
	return func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if t.assessment == nil || t.assessment.PG == nil || t.assessment.TaskID <= 0 || t.assessment.RoundID <= 0 {
			return actool.Errorf(name + " 需要评估轮次上下文，当前不可用"), nil
		}
		return run(ctx, in)
	}
}

func (t *ToolSet) readAssessmentTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return readTool(name, desc, schema, t.needAssessmentContext(name, run))
}

func (t *ToolSet) writeAssessmentTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return writeTool(name, desc, schema, t.needAssessmentContext(name, run))
}

func (t *ToolSet) assessmentOverviewData() map[string]any {
	ac := t.assessment
	if ac == nil || ac.PG == nil {
		return map[string]any{}
	}
	out := map[string]any{
		"task_id":          ac.TaskID,
		"round_id":         ac.RoundID,
		"round_no":         ac.RoundNo,
		"profile_version":  ac.ProfileVersion,
		"execution_mode":   ac.ExecutionMode,
		"assessment_phase": ac.AssessmentPhase,
		"business_focus":   ac.BusinessFocus,
		"scope_notes":      ac.ScopeNotes,
	}
	if sum, err := ac.PG.GetAssessmentProfileSummary(ac.TaskID, ac.RoundID); err == nil && sum != nil {
		out["profile_summary"] = sum
		out["unresolved_gaps_count"] = sum.UnresolvedGapCount
	}
	if dims, err := ac.PG.GetCoverageSummaryByDimension(ac.TaskID, ac.RoundID); err == nil {
		out["coverage_by_dimension"] = dims
	}
	if attempts, err := ac.PG.ListTestAttempts(ac.TaskID, ac.RoundID, 0, 15); err == nil {
		out["recent_attempts"] = attempts
	}
	if evCnt, err := ac.PG.CountUnprocessedAssessmentEvents(ac.TaskID); err == nil {
		out["unprocessed_events"] = evCnt
	}

	totalSlots := max(ac.WorkerSlots, 1)
	slotStatus := map[string]any{
		"total_slots":                totalSlots,
		"code_audit_batch_max_slots": assessmentMaxBatchSlots(totalSlots),
	}
	if t.ts != nil {
		runBatch, _ := t.ts.CountRunningIntentsByMode(db.ExecModeCodeAuditBatch)
		runInv, _ := t.ts.CountRunningIntentsByMode(db.ExecModeCodeInvestigate)
		runDyn, _ := t.ts.CountRunningIntentsByMode(db.ExecModeDynamicVerify)
		slotStatus["running_code_audit_batch"] = runBatch
		slotStatus["running_code_investigate"] = runInv
		slotStatus["running_dynamic_verify"] = runDyn

		if active, err := t.ts.ListActiveIntents(40); err == nil {
			out["active_intents"] = compactIntents(active, nil, nil)
		}
		if hints, err := t.ts.ListByKind(db.KindHint, 30); err == nil {
			hsum := make([]map[string]any, 0, len(hints))
			for _, h := range hints {
				var p map[string]any
				_ = json.Unmarshal(h.Payload, &p)
				hsum = append(hsum, map[string]any{"id": h.ID, "state": h.State, "text": p["text"]})
			}
			out["hints"] = hsum
		}
	}
	out["worker_slots"] = slotStatus
	return out
}

func (t *ToolSet) getAssessmentOverviewTool() actool.CoreTool {
	return t.readAssessmentTool("get_assessment_overview",
		"读取当前评估轮次的整体态势：轮次与画像版本、各维度覆盖进度、并发槽位配额与在跑分布、活动意图、最近尝试、未处理事件与战略 hints。",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			return jsonResult(t.assessmentOverviewData())
		})
}

func (t *ToolSet) listCoverageObligationsTool() actool.CoreTool {
	return t.readAssessmentTool("list_coverage_obligations",
		"分页查询本轮覆盖义务，含状态、前置依赖与未满足依赖（unmet_dependency_ids）。只能派发前置依赖已全部满足且状态为 ready/stale 的义务。",
		obj(map[string]any{
			"status":           str("可选状态过滤：pending|ready|running|satisfied|blocked|stale|not_applicable"),
			"dimension":        str("可选维度过滤：code_audit|config_audit|entry_test|identity_resource|cross_module|runtime_asset|hypothesis"),
			"execution_mode":   str("可选执行模式过滤：code_audit_batch|code_investigate|dynamic_verify"),
			"origin":           str("可选来源过滤：program|planner|user"),
			"exclude_terminal": map[string]any{"type": "boolean", "description": "是否排除 satisfied/not_applicable 终态义务（默认 false）"},
			"limit":            intp("返回条数上限，默认 50，最大 200"),
			"offset":           intp("分页偏移，默认 0"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Status          string `json:"status"`
				Dimension       string `json:"dimension"`
				ExecutionMode   string `json:"execution_mode"`
				Origin          string `json:"origin"`
				ExcludeTerminal bool   `json:"exclude_terminal"`
				Limit           int    `json:"limit"`
				Offset          int    `json:"offset"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 || limit > 200 {
				limit = 50
			}
			items, err := t.assessment.PG.ListCoverageObligations(db.CoverageObligationFilter{
				TaskID:          t.assessment.TaskID,
				RoundID:         t.assessment.RoundID,
				Status:          strings.TrimSpace(a.Status),
				Dimension:       strings.TrimSpace(a.Dimension),
				ExecutionMode:   strings.TrimSpace(a.ExecutionMode),
				Origin:          strings.TrimSpace(a.Origin),
				ExcludeTerminal: a.ExcludeTerminal,
				Limit:           limit,
				Offset:          max(a.Offset, 0),
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"round_id":    t.assessment.RoundID,
				"count":       len(items),
				"obligations": items,
			})
		})
}

func (t *ToolSet) queryProfileSliceTool() actool.CoreTool {
	return t.readAssessmentTool("query_profile_slice",
		"按目标 subject（如 service:order-svc、instance:staging、shared_library:auth-core）读取当前轮次的靶向画像切片（实体、断言、冲突、未知项与缺口）。不要试图一次性拉全库。",
		obj(map[string]any{
			"subjects": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "目标 subject 列表；省略则返回有限摘要切片"},
			"limit":    intp("切片条目上限，默认 50，最大 200"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Subjects []string `json:"subjects"`
				Limit    int      `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 || limit > 200 {
				limit = 50
			}
			slice, err := t.assessment.PG.QueryProfileContext(t.assessment.TaskID, t.assessment.RoundID, a.Subjects, limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(slice)
		})
}

func (t *ToolSet) listCodeAuditCoverageTool() actool.CoreTool {
	return t.readAssessmentTool("list_code_audit_coverage",
		"查看当前任务的白盒静态审计覆盖台账摘要（已读文件数、总文件数、分片进度、检查点与候选计数）。",
		obj(map[string]any{
			"limit": intp("返回运行条数上限，默认 30"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Limit int `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			runs, err := t.assessment.PG.ListCodeAuditCoverageSummaries(t.assessment.TaskID, a.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"runs": runs})
		})
}

func (t *ToolSet) dispatchOneAssessmentIntent(it assessmentIntentDispatchItem) (*db.DispatchAssessmentIntentResult, error) {
	obID := pid(it.ObligationID)
	if obID <= 0 {
		return nil, fmt.Errorf("obligation_id 必须是正整数")
	}
	if strings.TrimSpace(it.Summary) == "" {
		return nil, fmt.Errorf("summary 不能为空")
	}
	if !db.IsValidExecutionMode(strings.TrimSpace(it.ExecutionMode)) {
		return nil, fmt.Errorf("execution_mode 必须是 code_audit_batch / code_investigate / dynamic_verify 之一")
	}
	parents := pidList(it.ParentIDs)
	if len(parents) > 0 && t.ts != nil {
		for _, pidv := range parents {
			n, err := t.ts.GetNode(pidv)
			if err != nil || n == nil {
				return nil, fmt.Errorf("parent_id %d 不存在于当前任务探索图中：只能引用已存在的 fact/finding 节点", pidv)
			}
			if n.Kind != db.KindFact && n.Kind != db.KindFinding {
				return nil, fmt.Errorf("parent_id %d 类型为 %q，不能作为意图血缘锚点（仅允许 fact/finding）", pidv, n.Kind)
			}
		}
	}
	anchors := normalizeAnchorIDs(pidList(it.AssetIDs))
	if t.as != nil && t.taskID > 0 && len(anchors) > 0 {
		visible, err := t.as.GetByIDsInScope(t.taskID, anchors)
		if err != nil {
			return nil, fmt.Errorf("资产可见范围校验失败：%w", err)
		}
		if len(visible) != len(anchors) {
			return nil, fmt.Errorf("目标资产不属于本任务或直接关联任务")
		}
		hits, err := t.as.CheckAssetsIntercept(t.taskID, anchors)
		if err != nil {
			return nil, fmt.Errorf("资产拦截校验失败：%w", err)
		}
		if len(hits) > 0 {
			var b strings.Builder
			fmt.Fprintf(&b, "意图「%s」绑定的资产未通过测试范围校验：", it.Summary)
			for _, h := range hits {
				fmt.Fprintf(&b, "\n - %s", h.Describe())
			}
			return nil, fmt.Errorf("%s", b.String())
		}
	}
	return t.assessment.PG.DispatchAssessmentIntent(db.DispatchAssessmentIntentInput{
		TaskID:         t.assessment.TaskID,
		RoundID:        t.assessment.RoundID,
		ObligationID:   obID,
		ExecutionMode:  strings.TrimSpace(it.ExecutionMode),
		Summary:        it.Summary,
		Priority:       it.Priority,
		IdempotencyKey: strings.TrimSpace(it.IdempotencyKey),
		AssetIDs:       anchors,
		ParentIDs:      parents,
		WorkOrder:      it.WorkOrder,
		Origin:         db.ObligationOriginPlanner,
	})
}

func normalizeAnchorIDs(ids []int64) []int64 {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func (t *ToolSet) dispatchAssessmentIntentTool() actool.CoreTool {
	return t.writeAssessmentTool("dispatch_assessment_intent",
		"为已就绪的覆盖义务派发绑定执行器模式（execution_mode）的 Intent 与尝试记录。支持单条或通过 intents 批量提交（每次最多 4 条）。重复派同一义务会幂等返回已有活动意图，未满足前置依赖或执行模式不兼容会被程序拒绝。",
		obj(map[string]any{
			"intents": map[string]any{
				"type":        "array",
				"description": "可选批量数组（最多 4 条），每项字段同顶层（obligation_id/execution_mode/summary/priority/idempotency_key/asset_ids/parent_ids/work_order）",
				"items":       map[string]any{"type": "object"},
			},
			"obligation_id":   idp("目标覆盖义务 ID"),
			"execution_mode":  str("执行器模式：code_audit_batch | code_investigate | dynamic_verify"),
			"summary":         str("本次执行任务的一句话明确说明（测什么、依据什么、目标与预期）"),
			"priority":        intp("优先级 1-10（默认沿用义务优先级）"),
			"idempotency_key": str("可选幂等标识（省略则自动按轮次+义务+模式生成）"),
			"asset_ids":       map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "关联目标资产 ID（如有）"},
			"parent_ids":      map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "关联上游事实/发现节点 ID（纯谱系记录，不构成执行依赖）"},
			"work_order":      map[string]any{"type": "object", "description": "可选结构化工作单（hypothesis/entry/identity/expected_behavior/evidence_plan/stop_condition）"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Intents []assessmentIntentDispatchItem `json:"intents"`
				assessmentIntentDispatchItem
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			batch := len(a.Intents) > 0
			items := a.Intents
			if !batch {
				items = []assessmentIntentDispatchItem{a.assessmentIntentDispatchItem}
			}
			if len(items) > 4 {
				return actool.Errorf(fmt.Sprintf("单次最多批量派发 4 条意图（当前传入 %d 条）", len(items))), nil
			}
			results := make([]*db.DispatchAssessmentIntentResult, len(items))
			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				res, err := t.dispatchOneAssessmentIntent(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				results[i] = res
				ids[i] = res.IntentID
			}
			if !batch {
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return jsonResult(results[0])
			}
			out := map[string]any{"ids": ids, "dispatches": results}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) addExplorationObligationTool() actool.CoreTool {
	return t.writeAssessmentTool("add_exploration_obligation",
		"基于已有代码线索、动态异常或画像冲突增补一条深入探索必需覆盖义务（origin=planner）。必须给出 evidence_note 说明证据依据与验证目标；同一 dedupe_key 在本轮幂等。",
		obj(map[string]any{
			"dimension":            str("维度：code_audit|config_audit|entry_test|identity_resource|cross_module|runtime_asset|hypothesis"),
			"purpose":              str("深入探索目的与待验证假设"),
			"execution_mode":       str("建议执行器：code_audit_batch|code_investigate|dynamic_verify"),
			"dedupe_key":           str("本轮唯一幂等键（例如 hypothesis:auth-bypass:/api/admin）"),
			"evidence_note":        str("基于哪条代码位置、流量异常或画像冲突产生本深入义务"),
			"target_entity_id":     idp("可选关联目标实体 ID"),
			"dependency_ids":       map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "可选前置义务 ID"},
			"priority":             intp("优先级 1-10，默认 6"),
			"requires_credentials": map[string]any{"type": "boolean", "description": "是否需要绑定测试身份凭证"},
			"credential_ref":       str("凭证引用名（仅存引用路径/标识，严禁写明文密码或 Token）"),
			"acceptance_rule":      map[string]any{"type": "object", "description": "可选验收规则字段"},
		}, "dimension", "purpose", "execution_mode", "dedupe_key", "evidence_note"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Dimension           string            `json:"dimension"`
				Purpose             string            `json:"purpose"`
				ExecutionMode       string            `json:"execution_mode"`
				DedupeKey           string            `json:"dedupe_key"`
				EvidenceNote        string            `json:"evidence_note"`
				TargetEntityID      json.RawMessage   `json:"target_entity_id"`
				DependencyIDs       []json.RawMessage `json:"dependency_ids"`
				Priority            int               `json:"priority"`
				RequiresCredentials bool              `json:"requires_credentials"`
				CredentialRef       string            `json:"credential_ref"`
				AcceptanceRule      map[string]any    `json:"acceptance_rule"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if strings.TrimSpace(a.Purpose) == "" || strings.TrimSpace(a.DedupeKey) == "" || strings.TrimSpace(a.EvidenceNote) == "" {
				return actool.Errorf("purpose、dedupe_key 与 evidence_note 均为必填"), nil
			}
			if err := db.ValidateObligationExecutionMode(strings.TrimSpace(a.Dimension), strings.TrimSpace(a.ExecutionMode), t.assessment.ExecutionMode); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var targetPtr *int64
			if tid := pid(a.TargetEntityID); tid > 0 {
				targetPtr = &tid
			}
			deps := pidList(a.DependencyIDs)
			priority := a.Priority
			if priority <= 0 {
				priority = 6
			}
			rule := map[string]any{}
			for k, v := range a.AcceptanceRule {
				rule[k] = v
			}
			rule["evidence_note"] = strings.TrimSpace(a.EvidenceNote)
			ruleBytes, _ := json.Marshal(rule)

			roundID := t.assessment.RoundID
			ob, err := t.assessment.PG.CreateCoverageObligation(db.CreateCoverageObligationInput{
				TaskID:              t.assessment.TaskID,
				RoundID:             &roundID,
				Dimension:           strings.TrimSpace(a.Dimension),
				TargetEntityID:      targetPtr,
				Purpose:             strings.TrimSpace(a.Purpose),
				Required:            true,
				DedupeKey:           strings.TrimSpace(a.DedupeKey),
				RequiresCredentials: a.RequiresCredentials,
				CredentialRef:       strings.TrimSpace(a.CredentialRef),
				AcceptanceRule:      ruleBytes,
				ExecutionMode:       strings.TrimSpace(a.ExecutionMode),
				Origin:              db.ObligationOriginPlanner,
				Priority:            priority,
				ProfileVersion:      t.assessment.ProfileVersion,
				DependencyIDs:       deps,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			_, _, _ = t.assessment.PG.ReconcileObligationReadiness(t.assessment.TaskID, roundID)
			if refreshed, rErr := t.assessment.PG.GetCoverageObligation(t.assessment.TaskID, ob.ID); rErr == nil && refreshed != nil {
				ob = refreshed
			}
			return jsonResult(ob)
		})
}

func (t *ToolSet) updateObligationPriorityTool() actool.CoreTool {
	return t.writeAssessmentTool("update_obligation_priority",
		"调整一条未完结覆盖义务的调度优先级（1-10）。不能修改义务的必需标记、状态或适用性。",
		obj(map[string]any{
			"obligation_id": idp("覆盖义务 ID"),
			"priority":      intp("新优先级（1-10）"),
		}, "obligation_id", "priority"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ObligationID json.RawMessage `json:"obligation_id"`
				Priority     int             `json:"priority"`
			}
			_ = json.Unmarshal(in, &a)
			obID := pid(a.ObligationID)
			if obID <= 0 || a.Priority <= 0 {
				return actool.Errorf("obligation_id 与正整数 priority 必填"), nil
			}
			if err := t.assessment.PG.UpdateObligationPriority(t.assessment.TaskID, obID, a.Priority); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"obligation_id": obID, "priority": min(max(a.Priority, 1), 10)})
		})
}

func (t *ToolSet) recordProfileClaimTool() actool.CoreTool {
	return t.writeAssessmentTool("record_profile_claim",
		"向当前轮次画像写入一条带来源说明的推断或未知断言（Planner 只能记录 model_inference，且确认状态仅限 unverified/unknown；严禁写入明文密码/Token/私钥）。",
		obj(map[string]any{
			"subject":             str("主体标识（如 service:order-svc / entry:POST /pay）"),
			"relation":            str("关系或属性名"),
			"object_value":        str("关系客体或属性值"),
			"confirmation_status": str("状态：unverified | unknown（model_inference 不可自称 confirmed）"),
			"evidence_kind":       str("可选证据类型：code_range|decompiled|config|manual"),
			"evidence_reference":  str("可选证据引用位置"),
			"conflict_note":       str("可选冲突或不确定说明"),
			"environment":         str("可选适用环境名称"),
			"valid_code_version":  str("可选适用代码版本 ID"),
		}, "subject", "relation", "object_value", "confirmation_status"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Subject            string `json:"subject"`
				Relation           string `json:"relation"`
				ObjectValue        string `json:"object_value"`
				ConfirmationStatus string `json:"confirmation_status"`
				EvidenceKind       string `json:"evidence_kind"`
				EvidenceReference  string `json:"evidence_reference"`
				ConflictNote       string `json:"conflict_note"`
				Environment        string `json:"environment"`
				ValidCodeVersion   string `json:"valid_code_version"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			st := strings.TrimSpace(a.ConfirmationStatus)
			if st != db.ClaimStatusUnverified && st != db.ClaimStatusUnknown {
				return actool.Errorf(fmt.Sprintf("model_inference 断言状态仅允许 unverified 或 unknown，不允许设为 %q", st)), nil
			}
			var evPtr *int64
			if ref := strings.TrimSpace(a.EvidenceReference); ref != "" {
				kind := db.EvidenceRefKind(strings.TrimSpace(a.EvidenceKind))
				switch kind {
				case db.EvidenceCodeRange, db.EvidenceDecompiled, db.EvidenceConfig, db.EvidenceManual:
				case "":
					kind = db.EvidenceManual
				default:
					return actool.Errorf(fmt.Sprintf("评估 Planner 仅支持附带静态/手工证据引用类型，不支持伪造 %q", a.EvidenceKind)), nil
				}
				if id, err := t.assessment.PG.GetOrCreateEvidenceRef(t.assessment.TaskID, kind, ref, nil); err == nil && id > 0 {
					evPtr = &id
				}
			}
			roundID := t.assessment.RoundID
			claim, conflicted, err := t.assessment.PG.CreateProfileClaim(db.CreateProfileClaimInput{
				TaskID:             t.assessment.TaskID,
				RoundID:            &roundID,
				Subject:            strings.TrimSpace(a.Subject),
				Relation:           strings.TrimSpace(a.Relation),
				ObjectValue:        strings.TrimSpace(a.ObjectValue),
				SourceType:         db.ClaimSourceModelInference,
				EvidenceRefID:      evPtr,
				ValidCodeVersion:   strings.TrimSpace(a.ValidCodeVersion),
				Environment:        strings.TrimSpace(a.Environment),
				ConfirmationStatus: st,
				ConflictNote:       strings.TrimSpace(a.ConflictNote),
				ExecutionRef:       fmt.Sprintf("planner:round-%d", t.assessment.RoundNo),
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"claim": claim, "conflicted": conflicted})
		})
}

func (t *ToolSet) requestAssessmentCompletionTool() actool.CoreTool {
	return t.writeAssessmentTool("request_assessment_completion",
		"向程序完成判定契约申请收尾对账。仅当全部必需义务、材料缺口、活动意图与未处理事件均已清零时，程序才会原子提交任务 done；否则返回 can_complete=false 及逐条未满足原因，供你继续补派工作。",
		obj(map[string]any{
			"reason": str("收尾对账说明"),
		}, "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Reason) == "" {
				return actool.Errorf("reason 必填"), nil
			}
			if t.assessment.RequestCompletion == nil {
				return actool.Errorf("完成判定回调未配置，无法提交收尾"), nil
			}
			completed, report, err := t.assessment.RequestCompletion(strings.TrimSpace(a.Reason))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if completed {
				t.GoalMet = true
				t.Reason = strings.TrimSpace(a.Reason)
			}
			var reasons []string
			canComplete := completed
			if report != nil {
				canComplete = report.CanComplete
				reasons = report.Reasons
			}
			return jsonResult(map[string]any{
				"completed":    completed,
				"can_complete": canComplete,
				"reasons":      reasons,
				"report":       report,
			})
		})
}

func assessmentPlannerSystem(ac AssessmentPlannerContext) string {
	overview := strings.TrimSpace(ac.BusinessOverview)
	if overview == "" {
		overview = "未提供额外业务说明，请依据代码清单、入口与运行反馈自行识别重点。"
	}
	if len(ac.BusinessFocus) > 0 {
		overview += "（关注重点：" + strings.Join(ac.BusinessFocus, "、") + "）"
	}
	execMode := strings.TrimSpace(ac.ExecutionMode)
	if execMode == "" {
		execMode = db.AssessmentExecDynamic
	}
	return renderSystem("assessment_planner", assessmentPlannerDefaultTmpl, AssessmentPlannerVars{
		BusinessOverview: overview,
		Scope:            ac.ScopeNotes,
		ExecutionMode:    execMode,
		RoundNo:          strconv.Itoa(max(ac.RoundNo, 1)),
		ProfileVersion:   strconv.Itoa(ac.ProfileVersion),
		WorkerSlots:      strconv.Itoa(max(ac.WorkerSlots, 1)),
		Now:              nowStr(),
	})
}

// PlanAssessment executes one Assessment Planner orchestration round for an
// assessment_mode=true task, returning whether program completion was committed.
func (p *Planner) PlanAssessment(ctx context.Context, ac AssessmentPlannerContext, as *db.AssetStore, ts *db.ExplorationStore, triggers []TriggerEvent, emit func(db.Activity)) (completed bool, reason string, err error) {
	p.compactor.OnPlannerRound(ctx, ts)
	tsx := NewToolSet(ts, "planner")
	tsx.SetFindingRecorder(p.findingRecorder)
	tsx.SetEscalationRecorder(p.escalations)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(ac.TaskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(ac.TaskID))
	tsx.killWork = p.killWork
	tsx.steerWork = p.steerWork
	tsx.SetAssessmentContext(&ac)
	if ts != nil {
		if origin, _ := ts.OriginFactID(); origin > 0 {
			tsx.SetOwnerNode(origin)
		}
	}

	rawTools := tsx.AssessmentPlannerTools()
	tools := make([]actool.CoreTool, len(rawTools))
	for i, rt := range rawTools {
		tools[i] = guardPanic(rt)
	}

	situational := renderTriggers(ts, triggers)
	if ov, mErr := json.Marshal(tsx.assessmentOverviewData()); mErr == nil {
		situational += "\n\n【当前评估态势（get_assessment_overview 预取快照）】：\n" + string(ov)
	}
	if ac.PG != nil && ac.TaskID > 0 && ac.RoundID > 0 {
		if obs, oErr := ac.PG.ListCoverageObligations(db.CoverageObligationFilter{
			TaskID:          ac.TaskID,
			RoundID:         ac.RoundID,
			ExcludeTerminal: true,
			Limit:           30,
		}); oErr == nil {
			if obJSON, mErr := json.Marshal(obs); mErr == nil {
				situational += "\n\n【待处理覆盖义务切片（最多前 30 条未完结义务；更多请用 list_coverage_obligations）】：\n" + string(obJSON)
			}
		}
	}

	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n【任务终局收尾（本轮特殊指令，覆盖上面常规调度）】：\n" + resolveTaskTimeoutWrapup("assessment_planner")
	}

	sysBody := assessmentPlannerSystem(ac)
	if p.wantConstraints() && ts != nil {
		sysBody += constraintBlock(ts)
	}
	system, boundary := deferredSystem(sysBody, DeferredInfo{})

	taskDir := ensureRunDir(p.workDir, ac.TaskID, 0)
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("assessment_planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("assessment_planner", nil, clamped)
	}

	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		PermissionMode:  permission.ModeBypass,
		WorkingDir:      taskDir,
		MaxTurns:        p.maxTurns,
		MaxDuration:     maxDur,
		Compaction:      compactionConfig(p.compactionWindow()),
		Todos:           p.todoFor(explorationID(ts)),
		Settlement:      settle,
		NonStreaming:    p.nonStreaming(),
		MaxTokens:       p.maxTokens(),
	}
	if p.tx != nil && ts != nil {
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	if ts != nil {
		noaSession := fmt.Sprintf("exp%d-planner", ts.ID())
		enableNoa(&opts, p.noaEnabledFn, p.workDir, noaSession, noaWarn(noaSession))
	}

	lead := "本轮评估唤醒：基于下方触发事件与当前覆盖态势进行统筹决策。"
	if len(triggers) == 0 {
		lead = "本轮是评估周期复查/唤醒，请检查在跑意图进展（必要时 steer_work / kill_work）、就绪义务与跨端联动："
		if ts != nil {
			if active, aErr := ts.HasActiveIntent(); aErr == nil && !active {
				lead = "当前已没有任何 open/running 意图。若仍有未完成或未对账义务，请立即通过 dispatch_assessment_intent 派发就绪工作；若确认已满足全部完成条件，调用 request_assessment_completion 申请收尾："
			}
		}
	}
	var todoItems []actool.Todo
	if opts.Todos != nil {
		todoItems = opts.Todos.List()
	}
	input := lead + situational + renderPlannerTodos(todoItems)

	_, _, err = captureRun(ctx, opts, input, func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	})
	return tsx.GoalMet, tsx.Reason, err
}
