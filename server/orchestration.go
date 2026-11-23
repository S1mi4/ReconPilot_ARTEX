package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// jsonResult marshals v to a JSON tool result.
func jsonResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// 本文件实现 P2「跨任务编排工具集」(docs/跑分编排 §2 P2)。这些是 host 工具——需要
// 访问 Manager(任意任务的 Store)、Engine(暂停)、以及建任务流程,所以住在 server 层。
// 读类工具把「现有 per-task 工具」重定向到目标任务的 store 上跑(建一个临时 ToolSet
// 并 Call 其对应工具),从而复用完全相同的逻辑;控制类(spawn/pause)直接调 Manager/Engine。
// 它们像流量工具一样 seed 进 tools 表、按 agent 绑定(只绑给编排 agent 才可见)。

// hostTools is the runtime host-tool provider fed to ToolAugment: traffic tools
// (gated by capture) + cross-task orchestration tools + user-defined custom tools.
// The second return is the names of custom tools flagged `deferred` (schema
// withheld, routed via SearchExtraTools/ExecuteExtraTool). Per-agent binding still
// decides who actually sees any of them.
//
//nolint:unused // used as the hostTools provider in wireAgentAugment
func (s *Server) hostTools() ([]actool.CoreTool, map[string][]string) {
	tools := append(s.m.HostTools(), s.orchestrationTools()...)
	tools = append(tools, s.findingRetestTools()...)
	tools = append(tools, s.platformTools()...) // 平台操作工具(建改 skill/工具/MCP，给 Auto 用)
	custom, err := s.customTools()
	if err != nil {
		log.Printf("[custom-tool] 加载失败: %v", err)
		return tools, nil
	}
	tools = append(tools, custom...)
	// deferred custom tools → name -> its bound agent keys. ToolAugment turns a
	// name into a deferred entry only for agents it's actually bound to (so we don't
	// advertise a tool the per-agent binding will drop from the callable set).
	deferred := map[string][]string{}
	rows, _ := s.m.pg.ListCustomTools()
	for _, t := range rows {
		if t.Deferred && t.Enabled {
			deferred[t.Key] = t.Agents
		}
	}
	return tools, deferred
}

// orchestrationTools returns the cross-task tool set. Bound per-agent via the
// tools table (default: no binding — opt-in for orchestration agents).
func (s *Server) orchestrationTools() []actool.CoreTool {
	return append([]actool.CoreTool{
		s.toolListTasks(),
		s.toolListLLMProfiles(),
		s.toolSpawnTask(),
		s.toolGetTaskDraft(),
		s.toolUpdateTaskDraft(),
		s.toolAttachTaskCodebase(),
		s.toolCheckTaskMaterials(),
		s.toolStartTask(),
		s.toolGetTaskProfile(),
		s.toolRebuildTaskProfile(),
		s.toolRecordTaskProfileClaim(),
		s.toolGetTaskCoveragePlan(),
		s.toolGenerateTaskCoveragePlan(),
		s.toolPauseTask(),
		s.toolGetTaskGraph(),
		s.toolListTaskFindings(),
		s.toolAddHint(),
		s.toolGetWorkerTrace(),
		s.toolListWorkerTraces(),
		s.toolSearchWorkerTraces(),
		s.toolGetTaskNodeDetail(),
		s.toolUpdateFindingReport(),
		s.toolGetFindingTraffic(),
		s.toolBindFindingTraffic(),
	}, s.findingCaseTools()...)
}

// --- schema helpers ---

func strParam(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

// parseProfileID reads an LLM profile id from a tool arg that may arrive as a JSON
// number (5) or a numeric string ("5"); returns 0 when absent/unparseable.
func parseProfileID(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(str), 10, 64)
		return v
	}
	return 0
}

func objSchema(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		req := make([]any, len(required))
		for i, r := range required {
			req[i] = r
		}
		m["required"] = req
	}
	return m
}

func roTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func wrTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

// delegateToTask resolves the `task_id` in the input, builds a ToolSet bound to
// that task's store, strips task_id, and calls the chosen per-task tool — so the
// cross-task read reuses the exact in-task logic against another task.
func (s *Server) delegateToTask(ctx context.Context, in json.RawMessage, pick func(*agent.ToolSet) actool.CoreTool) (actool.Result, error) {
	var head struct {
		TaskID string `json:"task_id"`
	}
	_ = json.Unmarshal(in, &head)
	if strings.TrimSpace(head.TaskID) == "" {
		return actool.Errorf("task_id 为必填"), nil
	}
	t, ok := s.m.Task(head.TaskID)
	if !ok {
		return actool.Errorf("task 不存在: " + head.TaskID), nil
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(in, &m)
	delete(m, "task_id")
	inner, _ := json.Marshal(m)
	tsx := agent.NewToolSet(t.Store, "orchestrator")
	if as := s.m.assetsForTask(t); as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetNotify(t.Notify)         // 通用唤醒（无专用回调的写操作走它；读工具为 no-op）
	tsx.SetNotifyHint(t.NotifyHint) // add_hint → 记一条「人新增了 N 条战略提示：…」触发并唤醒 planner
	return pick(tsx).Call(ctx, inner, nil)
}

// --- tools ---

func (s *Server) toolListTasks() actool.CoreTool {
	return roTool("list_tasks",
		"列出所有任务(id/描述/目标/状态/运行时长/父任务/LLM 配置)，编排 agent 用它掌握全局、看哪些任务卡太久、各自用哪个 LLM。运行时长只累计实际执行时间，暂停、排队和终态后的时间不计入。llm_profile：任务 planner/worker 用的配置名，(激活配置)=跟随全局激活。",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			// id -> name to resolve each task's pinned LLM profile.
			profName := map[int64]string{}
			if profs, err := s.m.pg.ListProfiles(); err == nil {
				for _, p := range profs {
					profName[p.ID] = p.Name
				}
			}
			out := make([]map[string]any, 0)
			for _, t := range s.m.List() {
				status := s.deriveTaskStatus(t)
				lifecycle := t.lifecycleSnapshot()
				dur := taskRunSeconds(lifecycle.ActiveRunSeconds, lifecycle.RunSegmentStartedAt, time.Now().Unix(), status, lifecycle.Paused, lifecycle.Queued)
				row := map[string]any{
					"id":          t.ID,
					"description": lifecycle.Description,
					"goal":        lifecycle.Goal,
					"status":      status,
					"run_seconds": dur,
				}
				if lifecycle.Name != "" {
					row["name"] = lifecycle.Name
				}
				if lifecycle.AssessmentMode {
					row["assessment_mode"] = true
					row["assessment_phase"] = lifecycle.AssessmentPhase
					row["draft"] = lifecycle.Draft
				}
				if t.ParentRef != "" {
					row["parent_ref"] = t.ParentRef
				}
				llmState := t.llmStateSnapshot()
				if llmState.ProfileID == nil {
					row["llm_profile"] = "(激活配置)"
				} else if n, ok := profName[*llmState.ProfileID]; ok {
					row["llm_profile"] = n
				} else {
					row["llm_profile"] = fmt.Sprintf("#%d(已删除)", *llmState.ProfileID)
				}
				out = append(out, row)
			}
			return jsonResult(out)
		})
}

// toolListLLMProfiles lists the available LLM profiles (name/model/active) so an
// orchestration agent can pick one for spawn_task's llm_profile. Never leaks keys.
func (s *Server) toolListLLMProfiles() actool.CoreTool {
	return roTool("list_llm_profiles",
		"列出可用的 LLM 配置(profile)：id、名称、模型、格式、是否为当前激活配置。用 id 给 spawn_task 的 llm_profile_id 参数指定子任务专属 LLM（如侦察用便宜模型、利用用强模型）。不含 API Key。",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			profs, err := s.m.pg.ListProfiles()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out := make([]map[string]any, 0, len(profs))
			for _, p := range profs {
				out = append(out, map[string]any{
					"id": p.ID, "name": p.Name, "model": p.Model, "format": p.Format, "is_active": p.IsDefault,
				})
			}
			return jsonResult(map[string]any{"profiles": out})
		})
}

func (s *Server) resolveToolProjectID(ctx context.Context, parentRef string, explicitProjectID int64) (int64, error) {
	if ri := agent.RunInfoFrom(ctx); ri.TaskID > 0 {
		if pt, ok := s.m.Task(strconv.FormatInt(ri.TaskID, 10)); ok {
			if explicitProjectID > 0 && explicitProjectID != pt.ProjectID {
				return 0, fmt.Errorf("不能跨项目操作任务")
			}
			return pt.ProjectID, nil
		}
	}
	if ri := agent.RunInfoFrom(ctx); ri.SessionID != "" {
		if convID, err := strconv.ParseInt(ri.SessionID, 10, 64); err == nil && convID > 0 {
			if pid := s.projectOfConversation(convID); pid > 0 {
				if explicitProjectID > 0 && explicitProjectID != pid {
					return 0, fmt.Errorf("不能跨项目操作任务")
				}
				return pid, nil
			}
		}
	}
	if parentRef != "" {
		if pt, ok := s.m.Task(parentRef); ok {
			if explicitProjectID > 0 && explicitProjectID != pt.ProjectID {
				return 0, fmt.Errorf("不能跨项目操作任务")
			}
			return pt.ProjectID, nil
		}
	}
	if explicitProjectID > 0 {
		if p, err := s.m.pg.Projects().Get(explicitProjectID); err == nil && p != nil {
			return p.ID, nil
		}
		return 0, fmt.Errorf("project #%d 不存在", explicitProjectID)
	}
	return 0, fmt.Errorf("无法确定所属项目：请在任务/项目会话上下文中调用或显式传入 project_id")
}

func (s *Server) requireToolTask(ctx context.Context, taskID string) (*Task, error) {
	taskID = strings.TrimSpace(taskID)
	t, ok := s.m.Task(taskID)
	if !ok {
		return nil, fmt.Errorf("task #%s 不存在", taskID)
	}
	if ri := agent.RunInfoFrom(ctx); ri.TaskID > 0 {
		if pt, ok := s.m.Task(strconv.FormatInt(ri.TaskID, 10)); ok && pt.ProjectID != t.ProjectID {
			return nil, fmt.Errorf("无权跨项目访问任务 #%s", taskID)
		}
	} else if ri.SessionID != "" {
		if convID, err := strconv.ParseInt(ri.SessionID, 10, 64); err == nil && convID > 0 {
			if pid := s.projectOfConversation(convID); pid > 0 && pid != t.ProjectID {
				return nil, fmt.Errorf("无权跨项目访问任务 #%s", taskID)
			}
		}
	}
	return t, nil
}

// toolSpawnTask creates either a legacy exploration task or (when assessment_mode=true)
// a persisted whitebox-driven assessment draft via the exact same unified creation flow
// as POST /api/tasks.
func (s *Server) toolSpawnTask() actool.CoreTool {
	return wrTool("spawn_task",
		"新建任务：传统模式(assessment_mode=false, 默认)直接启动目标驱动探索；白盒驱动评估模式(assessment_mode=true)创建持久化草稿(draft=true, goal 可留空)，随后用 attach_task_codebase / update_task_draft / check_task_materials / start_task 完成两阶段检查与显式启动。",
		objSchema(map[string]any{
			"name":                   strParam("可选：任务名称"),
			"description":            strParam("任务描述或业务概况(简短说明)"),
			"goal":                   strParam("传统模式必填目标；当 assessment_mode=true 时可留空"),
			"assessment_mode":        map[string]any{"type": "boolean", "description": "是否启用白盒驱动评估两阶段草稿模式；默认 false。启用后只建草稿，需挂载材料检查并通过 start_task 显式启动"},
			"project_id":             map[string]any{"type": "integer", "description": "可选：所属项目 id（若在任务/项目会话中会自动继承）"},
			"parent_ref":             strParam("可选：父任务 id(做父子关联)"),
			"source_task_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": fmt.Sprintf("可选：只读继承的来源任务 id 列表(最多 %d 个)", db.MaxTaskSourceCount)},
			"company_ids":            map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "可选：关联企业 id 列表"},
			"llm_profile_id":         map[string]any{"type": "integer", "description": "可选：指定本任务用的 LLM 配置 id(见 list_llm_profiles)"},
			"no_result_seconds":      map[string]any{"type": "integer", "description": "可选：累计运行无成果止损阈值(秒)；0=关闭，正数>=60"},
			"no_result_min_findings": map[string]any{"type": "integer", "description": "无成果止损最少独立漏洞数，默认1"},
			"no_result_min_severity": map[string]any{"type": "string", "enum": []string{"", "low", "medium", "high", "critical"}, "description": "计数的最低漏洞等级"},
			"timeout_seconds":        map[string]any{"type": "integer", "description": "可选：任务级超时(秒)；0=不限时"},
			"plan_heartbeat_seconds": map[string]any{"type": "integer", "description": "可选：心跳触发间隔(秒)"},
			"seed_first_intent":      map[string]any{"type": "boolean", "description": "仅传统模式：直接下发首条种子意图"},
			"execution_mode":         map[string]any{"type": "string", "enum": []string{"dynamic", "offline"}, "description": "白盒评估执行模式：dynamic(默认联调)/offline(显式离线审计)"},
			"business_overview":      strParam("白盒评估业务说明"),
			"business_focus":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "白盒评估重点业务/模块关注列表"},
			"environments":           map[string]any{"type": "array", "items": map[string]any{"type": "object"}, "description": "目标环境列表，例如 [{\"name\":\"staging\",\"url\":\"http://127.0.0.1:8080\"}]"},
			"env_access":             map[string]any{"type": "object", "description": "环境接入方式，如 {\"mode\":\"direct\",\"notes\":\"...\"}"},
			"identities":             map[string]any{"type": "array", "items": map[string]any{"type": "object"}, "description": "测试身份参考列表（严禁放明文密码/私钥/token，请只填 role/username/credential_ref/auth_type）"},
			"scope_notes":            strParam("额外测试范围说明"),
			"operation_constraints":  map[string]any{"type": "array", "items": map[string]any{"type": "object"}, "description": "操作约束列表，如 [{\"kind\":\"deny\",\"text\":\"禁止压测\"}]"},
			"source_acknowledged":    map[string]any{"type": "boolean", "description": "是否已确认源码可外发给 LLM（真正启动时必选）"},
			"assessment_config":      map[string]any{"type": "object", "description": "可选：完整结构化 AssessmentConfig 对象"},
		}, "description"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name                 string                          `json:"name"`
				Description          string                          `json:"description"`
				Goal                 string                          `json:"goal"`
				AssessmentMode       bool                            `json:"assessment_mode"`
				ProjectID            int64                           `json:"project_id"`
				ParentRef            string                          `json:"parent_ref"`
				SourceTaskIDs        []string                        `json:"source_task_ids"`
				CompanyIDs           []int64                         `json:"company_ids"`
				LLMProfileID         json.RawMessage                 `json:"llm_profile_id"`
				NoResultSeconds      int                             `json:"no_result_seconds"`
				NoResultMinFindings  int                             `json:"no_result_min_findings"`
				NoResultMinSeverity  string                          `json:"no_result_min_severity"`
				TimeoutSeconds       int                             `json:"timeout_seconds"`
				PlanHeartbeatSeconds int                             `json:"plan_heartbeat_seconds"`
				SeedFirstIntent      bool                            `json:"seed_first_intent"`
				ExecutionMode        string                          `json:"execution_mode"`
				BusinessOverview     string                          `json:"business_overview"`
				BusinessFocus        []string                        `json:"business_focus"`
				Environments         []db.AssessmentEnvironmentInput `json:"environments"`
				EnvAccess            *db.AssessmentEnvAccessInput    `json:"env_access"`
				Identities           []db.AssessmentIdentityInput    `json:"identities"`
				ScopeNotes           string                          `json:"scope_notes"`
				OperationConstraints []db.AssessmentConstraintInput  `json:"operation_constraints"`
				SourceAcknowledged   bool                            `json:"source_acknowledged"`
				AssessmentConfig     *db.AssessmentConfig            `json:"assessment_config"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if !a.AssessmentMode && strings.TrimSpace(a.Goal) == "" {
				return actool.Errorf("goal 为必填（若需无 goal 的白盒驱动评估，请传入 assessment_mode=true）"), nil
			}

			projectID, err := s.resolveToolProjectID(ctx, a.ParentRef, a.ProjectID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}

			var llmIDs []int64
			if id := parseProfileID(a.LLMProfileID); id > 0 {
				llmIDs = []int64{id}
			} else if a.ParentRef != "" {
				if pt, ok := s.m.Task(a.ParentRef); ok && pt.LLMProfileID != nil {
					llmIDs = []int64{*pt.LLMProfileID}
				}
			}

			name := strings.TrimSpace(a.Name)
			if !a.AssessmentMode && name == "" && s.m.pg.GetBool(db.SettingTaskAutoTitle, false) {
				if active, activeErr := s.m.pg.ActiveProfile(); activeErr == nil && active != nil {
					if prov, _, providerOK := s.providerForProfile(active.ID); providerOK {
						titleCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
						defer cancel()
						if generated, titleErr := agent.GenerateAutoTitle(titleCtx, prov, a.Description+"\n"+a.Goal); titleErr == nil {
							name = generated
						}
					}
				}
			}

			var cfg db.AssessmentConfig
			if a.AssessmentConfig != nil {
				cfg = *a.AssessmentConfig
			}
			if a.ExecutionMode != "" {
				cfg.ExecutionMode = a.ExecutionMode
			}
			if a.BusinessOverview != "" {
				cfg.BusinessOverview = a.BusinessOverview
			}
			if len(a.BusinessFocus) > 0 {
				cfg.BusinessFocus = a.BusinessFocus
			}
			if len(a.Environments) > 0 {
				cfg.Environments = a.Environments
			}
			if a.EnvAccess != nil {
				cfg.EnvAccess = a.EnvAccess
			}
			if len(a.Identities) > 0 {
				cfg.Identities = a.Identities
			}
			if a.ScopeNotes != "" {
				cfg.ScopeNotes = a.ScopeNotes
			}
			if len(a.OperationConstraints) > 0 {
				cfg.OperationConstraints = a.OperationConstraints
			}
			if a.SourceAcknowledged {
				cfg.SourceAcknowledged = true
			}

			seedFlag := a.SeedFirstIntent
			req := createTaskReq{
				Name:                 name,
				Description:          a.Description,
				Goal:                 a.Goal,
				LLMProfileIDs:        llmIDs,
				SourceTaskIDs:        a.SourceTaskIDs,
				CompanyIDs:           a.CompanyIDs,
				NoResultSeconds:      a.NoResultSeconds,
				NoResultMinFindings:  a.NoResultMinFindings,
				NoResultMinSeverity:  a.NoResultMinSeverity,
				TimeoutSeconds:       a.TimeoutSeconds,
				PlanHeartbeatSeconds: a.PlanHeartbeatSeconds,
				SeedFirstIntent:      &seedFlag,
				AssessmentMode:       a.AssessmentMode,
				AssessmentConfig:     cfg,
			}
			t, _, err := s.createTaskUnified(projectID, req, a.ParentRef)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if !t.IsDraft() {
				return actool.Text(fmt.Sprintf("task created: %s", t.ID)), nil
			}
			return jsonResult(map[string]any{
				"task_id":          t.ID,
				"draft":            true,
				"assessment_mode":  true,
				"assessment_phase": t.lifecycleSnapshot().AssessmentPhase,
				"task":             taskDTO(t, s.resolvedTaskStatus(t)),
				"next_steps": []string{
					"使用 attach_task_codebase 挂载源码/目录/包（可多次挂载不同服务或仓库）",
					"需要修改配置时使用 update_task_draft",
					"使用 check_task_materials 运行材料检查并确认 ready=true",
					"传入 source_acknowledged=true 调用 start_task 显式启动任务",
				},
			})
		})
}

func (s *Server) toolGetTaskDraft() actool.CoreTool {
	return roTool("get_task_draft",
		"读取草稿或评估任务的结构化配置、已挂载代码库列表与最新材料检查报告，用于恢复草稿配置或核对启动前提。",
		objSchema(map[string]any{
			"task_id": strParam("任务 id"),
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID string `json:"task_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t, err := s.requireToolTask(ctx, a.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			latest, broken, listErr := s.loadTaskLatestCodebases(t.ID)
			if listErr != nil {
				return actool.Errorf(listErr.Error()), nil
			}
			codebases := make([]taskCodebaseVersion, 0, len(latest))
			for _, item := range latest {
				codebases = append(codebases, item.version)
			}
			return jsonResult(map[string]any{
				"task":             taskDTO(t, s.resolvedTaskStatus(t)),
				"codebases":        codebases,
				"broken_manifests": broken,
			})
		})
}

func (s *Server) toolUpdateTaskDraft() actool.CoreTool {
	return wrTool("update_task_draft",
		"修改尚未启动的评估草稿任务（业务说明/重点、execution_mode、目标环境、测试身份、范围说明、操作约束、外发确认等），会自动清空旧的材料检查缓存。",
		objSchema(map[string]any{
			"task_id":               strParam("草稿任务 id"),
			"name":                  strParam("可选：任务名称"),
			"description":           strParam("可选：任务描述"),
			"remark":                strParam("可选：备注"),
			"execution_mode":        map[string]any{"type": "string", "enum": []string{"dynamic", "offline"}, "description": "执行模式：dynamic / offline"},
			"business_overview":     strParam("业务说明"),
			"business_focus":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "业务重点模块列表"},
			"environments":          map[string]any{"type": "array", "items": map[string]any{"type": "object"}, "description": "环境列表"},
			"env_access":            map[string]any{"type": "object", "description": "环境接入信息"},
			"identities":            map[string]any{"type": "array", "items": map[string]any{"type": "object"}, "description": "测试身份参考列表（严禁明文密码/私钥/token）"},
			"scope_notes":           strParam("测试范围说明"),
			"operation_constraints": map[string]any{"type": "array", "items": map[string]any{"type": "object"}, "description": "操作约束列表"},
			"source_acknowledged":   map[string]any{"type": "boolean", "description": "外发源码确认开关"},
			"llm_profile_ids":       map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "可选：任务级 LLM 配置链"},
			"company_ids":           map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "可选：关联企业列表"},
			"source_task_ids":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选：来源任务列表"},
			"worker_count":          map[string]any{"type": "integer", "description": "可选：并发 Worker 数"},
			"timeout_seconds":       map[string]any{"type": "integer", "description": "可选：任务超时秒数"},
			"assessment_config":     map[string]any{"type": "object", "description": "可选：整体覆盖 AssessmentConfig"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID               string                          `json:"task_id"`
				Name                 *string                         `json:"name"`
				Description          *string                         `json:"description"`
				Remark               *string                         `json:"remark"`
				ExecutionMode        *string                         `json:"execution_mode"`
				BusinessOverview     *string                         `json:"business_overview"`
				BusinessFocus        []string                        `json:"business_focus"`
				Environments         []db.AssessmentEnvironmentInput `json:"environments"`
				EnvAccess            *db.AssessmentEnvAccessInput    `json:"env_access"`
				Identities           []db.AssessmentIdentityInput    `json:"identities"`
				ScopeNotes           *string                         `json:"scope_notes"`
				OperationConstraints []db.AssessmentConstraintInput  `json:"operation_constraints"`
				SourceAcknowledged   *bool                           `json:"source_acknowledged"`
				LLMProfileIDs        *[]int64                        `json:"llm_profile_ids"`
				CompanyIDs           *[]int64                        `json:"company_ids"`
				SourceTaskIDs        *[]string                       `json:"source_task_ids"`
				WorkerCount          *int                            `json:"worker_count"`
				TimeoutSeconds       *int                            `json:"timeout_seconds"`
				AssessmentConfig     *db.AssessmentConfig            `json:"assessment_config"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			t, err := s.requireToolTask(ctx, a.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var rawKeys map[string]json.RawMessage
			_ = json.Unmarshal(in, &rawKeys)

			cfg := t.lifecycleSnapshot().AssessmentConfig
			cfgTouched := false
			if a.AssessmentConfig != nil {
				cfg = *a.AssessmentConfig
				cfgTouched = true
			}
			if a.ExecutionMode != nil {
				cfg.ExecutionMode = *a.ExecutionMode
				cfgTouched = true
			}
			if a.BusinessOverview != nil {
				cfg.BusinessOverview = *a.BusinessOverview
				cfgTouched = true
			}
			if _, ok := rawKeys["business_focus"]; ok {
				cfg.BusinessFocus = a.BusinessFocus
				cfgTouched = true
			}
			if _, ok := rawKeys["environments"]; ok {
				cfg.Environments = a.Environments
				cfgTouched = true
			}
			if _, ok := rawKeys["env_access"]; ok {
				cfg.EnvAccess = a.EnvAccess
				cfgTouched = true
			}
			if _, ok := rawKeys["identities"]; ok {
				cfg.Identities = a.Identities
				cfgTouched = true
			}
			if a.ScopeNotes != nil {
				cfg.ScopeNotes = *a.ScopeNotes
				cfgTouched = true
			}
			if _, ok := rawKeys["operation_constraints"]; ok {
				cfg.OperationConstraints = a.OperationConstraints
				cfgTouched = true
			}
			if a.SourceAcknowledged != nil {
				cfg.SourceAcknowledged = *a.SourceAcknowledged
				cfgTouched = true
			}

			req := updateTaskDraftReq{
				Name:           a.Name,
				Remark:         a.Remark,
				Description:    a.Description,
				LLMProfileIDs:  a.LLMProfileIDs,
				CompanyIDs:     a.CompanyIDs,
				SourceTaskIDs:  a.SourceTaskIDs,
				WorkerCount:    a.WorkerCount,
				TimeoutSeconds: a.TimeoutSeconds,
			}
			if cfgTouched {
				req.AssessmentConfig = &cfg
			}
			updated, _, err := s.updateTaskDraftUnified(t.ID, req)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"task": taskDTO(updated, s.resolvedTaskStatus(updated)),
			})
		})
}

func (s *Server) toolAttachTaskCodebase() actool.CoreTool {
	return wrTool("attach_task_codebase",
		"给评估任务挂载本地源码目录、源码压缩包(ZIP/TAR/TGZ)或软件包(JAR/WAR/CLASS)，与网页上传代码库走完全一致的落盘快照、发现与材料校验流程。",
		objSchema(map[string]any{
			"task_id":     strParam("目标任务 id"),
			"path":        strParam("本地文件或目录路径"),
			"kind":        map[string]any{"type": "string", "enum": []string{"", "directory", "source_archive", "artifact"}, "description": "可选：类型提示；留空自动按路径判断"},
			"codebase_id": strParam("可选：32位十六进制 codebase_id，传入则作为该代码库的新版本"),
		}, "task_id", "path"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID     string `json:"task_id"`
				Path       string `json:"path"`
				Kind       string `json:"kind"`
				CodebaseID string `json:"codebase_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t, err := s.requireToolTask(ctx, a.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if !t.AssessmentMode {
				return actool.Errorf(db.ErrTaskNotAssessmentMode.Error()), nil
			}
			ver, discoveryStatus, err := s.saveTaskCodebaseVersionFromPath(t.ID, a.Path, a.Kind, a.CodebaseID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"version":          ver,
				"discovery_status": discoveryStatus,
			})
		})
}

func (s *Server) toolCheckTaskMaterials() actool.CoreTool {
	return wrTool("check_task_materials",
		"对白盒评估草稿任务执行启动前材料检查（代码可解包/文本真实性/JavaCodeDB/运行环境或离线模式/LLM 状态/缺口提示），返回结构化 MaterialCheckReport。",
		objSchema(map[string]any{
			"task_id": strParam("草稿任务 id"),
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID string `json:"task_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t, err := s.requireToolTask(ctx, a.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			updated, report, _, err := s.runTaskMaterialCheck(t.ID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"ready":  report.Ready,
				"report": report,
				"task":   taskDTO(updated, s.resolvedTaskStatus(updated)),
			})
		})
}

func (s *Server) toolStartTask() actool.CoreTool {
	return wrTool("start_task",
		"显式启动白盒评估草稿任务：重新核验材料检查全部通过且 source_acknowledged=true 后解除 draft 锁，开启第 1 轮评估并进入 profiling 阶段，不会启动旧的发散目标分解。",
		objSchema(map[string]any{
			"task_id":             strParam("草稿任务 id"),
			"source_acknowledged": map[string]any{"type": "boolean", "description": "是否确认允许将源码发送至所选 LLM（必须为 true，或已在草稿配置中确认）"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID             string `json:"task_id"`
				SourceAcknowledged bool   `json:"source_acknowledged"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t, err := s.requireToolTask(ctx, a.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			started, round, report, _, err := s.startAssessmentTaskUnified(t.ID, a.SourceAcknowledged)
			if err != nil {
				return jsonResult(map[string]any{
					"started": false,
					"error":   err.Error(),
					"report":  report,
				})
			}
			return jsonResult(map[string]any{
				"started": true,
				"task":    taskDTO(started, s.resolvedTaskStatus(started)),
				"round":   round,
				"report":  report,
			})
		})
}

func (s *Server) toolGetTaskProfile() actool.CoreTool {
	return roTool("get_task_profile",
		"读取白盒评估任务当前轮次的靶向画像切片（代码清单、共享库、入口、实例、断言、冲突、未知项与待对账缺口，附带 profile_version）。",
		objSchema(map[string]any{
			"task_id":     strParam("评估任务 id"),
			"subjects":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选：按目标 subject（如 service:order-service、instance:staging）筛选靶向切片"},
			"entity_type": strParam("可选：按实体类型筛选（service/shared_library/module/entry/config/instance/identity/business_object/protocol）"),
			"gap_only":    map[string]any{"type": "boolean", "description": "可选：仅查看清单缺口"},
			"status":      strParam("可选：按断言状态筛选（conflicted/unknown/unverified/confirmed）"),
			"source_type": strParam("可选：按断言来源筛选（static_extraction/user_declared/runtime_observation/model_inference）"),
			"limit":       map[string]any{"type": "integer", "description": "可选：返回数量上限（默认 100）"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID     string   `json:"task_id"`
				Subjects   []string `json:"subjects"`
				EntityType string   `json:"entity_type"`
				GapOnly    bool     `json:"gap_only"`
				Status     string   `json:"status"`
				SourceType string   `json:"source_type"`
				Limit      int      `json:"limit"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t, err := s.requireToolTask(ctx, a.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if !t.AssessmentMode {
				return actool.Errorf(db.ErrTaskNotAssessmentMode.Error()), nil
			}
			taskNum, err := parseTaskID(t.ID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(a.Subjects) > 0 && a.EntityType == "" && !a.GapOnly && a.Status == "" && a.SourceType == "" {
				round, rErr := s.m.pg.LatestAssessmentRound(taskNum)
				if rErr != nil {
					return actool.Errorf(rErr.Error()), nil
				}
				if round == nil {
					return actool.Errorf("任务尚未开启评估轮次"), nil
				}
				slice, sErr := s.m.pg.QueryProfileContext(taskNum, round.ID, a.Subjects, a.Limit)
				if sErr != nil {
					return actool.Errorf(sErr.Error()), nil
				}
				return jsonResult(slice)
			}
			resp, _, bErr := s.buildAssessmentProfileResponse(t, 0,
				db.TargetEntityFilter{EntityType: strings.TrimSpace(a.EntityType), GapOnly: a.GapOnly, Limit: a.Limit},
				db.ProfileClaimFilter{ConfirmationStatus: strings.TrimSpace(a.Status), SourceType: strings.TrimSpace(a.SourceType), Limit: a.Limit},
			)
			if bErr != nil {
				return actool.Errorf(bErr.Error()), nil
			}
			return jsonResult(resp)
		})
}

func (s *Server) toolRebuildTaskProfile() actool.CoreTool {
	return wrTool("rebuild_task_profile",
		"在已启动的白盒评估任务上重新运行确定性代码清单清点、结构提取、部署映射与画像版本递增。",
		objSchema(map[string]any{
			"task_id":      strParam("已启动的评估任务 id"),
			"enable_agent": map[string]any{"type": "boolean", "description": "可选：是否补充模型关联推断（默认 false）"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID      string `json:"task_id"`
				EnableAgent bool   `json:"enable_agent"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t, err := s.requireToolTask(ctx, a.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			resp, _, bErr := s.BuildAssessmentInitialProfile(ctx, t.ID, BuildProfileOptions{EnableAgent: a.EnableAgent})
			if bErr != nil {
				return actool.Errorf(bErr.Error()), nil
			}
			return jsonResult(resp)
		})
}

func (s *Server) toolRecordTaskProfileClaim() actool.CoreTool {
	return wrTool("record_task_profile_claim",
		"为已启动的白盒评估任务登记带证据引用的画像断言（仅允许 model_inference 或 user_declared；严禁明文秘钥，严禁将 model_inference 标为 confirmed 或冒充 runtime_observation）。",
		objSchema(map[string]any{
			"task_id":             strParam("评估任务 id"),
			"subject":             strParam("主体，如 service:order-service、entry:HTTP GET /api/orders、instance:staging"),
			"relation":            strParam("关系/属性，如 auth_mechanism、auth_required、depends_on、deployed_to_instance"),
			"object_value":        strParam("客体或属性值（严禁包含明文密码/Token/私钥）"),
			"source_type":         map[string]any{"type": "string", "enum": []string{"model_inference", "user_declared"}, "description": "来源类型：仅允许 model_inference（默认）或 user_declared"},
			"confirmation_status": map[string]any{"type": "string", "enum": []string{"unverified", "unknown"}, "description": "确认状态：unverified（默认）或 unknown；推断不能标为 confirmed"},
			"evidence_ref_id":     map[string]any{"type": "integer", "description": "已有 task_evidence_refs ID（与 evidence_kind/evidence_reference 二选一）"},
			"evidence_kind":       map[string]any{"type": "string", "enum": []string{"code_range", "decompiled", "config", "manual"}, "description": "新建证据引用类型"},
			"evidence_reference":  strParam("新建证据引用位置，如 OrderController.java:42"),
			"valid_code_version":  strParam("可选：适用代码版本"),
			"environment":         strParam("可选：适用环境"),
			"valid_config":        strParam("可选：适用配置文件"),
			"conflict_note":       strParam("可选：不确定性或冲突说明"),
		}, "task_id", "subject", "relation", "object_value"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID             string `json:"task_id"`
				Subject            string `json:"subject"`
				Relation           string `json:"relation"`
				ObjectValue        string `json:"object_value"`
				SourceType         string `json:"source_type"`
				ConfirmationStatus string `json:"confirmation_status"`
				EvidenceRefID      *int64 `json:"evidence_ref_id"`
				EvidenceKind       string `json:"evidence_kind"`
				EvidenceReference  string `json:"evidence_reference"`
				ValidCodeVersion   string `json:"valid_code_version"`
				Environment        string `json:"environment"`
				ValidConfig        string `json:"valid_config"`
				ConflictNote       string `json:"conflict_note"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			t, err := s.requireToolTask(ctx, a.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if !t.AssessmentMode {
				return actool.Errorf(db.ErrTaskNotAssessmentMode.Error()), nil
			}
			if t.IsDraft() {
				return actool.Errorf("草稿任务尚未启动，不能写入画像断言"), nil
			}
			taskNum, err := parseTaskID(t.ID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			round, err := s.m.pg.OpenAssessmentRound(taskNum)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if round == nil {
				return actool.Errorf("没有进行中的评估轮次"), nil
			}

			src := strings.TrimSpace(a.SourceType)
			if src == "" {
				src = db.ClaimSourceModelInference
			}
			if src != db.ClaimSourceModelInference && src != db.ClaimSourceUserDeclared {
				return actool.Errorf(fmt.Sprintf("Agent 工具仅允许写入 model_inference 或 user_declared 断言，禁止冒充 %q", src)), nil
			}
			status := strings.TrimSpace(a.ConfirmationStatus)
			if status == "" {
				status = db.ClaimStatusUnverified
			}
			if status == db.ClaimStatusConfirmed && src == db.ClaimSourceModelInference {
				return actool.Errorf(db.ErrInferenceCannotClaimConfirmed.Error()), nil
			}

			evID := a.EvidenceRefID
			if evID == nil {
				if strings.TrimSpace(a.EvidenceKind) == "" || strings.TrimSpace(a.EvidenceReference) == "" {
					return actool.Errorf("必须提供有效的 evidence_ref_id 或 (evidence_kind + evidence_reference)"), nil
				}
				switch db.EvidenceRefKind(strings.TrimSpace(a.EvidenceKind)) {
				case db.EvidenceCodeRange, db.EvidenceDecompiled, db.EvidenceConfig, db.EvidenceManual:
				default:
					return actool.Errorf(fmt.Sprintf("Agent 画像断言不允许伪造 %q 类型运行证据", a.EvidenceKind)), nil
				}
				id, evErr := s.m.pg.GetOrCreateEvidenceRef(taskNum, db.EvidenceRefKind(strings.TrimSpace(a.EvidenceKind)), a.EvidenceReference, nil)
				if evErr != nil {
					return actool.Errorf(evErr.Error()), nil
				}
				evID = &id
			}

			claim, created, cErr := s.m.pg.CreateProfileClaim(db.CreateProfileClaimInput{
				TaskID:             taskNum,
				RoundID:            &round.ID,
				Subject:            a.Subject,
				Relation:           a.Relation,
				ObjectValue:        a.ObjectValue,
				SourceType:         src,
				EvidenceRefID:      evID,
				ValidCodeVersion:   a.ValidCodeVersion,
				Environment:        a.Environment,
				ValidConfig:        a.ValidConfig,
				ConfirmationStatus: status,
				ConflictNote:       a.ConflictNote,
				ExecutionRef:       "agent-tool:record_task_profile_claim",
			})
			if cErr != nil {
				return actool.Errorf(cErr.Error()), nil
			}
			return jsonResult(map[string]any{"claim": claim, "created": created})
		})
}

func (s *Server) toolPauseTask() actool.CoreTool {
	return wrTool("pause_task", "暂停指定任务(停止其 planner/worker 循环)。",
		objSchema(map[string]any{"task_id": strParam("要暂停的任务 id")}, "task_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID string `json:"task_id"`
			}
			_ = json.Unmarshal(in, &a)
			t, ok := s.m.Task(a.TaskID)
			if !ok {
				return actool.Errorf("task 不存在: " + a.TaskID), nil
			}
			if _, err := s.applyTaskControlWithCause(t, "pause", agent.AbortPausedByOrchestrator); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("task paused: " + a.TaskID), nil
		})
}

func (s *Server) toolGetTaskGraph() actool.CoreTool {
	return roTool("get_task_graph", "读指定任务的探索图总览(同 graph_overview：资产计数/frontier/发现/覆盖等)，用 task_id 指定任务。",
		objSchema(map[string]any{"task_id": strParam("任务 id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GraphOverviewTool)
		})
}

func (s *Server) toolListTaskFindings() actool.CoreTool {
	return roTool("list_task_findings", "读指定任务的确认漏洞(含 flag/PoC；每条带 id/task_id/intent_id/vulnclass/severity/摘要/状态)，用 task_id 指定任务。",
		objSchema(map[string]any{"task_id": strParam("任务 id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListFindingsTool)
		})
}

func (s *Server) toolAddHint() actool.CoreTool {
	return wrTool("add_task_hint", "给指定任务注入战略提示(该任务的 planner 下轮生成意图时会读到)。\n"+
		"★优先批量：多条提示放进 hints 数组一次提交（返回 ids 数组，与 hints 等长同序，失败项 id=0）；单条则省略 hints 直接给顶层 text。",
		objSchema(map[string]any{
			"task_id":      strParam("任务 id"),
			"hints":        map[string]any{"type": "array", "description": "【优先用这个】提示数组，每个元素字段同顶层（text/asset_ids/traffic_refs）。", "items": objSchema(map[string]any{"text": strParam("提示内容"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "traffic_refs": agent.HintTrafficSchema()})},
			"text":         strParam("[单条] 提示内容"),
			"traffic_refs": agent.HintTrafficSchema(),
			"asset_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "锚定的资产 id（可选，0/1/多个；该任务内的资产 id）"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).AddHintTool)
		})
}

func (s *Server) toolGetWorkerTrace() actool.CoreTool {
	return roTool("get_task_worker_trace",
		"看指定任务里某个 work(意图)的执行过程：get_task_worker_trace(task_id, intent_id) 看步骤摘要；再带 step_ids=[...] 取那几步完整内容(一次最多 5 个,多传只返回前 5 个)。",
		objSchema(map[string]any{
			"task_id":   strParam("任务 id"),
			"intent_id": map[string]any{"type": "integer", "description": "意图 id(该任务里的 work)"},
			"step_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "可选：要取完整内容的步骤 id(一次最多 5 个,多传只返回前 5 个,其余在 omitted_step_ids 里列出)"},
		}, "task_id", "intent_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GetWorkerTraceTool)
		})
}

func (s *Server) toolListWorkerTraces() actool.CoreTool {
	return roTool("list_task_worker_traces", "列出指定任务里跑过哪些 work(意图) + 各自步数，用于发现哪些 work 值得翻看(再用 get_task_worker_trace)。",
		objSchema(map[string]any{"task_id": strParam("任务 id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListWorkerTracesTool)
		})
}

func (s *Server) toolSearchWorkerTraces() actool.CoreTool {
	return roTool("search_task_worker_traces", "在指定任务里按关键字搜索所有 work 的执行过程(返回命中步骤摘要 + intent_id)。",
		objSchema(map[string]any{"task_id": strParam("任务 id"), "q": strParam("搜索关键字")}, "task_id", "q"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).SearchWorkerTracesTool)
		})
}

func (s *Server) toolGetTaskNodeDetail() actool.CoreTool {
	return roTool("get_task_node_detail",
		"读指定任务里某个探索图节点的完整内容(发现/事实/意图/目标：摘要 + 详情/证据/PoC)。id 为探索节点 id(如 report_finding 返回、或 list_task_findings 里的 id)。写漏洞报告前用它取该漏洞的完整证据。",
		objSchema(map[string]any{
			"task_id": strParam("任务 id"),
			"id":      map[string]any{"type": "integer", "description": "探索图节点 id(非资产 id)"},
		}, "task_id", "id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).NodeDetailTool)
		})
}

// toolUpdateFindingReport writes/overwrites a finding's detailed Markdown report.
// finding_id is the id report_finding returned ("finding recorded: <id>", the
// finding node id). The write (SetFindingReportByNodeID) is keyed by node_id and
// task-agnostic, so this host tool needs no task_id / exploration store.
func (s *Server) toolUpdateFindingReport() actool.CoreTool {
	return wrTool("update_finding_report",
		"为已登记的漏洞写入/更新【详细报告】(Markdown 全文,整段覆盖旧内容)。finding_id 传 report_finding 返回的那个 id(\"finding recorded: <id>\" 里的数字)。报告建议包含:漏洞概述、影响与危害、复现步骤、证据/PoC、修复建议。",
		objSchema(map[string]any{
			"finding_id":       map[string]any{"type": "integer", "description": "目标漏洞 id(report_finding 返回的 id)"},
			"report":           strParam("详细报告全文,Markdown 格式"),
			"evidence_version": map[string]any{"type": "integer", "description": "get_finding_traffic 返回的证据 version；用于防止报告覆盖新的证据变更"},
		}, "finding_id", "report"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				EvidenceVersion *int64          `json:"evidence_version"`
				FindingID       json.RawMessage `json:"finding_id"`
				Report          string          `json:"report"`
			}
			_ = json.Unmarshal(in, &a)
			nodeID := parseProfileID(a.FindingID) // 复用「数字或数字字符串」解析
			if nodeID <= 0 {
				return actool.Errorf("finding_id 无效"), nil
			}
			fid, err := s.m.pg.FindingIDByNodeID(nodeID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if fid > 0 {
				if err := s.checkCaseReviewScope(ctx, "update_finding_report", findingCaseRequest{FindingID: json.RawMessage(i64s(fid))}); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if f, err := s.m.pg.GetFinding(fid); err == nil && f != nil && f.TaskID != nil {
					if err := s.archiveFindingScreenshots(*f.TaskID, a.Report); err != nil {
						return actool.Errorf("归档报告截图失败: " + err.Error()), nil
					}
				}
				if conversationID := intercept.ConvIDFromContext(ctx); conversationID > 0 {
					if err := s.m.pg.SetFindingReportConversationID(fid, conversationID); err != nil {
						return actool.Errorf("关联报告对话失败: " + err.Error()), nil
					}
				}
			}
			n, err := s.m.pg.SetFindingReportVersionByNodeID(ctx, nodeID, a.Report, a.EvidenceVersion)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if n == 0 {
				return actool.Errorf(fmt.Sprintf("未找到 finding_id=%d 对应的漏洞记录(先用 report_finding 登记)", nodeID)), nil
			}
			return actool.Text(fmt.Sprintf("finding %d report updated (%d chars)", nodeID, len(a.Report))), nil
		})
}

// deriveTaskStatus mirrors listTasks' status derivation for the list_tasks tool.
func (s *Server) deriveTaskStatus(t *Task) string {
	lifecycle := t.lifecycleSnapshot()
	switch {
	case isTerminalStatus(lifecycle.Status):
		return lifecycle.Status
	case lifecycle.Paused || s.engine.IsPaused(t.ID):
		return "paused"
	case s.engine.ReadyFor(t) && s.engine.Started(t.ID):
		return "running"
	}
	return "created"
}

// orchestrationToolSeeds seeds the cross-task tools into the tools table so they
// are bindable per-agent (default: bound to nobody — opt-in for orchestration
// agents). First-insert only, like the traffic seeds.
func (s *Server) seedOrchestrationTools() {
	// task-op + platform tools default-bind to the built-in Auto agent (它天生用来
	// 操作平台)。SeedTool 首插入生效;老库已 seed 的行由 seedAutoDefaultBindings 补绑。
	autoAgents, _ := json.Marshal([]string{"auto"})
	for _, t := range s.orchestrationTools() {
		schema, _ := json.Marshal(t.InputSchema())
		bindings := autoAgents
		if t.Name() == "bind_finding_traffic" || strings.Contains(t.Name(), "finding_case") || t.Name() == "search_finding_duplicates" || t.Name() == "get_finding_record" || t.Name() == "merge_finding_records" || t.Name() == "suggest_finding_merge" {
			bindings = json.RawMessage(`["reporter"]`)
		}
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, bindings)
	}
	for _, t := range s.platformTools() {
		schema, _ := json.Marshal(t.InputSchema())
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, autoAgents)
	}
	s.refreshBuiltinToolSchemas()
	s.seedAutoDefaultBindings()
	s.seedPlannerDefaultBindings()
	s.seedPlannerListAssetsBinding()
	s.seedCompanyScopeRebind()
	s.seedWorkerReadToolsUnbind() // list_facts/list_companies/list_worker_traces 从 worker 默认解绑(一次性)
	s.seedWorkerReadbackRebind()  // 修复旧迁移误删：把 search_all_worker_traces/get_worker_trace/node_detail 补绑回 worker(一次性)
	s.seedAutoReportFindingBinding()
	s.unbindGoalMetDefault()
	s.reseedGoalsPrompt()             // goals 提示词加入「抽操作约束」步 → 旧库追加一版新默认(一次性)
	s.reseedMainAgentPrompt()         // mainagent 提示词加入「目标达成后 add_intent 反问是否建目标」(一次性)
	s.reseedPlannerPrompt()           // planner 提示词:重写「0 意图」正当理由 + 加量化验收核对(一次性)
	s.reseedWorkerPrompt()            // worker 提示词:加否定结论证据门槛(一次性)
	s.seedReporterAgent()             // 预置「报告撰写」agent + 工具绑定 + finding 触发器(一次性)
	s.upgradeReporterTriggerMessage() // 老库补迁移:让 reporter 回传 evidence_version(一次性)
	s.migrateReporterWorkflow()       // 修复旧库残留的 reproduction 工具/提示词绑定
	s.migrateReporterWhiteboxPrompt() // 为既有 reporter 提示词追加静态白盒报告规则
	if s.m.pg.GetBool(settingBrowserScreenshot, false) {
		// Re-apply the opt-in after startup seeding so an existing database gets
		// both reporter visibility and the repaired Playwright launch arguments.
		if err := s.setReporterBrowserScreenshotVisibility(true); err != nil {
			log.Printf("[reporter] 截图 MCP 启动配置同步失败: %v", err)
		}
	}
	s.seedFindingTrafficTools() // 增加可选证据参数及只读证据工具，保留用户配置
	s.seedFindingWorkflowTools()
	s.seedFindingCaseTools()
	// 注：pentest 的默认工具绑定无需迁移——BuiltinToolSeeds 在全新初始化时就把
	// list_assets/insert_assets/report_finding/list_findings/list_companies 连同
	// pentest 一起 seed 好了（项目尚无旧库，不做迁移）。
}

// migrateReporterWhiteboxPrompt adds the static-audit-specific reporting rules
// to an existing reporter prompt without replacing administrator-authored text.
func (s *Server) migrateReporterWhiteboxPrompt() {
	reporter, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil || reporter == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(reporter.ID)
	if err != nil {
		log.Printf("[reporter] 读取提示词失败，未追加白盒审计规则: %v", err)
		return
	}
	if strings.Contains(current, "【Java 白盒静态审计报告规则】") {
		return
	}
	updated := strings.TrimSpace(current) + agent.ReporterWhiteboxAuditPolicy
	if _, err := s.m.pg.ResetPromptToDefault(reporter.ID, updated); err != nil {
		log.Printf("[reporter] 追加白盒静态审计规则失败: %v", err)
		return
	}
	log.Printf("[reporter] 已为既有提示词追加 Java 白盒静态审计报告规则")
}

// migrateReporterWorkflow repairs databases created by the short-lived
// structured-reproduction reporter. That workflow referenced
// update_finding_reproduction, which is no longer a runtime tool; leaving the
// old prompt/trigger in place makes a newly reported vulnerability fail after
// all evidence has already been collected. User-authored reporter prompts are
// preserved unless they contain the removed tool contract.
func (s *Server) migrateReporterWorkflow() {
	const flag = "reporter_workflow_markdown_v2"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()

	reporter, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil || reporter == nil {
		return
	}
	if current, err := s.m.pg.CurrentPrompt(reporter.ID); err == nil &&
		(strings.Contains(current, "update_finding_reproduction") || strings.Contains(current, "漏洞步骤编写 agent")) {
		if _, err := s.m.pg.ResetPromptToDefault(reporter.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 旧版提示词迁移失败: %v", err)
		} else {
			log.Printf("[reporter] 已将旧版复现步骤提示词迁移为 Markdown 报告流程")
		}
	}

	// 只补齐当前报告流程需要的绑定，不覆盖管理员已有的其它配置。
	_ = s.m.pg.AddAgentToToolBinding("reporter", []string{
		"update_finding_report", "get_finding_traffic", "bind_finding_traffic",
		"get_task_node_detail", "list_task_findings", "get_task_worker_trace",
		"list_task_worker_traces", "search_task_worker_traces", "get_task_graph",
	})
	// 旧行保留在工具目录里供历史审计，但不能继续被运行时广告或调用。
	if _, err := s.m.pg.Exec(`UPDATE tools SET enabled=false, updated_at=now() WHERE key='update_finding_reproduction' AND system`); err != nil {
		log.Printf("[reporter] 旧 reproduction 工具停用失败: %v", err)
	}

	triggers, err := s.m.pg.ListTriggersFor("reporter")
	if err != nil {
		log.Printf("[reporter] 读取触发器失败: %v", err)
		return
	}
	for _, t := range triggers {
		if !t.OnToolCall || !strings.Contains(t.ToolCallMessage, "update_finding_reproduction") {
			continue
		}
		t.ToolCallMessage = reporterToolCallMessage
		if err := s.m.pg.UpdateTrigger(t); err != nil {
			log.Printf("[reporter] 旧触发器迁移失败: %v", err)
			continue
		}
		log.Printf("[reporter] 已将旧 reproduction 触发器迁移为报告保存流程")
	}
}

// refreshBuiltinToolSchemas propagates code schema/description changes on the
// orchestration + platform tools into already-seeded rows ONCE per version flag —
// SeedTool is first-insert-only, so a new param (e.g. spawn_task 的 llm_profile) never
// reaches an old DB otherwise. Preserves each tool's agent binding + enabled flag.
// Bump the flag whenever these tools' schemas/descriptions change in code.
func (s *Server) refreshBuiltinToolSchemas() {
	const flag = "tool_schema_refresh_v9_assessment_step2"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	tools := append(s.orchestrationTools(), s.platformTools()...)
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema); err != nil {
			log.Printf("[tools] refresh %s schema failed: %v", t.Name(), err)
		}
	}
	// 同时把部分内置 agent 工具刷成代码默认：
	//   - goal_met：旧库 seed 的描述带“结束本轮规划”的误导，会让 planner 把它当成
	//     “结束空轮”的手段、刚开跑就误判整个任务完成。
	//   - insert_assets：新增 related 入参(标记资产是否与当前任务相关、决定是否入覆盖度)，
	//     SeedTool 首插入only，旧库已 seed 的 schema 否则收不到这个新参数。
	//   - list_facts：改为分页，新增 limit/before/q 入参；旧库已 seed 的空 schema 否则
	//     在工具管理页显示「无参数」，模型也拿不到这几个参数说明。
	refreshBuiltin := map[string]bool{"goal_met": true, "insert_assets": true, "list_facts": true}
	for _, sd := range agent.BuiltinToolSeeds() {
		if !refreshBuiltin[sd.Key] {
			continue
		}
		schema, _ := json.Marshal(sd.Schema)
		if err := s.m.pg.RefreshToolDefaults(sd.Key, sd.Desc, schema); err != nil {
			log.Printf("[tools] refresh %s desc failed: %v", sd.Key, err)
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
	log.Printf("[tools] 已刷新 orchestration/platform 工具 schema 到代码默认(一次性)")
}

// unbindGoalMetDefault removes goal_met's default "planner" binding ONCE (guarded by
// a settings flag), so existing DBs match the new default of NO agent. goal_met bypasses
// per-goal prove_goal to declare the whole task done — powerful/risky and redundant with
// the prove_goal→auto-complete path — so it ships unbound; users can re-bind it per agent
// in the UI. A user's own binding to another agent is untouched (we only strip planner).
func (s *Server) unbindGoalMetDefault() {
	const flag = "goal_met_unbind_default_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.RemoveAgentFromTool("planner", "goal_met"); err != nil {
		log.Printf("[tools] goal_met 解绑 planner 失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// reseedGoalsPrompt 把 goals 目标拆解器的提示词刷成【当前代码默认】——因为默认正文新增了
// 「先抽操作约束(set_constraints)再拆目标」这一步,而 SeedPromptIfEmpty 首插入only,旧库
// 已有的 version 1 收不到这步。这里用版本管理【追加一个新版本】并切过去(ResetPromptToDefault),
// 旧的版本仍保留在历史里,用户若自定义过可从版本记录找回。settings flag 守卫 → 只做一次;
// 以后默认再变就 bump 这个 flag。全新库无需处理(SeedPromptIfEmpty 已 seed 最新默认)。
func (s *Server) reseedGoalsPrompt() {
	const flag = "goals_prompt_constraint_step_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次
	a, err := s.m.pg.GetAgentByKey("goals")
	if err != nil || a == nil {
		return // 全新库尚未建 agent 行时,seedPrompts 会直接 seed 最新默认,无需此迁移
	}
	tmpl := agent.BuiltinPromptSeeds()["goals"]
	if tmpl == "" {
		return
	}
	// 全新库 seedPrompts 已 seed 最新默认 → 当前版本已等于代码默认,不必再追加重复版本。
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] goals 提示词重刷为新默认失败: %v", err)
		return
	}
	log.Printf("[prompts] goals 提示词已追加新默认版本(加入抽操作约束步,一次性)")
}

// reseedMainAgentPrompt 把 mainagent 提示词刷成【当前代码默认】——默认正文新增了「目标全部
// 达成后 add_intent 直投意图时,反问人是否登记为正式目标」这段引导,而 SeedPromptIfEmpty 首插入
// only,旧库已有版本收不到。用版本管理【追加一个新版本】并切过去(ResetPromptToDefault),旧版本仍
// 保留在历史里,用户若自定义过可从版本记录找回。settings flag 守卫 → 只做一次。全新库无需处理
// (SeedPromptIfEmpty 已 seed 最新默认)。与 reseedGoalsPrompt 完全同构。
func (s *Server) reseedMainAgentPrompt() {
	const flag = "mainagent_prompt_goalless_intent_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次
	a, err := s.m.pg.GetAgentByKey("mainagent")
	if err != nil || a == nil {
		return // 全新库尚未建 agent 行时,seedPrompts 会直接 seed 最新默认,无需此迁移
	}
	tmpl := agent.BuiltinPromptSeeds()["mainagent"]
	if tmpl == "" {
		return
	}
	// 全新库 seedPrompts 已 seed 最新默认 → 当前版本已等于代码默认,不必再追加重复版本。
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] mainagent 提示词重刷为新默认失败: %v", err)
		return
	}
	log.Printf("[prompts] mainagent 提示词已追加新默认版本(加入目标达成后反问建目标,一次性)")
}

// reseedPlannerPrompt 把 planner 提示词刷成【当前代码默认】——默认正文做了精简重构,并把「克制」降级为
// 仅去重、新增「深度优先于覆盖度」「硬底线:目标未达成且无在跑意图必须产出」、给否定结论复核加上界。
// 每次默认有实质变更就 bump 下面的 flag(当前 v2)让存量旧库再刷一次。SeedPromptIfEmpty 首插入only,旧库已有版本收不到,故用版本管理
// 【追加一个新版本】并切过去(ResetPromptToDefault),旧版本仍保留在历史里,用户若自定义过可从版本记录
// 找回。settings flag 守卫 → 只做一次。全新库无需处理(SeedPromptIfEmpty 已 seed 最新默认)。与
// reseedGoalsPrompt 完全同构。
func (s *Server) reseedPlannerPrompt() {
	const flag = "planner_prompt_compact_realistic_v2"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次
	a, err := s.m.pg.GetAgentByKey("planner")
	if err != nil || a == nil {
		return // 全新库尚未建 agent 行时,seedPrompts 会直接 seed 最新默认,无需此迁移
	}
	tmpl := agent.BuiltinPromptSeeds()["planner"]
	if tmpl == "" {
		return
	}
	// 全新库 seedPrompts 已 seed 最新默认 → 当前版本已等于代码默认,不必再追加重复版本。
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] planner 提示词重刷为新默认失败: %v", err)
		return
	}
	log.Printf("[prompts] planner 提示词已追加新默认版本(精简重构+克制降级去重+深度优先+否定复核上界,一次性)")
}

// reseedWorkerPrompt 把 worker 提示词刷成【当前代码默认】——默认正文 record_fact 段删掉了「否定类结论
// 写观察+试探性读法」整句、并把 confidence(observed/inferred)与「是否穷尽本意图手段」解耦(这些易误导规划者),
// 同时把 facts 数组分条收紧为「彼此完全独立、无法归并」的极少数例外。bump flag 至 v3 让存量旧库再刷一次。
// SeedPromptIfEmpty 首插入only,旧库已有版本收不到,故用版本管理【追加一个新版本】并切过去,旧版本仍保留在历史里可找回。
// settings flag 守卫 → 只做一次。全新库无需处理。与 reseedGoalsPrompt 完全同构。
func (s *Server) reseedWorkerPrompt() {
	const flag = "worker_prompt_compact_v4"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次
	a, err := s.m.pg.GetAgentByKey("worker")
	if err != nil || a == nil {
		return // 全新库尚未建 agent 行时,seedPrompts 会直接 seed 最新默认,无需此迁移
	}
	tmpl := agent.BuiltinPromptSeeds()["worker"]
	if tmpl == "" {
		return
	}
	// 全新库 seedPrompts 已 seed 最新默认 → 当前版本已等于代码默认,不必再追加重复版本。
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] worker 提示词重刷为新默认失败: %v", err)
		return
	}
	log.Printf("[prompts] worker 提示词已追加新默认版本(查上下文段收敛为 list_assets/list_findings,去掉 list_facts/node_detail/asset_neighbors,一次性)")
}

// reporterToolCallMessage 必须无条件要求先读一次 get_finding_traffic 再写报告。
// 该工具是只读的、「不依赖捕获开关」,自动绑定关不关都能读到人工绑定的证据。若这里
// 写成「启用自动绑定才读」,默认关闭配置下 reporter 就不会传 evidence_version,
// SetFindingReportVersionByNodeID 便按 legacy 语义写 -1,漏洞详情与 Markdown 导出
// 从此常驻「证据已变更，报告待更新」,而 UI 上没有任何入口能把它清掉。
const reporterToolCallMessage = "上面刚有一个漏洞被 report_finding 登记。请读取返回 JSON 的 finding_id（独立漏洞记录 ID）与 finding_node_id（探索节点 ID），" +
	"先用 get_finding_traffic(finding_id) 读取当前证据清单及其 version（空清单是正常情况，照常写报告）；" +
	"若运行指引启用自动绑定，在读取前先核实并关联本次漏洞的流量。节点详情使用 finding_node_id。" +
	"最后调用 update_finding_report(finding_id=finding_node_id, report, evidence_version=实际读取版本) 保存，" +
	"evidence_version 必须传，否则报告会被永久标记为待更新。不要混用两种编号。"

// 旧版触发消息(0.3.8 及更早)。只有仍与它逐字相同的记录才会被迁移覆盖，用户改过的保持原样。
const reporterToolCallMessageV1 = "上面刚有一个漏洞被 report_finding 登记。请从触发上下文里取出 finding_id" +
	"（工具返回 \"finding recorded: <id>\" 里的数字）与任务 id，按你的职责撰写该漏洞的详细报告，" +
	"最后调用 update_finding_report(finding_id, report) 保存。"

// upgradeReporterTriggerMessage 把老库里仍是默认文案的 reporter 触发消息刷成新版本。
// seedReporterAgent 受 reporter_agent_seed_v1 守卫且只在新建 agent 时写触发器，所以
// 升级上来的库拿不到新文案 —— 工具 schema 由 seedFindingTrafficTools 补齐了
// evidence_version，但没有任何东西告诉 reporter 去用它。一次性，且只覆盖未被改动的文案。
func (s *Server) upgradeReporterTriggerMessage() {
	const flag = "reporter_trigger_evidence_version_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 只尝试一次
	triggers, err := s.m.pg.ListTriggersFor("reporter")
	if err != nil {
		log.Printf("[reporter] 读取触发器失败: %v", err)
		return
	}
	for _, t := range triggers {
		if !t.OnToolCall || t.ToolCallMessage != reporterToolCallMessageV1 {
			continue // 用户改过或不是 finding 触发器，不动。
		}
		t.ToolCallMessage = reporterToolCallMessage
		if err := s.m.pg.UpdateTrigger(t); err != nil {
			log.Printf("[reporter] 升级触发消息失败: %v", err)
			return
		}
		log.Printf("[reporter] 触发消息已升级为读取并回传 evidence_version")
	}
}

// seedReporterAgent 预置一个「报告撰写」自定义 agent(builtin=false，可在 UI 编辑/删除)：
// 绑定 update_finding_report + 任务查询工具，并挂一个「report_finding 被调用即触发」的
// 触发器 —— 每登记一个漏洞就唤起它写详细报告。一次性(settings flag 守卫)：用户删掉后不再重建。
// 依赖：orchestration 工具已在本函数上方 SeedTool 入库，故绑定得上。
func (s *Server) seedReporterAgent() {
	const flag = "reporter_agent_seed_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次

	if exist, _ := s.m.pg.GetAgentByKey("reporter"); exist != nil {
		return // key 已被占用(用户手建过)——不覆盖
	}
	a, err := s.m.pg.CreateAgent("reporter", "报告撰写",
		"漏洞详细报告撰写：发现漏洞时自动触发，查取证据与执行过程后写 Markdown 报告并回写。")
	if err != nil {
		log.Printf("[reporter] 创建 agent 失败: %v", err)
		return
	}
	if err := s.m.pg.SeedPromptIfEmpty(a.ID, agent.ReporterDefaultPrompt); err != nil {
		log.Printf("[reporter] seed prompt 失败: %v", err)
	}
	// 触发运行策略：parallel + none —— 一漏洞一报告、多个 finding 并发各写各的。
	// merge 必须为 none：否则(默认 all)一波 finding 会被合并成一次运行，并行就没意义。
	// maxParallel=5：同时最多 5 个报告会话，避免瞬时太多 LLM 调用。
	if err := s.m.pg.SetAgentTriggerBehavior("reporter", "parallel", "none", 5); err != nil {
		log.Printf("[reporter] 设置触发运行策略失败: %v", err)
	}
	// 绑定它需要的工具：写报告 + 读证据/执行过程/态势。
	if err := s.m.pg.AddAgentToToolBinding("reporter", []string{
		"update_finding_report", "get_task_node_detail", "list_task_findings",
		"get_task_worker_trace", "list_task_worker_traces", "search_task_worker_traces",
		"get_task_graph",
	}); err != nil {
		log.Printf("[reporter] 绑定工具失败: %v", err)
	}
	// 触发器：report_finding 被调用即触发（工具返回 "finding recorded: <id>" 带上 finding_id，
	// 任务 id 也在触发消息里）。
	if _, err := s.m.pg.CreateTrigger(&db.AgentTrigger{
		AgentKey:        "reporter",
		Enabled:         true,
		OnToolCall:      true,
		ToolNames:       []string{"report_finding"},
		ToolCallMessage: reporterToolCallMessage,
	}); err != nil {
		log.Printf("[reporter] 创建触发器失败: %v", err)
	}
	log.Printf("[reporter] 已预置「报告撰写」agent + finding 触发器")
}

// seedAutoReportFindingBinding adds "auto" to report_finding's binding ONCE so
// conversation-context agents can call it without requiring an intent_id.
func (s *Server) seedAutoReportFindingBinding() {
	const flag = "auto_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("auto", []string{"report_finding"}); err != nil {
		log.Printf("[auto] report_finding 默认绑定失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedPlannerDefaultBindings adds "planner" to report_finding's binding ONCE
// (guarded by a settings flag), so existing DBs — whose report_finding row was
// seeded as worker-only — also let the planner record findings. Fresh DBs already
// get it via PlannerTools(); this only backfills without overriding a user unbind.
func (s *Server) seedPlannerDefaultBindings() {
	const flag = "planner_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"report_finding"}); err != nil {
		log.Printf("[planner] report_finding 默认绑定失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedPlannerListAssetsBinding adds "planner" to list_assets's binding ONCE
// (guarded by a settings flag), so existing DBs — whose list_assets row was seeded
// as auto/pentest-only — also let the planner query the asset store by DSL. Fresh
// DBs already get it via PlannerTools(); this only backfills without overriding a
// user unbind.
func (s *Server) seedPlannerListAssetsBinding() {
	const flag = "planner_list_assets_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"list_assets"}); err != nil {
		log.Printf("[planner] list_assets 默认绑定失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedCompanyScopeRebind changes add_company_scope's default binding ONCE on
// existing DBs (guarded by a settings flag): the tool moves off worker and onto
// planner — defining a company's asset scope is a planning/main/auto concern, not
// something a worker does mid-exploration. Fresh DBs already get planner via
// PlannerTools() and lack worker via WorkerTools(); this only backfills old rows.
// One-shot + flag-guarded so a user who later re-binds worker isn't overridden.
func (s *Server) seedCompanyScopeRebind() {
	const flag = "company_scope_rebind_v1" // worker→planner 默认绑定切换
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"add_company_scope"}); err != nil {
		log.Printf("[planner] add_company_scope 默认绑定失败: %v", err)
		return
	}
	if err := s.m.pg.RemoveAgentFromTool("worker", "add_company_scope"); err != nil {
		log.Printf("[worker] add_company_scope 解绑失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedWorkerReadToolsUnbind strips the read-context tools off worker's default
// binding ONCE on existing DBs (guarded by a settings flag): a worker executes one
// intent and writes back — reading facts/companies and listing all workers' traces is
// a planning/main concern, not the executor's. Fresh DBs already lack these via
// WorkerTools(); this only backfills old rows without overriding a user who
// deliberately re-binds worker. Each RemoveAgentFromTool is per-tool +
// membership-guarded, so planner/mainagent bindings of the same tool are untouched.
//
// NOTE: search_all_worker_traces / get_worker_trace / node_detail are intentionally NOT
// unbound — worker owns them for cross-work look-back + node drill-down (see WorkerTools).
// They used to be in this list back when worker lacked them; seedWorkerReadbackRebind
// repairs DBs whose old run stripped them.
func (s *Server) seedWorkerReadToolsUnbind() {
	const flag = "worker_readtools_unbind_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, k := range []string{
		"list_facts", "list_companies", "list_worker_traces",
	} {
		if err := s.m.pg.RemoveAgentFromTool("worker", k); err != nil {
			log.Printf("[worker] %s 从 worker 解绑失败: %v", k, err)
			return // 出错则不落 flag，下次启动重试
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedWorkerReadbackRebind re-binds the cross-work look-back / drill-down tools onto
// worker ONCE (guarded by a settings flag): an earlier seedWorkerReadToolsUnbind wrongly
// stripped search_all_worker_traces / get_worker_trace / node_detail from worker after
// they had been added to WorkerTools(), so any DB that ran that migration lost them.
// Fresh DBs already have them via WorkerTools() and this is a harmless no-op there.
// One-shot + flag-guarded so a user who later deliberately unbinds them isn't overridden.
func (s *Server) seedWorkerReadbackRebind() {
	const flag = "worker_readback_rebind_v2" // v2: 追加 node_detail
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("worker", []string{
		"search_all_worker_traces", "get_worker_trace", "node_detail",
	}); err != nil {
		log.Printf("[worker] 回看/详情工具补绑失败: %v", err)
		return // 出错则不落 flag，下次启动重试
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedAutoDefaultBindings adds "auto" to the task-op + platform tools' bindings
// ONCE (guarded by a settings flag), so existing DBs whose tool rows were seeded
// before Auto existed still give Auto its default toolset — without re-adding it
// after a user deliberately unbinds.
func (s *Server) seedAutoDefaultBindings() {
	const flag = "auto_default_bindings_v4_assessment_step2" // v4: 加入草稿/材料检查/启动白盒评估工具
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	keys := make([]string, 0, len(platformToolKeys)+12)
	for _, t := range s.orchestrationTools() {
		keys = append(keys, t.Name())
	}
	keys = append(keys, platformToolKeys...)
	// 资产工具：Auto 操作平台常要看/登记资产、管理公司范围。
	keys = append(keys, "insert_assets", "add_company_scope", "list_assets")
	if err := s.m.pg.AddAgentToToolBinding("auto", keys); err != nil {
		log.Printf("[auto] 默认绑定失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}
