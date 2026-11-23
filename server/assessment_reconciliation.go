package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	pgdb "github.com/Autumn-27/artex/db"
)

// ReopenAssessmentForNextRound closes any superseded round for taskID and opens
// Round N+1 in PostgreSQL and the Manager's in-memory lifecycle mirror under taskStateMu.
func (m *Manager) ReopenAssessmentForNextRound(taskID, reason, codebaseVersion, envVersion string) (*pgdb.ReopenRoundResult, error) {
	if m == nil || m.pg == nil {
		return nil, errors.New("database unavailable")
	}
	id, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || id <= 0 {
		return nil, errors.New("invalid task id")
	}
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()

	res, err := m.pg.ReopenAssessmentForNextRound(id, reason, codebaseVersion, envVersion)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	task := m.tasks[taskID]
	m.mu.RUnlock()
	if task != nil {
		now := time.Now().Unix()
		task.updateLifecycle(func(state *taskLifecycleState) {
			state.Status = "running"
			state.Draft = false
			state.Paused = false
			state.PauseReason = ""
			state.StopReason = ""
			state.Queued = false
			state.QueuedAt = 0
			state.QueueMode = ""
			state.CompletedAt = 0
			state.FirstRunAt = 0
			state.DeadlineAt = 0
			state.NoResultCheckedAt = 0
			state.AssessmentPhase = pgdb.AssessmentPhaseProfiling
			if state.RunSegmentStartedAt == 0 {
				state.RunSegmentStartedAt = now
			}
		})
	}
	return res, nil
}

type OpenRoundResponse struct {
	PreviousRoundID int64                           `json:"previous_round_id,omitempty"`
	NewRound        *pgdb.AssessmentRound           `json:"new_round"`
	ProfileSummary  *pgdb.AssessmentProfileSummary  `json:"profile_summary,omitempty"`
	CoverageSummary []pgdb.DimensionCoverageSummary `json:"coverage_summary,omitempty"`
}

// OpenNextAssessmentRound transitions a completed, timed-out, or superseded
// assessment task into Round N+1, rebuilds its deterministic baseline profile
// and coverage denominator, and wakes/resumes the engine cleanly.
func (s *Server) OpenNextAssessmentRound(ctx context.Context, taskID, reason, codebaseVersion, envVersion string) (*OpenRoundResponse, int, error) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return nil, http.StatusServiceUnavailable, errors.New("database unavailable")
	}
	if ctx == nil {
		if s.ctx != nil {
			ctx = s.ctx
		} else {
			ctx = context.Background()
		}
	}
	task, ok := s.m.Task(taskID)
	if !ok || task == nil {
		return nil, http.StatusNotFound, errors.New("task not found")
	}
	if !task.AssessmentMode {
		return nil, http.StatusBadRequest, pgdb.ErrTaskNotAssessmentMode
	}
	if task.IsDraft() {
		return nil, http.StatusConflict, errors.New("草稿任务尚未启动，不能开启新一轮评估")
	}

	if s.engine != nil && !pgdb.IsTerminal(task.lifecycleSnapshot().Status) {
		cause := agent.Causef("assessment_new_round", "开启新一轮评估", "因新一轮评估开启，中止旧轮次在跑意图")
		s.engine.Pause(taskID, cause)
	}

	reopenRes, err := s.m.ReopenAssessmentForNextRound(taskID, reason, codebaseVersion, envVersion)
	if err != nil {
		switch {
		case errors.Is(err, pgdb.ErrTaskNotAssessmentMode):
			return nil, http.StatusBadRequest, err
		case errors.Is(err, pgdb.ErrAssessmentSecretRejected):
			return nil, http.StatusBadRequest, err
		default:
			return nil, http.StatusInternalServerError, err
		}
	}

	if s.engine != nil {
		s.engine.resetTimeoutRevival(taskID)
		s.engine.Resume(task)
	}

	var profileSummary *pgdb.AssessmentProfileSummary
	if profResp, _, pErr := s.BuildAssessmentInitialProfile(ctx, taskID, BuildProfileOptions{}); pErr != nil {
		log.Printf("[assessment] task %s 新轮次构建初始画像失败: %v", taskID, pErr)
	} else if profResp != nil {
		profileSummary = profResp.Summary
	}

	var covSummary []pgdb.DimensionCoverageSummary
	if covResp, _, cErr := s.BuildAssessmentCoveragePlan(ctx, taskID); cErr != nil {
		log.Printf("[assessment] task %s 新轮次生成覆盖计划失败: %v", taskID, cErr)
	} else if covResp != nil {
		covSummary = covResp.Summary
	}

	if s.engine != nil {
		runCtx := s.ctx
		if runCtx == nil {
			runCtx = context.Background()
		}
		if s.engine.ReadyFor(task) {
			s.engine.Run(runCtx, task)
			s.engine.Resume(task)
			s.engine.startDeadlineCoordinator(runCtx, task)
		}
		s.engine.emitActivity(task, dbActivityForNewRound(reopenRes.NewRound, reason))
		task.Notify()
	}

	return &OpenRoundResponse{
		PreviousRoundID: reopenRes.PreviousRoundID,
		NewRound:        reopenRes.NewRound,
		ProfileSummary:  profileSummary,
		CoverageSummary: covSummary,
	}, http.StatusCreated, nil
}

func dbActivityForNewRound(round *pgdb.AssessmentRound, reason string) pgdb.Activity {
	summary := "已开启新一轮评估"
	if round != nil {
		summary = fmt.Sprintf("已开启第 %d 轮评估", round.RoundNo)
	}
	if strings.TrimSpace(reason) != "" {
		summary += "：" + strings.TrimSpace(reason)
	}
	return pgdb.Activity{
		Worker:  "system",
		Kind:    "text",
		Summary: summary,
	}
}

type reconcileAssetItem struct {
	agent.InsertedAssetSummary
	Name    string `json:"name,omitempty"`
	AssetID int64  `json:"asset_id,omitempty"`
}

// reconcileIncrementalAssessmentState turns pending incremental events
// (new_asset, new_entry, code_version_change) into updated target entities,
// incremental coverage obligations, invalidated stale obligations, and merged
// duplicate hypothesis obligations before the Planner inspects the round.
func (s *Server) reconcileIncrementalAssessmentState(ctx context.Context, taskID string, roundID int64) ([]agent.TriggerEvent, []int64, error) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return nil, nil, nil
	}
	taskNum, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || taskNum <= 0 {
		return nil, nil, nil
	}
	task, ok := s.m.Task(taskID)
	if !ok || task == nil || !task.AssessmentMode {
		return nil, nil, nil
	}
	round, err := s.m.pg.OpenAssessmentRound(taskNum)
	if err != nil || round == nil {
		return nil, nil, err
	}
	if roundID > 0 && round.ID != roundID {
		roundID = round.ID
	} else if roundID <= 0 {
		roundID = round.ID
	}

	execMode := strings.TrimSpace(task.lifecycleSnapshot().AssessmentConfig.ExecutionMode)
	if execMode == "" {
		execMode = pgdb.AssessmentExecDynamic
	}
	isDynamic := execMode != pgdb.AssessmentExecOffline

	var (
		triggers        []agent.TriggerEvent
		materializedIDs []int64
	)

	existingRuntimeIDs := s.roundRuntimeObligationIDs(taskNum, roundID)

	for _, evType := range []string{"new_entry", "new_asset"} {
		evs, evErr := s.m.pg.ListUnprocessedAssessmentEventsByType(taskNum, evType, 50)
		if evErr != nil {
			log.Printf("[assessment-reconcile] task %s 读取 %s 事件失败: %v", taskID, evType, evErr)
			continue
		}
		for _, ev := range evs {
			if ev.RoundID != nil && *ev.RoundID != roundID {
				continue
			}
			items := parseIncrementalAssetItems(ev.EventType, ev.Payload)
			if len(items) == 0 {
				continue
			}
			createdObs, entitiesTouched := s.materializeIncrementalAssetItems(taskNum, round, task, execMode, isDynamic, ev.EventType, items, existingRuntimeIDs)
			if entitiesTouched > 0 || createdObs > 0 {
				materializedIDs = append(materializedIDs, ev.ID)
				triggers = append(triggers, agent.TriggerEvent{
					Kind:   ev.EventType,
					Detail: fmt.Sprintf("增量对账[%s] 登记 %d 项目标实体，新增/关联 %d 条覆盖义务（执行模式 %s）", ev.EventType, entitiesTouched, createdObs, execMode),
				})
				existingRuntimeIDs = s.roundRuntimeObligationIDs(taskNum, roundID)
			}
		}
	}

	codeEvents, evErr := s.m.pg.ListUnprocessedAssessmentEventsByType(taskNum, "code_version_change", 20)
	if evErr == nil {
		for _, ev := range codeEvents {
			if ev.RoundID != nil && *ev.RoundID != roundID {
				continue
			}
			var p struct {
				Invalidated     bool     `json:"invalidated"`
				Environment     string   `json:"environment"`
				ObservedVersion string   `json:"observed_version"`
				Name            string   `json:"name"`
				VersionID       string   `json:"version_id"`
				Reason          string   `json:"reason"`
				Dimensions      []string `json:"dimensions"`
				TargetEntityIDs []int64  `json:"target_entity_ids"`
				ObligationIDs   []int64  `json:"obligation_ids"`
			}
			_ = json.Unmarshal(ev.Payload, &p)
			if p.Invalidated {
				// Already invalidated synchronously by upload/invalidate handler; leave for trigger drain.
				continue
			}
			reason := strings.TrimSpace(p.Reason)
			if reason == "" {
				if p.ObservedVersion != "" {
					reason = fmt.Sprintf("动态观察到部署版本变更为 %s（环境 %s），历史动态覆盖证据失效待重测", p.ObservedVersion, firstNonEmpty(p.Environment, "default"))
				} else if p.VersionID != "" || p.Name != "" {
					reason = fmt.Sprintf("代码版本变更为 %s，相关覆盖义务失效待重测", firstNonEmpty(p.Name, p.VersionID))
				} else {
					reason = "检测到代码或部署版本变更，受影响覆盖义务失效待重测"
				}
			}
			dims := p.Dimensions
			if len(dims) == 0 {
				if p.ObservedVersion != "" || p.Environment != "" {
					dims = []string{
						pgdb.DimensionRuntimeAsset,
						pgdb.DimensionEntryTest,
						pgdb.DimensionIdentityResource,
						pgdb.DimensionCrossModule,
						pgdb.DimensionHypothesis,
					}
				} else {
					dims = []string{
						pgdb.DimensionCodeAudit,
						pgdb.DimensionConfigAudit,
						pgdb.DimensionEntryTest,
						pgdb.DimensionIdentityResource,
						pgdb.DimensionCrossModule,
						pgdb.DimensionHypothesis,
					}
				}
			}
			invRes, invErr := s.m.pg.InvalidateObligationsOnChange(pgdb.InvalidateObligationsInput{
				TaskID:             taskNum,
				RoundID:            roundID,
				ChangeKind:         "code_version_change",
				Reason:             reason,
				Dimensions:         dims,
				TargetEntityIDs:    p.TargetEntityIDs,
				ObligationIDs:      p.ObligationIDs,
				IncludeTransitive:  true,
				BumpProfileVersion: true,
				NewCodebaseVersion: p.VersionID,
				NewEnvVersion:      p.ObservedVersion,
			})
			if invErr != nil {
				log.Printf("[assessment-reconcile] task %s 版本变更失效处理失败: %v", taskID, invErr)
				continue
			}
			s.cancelInvalidatedIntents(invRes)
			materializedIDs = append(materializedIDs, ev.ID)
			triggers = append(triggers, agent.TriggerEvent{
				Kind:   "code_version_change",
				Detail: fmt.Sprintf("版本变更已使 %d 条覆盖义务变为 stale（新画像版本 v%d）：%s", len(invRes.InvalidatedIDs), invRes.NewProfileVersion, reason),
			})
		}
	}

	if mergeRes, mErr := s.m.pg.MergeDuplicateHypothesisObligations(taskNum, roundID); mErr == nil && mergeRes != nil && mergeRes.MergedPairs > 0 {
		triggers = append(triggers, agent.TriggerEvent{
			Kind:   "profile_change",
			Detail: fmt.Sprintf("已自动合并 %d 条重复开放 hypothesis 义务，避免重复验证", mergeRes.MergedPairs),
		})
	}

	_, _, _ = s.m.pg.ReconcileObligationReadiness(taskNum, roundID)
	if len(materializedIDs) > 0 {
		_ = s.m.pg.MarkAssessmentEventIDsProcessed(taskNum, materializedIDs)
	}
	return triggers, materializedIDs, nil
}

func (s *Server) roundRuntimeObligationIDs(taskID, roundID int64) []int64 {
	obs, err := s.m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{
		TaskID:    taskID,
		RoundID:   roundID,
		Dimension: pgdb.DimensionRuntimeAsset,
		Limit:     200,
	})
	if err != nil {
		return nil
	}
	var ids []int64
	for _, ob := range obs {
		if ob.Status != pgdb.ObligationNotApplicable {
			ids = append(ids, ob.ID)
		}
	}
	return ids
}

func parseIncrementalAssetItems(evType string, raw json.RawMessage) []reconcileAssetItem {
	if len(raw) == 0 {
		return nil
	}
	var p struct {
		InsertedAssets []reconcileAssetItem `json:"inserted_assets"`
		ID             int64                `json:"id"`
		AssetID        int64                `json:"asset_id"`
		Type           string               `json:"type"`
		Name           string               `json:"name"`
		URL            string               `json:"url"`
		Method         string               `json:"method"`
		Domain         string               `json:"domain"`
		IP             string               `json:"ip"`
		ServiceName    string               `json:"service_name"`
		Port           int                  `json:"port"`
		AppName        string               `json:"app_name"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil
	}
	if len(p.InsertedAssets) > 0 {
		out := make([]reconcileAssetItem, 0, len(p.InsertedAssets))
		for _, it := range p.InsertedAssets {
			if it.ID == 0 && it.AssetID > 0 {
				it.ID = it.AssetID
			}
			out = append(out, it)
		}
		return out
	}
	if p.URL == "" && p.Name == "" && p.Domain == "" && p.IP == "" && p.AppName == "" {
		return nil
	}
	typ := strings.TrimSpace(p.Type)
	if typ == "" {
		if evType == "new_entry" {
			typ = "endpoint"
		} else {
			typ = "service"
		}
	}
	aid := p.ID
	if aid == 0 {
		aid = p.AssetID
	}
	return []reconcileAssetItem{{
		InsertedAssetSummary: agent.InsertedAssetSummary{
			ID:          aid,
			Type:        typ,
			URL:         strings.TrimSpace(p.URL),
			Method:      strings.TrimSpace(p.Method),
			Domain:      strings.TrimSpace(p.Domain),
			IP:          strings.TrimSpace(p.IP),
			ServiceName: strings.TrimSpace(p.ServiceName),
			Port:        p.Port,
			AppName:     strings.TrimSpace(p.AppName),
		},
		Name: strings.TrimSpace(p.Name),
	}}
}

func (s *Server) isIncrementalAssetAllowed(taskNum int64, task *Task, item reconcileAssetItem) bool {
	as := s.m.assetsForTask(task)
	if as == nil {
		return true
	}
	blockRules, _ := as.ListAssetInterceptRules()
	var allowRules []pgdb.AssetInterceptRule
	if tb, ta, err := as.TaskInterceptRulesSplit(taskNum); err == nil {
		blockRules = append(blockRules, tb...)
		allowRules = ta
	}
	var domains, ips, urls []string
	if item.Domain != "" {
		domains = append(domains, item.Domain)
	}
	if item.IP != "" {
		ips = append(ips, item.IP)
	}
	if item.URL != "" {
		urls = append(urls, item.URL)
		if u, err := url.Parse(item.URL); err == nil {
			if h := u.Hostname(); h != "" {
				if net.ParseIP(h) != nil {
					ips = append(ips, h)
				} else {
					domains = append(domains, h)
				}
			}
		}
	}
	d := pgdb.EvaluateAssetGate(blockRules, allowRules, domains, ips, urls)
	return d.Allowed
}

func (s *Server) materializeIncrementalAssetItems(
	taskNum int64,
	round *pgdb.AssessmentRound,
	task *Task,
	execMode string,
	isDynamic bool,
	evType string,
	items []reconcileAssetItem,
	existingRuntimeIDs []int64,
) (createdObs int, entitiesTouched int) {
	for _, item := range items {
		if !s.isIncrementalAssetAllowed(taskNum, task, item) {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(item.Type))
		if typ == "" && evType == "new_entry" {
			typ = "endpoint"
		}
		var assetPtr *int64
		if item.ID > 0 {
			aid := item.ID
			assetPtr = &aid
		}

		isEndpoint := typ == "endpoint" || (evType == "new_entry" && item.URL != "")
		if isEndpoint {
			method := strings.ToUpper(firstNonEmpty(item.Method, "GET"))
			targetPath := strings.TrimSpace(item.URL)
			if strings.HasPrefix(strings.ToLower(targetPath), "http://") || strings.HasPrefix(strings.ToLower(targetPath), "https://") {
				if u, uErr := url.Parse(targetPath); uErr == nil && u.RequestURI() != "" {
					targetPath = u.RequestURI()
				}
			}
			entName := strings.TrimSpace(item.Name)
			if entName == "" {
				entName = fmt.Sprintf("HTTP %s %s", method, firstNonEmptyStr(targetPath, item.Domain, item.IP, "unknown"))
			}
			attrs, _ := json.Marshal(map[string]any{
				"source":     "incremental_" + evType,
				"method":     method,
				"url":        item.URL,
				"path":       targetPath,
				"asset_id":   item.ID,
				"discovered": true,
			})
			ent, err := s.upsertIncrementalTargetEntity(pgdb.CreateTargetEntityInput{
				TaskID:     taskNum,
				RoundID:    &round.ID,
				EntityType: "entry",
				Name:       entName,
				AssetID:    assetPtr,
				Attributes: attrs,
			})
			if err != nil {
				continue
			}
			entitiesTouched++
			if !isDynamic {
				continue
			}
			dedupe := fmt.Sprintf("entry_test:inc:%s", normalizeObligationDedupeToken(entName))
			rule, _ := json.Marshal(map[string]any{
				"required_evidence": "effective_dynamic_attempt",
				"incremental":       true,
			})
			snap, _ := json.Marshal(map[string]any{
				"entity_type": ent.EntityType,
				"name":        ent.Name,
				"url":         item.URL,
				"method":      method,
				"attributes":  json.RawMessage(nonEmptyJSON(ent.Attributes)),
			})
			if _, cErr := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
				TaskID:          taskNum,
				RoundID:         &round.ID,
				Dimension:       pgdb.DimensionEntryTest,
				TargetEntityID:  &ent.ID,
				Purpose:         fmt.Sprintf("对增量发现入口「%s」执行动态覆盖与安全检查", entName),
				Required:        true,
				DedupeKey:       dedupe,
				AcceptanceRule:  rule,
				ExecutionMode:   pgdb.ExecModeDynamicVerify,
				Origin:          pgdb.ObligationOriginProgram,
				Priority:        7,
				ProfileVersion:  round.ProfileVersion,
				DependencyIDs:   existingRuntimeIDs,
				ContextSnapshot: snap,
			}); cErr == nil {
				createdObs++
			}
			continue
		}

		entName := firstNonEmptyStr(item.Name, item.URL, item.Domain, item.IP, item.AppName)
		if item.ServiceName != "" && item.Port > 0 && entName == item.IP {
			entName = fmt.Sprintf("%s:%d(%s)", item.IP, item.Port, item.ServiceName)
		}
		if entName == "" {
			continue
		}
		attrs, _ := json.Marshal(map[string]any{
			"source":       "incremental_" + evType,
			"asset_type":   typ,
			"url":          item.URL,
			"domain":       item.Domain,
			"ip":           item.IP,
			"service_name": item.ServiceName,
			"port":         item.Port,
			"app_name":     item.AppName,
			"asset_id":     item.ID,
		})
		ent, err := s.upsertIncrementalTargetEntity(pgdb.CreateTargetEntityInput{
			TaskID:     taskNum,
			RoundID:    &round.ID,
			EntityType: "runtime_asset",
			Name:       entName,
			AssetID:    assetPtr,
			Attributes: attrs,
		})
		if err != nil {
			continue
		}
		entitiesTouched++
		if !isDynamic {
			continue
		}
		dedupe := fmt.Sprintf("runtime_asset:inc:%s", normalizeObligationDedupeToken(entName))
		rule, _ := json.Marshal(map[string]any{
			"required_evidence": "execution_or_traffic",
			"verify_target":     "deployed_version_and_reachability",
			"incremental":       true,
		})
		snap, _ := json.Marshal(map[string]any{
			"entity_type": ent.EntityType,
			"name":        ent.Name,
			"attributes":  json.RawMessage(nonEmptyJSON(ent.Attributes)),
		})
		if _, cErr := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID:          taskNum,
			RoundID:         &round.ID,
			Dimension:       pgdb.DimensionRuntimeAsset,
			TargetEntityID:  &ent.ID,
			Purpose:         fmt.Sprintf("核实增量发现运行资产「%s」的可达性、版本与开放暴露面", entName),
			Required:        true,
			DedupeKey:       dedupe,
			AcceptanceRule:  rule,
			ExecutionMode:   pgdb.ExecModeDynamicVerify,
			Origin:          pgdb.ObligationOriginProgram,
			Priority:        8,
			ProfileVersion:  round.ProfileVersion,
			ContextSnapshot: snap,
		}); cErr == nil {
			createdObs++
		}
	}
	return createdObs, entitiesTouched
}

func (s *Server) upsertIncrementalTargetEntity(in pgdb.CreateTargetEntityInput) (*pgdb.TargetEntity, error) {
	ent, _, err := s.m.pg.UpsertTargetEntity(in)
	if err != nil && in.AssetID != nil {
		// AssetID may refer to a synthetic test ID or an already deleted global asset row;
		// retry without the foreign-key link so incremental obligations never silently drop.
		in.AssetID = nil
		ent, _, err = s.m.pg.UpsertTargetEntity(in)
	}
	if err != nil {
		log.Printf("[assessment-reconcile] task %d UpsertTargetEntity(%s, %q) 失败: %v", in.TaskID, in.EntityType, in.Name, err)
		return nil, err
	}
	return ent, nil
}

func (s *Server) cancelInvalidatedIntents(res *pgdb.InvalidateObligationsResult) {
	if s == nil || s.engine == nil || res == nil {
		return
	}
	for _, iid := range res.StoppedIntentIDs {
		if iid > 0 {
			_ = s.engine.KillWork(iid)
		}
	}
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func boolPtrDefault(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

// POST /api/tasks/{id}/assessment/invalidate
func (s *Server) invalidateAssessmentObligationsHandler(w http.ResponseWriter, r *http.Request) {
	taskNum, ok := s.requireTaskInProject(w, r, r.PathValue("id"), true)
	if !ok {
		return
	}
	taskID := strconv.FormatInt(taskNum, 10)
	t, ok := s.m.Task(taskID)
	if !ok || t == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if !t.AssessmentMode {
		writeErr(w, http.StatusBadRequest, pgdb.ErrTaskNotAssessmentMode.Error())
		return
	}
	if t.IsDraft() {
		writeErr(w, http.StatusConflict, "草稿任务尚未启动，请直接修改材料或重跑材料检查")
		return
	}
	if pgdb.IsTerminal(t.lifecycleSnapshot().Status) {
		writeErr(w, http.StatusConflict, "已完成/超时任务请通过开启新一轮评估接口重建评估")
		return
	}
	round, err := s.m.pg.OpenAssessmentRound(taskNum)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if round == nil {
		writeErr(w, http.StatusConflict, "当前没有开放的评估轮次")
		return
	}

	var req struct {
		ChangeKind         string   `json:"change_kind"`
		Reason             string   `json:"reason"`
		Dimensions         []string `json:"dimensions"`
		TargetEntityIDs    []int64  `json:"target_entity_ids"`
		ObligationIDs      []int64  `json:"obligation_ids"`
		IncludeTransitive  *bool    `json:"include_transitive"`
		BumpProfileVersion *bool    `json:"bump_profile_version"`
		NewCodebaseVersion string   `json:"new_codebase_version"`
		NewEnvVersion      string   `json:"new_env_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}

	res, err := s.m.pg.InvalidateObligationsOnChange(pgdb.InvalidateObligationsInput{
		TaskID:             taskNum,
		RoundID:            round.ID,
		ChangeKind:         strings.TrimSpace(req.ChangeKind),
		Reason:             strings.TrimSpace(req.Reason),
		Dimensions:         req.Dimensions,
		TargetEntityIDs:    req.TargetEntityIDs,
		ObligationIDs:      req.ObligationIDs,
		IncludeTransitive:  boolPtrDefault(req.IncludeTransitive, true),
		BumpProfileVersion: boolPtrDefault(req.BumpProfileVersion, true),
		NewCodebaseVersion: strings.TrimSpace(req.NewCodebaseVersion),
		NewEnvVersion:      strings.TrimSpace(req.NewEnvVersion),
	})
	if err != nil {
		switch {
		case errors.Is(err, pgdb.ErrObligationEvidenceMissing),
			errors.Is(err, pgdb.ErrAssessmentSecretRejected):
			writeErr(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, pgdb.ErrAttemptStaleOrSuperseded):
			writeErr(w, http.StatusConflict, err.Error())
		default:
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	s.cancelInvalidatedIntents(res)
	if s.engine != nil {
		s.engine.emitActivity(t, pgdb.Activity{
			Worker:  "system",
			Kind:    "text",
			Summary: fmt.Sprintf("评估证据失效：%d 条义务标记为 stale（画像版本 v%d）：%s", len(res.InvalidatedIDs), res.NewProfileVersion, strings.TrimSpace(req.Reason)),
		})
	}
	t.Notify()
	writeJSON(w, http.StatusOK, res)
}

// POST /api/tasks/{id}/coverage-plan/reconcile
func (s *Server) reconcileTaskCoveragePlanHandler(w http.ResponseWriter, r *http.Request) {
	taskNum, ok := s.requireTaskInProject(w, r, r.PathValue("id"), true)
	if !ok {
		return
	}
	taskID := strconv.FormatInt(taskNum, 10)
	t, ok := s.m.Task(taskID)
	if !ok || t == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if !t.AssessmentMode {
		writeErr(w, http.StatusBadRequest, pgdb.ErrTaskNotAssessmentMode.Error())
		return
	}
	if t.IsDraft() || pgdb.IsTerminal(t.lifecycleSnapshot().Status) {
		writeErr(w, http.StatusConflict, "仅运行中/暂停中的开放评估轮次可执行覆盖对账")
		return
	}
	round, err := s.m.pg.OpenAssessmentRound(taskNum)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if round == nil {
		writeErr(w, http.StatusConflict, "当前没有开放的评估轮次")
		return
	}

	var req struct {
		ReopenStale     bool    `json:"reopen_stale"`
		ObligationIDs   []int64 `json:"obligation_ids"`
		ReopenReason    string  `json:"reopen_reason"`
		MergeHypotheses *bool   `json:"merge_hypotheses"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	if err := s.ensureStaticHypothesisObligations(r.Context(), taskNum, round.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	triggers, materializedIDs, err := s.reconcileIncrementalAssessmentState(r.Context(), taskID, round.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	var reopenRes *pgdb.ReopenStaleResult
	if req.ReopenStale {
		reopenRes, err = s.m.pg.ReopenStaleObligations(taskNum, round.ID, req.ObligationIDs, firstNonEmpty(req.ReopenReason, "人工/接口触发重新打开失效义务"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	var mergeRes *pgdb.MergeHypothesesResult
	if boolPtrDefault(req.MergeHypotheses, true) {
		mergeRes, err = s.m.pg.MergeDuplicateHypothesisObligations(taskNum, round.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	_, _, _ = s.m.pg.ReconcileObligationReadiness(taskNum, round.ID)
	summary, _ := s.m.pg.GetCoverageSummaryByDimension(taskNum, round.ID)
	t.Notify()
	writeJSON(w, http.StatusOK, map[string]any{
		"round_id":               round.ID,
		"triggers":               triggers,
		"materialized_event_ids": materializedIDs,
		"reopened":               reopenRes,
		"merged_hypotheses":      mergeRes,
		"summary":                summary,
	})
}

// POST /api/tasks/{id}/assessment-rounds
func (s *Server) createNextAssessmentRoundHandler(w http.ResponseWriter, r *http.Request) {
	taskNum, ok := s.requireTaskInProject(w, r, r.PathValue("id"), true)
	if !ok {
		return
	}
	var req struct {
		Reason             string `json:"reason"`
		CodebaseVersion    string `json:"codebase_version"`
		EnvironmentVersion string `json:"environment_version"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, http.ErrBodyReadAfterClose) && err.Error() != "EOF" {
			writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
			return
		}
	}
	resp, code, err := s.OpenNextAssessmentRound(r.Context(), strconv.FormatInt(taskNum, 10), req.Reason, req.CodebaseVersion, req.EnvironmentVersion)
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, code, resp)
}
