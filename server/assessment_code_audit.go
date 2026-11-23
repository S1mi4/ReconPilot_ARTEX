package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Autumn-27/artex/agent"
	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

type resolvedAssessmentAuditTarget struct {
	TargetEntityID *int64
	CodeServiceID  *int64
	Service        pgdb.TaskCodeService
	Version        taskCodebaseVersion
	TargetType     string
}

func (s *Server) resolveAssessmentAuditTarget(taskID int64, ob *pgdb.CoverageObligation, preferRootForInvestigate bool) (resolvedAssessmentAuditTarget, error) {
	var out resolvedAssessmentAuditTarget
	if ob == nil {
		return out, errors.New("coverage obligation is required")
	}
	taskKey := strconv.FormatInt(taskID, 10)
	var snap map[string]any
	if len(ob.ContextSnapshot) > 0 {
		_ = json.Unmarshal(ob.ContextSnapshot, &snap)
	}
	strSnap := func(keys ...string) string {
		for _, k := range keys {
			if snap == nil {
				continue
			}
			if v, ok := snap[k].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}

	roundID := obligationRoundID(ob, 0)
	var matchedEnt *pgdb.TargetEntity
	var entAttrs map[string]any
	if ob.TargetEntityID != nil && *ob.TargetEntityID > 0 {
		out.TargetEntityID = ob.TargetEntityID
		if ents, err := s.m.pg.ListTargetEntities(pgdb.TargetEntityFilter{TaskID: taskID, RoundID: roundID, Limit: 500}); err == nil {
			for i := range ents {
				if ents[i].ID == *ob.TargetEntityID {
					matchedEnt = &ents[i]
					break
				}
			}
		}
	}
	if matchedEnt != nil && len(matchedEnt.Attributes) > 0 {
		_ = json.Unmarshal(matchedEnt.Attributes, &entAttrs)
	}
	strAttr := func(keys ...string) string {
		for _, k := range keys {
			if entAttrs == nil {
				continue
			}
			if v, ok := entAttrs[k].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}

	targetName := strSnap("name", "target_name")
	targetType := strSnap("entity_type", "target_type")
	codebaseID := strSnap("codebase_id")
	versionID := strSnap("version_id")
	rawRel := strSnap("relative_path", "rel_path")

	if matchedEnt != nil {
		if matchedEnt.Name != "" && targetName == "" {
			targetName = matchedEnt.Name
		}
		if matchedEnt.EntityType != "" && targetType == "" {
			targetType = matchedEnt.EntityType
		}
		if matchedEnt.CodebaseID != "" && codebaseID == "" {
			codebaseID = matchedEnt.CodebaseID
		}
		if matchedEnt.VersionID != "" && versionID == "" {
			versionID = matchedEnt.VersionID
		}
		if rawRel == "" {
			rawRel = strAttr("rel_path", "relative_path", "config_path")
		}
	}
	if targetType == "" {
		targetType = "module"
	}

	// Collect languages from context snapshot & entity attributes, filtered to
	// languages supported by taskCodeAuditCodebase.
	langSet := map[string]bool{}
	addLangs := func(src any) {
		switch items := src.(type) {
		case []any:
			for _, it := range items {
				if s, ok := it.(string); ok {
					l := strings.ToLower(strings.TrimSpace(s))
					if _, supported := taskCodeAuditLanguage(l); supported {
						langSet[l] = true
					}
				}
			}
		case []string:
			for _, s := range items {
				l := strings.ToLower(strings.TrimSpace(s))
				if _, supported := taskCodeAuditLanguage(l); supported {
					langSet[l] = true
				}
			}
		case string:
			for _, part := range strings.Split(items, ",") {
				l := strings.ToLower(strings.TrimSpace(part))
				if _, supported := taskCodeAuditLanguage(l); supported {
					langSet[l] = true
				}
			}
		}
	}
	if snap != nil {
		addLangs(snap["languages"])
	}
	if entAttrs != nil {
		addLangs(entAttrs["languages"])
		addLangs(entAttrs["language"])
	}

	latest, _, err := s.loadTaskLatestCodebases(taskKey)
	if err != nil {
		return out, fmt.Errorf("加载任务代码库失败: %w", err)
	}
	var chosen *materialCodebaseDiskVersion
	if versionID != "" {
		if ver, verr := s.loadTaskCodebaseVersion(taskKey, versionID); verr == nil {
			verDir := filepath.Join(s.m.taskCodebaseRoot(taskKey), ver.ID)
			chosen = &materialCodebaseDiskVersion{version: ver, versionDir: verDir}
		}
	}
	if chosen == nil && codebaseID != "" {
		for i := range latest {
			if latest[i].version.CodebaseID == codebaseID {
				chosen = &latest[i]
				break
			}
		}
	}
	if chosen == nil && len(latest) > 0 {
		chosen = &latest[0]
	}
	if chosen == nil {
		return out, errors.New("当前任务未关联可读代码库版本")
	}

	version := chosen.version
	if targetName == "" {
		targetName = version.Name
	}
	relPath := normalizeAssessmentModuleRelPath(filepath.Join(chosen.versionDir, "contents"), version, rawRel)
	if preferRootForInvestigate {
		switch targetType {
		case "config", "entry", "identity", "instance":
			relPath = "."
		default:
			if targetType == "" || ob.Dimension == pgdb.DimensionConfigAudit || ob.Dimension == pgdb.DimensionCrossModule || ob.Dimension == pgdb.DimensionIdentityResource || ob.Dimension == pgdb.DimensionHypothesis {
				relPath = "."
			}
		}
	}
	if relPath != "." {
		if _, perr := safeTaskCodebasePath(relPath); perr != nil {
			relPath = "."
		}
	}

	languages := make([]string, 0, len(langSet))
	for l := range langSet {
		languages = append(languages, l)
	}
	sort.Strings(languages)
	if len(languages) == 0 {
		languages = []string{"java", "python", "c"}
	}

	var matchedServiceID *int64
	var svcIDVal int64
	if targetType == "service" {
		if svcs, _, serr := s.m.pg.ListTaskCodeServices(taskID); serr == nil {
			for _, svc := range svcs {
				if svc.CodebaseID == version.CodebaseID && normalizeSlashClean(svc.RelativePath) == relPath {
					id := svc.ID
					matchedServiceID = &id
					svcIDVal = id
					break
				}
			}
		}
	}

	out.Version = version
	out.TargetType = targetType
	out.CodeServiceID = matchedServiceID
	out.Service = pgdb.TaskCodeService{
		ID:              svcIDVal,
		TaskID:          taskID,
		CodebaseID:      version.CodebaseID,
		LatestVersionID: version.ID,
		Name:            targetName,
		RelativePath:    relPath,
		Languages:       languages,
	}
	return out, nil
}

func obligationRoundID(ob *pgdb.CoverageObligation, fallback int64) int64 {
	if ob != nil && ob.RoundID != nil && *ob.RoundID > 0 {
		return *ob.RoundID
	}
	return fallback
}

func normalizeSlashClean(raw string) string {
	clean := path.Clean(filepath.ToSlash(strings.TrimSpace(raw)))
	if clean == "" || clean == "/" || clean == "." {
		return "."
	}
	return strings.TrimPrefix(clean, "./")
}

func normalizeAssessmentModuleRelPath(contentsDir string, version taskCodebaseVersion, rawRel string) string {
	rel := normalizeSlashClean(rawRel)
	if rel == "." {
		return "."
	}
	if version.Kind != "directory" || version.Name == "" {
		return rel
	}
	direct := filepath.Join(contentsDir, filepath.FromSlash(version.Name), filepath.FromSlash(rel))
	if ensureTaskCodebaseDirectories(direct, false) == nil {
		return rel
	}
	if rel == version.Name {
		rootDir := filepath.Join(contentsDir, filepath.FromSlash(version.Name))
		if ensureTaskCodebaseDirectories(rootDir, false) == nil {
			return "."
		}
	}
	if strings.HasPrefix(rel, version.Name+"/") {
		stripped := normalizeSlashClean(strings.TrimPrefix(rel, version.Name+"/"))
		candidate := filepath.Join(contentsDir, filepath.FromSlash(version.Name), filepath.FromSlash(stripped))
		if ensureTaskCodebaseDirectories(candidate, false) == nil {
			return stripped
		}
	}
	return rel
}

func (s *Server) resolveAssessmentAuditLLM(taskID int64) (taskCodeAuditLLMConfig, llm.Provider, error) {
	if s.assessmentAuditProviderOverride != nil {
		if cfg, prov, ok := s.assessmentAuditProviderOverride(taskID); ok && prov != nil {
			if cfg.Model == "" {
				cfg.Model = "mock-audit-model"
			}
			if cfg.ProfileFrom == "" {
				cfg.ProfileFrom = "override"
			}
			if cfg.Format == "" {
				cfg.Format = "mock"
			}
			cfg.Available = true
			return cfg, prov, nil
		}
	}
	cfg, err := s.resolveTaskCodeAuditLLM(taskID, nil)
	if err != nil {
		return cfg, nil, err
	}
	if !cfg.Available {
		reason := strings.TrimSpace(cfg.Reason)
		if reason == "" {
			reason = "任务没有可用的白盒审计 LLM 配置"
		}
		return cfg, nil, errors.New(reason)
	}
	var (
		prov llm.Provider
		ok   bool
	)
	if cfg.ProfileID != nil && *cfg.ProfileID > 0 {
		prov, _, ok = s.providerForProfile(*cfg.ProfileID)
	} else {
		prov, _, ok = s.globalProvider()
	}
	if !ok || prov == nil {
		return cfg, nil, errors.New("无法解析白盒审计 LLM Provider 实例")
	}
	return cfg, prov, nil
}

func (s *Server) buildAssessmentAuditProfileContext(taskID, roundID int64, subjects ...string) string {
	if s.m == nil || s.m.pg == nil || roundID <= 0 {
		return ""
	}
	cleanSubs := make([]string, 0, len(subjects))
	for _, sub := range subjects {
		if trimmed := strings.TrimSpace(sub); trimmed != "" {
			cleanSubs = append(cleanSubs, trimmed)
		}
	}
	slice, err := s.m.pg.QueryProfileContext(taskID, roundID, cleanSubs, 15)
	if err != nil || slice == nil || (len(slice.Entities) == 0 && len(slice.Claims) == 0) {
		return ""
	}
	data, err := json.Marshal(slice)
	if err != nil {
		return ""
	}
	return trimAuditText(string(data), 4000)
}

func (s *Server) runAssessmentCodeAuditBatch(ctx context.Context, t *Task, slotName string, intent *pgdb.Node, meta pgdb.IntentAssessmentMeta, emit func(pgdb.Activity)) (AssessmentExecResult, error) {
	taskIDInt, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskIDInt <= 0 || s.m == nil || s.m.pg == nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptFailed,
			BlockedReason: "任务或数据库不可用，无法执行批量白盒审计",
			IntentState:   "blocked",
		}, nil
	}
	ob, err := s.m.pg.GetCoverageObligation(taskIDInt, meta.ObligationID)
	if err != nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptDependencyMissing,
			BlockedReason: fmt.Sprintf("读取覆盖义务 #%d 失败: %v", meta.ObligationID, err),
			IntentState:   "blocked",
		}, nil
	}
	target, err := s.resolveAssessmentAuditTarget(taskIDInt, ob, false)
	if err != nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptDependencyMissing,
			BlockedReason: err.Error(),
			IntentState:   "blocked",
		}, nil
	}
	llmCfg, prov, err := s.resolveAssessmentAuditLLM(taskIDInt)
	if err != nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptDependencyMissing,
			BlockedReason: err.Error(),
			IntentState:   "blocked",
		}, nil
	}

	run, resumed, err := s.m.pg.CreateOrResumeEngineCodeAuditRun(pgdb.CreateEngineCodeAuditInput{
		TaskID:             taskIDInt,
		ObligationID:       ob.ID,
		TargetEntityID:     target.TargetEntityID,
		CodeServiceID:      target.CodeServiceID,
		TargetName:         target.Service.Name,
		TargetType:         target.TargetType,
		CodebaseID:         target.Service.CodebaseID,
		VersionID:          target.Service.LatestVersionID,
		RelativePath:       target.Service.RelativePath,
		ScopePath:          ".",
		Languages:          target.Service.Languages,
		ProfileID:          llmCfg.ProfileID,
		ProfileSource:      llmCfg.ProfileFrom,
		ProfileName:        llmCfg.ProfileName,
		ProfileFormat:      llmCfg.Format,
		Model:              llmCfg.Model,
		Endpoint:           llmCfg.Endpoint,
		SourceAcknowledged: true,
	})
	if err != nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptFailed,
			BlockedReason: fmt.Sprintf("创建或恢复白盒审计运行失败: %v", err),
			IntentState:   "blocked",
		}, nil
	}
	if err := s.m.pg.LinkAttemptCodeAuditRun(taskIDInt, meta.AttemptID, run.ID); err != nil {
		log.Printf("[assessment-code-audit] task %s link attempt #%d -> run #%d failed: %v", t.ID, meta.AttemptID, run.ID, err)
	}

	if emit != nil {
		action := "启动"
		if resumed {
			action = fmt.Sprintf("续跑（检查点 next=%d）", run.NextFileIndex)
		}
		emit(pgdb.Activity{
			Kind:    "text",
			Summary: fmt.Sprintf("%s白盒批量审计 #%d（目标 %s [%s]，路径 %s）。", action, run.ID, target.Service.Name, target.TargetType, target.Service.RelativePath),
		})
	}

	runCtx, releaseAudit := s.engine.registerAuditRun(ctx, t.ID, run.ID)
	defer releaseAudit()

	obRoundID := obligationRoundID(ob, meta.RoundID)
	profileSlice := s.buildAssessmentAuditProfileContext(taskIDInt, obRoundID, target.Service.Name, target.Service.RelativePath)
	hooks := &taskCodeAuditExecHooks{
		ActivityWorker: taskCodeAuditWorkerActivityKey(run.ID),
		ActivityEmit: func(act pgdb.Activity) {
			if emit != nil && strings.TrimSpace(act.Summary) != "" {
				act.Worker = slotName
				emit(act)
			}
		},
		ProfileContext: profileSlice,
		SteerDrain: func() []string {
			var drained []string
			for {
				msg, ok := s.engine.drainSteer(intent.ID)
				if !ok {
					break
				}
				if strings.TrimSpace(msg) != "" {
					drained = append(drained, msg)
				}
			}
			return drained
		},
		Provider: prov,
		OnChunkCompleted: func(ev taskCodeAuditChunkEvent) {
			payload, _ := json.Marshal(map[string]any{
				"intent_id":             intent.ID,
				"obligation_id":         ob.ID,
				"code_audit_run_id":     run.ID,
				"chunk_index":           ev.ChunkIndex,
				"chunks_total":          ev.ChunksTotal,
				"files_analyzed":        ev.FilesAnalyzed,
				"files_total":           ev.FilesTotal,
				"assigned_items":        ev.AssignedItems,
				"candidates_registered": ev.CandidatesRegistered,
				"candidates_incomplete": ev.CandidatesIncomplete,
				"finding_ids":           ev.RegisteredFindingIDs,
				"binary_phase":          ev.BinaryPhase,
				"summary":               ev.Summary,
			})
			if _, evErr := s.m.pg.RecordAssessmentRoundEvent(taskIDInt, obRoundID, "code_audit_chunk_completed", payload); evErr != nil {
				log.Printf("[assessment-code-audit] task %s record chunk event failed: %v", t.ID, evErr)
			}
			t.Notify()
			if ev.CandidatesRegistered > 0 {
				t.NotifyFinding(intent.ID, fmt.Sprintf("白盒审计 run #%d 分片 %d/%d 登记 %d 个静态候选", run.ID, ev.ChunkIndex, ev.ChunksTotal, ev.CandidatesRegistered))
			}
		},
	}

	var execErr error
	if run.Status != "completed" {
		execErr = s.executeTaskCodeAuditForTarget(runCtx, run, 0, target.Service, target.Version, hooks)
	}

	// Check parent context cancellation FIRST because stopTaskCodeAudit parks
	// interrupted runs as "incomplete" and returns nil.
	if ctx.Err() != nil {
		if latest, lerr := s.m.pg.GetTaskCodeAudit(taskIDInt, run.ID); lerr == nil && latest.Status == "running" {
			_ = s.stopTaskCodeAudit(ctx, latest, taskAuditProgressFromRun(latest), taskCodeAuditChunkOutcome{})
		}
		return AssessmentExecResult{CodeAuditRunID: &run.ID}, ctx.Err()
	}
	if runCtx.Err() != nil {
		if latest, lerr := s.m.pg.GetTaskCodeAudit(taskIDInt, run.ID); lerr == nil && latest.Status == "running" {
			_ = s.stopTaskCodeAudit(runCtx, latest, taskAuditProgressFromRun(latest), taskCodeAuditChunkOutcome{})
		}
		return AssessmentExecResult{
			Outcome:        pgdb.AttemptFailed,
			CodeAuditRunID: &run.ID,
			IntentState:    "stopped",
			BlockedReason:  "白盒批量审计已停止并保留检查点，可续跑",
			Output: map[string]any{
				"code_audit_run_id": run.ID,
				"stopped":           true,
			},
		}, nil
	}

	finalRun, getErr := s.m.pg.GetTaskCodeAudit(taskIDInt, run.ID)
	if getErr != nil {
		return AssessmentExecResult{
			Outcome:        pgdb.AttemptFailed,
			CodeAuditRunID: &run.ID,
			BlockedReason:  fmt.Sprintf("读取审计运行 #%d 最终状态失败: %v", run.ID, getErr),
			IntentState:    "blocked",
		}, nil
	}

	if execErr != nil {
		if finalRun.Status == "running" {
			_ = s.m.pg.FailTaskCodeAudit(run.ID, trimAuditText(execErr.Error(), 400))
		}
		return AssessmentExecResult{
			Outcome:        pgdb.AttemptFailed,
			CodeAuditRunID: &finalRun.ID,
			BlockedReason:  execErr.Error(),
			IntentState:    "blocked",
			Output: map[string]any{
				"code_audit_run_id": finalRun.ID,
				"status":            finalRun.Status,
				"error":             execErr.Error(),
			},
		}, nil
	}

	ok, gateReason := pgdb.TaskCodeAuditCoverageAllowsCompletion(finalRun)
	if !ok {
		return AssessmentExecResult{
			Outcome:        pgdb.AttemptFailed,
			CodeAuditRunID: &finalRun.ID,
			BlockedReason:  gateReason,
			IntentState:    "blocked",
			Output: map[string]any{
				"code_audit_run_id": finalRun.ID,
				"status":            finalRun.Status,
				"files_analyzed":    finalRun.FilesAnalyzed,
				"files_total":       finalRun.FilesTotal,
				"chunks_completed":  finalRun.ChunksCompleted,
				"error":             finalRun.Error,
				"gate_reason":       gateReason,
			},
		}, nil
	}

	evPayload, _ := json.Marshal(map[string]any{
		"code_audit_run_id": finalRun.ID,
		"target_name":       target.Service.Name,
		"target_type":       target.TargetType,
		"relative_path":     target.Service.RelativePath,
		"files_analyzed":    finalRun.FilesAnalyzed,
		"files_total":       finalRun.FilesTotal,
		"chunks_completed":  finalRun.ChunksCompleted,
	})
	evRef := fmt.Sprintf("code_audit_run:%d:%s", finalRun.ID, target.Service.RelativePath)
	evID, evErr := s.m.pg.GetOrCreateEvidenceRef(taskIDInt, pgdb.EvidenceCodeRange, evRef, evPayload)
	if evErr != nil {
		return AssessmentExecResult{
			Outcome:        pgdb.AttemptFailed,
			CodeAuditRunID: &finalRun.ID,
			BlockedReason:  fmt.Sprintf("保存白盒审计覆盖证据引用失败: %v", evErr),
			IntentState:    "blocked",
		}, nil
	}

	return AssessmentExecResult{
		Outcome:           pgdb.AttemptSupported,
		EvidenceRefID:     &evID,
		CodeAuditRunID:    &finalRun.ID,
		SatisfyObligation: true,
		IntentState:       "done",
		Output: map[string]any{
			"code_audit_run_id": finalRun.ID,
			"target_name":       target.Service.Name,
			"target_type":       target.TargetType,
			"relative_path":     target.Service.RelativePath,
			"files_analyzed":    finalRun.FilesAnalyzed,
			"files_total":       finalRun.FilesTotal,
			"chunks_completed":  finalRun.ChunksCompleted,
			"candidates_count":  len(finalRun.Candidates),
			"evidence_ref_id":   evID,
		},
	}, nil
}

func (s *Server) runAssessmentCodeInvestigate(ctx context.Context, t *Task, slotName string, intent *pgdb.Node, meta pgdb.IntentAssessmentMeta, emit func(pgdb.Activity)) (AssessmentExecResult, error) {
	taskIDInt, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskIDInt <= 0 || s.m == nil || s.m.pg == nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptFailed,
			BlockedReason: "任务或数据库不可用，无法执行定向代码排查",
			IntentState:   "blocked",
		}, nil
	}
	ob, err := s.m.pg.GetCoverageObligation(taskIDInt, meta.ObligationID)
	if err != nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptDependencyMissing,
			BlockedReason: fmt.Sprintf("读取覆盖义务 #%d 失败: %v", meta.ObligationID, err),
			IntentState:   "blocked",
		}, nil
	}
	target, err := s.resolveAssessmentAuditTarget(taskIDInt, ob, true)
	if err != nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptDependencyMissing,
			BlockedReason: err.Error(),
			IntentState:   "blocked",
		}, nil
	}
	codebase, err := s.loadTaskCodeAuditCodebase(ctx, taskIDInt, target.Service, target.Version, ".")
	if err != nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptDependencyMissing,
			BlockedReason: fmt.Sprintf("加载只读代码快照失败: %v", err),
			IntentState:   "blocked",
		}, nil
	}

	state := newTaskCodeAuditSourceState(codebase)
	state.ctx = ctx
	var stateMu sync.Mutex

	var jcdClient *taskJavaCodeDBClient
	if codebase.BinaryOnly() || (len(codebase.BinaryClassFiles) > 0 && countAuditFiles(codebase.Files, "java") == 0) {
		jcfg := s.probeJavaCodeDB()
		if jcfg.Ready {
			if workspace, werr := s.prepareTaskJavaCodeDBWorkspace(codebase, target.Service.ID, target.Version); werr == nil {
				if client, cerr := startTaskJavaCodeDB(ctx, jcfg, workspace); cerr == nil {
					if _, ierr := client.waitForIndex(ctx); ierr == nil {
						jcdClient = client
						state.javaCodeDB = client
					} else {
						client.close()
					}
				}
			}
		}
	}
	if jcdClient != nil {
		defer jcdClient.close()
	}

	wrapReadSchema := func(schema llm.ToolSchema, isBinary bool) actool.CoreTool {
		toolName := schema.Name
		return actool.Build(actool.Spec{
			Name:        toolName,
			Description: schema.Description,
			Schema:      schema.InputSchema,
			ReadOnly:    func(json.RawMessage) bool { return true },
			Concurrent:  func(json.RawMessage) bool { return true },
			Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
			Run: func(callCtx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
				stateMu.Lock()
				defer stateMu.Unlock()
				state.ctx = callCtx
				var (
					resText string
					callErr error
				)
				if isBinary {
					resText, callErr = state.callJavaCodeDB(toolName, in)
				} else {
					resText, callErr = state.call(toolName, in)
				}
				if callErr != nil {
					if strings.TrimSpace(resText) != "" {
						return actool.Errorf(resText), nil
					}
					return actool.Errorf(callErr.Error()), nil
				}
				return actool.Text(resText), nil
			},
		})
	}

	readTools := make([]actool.CoreTool, 0, len(taskCodeAuditTools)+len(taskCodeAuditBinaryTools))
	for _, sc := range taskCodeAuditTools {
		readTools = append(readTools, wrapReadSchema(sc, false))
	}
	if jcdClient != nil {
		for _, sc := range taskCodeAuditBinaryTools {
			readTools = append(readTools, wrapReadSchema(sc, true))
		}
	}

	verifyRead := func(filePath string, line int, excerpt string) error {
		clean := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(filePath)), "./")
		if clean == "" || line <= 0 {
			return errors.New("path 与 line(>0) 必填")
		}
		stateMu.Lock()
		defer stateMu.Unlock()
		vis := state.visible[clean]
		if vis == nil || !vis[line] {
			return fmt.Errorf("文件 %s 第 %d 行尚未通过只读 read_file/read_class 实际读取", clean, line)
		}
		if strings.TrimSpace(excerpt) != "" {
			win := normalizeAuditExcerptText(state.windowText(clean, line, 5))
			want := normalizeAuditExcerptText(excerpt)
			if want != "" && !strings.Contains(win, want) {
				return fmt.Errorf("提供的摘录内容与 %s:%d 附近已读源码不匹配", clean, line)
			}
		}
		return nil
	}

	var wk *agent.Worker
	if s.taskRuntimeAvailable(t, "code_investigate") || s.taskRuntimeAvailable(t, "worker") {
		wk = s.agentsForTask(t).wk
	}
	if wk == nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptDependencyMissing,
			BlockedReason: "当前任务未配置可用的 LLM Worker，无法运行 code_investigate",
			IntentState:   "blocked",
		}, nil
	}

	obRoundID := obligationRoundID(ob, meta.RoundID)
	round, rerr := s.m.pg.OpenAssessmentRound(taskIDInt)
	if rerr != nil || round == nil {
		round = &pgdb.AssessmentRound{ID: obRoundID, RoundNo: 1, ProfileVersion: 1}
	}
	lifecycle := t.lifecycleSnapshot()
	profileSlice := s.buildAssessmentAuditProfileContext(taskIDInt, obRoundID, target.Service.Name, ob.Dimension, ob.Purpose)
	var objBuf strings.Builder
	fmt.Fprintf(&objBuf, "义务 #%d（维度=%s，目的=%s，目标=%s[%s]）", ob.ID, ob.Dimension, ob.Purpose, target.Service.Name, target.TargetType)
	if len(ob.ContextSnapshot) > 0 {
		objBuf.WriteString("\n上下文快照：")
		objBuf.WriteString(trimAuditText(string(ob.ContextSnapshot), 1200))
	}

	ic := agent.CodeInvestigateContext{
		PG:                 s.m.pg,
		TaskID:             taskIDInt,
		RoundID:            obRoundID,
		RoundNo:            round.RoundNo,
		ProfileVersion:     round.ProfileVersion,
		ObligationID:       ob.ID,
		AttemptID:          meta.AttemptID,
		ScopeNotes:         lifecycle.AssessmentConfig.ScopeNotes,
		ReadTools:          readTools,
		VerifyEvidenceRead: verifyRead,
		Objective:          objBuf.String(),
		ProfileSlice:       profileSlice,
	}

	hooks := steerHooks{
		drain:  func() (string, bool) { return s.engine.drainSteer(intent.ID) },
		nudges: new(atomic.Int64),
		limit:  s.engine.emptyTurnNudgeLimit(),
		label:  fmt.Sprintf("%s · #%d", slotName, intent.ID),
	}
	outcome, reason, runErr := wk.ExecuteCodeInvestigate(ctx, slotName, ic, t.Store, intent, hooks, emit)
	if ctx.Err() != nil {
		return AssessmentExecResult{}, ctx.Err()
	}
	if runErr != nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptFailed,
			BlockedReason: runErr.Error(),
			IntentState:   "blocked",
		}, nil
	}
	if !outcome.Submitted {
		stateName := "blocked"
		blockedMsg := "定向代码排查未提交经实读核验的 submit_investigation_result 结论"
		if reason == "max_turns" || reason == "timeout" {
			stateName = "exhausted"
			blockedMsg = "定向代码排查达到步数/时间上限且未提交结论"
		}
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptFailed,
			BlockedReason: blockedMsg,
			IntentState:   stateName,
			Output: map[string]any{
				"terminal_reason": reason,
				"submitted":       false,
			},
		}, nil
	}
	if outcome.Verdict == "blocked" {
		return AssessmentExecResult{
			Outcome:           pgdb.AttemptDependencyMissing,
			EvidenceRefID:     outcome.EvidenceRefID,
			SatisfyObligation: false,
			BlockedReason:     outcome.BlockedReason,
			IntentState:       "blocked",
			Output: map[string]any{
				"verdict":        outcome.Verdict,
				"summary":        outcome.Summary,
				"blocked_reason": outcome.BlockedReason,
				"followups":      outcome.Followups,
			},
		}, nil
	}
	if outcome.EvidenceRefID == nil || *outcome.EvidenceRefID <= 0 {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptFailed,
			BlockedReason: "定向代码排查结论缺少持久化 code_range 证据引用",
			IntentState:   "blocked",
		}, nil
	}
	attemptOutcome := pgdb.AttemptSupported
	if outcome.Verdict == "cleared" {
		attemptOutcome = pgdb.AttemptDisproved
	}
	return AssessmentExecResult{
		Outcome:           attemptOutcome,
		EvidenceRefID:     outcome.EvidenceRefID,
		SatisfyObligation: true,
		IntentState:       "done",
		Output: map[string]any{
			"verdict":         outcome.Verdict,
			"summary":         outcome.Summary,
			"evidence_ref_id": *outcome.EvidenceRefID,
			"evidence":        outcome.Evidence,
			"followups":       outcome.Followups,
		},
	}, nil
}

func normalizeAuditExcerptText(raw string) string {
	lines := strings.Split(raw, "\n")
	parts := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if idx := strings.Index(trimmed, ": "); idx > 0 {
			if _, err := strconv.Atoi(strings.TrimSpace(trimmed[:idx])); err == nil {
				trimmed = strings.TrimSpace(trimmed[idx+2:])
			}
		}
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
}

func (s *Server) assessmentMainAgentTools(t *Task, taskID int64, round *pgdb.AssessmentRound, sourceAcknowledged bool) []actool.CoreTool {
	jsonOut := func(v any) actool.Result {
		b, _ := json.Marshal(v)
		return actool.Text(string(b))
	}

	listModules := actool.Build(actool.Spec{
		Name:        "list_code_modules",
		Description: "查询本任务已发现的代码服务、非服务模块、共享库及其当前白盒审计覆盖进展。只读。",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var roundID int64
			if round != nil {
				roundID = round.ID
			}
			var entities []pgdb.TargetEntity
			if roundID > 0 {
				all, err := s.m.pg.ListTargetEntities(pgdb.TargetEntityFilter{TaskID: taskID, RoundID: roundID, Limit: 500})
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				for _, e := range all {
					switch e.EntityType {
					case "service", "module", "shared_library":
						entities = append(entities, e)
					}
				}
			}
			services, _, _ := s.m.pg.ListTaskCodeServices(taskID)
			cov, _ := s.m.pg.ListCodeAuditCoverageSummaries(taskID, 100)
			return jsonOut(map[string]any{
				"round_id":      roundID,
				"modules":       entities,
				"code_services": services,
				"coverage":      cov,
			}), nil
		},
	})

	listAudits := actool.Build(actool.Spec{
		Name:        "list_code_audits",
		Description: "查询本任务白盒批量审计运行记录（涵盖 engine 与 queue 来源、检查点进度、已分析文件数与候选数）。只读。",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			runs, err := s.m.pg.ListTaskCodeAudits(taskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			type item struct {
				ID              int64  `json:"id"`
				ServiceName     string `json:"service_name"`
				TargetName      string `json:"target_name"`
				TargetType      string `json:"target_type"`
				RelativePath    string `json:"relative_path"`
				ExecutionOrigin string `json:"execution_origin"`
				ObligationID    *int64 `json:"obligation_id,omitempty"`
				Status          string `json:"status"`
				FilesAnalyzed   int    `json:"files_analyzed"`
				FilesTotal      int    `json:"files_total"`
				ChunksCompleted int    `json:"chunks_completed"`
				ChunksTotal     int    `json:"chunks_total"`
				NextFileIndex   int    `json:"next_file_index"`
				CandidatesCount int    `json:"candidates_count"`
				Error           string `json:"error,omitempty"`
				Summary         string `json:"summary,omitempty"`
			}
			items := make([]item, 0, len(runs))
			for _, r := range runs {
				items = append(items, item{
					ID:              r.ID,
					ServiceName:     r.ServiceName,
					TargetName:      r.ServiceName,
					TargetType:      r.TargetType,
					RelativePath:    r.RelativePath,
					ExecutionOrigin: r.ExecutionOrigin,
					ObligationID:    r.ObligationID,
					Status:          r.Status,
					FilesAnalyzed:   r.FilesAnalyzed,
					FilesTotal:      r.FilesTotal,
					ChunksCompleted: r.ChunksCompleted,
					ChunksTotal:     r.ChunksTotal,
					NextFileIndex:   r.NextFileIndex,
					CandidatesCount: len(r.Candidates),
					Error:           r.Error,
					Summary:         trimAuditText(r.Summary, 400),
				})
			}
			return jsonOut(map[string]any{"runs": items}), nil
		},
	})

	dispatchWork := actool.Build(actool.Spec{
		Name:        "dispatch_assessment_work",
		Description: "在用户明确确认且 source_acknowledged=true 的前提下，为当前轮次的就绪覆盖/探索义务派发白盒工作（code_audit_batch 或 code_investigate）。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"obligation_id":  map[string]any{"type": "integer", "description": "要派发的覆盖或探索义务 ID"},
				"execution_mode": map[string]any{"type": "string", "description": "执行器模式：code_audit_batch | code_investigate"},
				"summary":        map[string]any{"type": "string", "description": "本次派工目标摘要"},
				"priority":       map[string]any{"type": "integer", "description": "优先级 1..10（默认 8）"},
				"confirm":        map[string]any{"type": "boolean", "description": "必须为 true：确认用户在本轮对话中明确要求立即派发该白盒工作"},
			},
			"required": []string{"obligation_id", "execution_mode", "summary", "confirm"},
		},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				ObligationID  int64  `json:"obligation_id"`
				ExecutionMode string `json:"execution_mode"`
				Summary       string `json:"summary"`
				Priority      int    `json:"priority"`
				Confirm       bool   `json:"confirm"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("参数 JSON 解析失败: %v", err)), nil
			}
			if !a.Confirm {
				return actool.Errorf("未获得用户明确确认（confirm 必须为 true），禁止直接派发白盒审计"), nil
			}
			if !sourceAcknowledged {
				return actool.Errorf("source_acknowledged=false：必须先确认本任务源码范围与白盒审计授权后再派发"), nil
			}
			if t == nil || t.Store == nil {
				return actool.Errorf("任务上下文不可用"), nil
			}
			if round == nil || round.Status != "open" {
				return actool.Errorf("当前没有进行中的评估轮次（任务可能尚未启动或已结束）"), nil
			}
			if a.ObligationID <= 0 || strings.TrimSpace(a.Summary) == "" {
				return actool.Errorf("obligation_id(>0) 与 summary 必填"), nil
			}
			mode := strings.TrimSpace(a.ExecutionMode)
			switch mode {
			case pgdb.ExecModeCodeAuditBatch, pgdb.ExecModeCodeInvestigate:
			default:
				return actool.Errorf("dispatch_assessment_work 仅支持 code_audit_batch 或 code_investigate"), nil
			}
			_, _, _ = s.m.pg.ReconcileObligationReadiness(taskID, round.ID)
			ok, reason, err := s.m.pg.IsObligationExecutable(taskID, a.ObligationID, round.ID, 0)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if !ok {
				return actool.Errorf(fmt.Sprintf("义务 #%d 当前不可派发：%s", a.ObligationID, reason)), nil
			}
			prio := a.Priority
			if prio <= 0 {
				prio = 8
			}
			res, err := s.m.pg.DispatchAssessmentIntent(pgdb.DispatchAssessmentIntentInput{
				TaskID:         taskID,
				RoundID:        round.ID,
				ObligationID:   a.ObligationID,
				ExecutionMode:  mode,
				Summary:        strings.TrimSpace(a.Summary),
				Priority:       prio,
				IdempotencyKey: fmt.Sprintf("main:%d:%d:%s:v%d", round.ID, a.ObligationID, mode, round.ProfileVersion),
				Origin:         pgdb.ObligationOriginUser,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			lifecycle := t.lifecycleSnapshot()
			if !lifecycle.Paused && !lifecycle.Draft {
				t.Notify()
			}
			return jsonOut(map[string]any{
				"dispatched":  res,
				"task_paused": lifecycle.Paused,
			}), nil
		},
	})

	stopAudit := actool.Build(actool.Spec{
		Name:        "stop_code_audit",
		Description: "按用户要求停止一条正在运行或排队中的白盒批量审计，保留其检查点以便后续续跑。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"run_id": map[string]any{"type": "integer", "description": "要停止的审计运行 ID"},
			},
			"required": []string{"run_id"},
		},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				RunID int64 `json:"run_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil || a.RunID <= 0 {
				return actool.Errorf("run_id(>0) 必填"), nil
			}
			status, err := s.requestStopTaskCodeAudit(taskID, a.RunID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if t != nil {
				t.Notify()
			}
			return jsonOut(map[string]any{"run_id": a.RunID, "status": status}), nil
		},
	})

	return []actool.CoreTool{listModules, listAudits, dispatchWork, stopAudit}
}
