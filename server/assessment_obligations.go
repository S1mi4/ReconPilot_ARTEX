package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode"

	pgdb "github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const maxUngroupedConfigAuditObligations = 25

// AssessmentCoveragePlanResponse is returned by BuildAssessmentCoveragePlan and the
// coverage-plan HTTP / orchestration endpoints.
type AssessmentCoveragePlanResponse struct {
	TaskID          string                           `json:"task_id"`
	AssessmentPhase string                           `json:"assessment_phase"`
	ExecutionMode   string                           `json:"execution_mode"`
	Round           *pgdb.AssessmentRound            `json:"round,omitempty"`
	Rounds          []pgdb.AssessmentRound           `json:"rounds,omitempty"`
	Summary         []pgdb.DimensionCoverageSummary  `json:"summary"`
	Obligations     []pgdb.CoverageObligation        `json:"obligations"`
	RecentAttempts  []pgdb.TestAttempt               `json:"recent_attempts"`
	CodeAudits      []pgdb.CodeAuditCoverageSummary  `json:"code_audits,omitempty"`
	EvidenceRefs    []pgdb.EvidenceRef               `json:"evidence_refs,omitempty"`
	CompletionCheck *pgdb.AssessmentCompletionReport `json:"completion_check,omitempty"`
	UnresolvedGaps  int                              `json:"unresolved_gaps"`
}

// BuildAssessmentCoveragePlan deterministically builds required baseline coverage
// obligations, dependency links, idempotency keys, and initial readiness from the
// current round's target inventory and profile claims (§5.3/§5.4/§10 step 4).
func (s *Server) BuildAssessmentCoveragePlan(ctx context.Context, taskID string) (*AssessmentCoveragePlanResponse, int, error) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return nil, http.StatusServiceUnavailable, errors.New("database unavailable")
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, http.StatusRequestTimeout, ctx.Err()
	}
	if s.engine != nil && s.engine.IsDeleting(taskID) {
		return nil, http.StatusConflict, errors.New("任务正在删除，无法生成覆盖计划")
	}
	t, ok := s.m.Task(taskID)
	if !ok || t == nil {
		return nil, http.StatusNotFound, errors.New("task not found")
	}
	if !t.AssessmentMode {
		return nil, http.StatusBadRequest, pgdb.ErrTaskNotAssessmentMode
	}
	if t.IsDraft() {
		return nil, http.StatusConflict, errors.New("草稿任务尚未启动，不能生成覆盖计划")
	}
	lifecycle := t.lifecycleSnapshot()
	if pgdb.IsTerminal(lifecycle.Status) {
		return nil, http.StatusConflict, errors.New("已结束任务不能生成覆盖计划")
	}
	taskNum, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || taskNum <= 0 {
		return nil, http.StatusBadRequest, errors.New("invalid task id")
	}

	s.coveragePlanMu.Lock()
	defer s.coveragePlanMu.Unlock()

	if s.engine != nil && s.engine.IsDeleting(taskID) {
		return nil, http.StatusConflict, errors.New("任务正在删除，无法生成覆盖计划")
	}

	round, err := s.m.pg.OpenAssessmentRound(taskNum)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if round == nil {
		return nil, http.StatusConflict, errors.New("没有进行中的评估轮次")
	}

	if t.lifecycleSnapshot().AssessmentPhase == pgdb.AssessmentPhaseProfiling {
		if err := s.m.SetAssessmentPhase(taskID, pgdb.AssessmentPhaseCoveragePlanning); err != nil {
			return nil, http.StatusInternalServerError, err
		}
	}

	entities, err := s.m.pg.ListTargetEntities(pgdb.TargetEntityFilter{
		TaskID:  taskNum,
		RoundID: round.ID,
		Limit:   1000,
	})
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	claims, err := s.m.pg.ListProfileClaims(pgdb.ProfileClaimFilter{
		TaskID:  taskNum,
		RoundID: round.ID,
		Limit:   1000,
	})
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	var (
		codeModules   []pgdb.TargetEntity
		configs       []pgdb.TargetEntity
		runtimeAssets []pgdb.TargetEntity
		entries       []pgdb.TargetEntity
		identities    []pgdb.TargetEntity
		hasSharedLib  bool
		unresolvedGap int
	)
	for _, ent := range entities {
		if ent.Gap {
			if !ent.Resolved {
				unresolvedGap++
			}
			continue // 缺口保留在缺口清单，绝不静默消失或冒充覆盖分母
		}
		switch ent.EntityType {
		case "service", "module", "shared_library":
			if ent.EntityType == "shared_library" {
				hasSharedLib = true
			}
			codeModules = append(codeModules, ent)
		case "config":
			configs = append(configs, ent)
		case "instance", "runtime_asset":
			runtimeAssets = append(runtimeAssets, ent)
		case "entry":
			entries = append(entries, ent)
		case "identity":
			identities = append(identities, ent)
		case "external_dependency":
			// 外部依赖只进入画像上下文，绝不自动扩展测试授权或生成主动测试义务（§1.1/§7.3）
		}
	}

	// 1. code_audit obligations for services, modules, and shared libraries (online + offline).
	codeAuditIDs := make([]int64, 0, len(codeModules))
	for _, mod := range codeModules {
		prio := 7
		if mod.EntityType == "service" {
			prio = 8
		}
		dedupe := fmt.Sprintf("code_audit:%s:%s:%s",
			mod.EntityType,
			firstNonEmpty(mod.CodebaseID, "-"),
			normalizeObligationDedupeToken(firstNonEmpty(extractEntityAttrString(mod.Attributes, "rel_path"), mod.Name)),
		)
		snap, _ := json.Marshal(map[string]any{
			"entity_type": mod.EntityType,
			"name":        mod.Name,
			"codebase_id": mod.CodebaseID,
			"version_id":  mod.VersionID,
		})
		rule, _ := json.Marshal(map[string]any{
			"required_evidence": "code_audit_coverage_ledger",
			"require_real_read": true,
		})
		ob, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID:          taskNum,
			RoundID:         &round.ID,
			Dimension:       pgdb.DimensionCodeAudit,
			TargetEntityID:  &mod.ID,
			Purpose:         fmt.Sprintf("白盒静态审计%s「%s」（含真实读取与分析台账及 A/B/C 线索登记）", entityTypeDisplayLabel(mod.EntityType), mod.Name),
			Required:        true,
			DedupeKey:       dedupe,
			AcceptanceRule:  rule,
			ExecutionMode:   pgdb.ExecModeCodeAuditBatch,
			Origin:          pgdb.ObligationOriginProgram,
			Priority:        prio,
			ProfileVersion:  round.ProfileVersion,
			ContextSnapshot: snap,
		})
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
		codeAuditIDs = append(codeAuditIDs, ob.ID)
	}

	// 2. config_audit obligations (grouped by codebase/top-dir if > 25 configs).
	if err := s.createConfigAuditObligations(taskNum, round, configs); err != nil {
		return nil, http.StatusInternalServerError, err
	}

	execMode := strings.TrimSpace(lifecycle.AssessmentConfig.ExecutionMode)
	if execMode == "" {
		execMode = pgdb.AssessmentExecDynamic
	}
	isDynamic := execMode != pgdb.AssessmentExecOffline

	// Map code module subject -> mapped instance names from deployed_to_instance claims.
	moduleToInstances := map[string][]string{}
	hasCrossModuleClaim := false
	for _, cl := range claims {
		if cl.Relation == "deployed_to_instance" && strings.HasPrefix(cl.ObjectValue, "instance:") {
			instName := strings.TrimPrefix(cl.ObjectValue, "instance:")
			moduleToInstances[strings.ToLower(cl.Subject)] = append(moduleToInstances[strings.ToLower(cl.Subject)], instName)
		}
		if cl.Relation == "depends_on" || cl.Relation == "calls" || cl.Relation == "cross_module" {
			hasCrossModuleClaim = true
		}
	}

	var runtimeIDs []int64
	runtimeByName := map[string]int64{}
	if isDynamic {
		// 3. runtime_asset obligations (highest priority to unlock entry/identity tests).
		for _, rt := range runtimeAssets {
			dedupe := fmt.Sprintf("runtime_asset:%s:%s", rt.EntityType, normalizeObligationDedupeToken(rt.Name))
			snap, _ := json.Marshal(map[string]any{
				"entity_type": rt.EntityType,
				"name":        rt.Name,
				"attributes":  json.RawMessage(nonEmptyJSON(rt.Attributes)),
			})
			rule, _ := json.Marshal(map[string]any{
				"required_evidence": "execution_or_traffic",
				"verify_target":     "deployed_version_and_reachability",
			})
			ob, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
				TaskID:          taskNum,
				RoundID:         &round.ID,
				Dimension:       pgdb.DimensionRuntimeAsset,
				TargetEntityID:  &rt.ID,
				Purpose:         fmt.Sprintf("核实运行环境「%s」的可达性、版本对应关系与配置一致性", rt.Name),
				Required:        true,
				DedupeKey:       dedupe,
				AcceptanceRule:  rule,
				ExecutionMode:   pgdb.ExecModeDynamicVerify,
				Origin:          pgdb.ObligationOriginProgram,
				Priority:        9,
				ProfileVersion:  round.ProfileVersion,
				ContextSnapshot: snap,
			})
			if err != nil {
				return nil, http.StatusInternalServerError, err
			}
			runtimeIDs = append(runtimeIDs, ob.ID)
			runtimeByName[normalizeObligationDedupeToken(rt.Name)] = ob.ID
		}

		// 4. entry_test obligations (all discovered entries, even without static candidates).
		for _, ent := range entries {
			dedupe := fmt.Sprintf("entry_test:%s:%s", firstNonEmpty(ent.CodebaseID, "-"), normalizeObligationDedupeToken(ent.Name))
			deps := resolveEntryRuntimeDeps(ent, moduleToInstances, runtimeByName, runtimeIDs)
			initStatus := pgdb.ObligationPending
			blockedReason := ""
			if len(runtimeIDs) == 0 {
				initStatus = pgdb.ObligationBlocked
				blockedReason = "动态评估模式缺少已映射的授权测试环境实例（instance/runtime_asset），无法满足入口动态测试前置条件"
			}
			snap, _ := json.Marshal(map[string]any{
				"entity_type": ent.EntityType,
				"name":        ent.Name,
				"codebase_id": ent.CodebaseID,
				"attributes":  json.RawMessage(nonEmptyJSON(ent.Attributes)),
			})
			rule, _ := json.Marshal(map[string]any{
				"required_evidence": "effective_dynamic_attempt",
			})
			if _, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
				TaskID:          taskNum,
				RoundID:         &round.ID,
				Dimension:       pgdb.DimensionEntryTest,
				TargetEntityID:  &ent.ID,
				Purpose:         fmt.Sprintf("对入口「%s」执行动态覆盖与安全检查（不依赖静态候选）", ent.Name),
				Required:        true,
				DedupeKey:       dedupe,
				InitialStatus:   initStatus,
				BlockedReason:   blockedReason,
				AcceptanceRule:  rule,
				ExecutionMode:   pgdb.ExecModeDynamicVerify,
				Origin:          pgdb.ObligationOriginProgram,
				Priority:        7,
				ProfileVersion:  round.ProfileVersion,
				DependencyIDs:   deps,
				ContextSnapshot: snap,
			}); err != nil {
				return nil, http.StatusInternalServerError, err
			}
		}

		// 5. identity_resource equivalence-group obligations (one per identity, no cartesian explosion).
		for _, idEnt := range identities {
			var idCfg pgdb.AssessmentIdentityInput
			if len(idEnt.Attributes) > 0 {
				_ = json.Unmarshal(idEnt.Attributes, &idCfg)
			}
			roleName := firstNonEmpty(strings.TrimSpace(idCfg.Role), idEnt.Name)
			isAnonymous := isAnonymousRoleName(roleName)
			reqCreds := !isAnonymous
			credRef := strings.TrimSpace(idCfg.CredentialRef)

			initStatus := pgdb.ObligationPending
			blockedReason := ""
			if len(runtimeIDs) == 0 {
				initStatus = pgdb.ObligationBlocked
				blockedReason = "动态评估模式缺少已映射的授权测试环境实例，无法执行身份与资源归属验证"
			} else if reqCreds && credRef == "" {
				initStatus = pgdb.ObligationBlocked
				blockedReason = fmt.Sprintf("身份等价组「%s」缺少测试凭证引用（credential_ref），需补充有效凭证引用后执行", roleName)
			}
			dedupe := fmt.Sprintf("identity_resource:%s", normalizeObligationDedupeToken(roleName))
			snap, _ := json.Marshal(map[string]any{
				"role":      roleName,
				"auth_type": idCfg.AuthType,
				"scope":     idCfg.Scope,
				"anonymous": isAnonymous,
			})
			rule, _ := json.Marshal(map[string]any{
				"required_evidence": "effective_dynamic_attempt",
				"equivalence_group": roleName,
			})
			if _, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
				TaskID:              taskNum,
				RoundID:             &round.ID,
				Dimension:           pgdb.DimensionIdentityResource,
				TargetEntityID:      &idEnt.ID,
				Purpose:             fmt.Sprintf("验证身份等价组「%s」的权限边界、资源归属与租户隔离", roleName),
				Required:            true,
				DedupeKey:           dedupe,
				RequiresCredentials: reqCreds,
				CredentialRef:       credRef,
				InitialStatus:       initStatus,
				BlockedReason:       blockedReason,
				AcceptanceRule:      rule,
				ExecutionMode:       pgdb.ExecModeDynamicVerify,
				Origin:              pgdb.ObligationOriginProgram,
				Priority:            7,
				ProfileVersion:      round.ProfileVersion,
				DependencyIDs:       runtimeIDs,
				ContextSnapshot:     snap,
			}); err != nil {
				return nil, http.StatusInternalServerError, err
			}
		}
	}

	// 6. cross_module closure obligation when >=2 modules, shared library + service, or cross-module claim exists.
	if len(codeModules) >= 2 || hasSharedLib || hasCrossModuleClaim {
		crossMode := pgdb.ExecModeCodeInvestigate
		var crossDeps []int64
		crossDeps = append(crossDeps, codeAuditIDs...)
		initStatus := pgdb.ObligationPending
		blockedReason := ""
		if isDynamic {
			crossMode = pgdb.ExecModeDynamicVerify
			crossDeps = append(crossDeps, runtimeIDs...)
			if len(runtimeIDs) == 0 {
				initStatus = pgdb.ObligationBlocked
				blockedReason = "跨模块动态链路验证缺少授权测试环境实例映射"
			}
		}
		rule, _ := json.Marshal(map[string]any{
			"required_evidence": "cross_module_closure",
		})
		if _, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID:         taskNum,
			RoundID:        &round.ID,
			Dimension:      pgdb.DimensionCrossModule,
			Purpose:        "执行跨模块收尾检查：核对共享库、服务间调用、身份与状态传递链一致性",
			Required:       true,
			DedupeKey:      "cross_module:round_closure",
			InitialStatus:  initStatus,
			BlockedReason:  blockedReason,
			AcceptanceRule: rule,
			ExecutionMode:  crossMode,
			Origin:         pgdb.ObligationOriginProgram,
			Priority:       5,
			ProfileVersion: round.ProfileVersion,
			DependencyIDs:  crossDeps,
		}); err != nil {
			return nil, http.StatusInternalServerError, err
		}
	}

	// 7. hypothesis obligations for conflicted profile claims.
	for _, cl := range claims {
		if cl.ConfirmationStatus != pgdb.ClaimStatusConflicted {
			continue
		}
		hypMode := pgdb.ExecModeCodeInvestigate
		var hypDeps []int64
		if isDynamic && len(runtimeIDs) > 0 {
			hypMode = pgdb.ExecModeDynamicVerify
			hypDeps = runtimeIDs
		}
		snap, _ := json.Marshal(map[string]any{
			"claim_id":      cl.ID,
			"subject":       cl.Subject,
			"relation":      cl.Relation,
			"object_value":  cl.ObjectValue,
			"conflict_note": cl.ConflictNote,
		})
		if _, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID:          taskNum,
			RoundID:         &round.ID,
			Dimension:       pgdb.DimensionHypothesis,
			Purpose:         fmt.Sprintf("核查画像冲突断言：%s %s = %s（%s）", cl.Subject, cl.Relation, cl.ObjectValue, firstNonEmpty(cl.ConflictNote, "存在相互矛盾来源")),
			Required:        true,
			DedupeKey:       fmt.Sprintf("hypothesis:conflict:%d", cl.ID),
			ExecutionMode:   hypMode,
			Origin:          pgdb.ObligationOriginProgram,
			Priority:        8,
			ProfileVersion:  round.ProfileVersion,
			DependencyIDs:   hypDeps,
			ContextSnapshot: snap,
		}); err != nil {
			return nil, http.StatusInternalServerError, err
		}
	}

	if err := s.ensureStaticHypothesisObligationsForRound(t, round, runtimeIDs); err != nil {
		return nil, http.StatusInternalServerError, err
	}

	// Reconcile pending -> ready / blocked purely from dependency_ids and credential_ref.
	_, _, err = s.m.pg.ReconcileObligationReadiness(taskNum, round.ID)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	curPhase := t.lifecycleSnapshot().AssessmentPhase
	if curPhase == pgdb.AssessmentPhaseProfiling || curPhase == pgdb.AssessmentPhaseCoveragePlanning {
		if err := s.m.SetAssessmentPhase(taskID, pgdb.AssessmentPhaseExecuting); err != nil {
			return nil, http.StatusInternalServerError, err
		}
	}

	resp, code, err := s.buildAssessmentCoveragePlanResponse(t, round.ID, pgdb.CoverageObligationFilter{
		TaskID:  taskNum,
		RoundID: round.ID,
		Limit:   500,
	})
	if err != nil {
		return nil, code, err
	}
	if resp != nil && s.engine != nil {
		readyCnt, pendingCnt, blockedCnt := countObligationsByStatus(resp.Obligations)
		s.engine.emitActivity(t, pgdb.Activity{
			Worker: "system",
			Kind:   "text",
			Summary: fmt.Sprintf("第 %d 轮覆盖计划已就绪：共 %d 条必需义务（ready %d / pending %d / blocked %d），未对账缺口 %d 个",
				round.RoundNo, len(resp.Obligations), readyCnt, pendingCnt, blockedCnt, unresolvedGap),
		})
	}
	return resp, http.StatusOK, nil
}

func (s *Server) createConfigAuditObligations(taskNum int64, round *pgdb.AssessmentRound, configs []pgdb.TargetEntity) error {
	if len(configs) == 0 {
		return nil
	}
	if len(configs) <= maxUngroupedConfigAuditObligations {
		for _, cfg := range configs {
			dedupe := fmt.Sprintf("config_audit:%s:%s", firstNonEmpty(cfg.CodebaseID, "-"), normalizeObligationDedupeToken(cfg.Name))
			snap, _ := json.Marshal(map[string]any{
				"entity_type": cfg.EntityType,
				"name":        cfg.Name,
				"codebase_id": cfg.CodebaseID,
				"version_id":  cfg.VersionID,
			})
			rule, _ := json.Marshal(map[string]any{
				"required_evidence": "config_analysis",
			})
			if _, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
				TaskID:          taskNum,
				RoundID:         &round.ID,
				Dimension:       pgdb.DimensionConfigAudit,
				TargetEntityID:  &cfg.ID,
				Purpose:         fmt.Sprintf("审计安全与部署配置文件「%s」的有效生效条件及安全影响", cfg.Name),
				Required:        true,
				DedupeKey:       dedupe,
				AcceptanceRule:  rule,
				ExecutionMode:   pgdb.ExecModeCodeInvestigate,
				Origin:          pgdb.ObligationOriginProgram,
				Priority:        7,
				ProfileVersion:  round.ProfileVersion,
				ContextSnapshot: snap,
			}); err != nil {
				return err
			}
		}
		return nil
	}

	type configGroup struct {
		key       string
		firstEnt  pgdb.TargetEntity
		names     []string
		entityIDs []int64
	}
	groupOrder := []string{}
	groups := map[string]*configGroup{}
	for _, cfg := range configs {
		topDir := topConfigDirectory(firstNonEmpty(extractEntityAttrString(cfg.Attributes, "rel_path"), cfg.Name))
		key := fmt.Sprintf("config_audit:group:%s:%s", firstNonEmpty(cfg.CodebaseID, "-"), topDir)
		g, ok := groups[key]
		if !ok {
			g = &configGroup{key: key, firstEnt: cfg}
			groups[key] = g
			groupOrder = append(groupOrder, key)
		}
		g.names = append(g.names, cfg.Name)
		g.entityIDs = append(g.entityIDs, cfg.ID)
	}
	sort.Strings(groupOrder)
	for _, key := range groupOrder {
		g := groups[key]
		snap, _ := json.Marshal(map[string]any{
			"grouped":         true,
			"grouped_configs": g.names,
			"entity_ids":      g.entityIDs,
		})
		rule, _ := json.Marshal(map[string]any{
			"required_evidence": "config_analysis",
			"grouped_count":     len(g.names),
		})
		if _, err := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID:          taskNum,
			RoundID:         &round.ID,
			Dimension:       pgdb.DimensionConfigAudit,
			TargetEntityID:  &g.firstEnt.ID,
			Purpose:         fmt.Sprintf("分组审计配置目录「%s」（含 %d 个配置文件）的生效条件与安全影响", g.firstEnt.Name, len(g.names)),
			Required:        true,
			DedupeKey:       g.key,
			AcceptanceRule:  rule,
			ExecutionMode:   pgdb.ExecModeCodeInvestigate,
			Origin:          pgdb.ObligationOriginProgram,
			Priority:        7,
			ProfileVersion:  round.ProfileVersion,
			ContextSnapshot: snap,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) buildAssessmentCoveragePlanResponse(t *Task, roundID int64, filter pgdb.CoverageObligationFilter) (*AssessmentCoveragePlanResponse, int, error) {
	taskNum, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskNum <= 0 {
		return nil, http.StatusBadRequest, errors.New("invalid task id")
	}
	var round *pgdb.AssessmentRound
	if roundID > 0 {
		round, err = s.m.pg.GetAssessmentRound(taskNum, roundID)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
		if round == nil {
			return nil, http.StatusNotFound, errors.New("未找到指定的评估轮次")
		}
	} else {
		round, err = s.m.pg.LatestAssessmentRound(taskNum)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
		if round == nil {
			return nil, http.StatusNotFound, errors.New("未找到评估轮次")
		}
	}
	if filter.RoundID == 0 {
		if roundID > 0 {
			filter.RoundID = roundID
		} else {
			filter.RoundID = round.ID
		}
	}
	filter.TaskID = taskNum

	obligations, err := s.m.pg.ListCoverageObligations(filter)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	summary, err := s.m.pg.GetCoverageSummaryByDimension(taskNum, filter.RoundID)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	attempts, err := s.m.pg.ListTestAttempts(taskNum, filter.RoundID, 0, 100)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	gapEntities, err := s.m.pg.ListTargetEntities(pgdb.TargetEntityFilter{
		TaskID:  taskNum,
		RoundID: filter.RoundID,
		GapOnly: true,
		Limit:   500,
	})
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	unresolvedGaps := 0
	for _, g := range gapEntities {
		if !g.Resolved {
			unresolvedGaps++
		}
	}

	rounds, _ := s.m.pg.ListAssessmentRounds(taskNum)
	codeAudits, _ := s.m.pg.ListCodeAuditCoverageSummaries(taskNum, 100)
	evidenceRefs, _ := s.m.pg.ListEvidenceRefs(taskNum, nil, "")
	var completionCheck *pgdb.AssessmentCompletionReport
	if round.Status == "open" {
		completionCheck, _ = s.m.pg.AssessmentCompletionCheck(taskNum)
	} else if len(round.CompletionReport) > 0 {
		var historical pgdb.AssessmentCompletionReport
		if json.Unmarshal(round.CompletionReport, &historical) == nil && historical.TaskID > 0 {
			completionCheck = &historical
		}
	}

	lifecycle := t.lifecycleSnapshot()
	execMode := strings.TrimSpace(lifecycle.AssessmentConfig.ExecutionMode)
	if execMode == "" {
		execMode = pgdb.AssessmentExecDynamic
	}
	return &AssessmentCoveragePlanResponse{
		TaskID:          t.ID,
		AssessmentPhase: lifecycle.AssessmentPhase,
		ExecutionMode:   execMode,
		Round:           round,
		Rounds:          rounds,
		Summary:         summary,
		Obligations:     obligations,
		RecentAttempts:  attempts,
		CodeAudits:      codeAudits,
		EvidenceRefs:    evidenceRefs,
		CompletionCheck: completionCheck,
		UnresolvedGaps:  unresolvedGaps,
	}, http.StatusOK, nil
}

// GET /api/tasks/{id}/coverage-plan
func (s *Server) getTaskCoveragePlanHandler(w http.ResponseWriter, r *http.Request) {
	taskNum, ok := s.requireTaskInProject(w, r, r.PathValue("id"), true)
	if !ok {
		return
	}
	t, ok := s.m.Task(strconv.FormatInt(taskNum, 10))
	if !ok || t == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if !t.AssessmentMode {
		writeErr(w, http.StatusBadRequest, pgdb.ErrTaskNotAssessmentMode.Error())
		return
	}
	q := r.URL.Query()
	roundID, _ := strconv.ParseInt(strings.TrimSpace(q.Get("round_id")), 10, 64)
	limit, _ := strconv.Atoi(strings.TrimSpace(q.Get("limit")))
	resp, code, err := s.buildAssessmentCoveragePlanResponse(t, roundID, pgdb.CoverageObligationFilter{
		Status:        strings.TrimSpace(q.Get("status")),
		Dimension:     strings.TrimSpace(q.Get("dimension")),
		ExecutionMode: strings.TrimSpace(q.Get("execution_mode")),
		Origin:        strings.TrimSpace(q.Get("origin")),
		Limit:         limit,
	})
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/tasks/{id}/coverage-plan/generate
func (s *Server) generateTaskCoveragePlanHandler(w http.ResponseWriter, r *http.Request) {
	taskNum, ok := s.requireTaskInProject(w, r, r.PathValue("id"), true)
	if !ok {
		return
	}
	resp, code, err := s.BuildAssessmentCoveragePlan(r.Context(), strconv.FormatInt(taskNum, 10))
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) toolGetTaskCoveragePlan() actool.CoreTool {
	return roTool("get_task_coverage_plan",
		"读取白盒评估任务当前轮次的覆盖计划（各维度覆盖统计、覆盖义务状态、前置依赖与最近执行尝试）。",
		objSchema(map[string]any{
			"task_id":        strParam("评估任务 id"),
			"status":         strParam("可选状态过滤（pending/ready/running/satisfied/blocked/stale/not_applicable）"),
			"dimension":      strParam("可选维度过滤（code_audit/config_audit/entry_test/identity_resource/cross_module/runtime_asset/hypothesis）"),
			"execution_mode": strParam("可选执行器过滤（code_audit_batch/code_investigate/dynamic_verify）"),
			"limit":          map[string]any{"type": "integer", "description": "返回义务条数上限（默认 200）"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID        string `json:"task_id"`
				Status        string `json:"status"`
				Dimension     string `json:"dimension"`
				ExecutionMode string `json:"execution_mode"`
				Limit         int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t, err := s.requireToolTask(ctx, a.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if !t.AssessmentMode {
				return actool.Errorf(pgdb.ErrTaskNotAssessmentMode.Error()), nil
			}
			resp, _, bErr := s.buildAssessmentCoveragePlanResponse(t, 0, pgdb.CoverageObligationFilter{
				Status:        strings.TrimSpace(a.Status),
				Dimension:     strings.TrimSpace(a.Dimension),
				ExecutionMode: strings.TrimSpace(a.ExecutionMode),
				Limit:         a.Limit,
			})
			if bErr != nil {
				return actool.Errorf(bErr.Error()), nil
			}
			return jsonResult(resp)
		})
}

func (s *Server) toolGenerateTaskCoveragePlan() actool.CoreTool {
	return wrTool("generate_task_coverage_plan",
		"根据当前轮次画像清单确定性生成或幂等补齐必需覆盖义务与前置依赖（不删除已推进或既有必需义务）。",
		objSchema(map[string]any{
			"task_id": strParam("已启动的评估任务 id"),
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
			resp, _, bErr := s.BuildAssessmentCoveragePlan(ctx, t.ID)
			if bErr != nil {
				return actool.Errorf(bErr.Error()), nil
			}
			return jsonResult(resp)
		})
}

func normalizeObligationDedupeToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "-"
	}
	var b strings.Builder
	b.Grow(len(s))
	lastSep := false
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '/' || r == ':' || r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
			lastSep = false
		default:
			if !lastSep {
				b.WriteByte('_')
				lastSep = true
			}
		}
	}
	res := strings.Trim(b.String(), "_")
	if res == "" {
		return "-"
	}
	return res
}

func extractEntityAttrString(raw json.RawMessage, key string) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	v, _ := m[key].(string)
	return strings.TrimSpace(v)
}

func nonEmptyJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

func entityTypeDisplayLabel(t string) string {
	switch t {
	case "service":
		return "服务"
	case "shared_library":
		return "共享库"
	default:
		return "模块"
	}
}

func topConfigDirectory(relPath string) string {
	relPath = strings.Trim(strings.ReplaceAll(strings.TrimSpace(relPath), "\\", "/"), "/")
	if relPath == "" {
		return "root"
	}
	idx := strings.IndexByte(relPath, '/')
	if idx <= 0 {
		return "root"
	}
	return normalizeObligationDedupeToken(relPath[:idx])
}

func isAnonymousRoleName(role string) bool {
	lower := strings.ToLower(strings.TrimSpace(role))
	switch lower {
	case "", "anonymous", "anon", "guest", "unauthenticated", "public", "匿名", "游客", "未登录":
		return true
	default:
		return false
	}
}

func resolveEntryRuntimeDeps(ent pgdb.TargetEntity, moduleToInstances map[string][]string, runtimeByName map[string]int64, fallbackRuntimeIDs []int64) []int64 {
	if len(fallbackRuntimeIDs) == 0 {
		return nil
	}
	var matched []int64
	if len(ent.Attributes) > 0 {
		var attrs map[string]any
		if json.Unmarshal(ent.Attributes, &attrs) == nil {
			if modSub, _ := attrs["module_subject"].(string); modSub != "" {
				for _, instName := range moduleToInstances[strings.ToLower(strings.TrimSpace(modSub))] {
					if id, ok := runtimeByName[normalizeObligationDedupeToken(instName)]; ok && id > 0 {
						matched = append(matched, id)
					}
				}
			}
			if svcName, _ := attrs["service"].(string); len(matched) == 0 && svcName != "" {
				for _, instName := range moduleToInstances["service:"+strings.ToLower(strings.TrimSpace(svcName))] {
					if id, ok := runtimeByName[normalizeObligationDedupeToken(instName)]; ok && id > 0 {
						matched = append(matched, id)
					}
				}
			}
		}
	}
	if len(matched) > 0 {
		return matched
	}
	return fallbackRuntimeIDs
}

func countObligationsByStatus(items []pgdb.CoverageObligation) (ready, pending, blocked int) {
	for _, it := range items {
		switch it.Status {
		case pgdb.ObligationReady:
			ready++
		case pgdb.ObligationPending:
			pending++
		case pgdb.ObligationBlocked:
			blocked++
		}
	}
	return ready, pending, blocked
}
