package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Autumn-27/artex/agent"
	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) ensureStaticHypothesisObligations(ctx context.Context, taskID, roundID int64) error {
	if s == nil || s.m == nil || s.m.pg == nil || taskID <= 0 || roundID <= 0 {
		return nil
	}
	t := s.m.ResolveTask(strconv.FormatInt(taskID, 10))
	if t == nil {
		return nil
	}
	round, err := s.m.pg.OpenAssessmentRound(taskID)
	if err != nil || round == nil || round.ID != roundID {
		return err
	}
	obligations, err := s.m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{
		TaskID:  taskID,
		RoundID: round.ID,
		Limit:   500,
	})
	if err != nil {
		return err
	}
	var runtimeIDs []int64
	for _, ob := range obligations {
		if ob.Dimension == pgdb.DimensionRuntimeAsset {
			runtimeIDs = append(runtimeIDs, ob.ID)
		}
	}
	if err := s.ensureStaticHypothesisObligationsForRound(t, round, runtimeIDs); err != nil {
		return err
	}
	_, _, _ = s.m.pg.ReconcileObligationReadiness(taskID, round.ID)
	return nil
}

func (s *Server) ensureStaticHypothesisObligationsForRound(t *Task, round *pgdb.AssessmentRound, runtimeIDs []int64) error {
	if s == nil || s.m == nil || s.m.pg == nil || t == nil || round == nil {
		return nil
	}
	taskNum, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskNum <= 0 {
		return nil
	}
	execMode := strings.TrimSpace(t.lifecycleSnapshot().AssessmentConfig.ExecutionMode)
	if execMode == pgdb.AssessmentExecOffline {
		return nil
	}
	published, err := s.m.pg.ListPublishedCodeAuditFindings(taskNum)
	if err != nil || len(published) == 0 {
		return err
	}

	initStatus := pgdb.ObligationPending
	blockedReason := ""
	if len(runtimeIDs) == 0 {
		initStatus = pgdb.ObligationBlocked
		blockedReason = "动态评估模式缺少已映射的授权测试环境实例，暂无法对静态发现执行动态复现"
	}

	for _, cand := range published {
		dedupe := "hypothesis:finding:" + firstNonEmpty(strings.TrimSpace(cand.CandidateKey), fmt.Sprintf("run-%d-cand-%d", cand.RunID, cand.CandidateID))
		title := firstNonEmpty(strings.TrimSpace(cand.Title), firstNonEmpty(strings.TrimSpace(cand.VulnClass), cand.CandidateKey))
		anchors, why, exploitability, remediation := extractStaticCandidateDetails(cand.Candidate, cand.CodeAuditEvidence)
		snapMap := map[string]any{
			"static_only":       true,
			"candidate_key":     cand.CandidateKey,
			"candidate_id":      cand.CandidateID,
			"code_audit_run_id": cand.RunID,
			"vulnclass":         cand.VulnClass,
			"title":             title,
			"severity":          cand.Severity,
			"registration_tier": cand.RegistrationTier,
			"verify_level":      cand.VerifyLevel,
			"service_name":      cand.ServiceName,
			"relative_path":     cand.RelativePath,
			"codebase_id":       cand.CodebaseID,
			"version_id":        cand.VersionID,
			"locations":         anchors,
			"why_unobstructed":  why,
			"exploitability":    exploitability,
			"remediation":       remediation,
		}
		if cand.FindingID != nil {
			snapMap["finding_id"] = *cand.FindingID
		}
		snapBytes, _ := json.Marshal(snapMap)
		ruleBytes, _ := json.Marshal(map[string]any{
			"required_evidence":       "effective_dynamic_attempt",
			"static_candidate_key":    cand.CandidateKey,
			"unreproduced_never_fix":  true,
			"distinguish_static_live": true,
		})
		if _, cerr := s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
			TaskID:          taskNum,
			RoundID:         &round.ID,
			Dimension:       pgdb.DimensionHypothesis,
			TargetEntityID:  cand.TargetEntityID,
			Purpose:         fmt.Sprintf("动态验证静态候选「%s」（%s/%s，仅为 theoretical 线索，须实测复现或严谨证伪）", trimAuditText(title, 90), firstNonEmpty(cand.Severity, "unknown"), firstNonEmpty(cand.ServiceName, firstNonEmpty(cand.RelativePath, "-"))),
			Required:        true,
			DedupeKey:       dedupe,
			InitialStatus:   initStatus,
			BlockedReason:   blockedReason,
			AcceptanceRule:  ruleBytes,
			ExecutionMode:   pgdb.ExecModeDynamicVerify,
			Origin:          pgdb.ObligationOriginProgram,
			Priority:        8,
			ProfileVersion:  round.ProfileVersion,
			DependencyIDs:   runtimeIDs,
			ContextSnapshot: snapBytes,
		}); cerr != nil {
			return cerr
		}
	}
	return nil
}

func (s *Server) ensureDynamicHypothesisFromInvestigate(taskID, roundID int64, t *Task, ob *pgdb.CoverageObligation, outcome agent.CodeInvestigateOutcome) {
	if s == nil || s.m == nil || s.m.pg == nil || t == nil || ob == nil || roundID <= 0 {
		return
	}
	if outcome.Verdict != "confirmed_static" && outcome.Verdict != "needs_dynamic_verify" {
		return
	}
	if strings.TrimSpace(t.lifecycleSnapshot().AssessmentConfig.ExecutionMode) == pgdb.AssessmentExecOffline {
		return
	}
	if ob.ExecutionMode == pgdb.ExecModeDynamicVerify {
		return
	}
	obligations, err := s.m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{
		TaskID:  taskID,
		RoundID: roundID,
		Limit:   500,
	})
	if err != nil {
		return
	}
	var runtimeIDs []int64
	for _, item := range obligations {
		if item.Dimension == pgdb.DimensionRuntimeAsset {
			runtimeIDs = append(runtimeIDs, item.ID)
		}
	}
	initStatus := pgdb.ObligationPending
	blockedReason := ""
	if len(runtimeIDs) == 0 {
		initStatus = pgdb.ObligationBlocked
		blockedReason = "定向代码排查建议动态验证，但当前缺少授权测试环境实例映射"
	}
	round, _ := s.m.pg.OpenAssessmentRound(taskID)
	profileVer := 1
	if round != nil && round.ProfileVersion > 0 {
		profileVer = round.ProfileVersion
	}
	snapBytes, _ := json.Marshal(map[string]any{
		"static_only":          true,
		"source_obligation_id": ob.ID,
		"source_verdict":       outcome.Verdict,
		"summary":              outcome.Summary,
		"locations":            outcome.Evidence,
		"followups":            outcome.Followups,
		"evidence_ref_id":      outcome.EvidenceRefID,
	})
	ruleBytes, _ := json.Marshal(map[string]any{
		"required_evidence":      "effective_dynamic_attempt",
		"source_obligation_id":   ob.ID,
		"unreproduced_never_fix": true,
	})
	_, _ = s.m.pg.CreateCoverageObligation(pgdb.CreateCoverageObligationInput{
		TaskID:          taskID,
		RoundID:         &roundID,
		Dimension:       pgdb.DimensionHypothesis,
		TargetEntityID:  ob.TargetEntityID,
		Purpose:         fmt.Sprintf("动态验证定向白盒结论：%s", trimAuditText(outcome.Summary, 100)),
		Required:        true,
		DedupeKey:       fmt.Sprintf("hypothesis:wb2dyn:o%d", ob.ID),
		InitialStatus:   initStatus,
		BlockedReason:   blockedReason,
		AcceptanceRule:  ruleBytes,
		ExecutionMode:   pgdb.ExecModeDynamicVerify,
		Origin:          pgdb.ObligationOriginPlanner,
		Priority:        8,
		ProfileVersion:  profileVer,
		DependencyIDs:   runtimeIDs,
		ContextSnapshot: snapBytes,
	})
	_, _, _ = s.m.pg.ReconcileObligationReadiness(taskID, roundID)
}

func extractStaticCandidateDetails(candRaw, evRaw json.RawMessage) (anchors []agent.DynamicCodeAnchor, why, exploitability, remediation string) {
	extractFromMap := func(m map[string]any, sourceLabel string) {
		if m == nil {
			return
		}
		if w, ok := m["why_unobstructed"].(string); ok && why == "" {
			why = strings.TrimSpace(w)
		}
		if ex, ok := m["exploitability"].(string); ok && exploitability == "" {
			exploitability = strings.TrimSpace(ex)
		}
		if rem, ok := m["remediation"].(string); ok && remediation == "" {
			remediation = strings.TrimSpace(rem)
		}
		parseLoc := func(raw any, role string) {
			obj, ok := raw.(map[string]any)
			if !ok {
				return
			}
			pathStr, _ := obj["file"].(string)
			if pathStr == "" {
				pathStr, _ = obj["path"].(string)
			}
			lineVal := 0
			switch v := obj["line"].(type) {
			case float64:
				lineVal = int(v)
			case int:
				lineVal = v
			}
			sym, _ := obj["symbol"].(string)
			desc, _ := obj["description"].(string)
			excerpt, _ := obj["excerpt"].(string)
			if r, ok := obj["role"].(string); ok && strings.TrimSpace(r) != "" {
				role = strings.TrimSpace(r)
			}
			if desc == "" && role != "" {
				desc = role
			}
			if pathStr == "" && sym == "" && desc == "" {
				return
			}
			anchors = append(anchors, agent.DynamicCodeAnchor{
				Path:        strings.TrimSpace(pathStr),
				Line:        lineVal,
				Symbol:      strings.TrimSpace(sym),
				Excerpt:     trimAuditText(strings.TrimSpace(excerpt), 240),
				Description: strings.TrimSpace(desc),
				Source:      sourceLabel,
			})
		}
		parseLoc(m["entry_point"], "entry_point")
		parseLoc(m["source"], "source")
		parseLoc(m["sink"], "sink")
		if arr, ok := m["anchors"].([]any); ok {
			for _, it := range arr {
				parseLoc(it, "anchor")
			}
		}
		if arr, ok := m["locations"].([]any); ok {
			for _, it := range arr {
				parseLoc(it, "location")
			}
		}
	}

	var candMap map[string]any
	if len(candRaw) > 0 {
		_ = json.Unmarshal(candRaw, &candMap)
		extractFromMap(candMap, "code_audit_candidate")
	}
	var evMap map[string]any
	if len(evRaw) > 0 {
		_ = json.Unmarshal(evRaw, &evMap)
		extractFromMap(evMap, "code_audit_evidence")
	}
	if len(anchors) > 12 {
		anchors = anchors[:12]
	}
	return anchors, why, exploitability, remediation
}

func (s *Server) buildDynamicVerifyWorkOrder(
	taskID, roundID int64,
	ob *pgdb.CoverageObligation,
	meta pgdb.IntentAssessmentMeta,
	t *Task,
	intent *pgdb.Node,
) (agent.DynamicWorkOrder, string) {
	cfg := t.lifecycleSnapshot().AssessmentConfig
	wo := agent.DynamicWorkOrder{
		ObligationID: ob.ID,
		Dimension:    ob.Dimension,
		Purpose:      ob.Purpose,
		DedupeKey:    ob.DedupeKey,
		Question:     ob.Purpose,
	}

	var snap map[string]any
	if len(ob.ContextSnapshot) > 0 {
		_ = json.Unmarshal(ob.ContextSnapshot, &snap)
	}
	snapStr := func(keys ...string) string {
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

	if fid, ok := snap["finding_id"].(float64); ok && fid > 0 {
		v := int64(fid)
		wo.LinkedFindingID = &v
	}
	if so, ok := snap["static_only"].(bool); ok {
		wo.StaticOnly = so
	}
	wo.Module = snapStr("module", "service_name", "service")
	wo.TargetAsset = snapStr("name", "target_name")

	var targetEnt *pgdb.TargetEntity
	entities, _ := s.m.pg.ListTargetEntities(pgdb.TargetEntityFilter{TaskID: taskID, RoundID: roundID, Limit: 500})
	claims, _ := s.m.pg.ListProfileClaims(pgdb.ProfileClaimFilter{TaskID: taskID, RoundID: roundID, Limit: 500})

	var instances []pgdb.TargetEntity
	var identityEnts []pgdb.TargetEntity
	for i := range entities {
		ent := &entities[i]
		if ob.TargetEntityID != nil && ent.ID == *ob.TargetEntityID {
			targetEnt = ent
		}
		switch ent.EntityType {
		case "instance":
			instances = append(instances, *ent)
		case "identity":
			identityEnts = append(identityEnts, *ent)
		}
	}

	if targetEnt != nil {
		if wo.TargetAsset == "" {
			wo.TargetAsset = targetEnt.Name
		}
		var attrs map[string]any
		if len(targetEnt.Attributes) > 0 {
			_ = json.Unmarshal(targetEnt.Attributes, &attrs)
		}
		attrStr := func(keys ...string) string {
			for _, k := range keys {
				if attrs == nil {
					continue
				}
				if v, ok := attrs[k].(string); ok && strings.TrimSpace(v) != "" {
					return strings.TrimSpace(v)
				}
			}
			return ""
		}
		if targetEnt.EntityType == "entry" {
			wo.EntryMethod = attrStr("method", "http_method")
			wo.EntryPath = attrStr("path", "route", "endpoint", "target")
			wo.EntryURL = attrStr("url", "target_url")
			if wo.Module == "" {
				wo.Module = attrStr("module", "service", "code_module")
			}
		} else if wo.Module == "" && (targetEnt.EntityType == "service" || targetEnt.EntityType == "module") {
			wo.Module = targetEnt.Name
		}
	}
	if attrsMap, ok := snap["attributes"].(map[string]any); ok {
		if wo.EntryMethod == "" {
			if m, ok := attrsMap["method"].(string); ok {
				wo.EntryMethod = strings.TrimSpace(m)
			}
		}
		if wo.EntryPath == "" {
			for _, k := range []string{"path", "route", "endpoint"} {
				if p, ok := attrsMap[k].(string); ok && strings.TrimSpace(p) != "" {
					wo.EntryPath = strings.TrimSpace(p)
					break
				}
			}
		}
		if wo.EntryURL == "" {
			if u, ok := attrsMap["url"].(string); ok {
				wo.EntryURL = strings.TrimSpace(u)
			}
		}
	}

	// Resolve target environment instance (mapped instance > default instance > config fallback).
	mappedInstance := ""
	if targetEnt != nil && targetEnt.EntityType == "instance" {
		mappedInstance = targetEnt.Name
	}
	if mappedInstance == "" && wo.Module != "" {
		wantSubj := "module:" + strings.ToLower(wo.Module)
		svcSubj := "service:" + strings.ToLower(wo.Module)
		for _, cl := range claims {
			if cl.Relation == "deployed_to_instance" && strings.HasPrefix(cl.ObjectValue, "instance:") {
				lsubj := strings.ToLower(cl.Subject)
				if lsubj == wantSubj || lsubj == svcSubj || strings.TrimSuffix(strings.TrimPrefix(lsubj, "service:"), "") == strings.ToLower(wo.Module) {
					mappedInstance = strings.TrimPrefix(cl.ObjectValue, "instance:")
					break
				}
			}
		}
	}
	var chosenEnv *pgdb.TargetEntity
	for i := range instances {
		inst := &instances[i]
		if mappedInstance != "" && strings.EqualFold(inst.Name, mappedInstance) {
			chosenEnv = inst
			break
		}
		var attrs map[string]any
		_ = json.Unmarshal(inst.Attributes, &attrs)
		if isDef, _ := attrs["is_default"].(bool); isDef && chosenEnv == nil {
			chosenEnv = inst
		}
	}
	if chosenEnv == nil && len(instances) > 0 {
		chosenEnv = &instances[0]
	}

	accessMode := ""
	accessNotes := ""
	if cfg.EnvAccess != nil {
		accessMode = strings.TrimSpace(cfg.EnvAccess.Mode)
		accessNotes = strings.TrimSpace(cfg.EnvAccess.Notes)
	}
	versionStatus := "unknown"
	expectedVersion := snapStr("version_id")
	if chosenEnv != nil {
		var envAttrs map[string]any
		_ = json.Unmarshal(chosenEnv.Attributes, &envAttrs)
		envURL, _ := envAttrs["url"].(string)
		envDesc, _ := envAttrs["description"].(string)
		isDef, _ := envAttrs["is_default"].(bool)
		if expectedVersion == "" && chosenEnv.VersionID != "" {
			expectedVersion = chosenEnv.VersionID
		}
		for _, cl := range claims {
			if strings.EqualFold(cl.Subject, "instance:"+chosenEnv.Name) && cl.Relation == "code_version_verified" {
				versionStatus = cl.ConfirmationStatus
				if cl.ObjectValue != "" && cl.ObjectValue != "unknown" {
					versionStatus += ":" + cl.ObjectValue
				}
			}
		}
		wo.Environment = &agent.DynamicEnvironmentTarget{
			Name:            chosenEnv.Name,
			URL:             strings.TrimSpace(envURL),
			Description:     strings.TrimSpace(envDesc),
			AccessMode:      accessMode,
			AccessNotes:     accessNotes,
			IsDefault:       isDef,
			VersionStatus:   versionStatus,
			ExpectedVersion: expectedVersion,
		}
	} else if len(cfg.Environments) > 0 {
		cfgEnv := cfg.Environments[0]
		for _, e := range cfg.Environments {
			if e.IsDefault {
				cfgEnv = e
				break
			}
		}
		wo.Environment = &agent.DynamicEnvironmentTarget{
			Name:          firstNonEmpty(cfgEnv.Name, "default"),
			URL:           strings.TrimSpace(cfgEnv.URL),
			Description:   strings.TrimSpace(cfgEnv.Description),
			AccessMode:    accessMode,
			AccessNotes:   accessNotes,
			IsDefault:     cfgEnv.IsDefault,
			VersionStatus: versionStatus,
		}
	}

	// Build concrete entry URL if only relative path + environment URL exist.
	if wo.EntryURL == "" && wo.Environment != nil && wo.Environment.URL != "" && strings.HasPrefix(wo.EntryPath, "/") {
		wo.EntryURL = strings.TrimRight(wo.Environment.URL, "/") + wo.EntryPath
	}

	// Resolve identity / credential_ref (never store/expose raw secrets).
	roleHint := snapStr("role")
	for _, idEnt := range identityEnts {
		matches := (ob.TargetEntityID != nil && idEnt.ID == *ob.TargetEntityID) ||
			(roleHint != "" && strings.EqualFold(idEnt.Name, roleHint))
		if !matches {
			continue
		}
		var idCfg pgdb.AssessmentIdentityInput
		_ = json.Unmarshal(idEnt.Attributes, &idCfg)
		anon, _ := snap["anonymous"].(bool)
		wo.Identity = &agent.DynamicIdentityRef{
			Role:                firstNonEmpty(idCfg.Role, idEnt.Name),
			Username:            idCfg.Username,
			AuthType:            idCfg.AuthType,
			CredentialRef:       firstNonEmpty(ob.CredentialRef, idCfg.CredentialRef),
			Scope:               idCfg.Scope,
			Notes:               idCfg.Notes,
			RequiresCredentials: ob.RequiresCredentials,
			Anonymous:           anon,
		}
		break
	}
	if wo.Identity == nil && (ob.RequiresCredentials || ob.CredentialRef != "" || roleHint != "") {
		anon, _ := snap["anonymous"].(bool)
		wo.Identity = &agent.DynamicIdentityRef{
			Role:                roleHint,
			CredentialRef:       ob.CredentialRef,
			RequiresCredentials: ob.RequiresCredentials,
			Anonymous:           anon,
		}
	}

	// Populate static code anchors from obligation snapshot + linked static finding.
	anchors, why, exploitability, _ := extractStaticCandidateDetails(nil, ob.ContextSnapshot)
	if len(anchors) == 0 {
		if arr, ok := snap["locations"].([]any); ok {
			raw, _ := json.Marshal(map[string]any{"locations": arr})
			anchors, _, _, _ = extractStaticCandidateDetails(raw, nil)
		}
	}
	if wo.LinkedFindingID != nil && *wo.LinkedFindingID > 0 {
		if f, err := s.m.pg.GetFinding(*wo.LinkedFindingID); err == nil && f != nil && len(f.CodeAuditEvidence) > 0 {
			fAnchors, fWhy, fExp, _ := extractStaticCandidateDetails(nil, f.CodeAuditEvidence)
			anchors = append(anchors, fAnchors...)
			if why == "" {
				why = fWhy
			}
			if exploitability == "" {
				exploitability = fExp
			}
		}
	}
	if len(anchors) > 12 {
		anchors = anchors[:12]
	}
	wo.CodeAnchors = anchors

	// Collect authorized hosts so external dependencies outside scope are clearly flagged read-only.
	authHosts := map[string]bool{}
	for _, env := range cfg.Environments {
		if h := extractHostLower(env.URL); h != "" {
			authHosts[h] = true
		}
	}
	if wo.Environment != nil {
		if h := extractHostLower(wo.Environment.URL); h != "" {
			authHosts[h] = true
		}
	}
	seenOutScope := map[string]bool{}
	for _, cl := range claims {
		if cl.Relation == "depends_on" || cl.Relation == "calls" || cl.Relation == "external_dependency" {
			val := strings.TrimSpace(cl.ObjectValue)
			if val == "" || seenOutScope[val] {
				continue
			}
			if h := extractHostLower(val); h != "" && !authHosts[h] {
				seenOutScope[val] = true
				wo.OutOfScopeDependencies = append(wo.OutOfScopeDependencies, fmt.Sprintf("%s -> %s（范围外依赖，仅作画像背景，禁止主动探测）", cl.Subject, val))
			}
		}
	}

	// Build dimension-specific hypothesis, expected behavior, evidence plan & stop condition.
	switch ob.Dimension {
	case pgdb.DimensionRuntimeAsset:
		wo.Hypothesis = "已映射测试环境实例可达，且实际部署的服务形态、关键入口与代码版本与当前静态代码库快照一致。"
		wo.ExpectedBehavior = "目标环境返回可达的业务/健康响应；版本指纹、接口路由与认证配置与源码一致，无错配环境。"
		wo.EvidencePlan = []string{
			"使用 HTTP/Bash 对授权环境 URL 发起最小可达性与版本指纹探测，留存 traffic_ids 或 command_evidence",
			"若版本/配置与源码矛盾，立即 submit_dynamic_verification(verdict=\"env_mismatch\") 并 record_profile_claim 记录冲突",
		}
		wo.StopCondition = "确认版本匹配（supported + version_matched=true）或明确发现环境错配（env_mismatch）或依赖不可达（dependency_missing）即止。"
	case pgdb.DimensionEntryTest:
		wo.Hypothesis = fmt.Sprintf("入口「%s」在运行时存在未充分校验、鉴权缺失或业务逻辑边界风险（不依赖预先静态候选）。", firstNonEmpty(wo.EntryPath, firstNonEmpty(wo.TargetAsset, ob.Purpose)))
		wo.ExpectedBehavior = "入口在正常请求与边界/恶意输入下均执行预期的输入校验、授权检查与错误处理，不触发越权或安全影响。"
		wo.EvidencePlan = []string{
			"使用授权环境对目标入口构造基线正常请求 + 边界/安全探测请求（通过记录代理）",
			"提交真实 traffic_ids 或 command_evidence；若触发未知参数/中间件行为，同时调用 add_exploration_obligation(code_investigate) 反向查码",
		}
		wo.StopCondition = "取得真实执行输出与流量证明，完成 supported/disproved 判定或明确 missing_preconditions 登记 unreproduced 即止。"
	case pgdb.DimensionIdentityResource:
		wo.Hypothesis = fmt.Sprintf("身份等价组「%s」严格受限于自身角色权限及资源归属边界，不存在越权访问或未授权旁路。", firstNonEmpty(roleHint, wo.TargetAsset))
		wo.ExpectedBehavior = "未认证、跨角色或跨租户请求应被稳定拒绝（401/403）；持有 credential_ref 身份仅能操作本人授权资源。"
		wo.EvidencePlan = []string{
			"执行权限正反对照：低权/跨租户/匿名请求对比预期授权控制；严禁写入任何明文凭证",
			"缺失必需 credential_ref 时须立即回报 dependency_missing，不可伪造认证成功",
		}
		wo.StopCondition = "完成权限边界实测并提交 traffic_ids / command_evidence，或因缺凭证/前置阻塞回报 dependency_missing。"
	case pgdb.DimensionCrossModule:
		wo.Hypothesis = "跨模块/服务间调用与鉴权/状态传递在真实部署配置下端到端受控，不存在信任边界失配。"
		wo.ExpectedBehavior = "网关/上游转发头、共享库与下游接口在实际部署态下的语义与权限校验保持一致。"
		wo.EvidencePlan = []string{
			"按需结合 read_code_slice 核对调用参数，再用动态请求验证跨模块链条的实际运行表现",
			"发现跨组件配置差异或语义偏差时记录 profile_claim 并提交对应结论",
		}
		wo.StopCondition = "取得端到端动态运行或流量证据，确认控制一致或暴露跨模块缺陷即止。"
	default: // hypothesis
		hypParts := []string{}
		if snapStr("title") != "" {
			hypParts = append(hypParts, snapStr("title"))
		}
		if exploitability != "" {
			hypParts = append(hypParts, exploitability)
		}
		if snapStr("conflict_note") != "" {
			hypParts = append(hypParts, "画像冲突说明："+snapStr("conflict_note"))
		}
		if len(hypParts) > 0 {
			wo.Hypothesis = strings.Join(hypParts, "；")
		} else {
			wo.Hypothesis = ob.Purpose
		}
		if why != "" {
			wo.ExpectedBehavior = "验证静态阻断判断是否成立，静态疑点原因：" + why
		} else {
			wo.ExpectedBehavior = "通过真实请求与对照实验区分静态理论候选是否可实际触发，避免把单次未触发误判为已修复。"
		}
		wo.EvidencePlan = []string{
			"优先对锚定入口与参数执行最小可行复现探测；若证实可利用，调 report_finding(verify_level=\"minimal\") 并 submit_dynamic_verification(supported)",
			"若未触发，区分：证据表明防护确定阻断(disproved) vs 前置缺失未触发(unreproduced，必须列 missing_preconditions 且不降级静态发现)",
		}
		wo.StopCondition = "完成动态验证分类（supported / disproved / unreproduced / env_mismatch / dependency_missing）并附可核验证据即止。"
	}

	if intent != nil && len(meta.WorkOrder) > 0 {
		var override map[string]any
		if json.Unmarshal(meta.WorkOrder, &override) == nil && len(override) > 0 {
			if err := pgdb.ValidateAssessmentTextSafe(string(meta.WorkOrder)); err == nil {
				if q, ok := override["question"].(string); ok && strings.TrimSpace(q) != "" {
					wo.Question = strings.TrimSpace(q)
				}
				if h, ok := override["hypothesis"].(string); ok && strings.TrimSpace(h) != "" {
					wo.Hypothesis = strings.TrimSpace(h)
				}
				if eb, ok := override["expected_behavior"].(string); ok && strings.TrimSpace(eb) != "" {
					wo.ExpectedBehavior = strings.TrimSpace(eb)
				}
				if sc, ok := override["stop_condition"].(string); ok && strings.TrimSpace(sc) != "" {
					wo.StopCondition = strings.TrimSpace(sc)
				}
				wo.PlannerOverrides = override
			}
		}
	}

	envSummary := ""
	if wo.Environment != nil {
		envSummary = fmt.Sprintf("%s (url=%s, access=%s)", wo.Environment.Name, firstNonEmpty(wo.Environment.URL, "-"), firstNonEmpty(wo.Environment.AccessMode, "direct"))
	}
	return wo, envSummary
}

func extractHostLower(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	if h, _, err := net.SplitHostPort(raw); err == nil && h != "" {
		return strings.ToLower(h)
	}
	return ""
}

func (s *Server) buildDynamicCodeSliceTools(ctx context.Context, taskID int64, ob *pgdb.CoverageObligation) ([]actool.CoreTool, func()) {
	noop := func() {}
	target, err := s.resolveAssessmentAuditTarget(taskID, ob, true)
	if err != nil {
		return nil, noop
	}
	codebase, err := s.loadTaskCodeAuditCodebase(ctx, taskID, target.Service, target.Version, ".")
	if err != nil {
		return nil, noop
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

	renameMap := map[string]string{
		"list_files":   "list_code_slice",
		"search_files": "search_code_slice",
		"read_file":    "read_code_slice",
	}
	wrap := func(schema llm.ToolSchema, isBinary bool) actool.CoreTool {
		origName := schema.Name
		exposedName := origName
		if mapped, ok := renameMap[origName]; ok {
			exposedName = mapped
		}
		return actool.Build(actool.Spec{
			Name:        exposedName,
			Description: schema.Description + "（只读代码切片辅助动态核实，不做全仓审计。）",
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
					resText, callErr = state.callJavaCodeDB(origName, in)
				} else {
					resText, callErr = state.call(origName, in)
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

	tools := make([]actool.CoreTool, 0, len(taskCodeAuditTools)+len(taskCodeAuditBinaryTools))
	for _, sc := range taskCodeAuditTools {
		tools = append(tools, wrap(sc, false))
	}
	if jcdClient != nil {
		for _, sc := range taskCodeAuditBinaryTools {
			tools = append(tools, wrap(sc, true))
		}
	}
	cleanup := func() {
		if jcdClient != nil {
			jcdClient.close()
		}
	}
	return tools, cleanup
}

func (s *Server) buildDynamicTrafficVerifier(t *Task, wo agent.DynamicWorkOrder) func(ctx context.Context, ids []string) ([]string, error) {
	return func(ctx context.Context, ids []string) ([]string, error) {
		if len(ids) == 0 {
			return nil, nil
		}
		if s.m == nil || s.m.traffic == nil {
			return nil, errors.New("平台代理流量存储未开启，无法核验 traffic_ids；请改用真实命令执行输出 command_evidence")
		}
		allowedHosts := map[string]bool{}
		cfg := t.lifecycleSnapshot().AssessmentConfig
		for _, env := range cfg.Environments {
			if h := extractHostLower(env.URL); h != "" {
				allowedHosts[h] = true
			}
		}
		if wo.Environment != nil {
			if h := extractHostLower(wo.Environment.URL); h != "" {
				allowedHosts[h] = true
			}
		}
		if as := s.m.assetsForTask(t); as != nil {
			if taskIDInt, err := strconv.ParseInt(t.ID, 10, 64); err == nil {
				if hosts, herr := as.HostsByTask(taskIDInt); herr == nil {
					for _, raw := range hosts {
						if h := extractHostLower(raw); h != "" {
							allowedHosts[h] = true
						} else if strings.TrimSpace(raw) != "" && !strings.Contains(raw, "://") {
							allowedHosts[strings.ToLower(strings.TrimSpace(raw))] = true
						}
					}
				}
			}
		}

		verified := make([]string, 0, len(ids))
		err := s.m.traffic.ReadEvidence(ctx, ids, func(ex traffic.EvidenceExchange) error {
			if len(allowedHosts) > 0 {
				exHost := extractHostLower(ex.URL)
				if exHost != "" && !allowedHosts[exHost] {
					return fmt.Errorf("流量 %s 目标主机 %q 不在当前任务的授权测试环境或范围资产内", ex.ID, exHost)
				}
			}
			verified = append(verified, ex.ID)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return verified, nil
	}
}

func (s *Server) runAssessmentDynamicVerify(
	ctx context.Context,
	t *Task,
	slotName string,
	intent *pgdb.Node,
	meta pgdb.IntentAssessmentMeta,
	emit func(pgdb.Activity),
) (AssessmentExecResult, error) {
	taskIDInt, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskIDInt <= 0 || s.m == nil || s.m.pg == nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptFailed,
			BlockedReason: "任务或数据库不可用，无法执行动态验证",
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

	lifecycle := t.lifecycleSnapshot()
	execMode := strings.TrimSpace(lifecycle.AssessmentConfig.ExecutionMode)
	if execMode == "" {
		execMode = pgdb.AssessmentExecDynamic
	}
	if execMode == pgdb.AssessmentExecOffline {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptDependencyMissing,
			BlockedReason: "当前任务运行在 offline 纯静态模式下，禁止执行 dynamic_verify 动态探测",
			IntentState:   "blocked",
		}, nil
	}
	if ob.RequiresCredentials && strings.TrimSpace(ob.CredentialRef) == "" {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptDependencyMissing,
			BlockedReason: fmt.Sprintf("覆盖义务 #%d 需要绑定测试凭证（credential_ref），当前为空", ob.ID),
			IntentState:   "blocked",
		}, nil
	}
	if lifecycle.AssessmentConfig.EnvAccess != nil && strings.EqualFold(strings.TrimSpace(lifecycle.AssessmentConfig.EnvAccess.Mode), "offline") {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptDependencyMissing,
			BlockedReason: "测试环境接入方式（env_access.mode）为 offline，当前无法进行动态探测",
			IntentState:   "blocked",
		}, nil
	}

	var wk *agent.Worker
	var slotProfileID int64
	if s.engine != nil {
		if value, ok := s.engine.slotPlans.Load(t.ID); ok {
			if plan, ok := value.(map[string]int64); ok {
				slotProfileID = plan[slotName]
			}
		}
	}
	if slotProfileID > 0 {
		wk, _ = s.workerForTaskSlot(t, WorkerSlot{Name: slotName, ProfileID: slotProfileID})
	}
	if wk == nil && (s.taskRuntimeAvailable(t, "dynamic_verify") || s.taskRuntimeAvailable(t, "worker")) {
		wk = s.agentsForTask(t).wk
	}
	if wk == nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptDependencyMissing,
			BlockedReason: "当前任务未配置可用的 LLM Worker，无法运行 dynamic_verify",
			IntentState:   "blocked",
		}, nil
	}

	obRoundID := obligationRoundID(ob, meta.RoundID)
	round, rerr := s.m.pg.OpenAssessmentRound(taskIDInt)
	if rerr != nil || round == nil {
		round = &pgdb.AssessmentRound{ID: obRoundID, RoundNo: 1, ProfileVersion: 1}
	}

	wo, envSummary := s.buildDynamicVerifyWorkOrder(taskIDInt, obRoundID, ob, meta, t, intent)
	profileSlice := s.buildAssessmentAuditProfileContext(taskIDInt, obRoundID, wo.TargetAsset, wo.Module, ob.Dimension, ob.Purpose)
	readCodeTools, cleanupCodeTools := s.buildDynamicCodeSliceTools(ctx, taskIDInt, ob)
	defer cleanupCodeTools()

	dc := agent.DynamicVerifyContext{
		PG:                  s.m.pg,
		TaskID:              taskIDInt,
		RoundID:             obRoundID,
		RoundNo:             round.RoundNo,
		ProfileVersion:      round.ProfileVersion,
		ExecutionMode:       execMode,
		ObligationID:        ob.ID,
		AttemptID:           meta.AttemptID,
		Dimension:           ob.Dimension,
		ScopeNotes:          lifecycle.AssessmentConfig.ScopeNotes,
		EnvironmentSummary:  envSummary,
		WorkOrder:           wo,
		ProfileSlice:        profileSlice,
		RequiresCredentials: ob.RequiresCredentials,
		CredentialRef:       strings.TrimSpace(ob.CredentialRef),
		ReadCodeTools:       readCodeTools,
		VerifyTrafficIDs:    s.buildDynamicTrafficVerifier(t, wo),
		ExecutionCounter:    &atomic.Int64{},
	}

	hooks := steerHooks{
		inner:  t.Guard.Hooks(),
		drain:  func() (string, bool) { return s.engine.drainSteer(intent.ID) },
		nudges: new(atomic.Int64),
		limit:  s.engine.emptyTurnNudgeLimit(),
		label:  fmt.Sprintf("%s · #%d", slotName, intent.ID),
	}
	outcome, wrote, reason, runErr := wk.ExecuteDynamicVerify(
		ctx, slotName, dc, s.m.assetsForTask(t), t.Store, intent, hooks, emit, s.m.enrich, t.NotifyFinding,
	)
	if ctx.Err() != nil {
		return AssessmentExecResult{}, ctx.Err()
	}
	if runErr != nil {
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptFailed,
			BlockedReason: runErr.Error(),
			IntentState:   "blocked",
			Output: map[string]any{
				"facts_written":    wrote.Facts,
				"assets_written":   wrote.Assets,
				"findings_written": wrote.Findings,
			},
		}, nil
	}
	if !outcome.Submitted {
		stateName := "blocked"
		blockedMsg := "动态验证未提交经核实的 submit_dynamic_verification 结果"
		if reason == "max_turns" || reason == "timeout" {
			stateName = "exhausted"
			blockedMsg = "动态验证达到步数或时间上限且未提交结构化结论"
		}
		return AssessmentExecResult{
			Outcome:       pgdb.AttemptFailed,
			BlockedReason: blockedMsg,
			IntentState:   stateName,
			Output: map[string]any{
				"terminal_reason":  reason,
				"submitted":        false,
				"facts_written":    wrote.Facts,
				"assets_written":   wrote.Assets,
				"findings_written": wrote.Findings,
			},
		}, nil
	}

	s.recordDynamicFeedbackEvents(taskIDInt, obRoundID, ob, wo, outcome, wrote)

	outMap := map[string]any{
		"verdict":                      outcome.Verdict,
		"summary":                      outcome.Summary,
		"observed_url":                 outcome.ObservedURL,
		"observed_version":             outcome.ObservedVersion,
		"version_matched":              outcome.VersionMatched,
		"traffic_ids":                  outcome.TrafficIDs,
		"command_evidence":             outcome.CommandEvidence,
		"missing_preconditions":        outcome.MissingPreconditions,
		"feedback_claims_created":      outcome.FeedbackClaimsCreated,
		"feedback_obligations_created": outcome.FeedbackObligationsCreated,
		"facts_written":                wrote.Facts,
		"assets_written":               wrote.Assets,
		"findings_written":             wrote.Findings,
	}
	if outcome.EvidenceRefID != nil {
		outMap["evidence_ref_id"] = *outcome.EvidenceRefID
	}

	switch outcome.Verdict {
	case pgdb.AttemptEnvMismatch:
		outMap["env_mismatch"] = true
		return AssessmentExecResult{
			Outcome:           pgdb.AttemptEnvMismatch,
			EvidenceRefID:     outcome.EvidenceRefID,
			SatisfyObligation: false,
			BlockedReason:     outcome.BlockedReason,
			IntentState:       "blocked",
			Output:            outMap,
		}, nil
	case pgdb.AttemptDependencyMissing, pgdb.AttemptFailed:
		return AssessmentExecResult{
			Outcome:           outcome.Verdict,
			EvidenceRefID:     outcome.EvidenceRefID,
			SatisfyObligation: false,
			BlockedReason:     outcome.BlockedReason,
			IntentState:       "blocked",
			Output:            outMap,
		}, nil
	case pgdb.AttemptUnreproduced:
		outMap["unreproduced_not_fixed"] = true
		if outcome.EvidenceRefID == nil || *outcome.EvidenceRefID <= 0 {
			return AssessmentExecResult{
				Outcome:       pgdb.AttemptFailed,
				BlockedReason: "unreproduced 结论缺少可执行/流量证据引用",
				IntentState:   "blocked",
				Output:        outMap,
			}, nil
		}
		return AssessmentExecResult{
			Outcome:           pgdb.AttemptUnreproduced,
			EvidenceRefID:     outcome.EvidenceRefID,
			SatisfyObligation: true,
			IntentState:       "done",
			Output:            outMap,
		}, nil
	default: // supported | disproved
		if ob.Dimension == pgdb.DimensionRuntimeAsset && outcome.VersionMatched != nil && !*outcome.VersionMatched {
			outMap["env_mismatch"] = true
			return AssessmentExecResult{
				Outcome:           pgdb.AttemptEnvMismatch,
				EvidenceRefID:     outcome.EvidenceRefID,
				SatisfyObligation: false,
				BlockedReason:     firstNonEmpty(outcome.BlockedReason, "目标运行时版本与预期代码版本不匹配"),
				IntentState:       "blocked",
				Output:            outMap,
			}, nil
		}
		if outcome.EvidenceRefID == nil || *outcome.EvidenceRefID <= 0 {
			return AssessmentExecResult{
				Outcome:       pgdb.AttemptFailed,
				BlockedReason: "动态验证有效结论缺少 execution_output/traffic 证据引用",
				IntentState:   "blocked",
				Output:        outMap,
			}, nil
		}
		return AssessmentExecResult{
			Outcome:           outcome.Verdict,
			EvidenceRefID:     outcome.EvidenceRefID,
			SatisfyObligation: true,
			IntentState:       "done",
			Output:            outMap,
		}, nil
	}
}

func (s *Server) recordDynamicFeedbackEvents(
	taskID, roundID int64,
	ob *pgdb.CoverageObligation,
	wo agent.DynamicWorkOrder,
	outcome agent.DynamicVerifyOutcome,
	wrote agent.WriteCounts,
) {
	if s == nil || s.m == nil || s.m.pg == nil || taskID <= 0 || roundID <= 0 {
		return
	}
	envName := "default"
	if wo.Environment != nil && strings.TrimSpace(wo.Environment.Name) != "" {
		envName = strings.TrimSpace(wo.Environment.Name)
	}
	envSubject := "instance:" + envName

	switch {
	case outcome.Verdict == pgdb.AttemptEnvMismatch || (outcome.VersionMatched != nil && !*outcome.VersionMatched):
		evRef := outcome.EvidenceRefID
		if evRef == nil {
			ref := fmt.Sprintf("dynamic_env_mismatch:o%d", ob.ID)
			payload, _ := json.Marshal(map[string]any{
				"obligation_id":    ob.ID,
				"environment":      envName,
				"observed_url":     outcome.ObservedURL,
				"observed_version": outcome.ObservedVersion,
				"blocked_reason":   outcome.BlockedReason,
			})
			if id, err := s.m.pg.GetOrCreateEvidenceRef(taskID, pgdb.EvidenceExecution, ref, payload); err == nil && id > 0 {
				evRef = &id
			}
		}
		roundPtr := roundID
		_, _, _ = s.m.pg.CreateProfileClaim(pgdb.CreateProfileClaimInput{
			TaskID:             taskID,
			RoundID:            &roundPtr,
			Subject:            envSubject,
			Relation:           "code_version_verified",
			ObjectValue:        "mismatch:" + firstNonEmpty(outcome.ObservedVersion, "version_conflict"),
			SourceType:         pgdb.ClaimSourceRuntimeObservation,
			EvidenceRefID:      evRef,
			Environment:        envName,
			ConfirmationStatus: pgdb.ClaimStatusConflicted,
			ConflictNote:       firstNonEmpty(outcome.BlockedReason, outcome.Summary),
			ExecutionRef:       fmt.Sprintf("dynamic_verify:o%d", ob.ID),
		})
		evPayload, _ := json.Marshal(map[string]any{
			"obligation_id":    ob.ID,
			"environment":      envName,
			"observed_version": outcome.ObservedVersion,
			"observed_url":     outcome.ObservedURL,
			"reason":           firstNonEmpty(outcome.BlockedReason, outcome.Summary),
		})
		_, _ = s.m.pg.RecordAssessmentRoundEvent(taskID, roundID, "code_version_change", evPayload)

	case ob.Dimension == pgdb.DimensionRuntimeAsset && outcome.Verdict == pgdb.AttemptSupported && outcome.EvidenceRefID != nil:
		roundPtr := roundID
		verVal := "matched"
		if outcome.ObservedVersion != "" {
			verVal = "matched:" + outcome.ObservedVersion
		}
		_, _, _ = s.m.pg.CreateProfileClaim(pgdb.CreateProfileClaimInput{
			TaskID:             taskID,
			RoundID:            &roundPtr,
			Subject:            envSubject,
			Relation:           "code_version_verified",
			ObjectValue:        verVal,
			SourceType:         pgdb.ClaimSourceRuntimeObservation,
			EvidenceRefID:      outcome.EvidenceRefID,
			ValidCodeVersion:   outcome.ObservedVersion,
			Environment:        envName,
			ConfirmationStatus: pgdb.ClaimStatusConfirmed,
			ExecutionRef:       fmt.Sprintf("dynamic_verify:o%d", ob.ID),
		})
	}

	if outcome.FeedbackObligationsCreated > 0 {
		payload, _ := json.Marshal(map[string]any{
			"obligation_id":   ob.ID,
			"reverse_summary": outcome.ReverseInvestigateSummary,
			"count":           outcome.FeedbackObligationsCreated,
		})
		_, _ = s.m.pg.RecordAssessmentRoundEvent(taskID, roundID, "knowledge_conflict", payload)
	}
	if wrote.Assets > 0 || len(outcome.InsertedAssets) > 0 {
		var entryAssets, otherAssets []agent.InsertedAssetSummary
		for _, a := range outcome.InsertedAssets {
			if strings.EqualFold(strings.TrimSpace(a.Type), "endpoint") {
				entryAssets = append(entryAssets, a)
			} else {
				otherAssets = append(otherAssets, a)
			}
		}
		if len(entryAssets) > 0 {
			payload, _ := json.Marshal(map[string]any{
				"obligation_id":   ob.ID,
				"assets_written":  len(entryAssets),
				"inserted_assets": entryAssets,
			})
			_, _ = s.m.pg.RecordAssessmentRoundEvent(taskID, roundID, "new_entry", payload)
		}
		if len(otherAssets) > 0 || (len(entryAssets) == 0 && wrote.Assets > 0) {
			count := len(otherAssets)
			if count == 0 {
				count = wrote.Assets
			}
			payload, _ := json.Marshal(map[string]any{
				"obligation_id":   ob.ID,
				"assets_written":  count,
				"inserted_assets": otherAssets,
			})
			_, _ = s.m.pg.RecordAssessmentRoundEvent(taskID, roundID, "new_asset", payload)
		}
	}
}
