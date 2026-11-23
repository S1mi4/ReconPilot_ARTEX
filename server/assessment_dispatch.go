package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// AssessmentExecResult captures the typed outcome produced by a specialized
// executor (code_audit_batch / code_investigate / dynamic_verify) inside Engine.runIntent.
type AssessmentExecResult struct {
	Outcome           string
	EvidenceRefID     *int64
	CodeAuditRunID    *int64
	Output            map[string]any
	SatisfyObligation bool
	BlockedReason     string
	IntentState       string
}

// AssessmentExecutorFunc executes one bound Intent under Engine's workCtx for
// specialized assessment execution modes (code_audit_batch / code_investigate).
type AssessmentExecutorFunc func(ctx context.Context, t *Task, slotName string, intent *db.Node, meta db.IntentAssessmentMeta, emit func(db.Activity)) (AssessmentExecResult, error)

// SetCodeAuditBatchExecutor installs the Step-5/test executor for code_audit_batch Intents.
func (e *Engine) SetCodeAuditBatchExecutor(fn AssessmentExecutorFunc) {
	e.codeAuditBatchExec = fn
}

// SetCodeInvestigateExecutor installs the Step-5/test executor for code_investigate Intents.
func (e *Engine) SetCodeInvestigateExecutor(fn AssessmentExecutorFunc) {
	e.codeInvestigateExec = fn
}

// SetDynamicVerifyExecutor installs the Step-6/test executor for dynamic_verify Intents.
func (e *Engine) SetDynamicVerifyExecutor(fn AssessmentExecutorFunc) {
	e.dynamicVerifyExec = fn
}

// SetAssessmentPlanBuilder installs the catch-up deterministic coverage plan builder.
func (e *Engine) SetAssessmentPlanBuilder(fn func(ctx context.Context, taskID string) error) {
	e.assessmentPlanBuilder = fn
}

// SetAssessmentHypothesisSync installs the hook that promotes static findings into
// dynamic hypothesis obligations before Planner inspects coverage.
func (e *Engine) SetAssessmentHypothesisSync(fn func(ctx context.Context, taskID string, roundID int64) error) {
	e.assessmentHypothesisSync = fn
}

// SetAssessmentEventReconciler installs the incremental reconciliation hook that
// turns pending events (new assets/entries, version changes) into obligations and
// stale invalidations before Planner inspects coverage.
func (e *Engine) SetAssessmentEventReconciler(fn func(ctx context.Context, taskID string, roundID int64) ([]agent.TriggerEvent, []int64, error)) {
	e.assessmentEventReconciler = fn
}

func (e *Engine) claimMutex(taskID string) *sync.Mutex {
	v, _ := e.claimMu.LoadOrStore(taskID, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func (e *Engine) taskSlotCount(t *Task) int {
	if t == nil {
		return 1
	}
	if value, ok := e.slotPlans.Load(t.ID); ok {
		if plan, ok := value.(map[string]int64); ok && len(plan) > 0 {
			return len(plan)
		}
	}
	if e.m != nil {
		if slots, err := workerSlotsForTask(t, e.m.WorkerPools(), e.m.Workers()); err == nil && len(slots) > 0 {
			return len(slots)
		}
		return max(workerCountForTask(t, e.m.Workers()), 1)
	}
	return 1
}

// maxAssessmentBatchSlots returns the concurrent ceiling for code_audit_batch Intents:
// when slots >= 2, cap code_audit_batch at slots - 1 so dynamic_verify / code_investigate
// always keep at least 1 guaranteed slot (§8.2 / §10 Step 4).
func maxAssessmentBatchSlots(totalSlots int) int {
	if totalSlots >= 2 {
		return totalSlots - 1
	}
	return 1
}

// claimNextAssessment claims the next executable open intent in assessment mode while
// enforcing task-local mutual exclusion, dependency readiness gating, active attempt
// currency, and shared WorkerSlots soft-quota protection for code_audit_batch.
func (e *Engine) claimNextAssessment(t *Task, name string) *db.Node {
	if t == nil || t.Store == nil {
		return nil
	}
	mu := e.claimMutex(t.ID)
	mu.Lock()
	defer mu.Unlock()

	totalSlots := e.taskSlotCount(t)
	maxBatch := maxAssessmentBatchSlots(totalSlots)
	runningBatch, _ := t.Store.CountRunningIntentsByMode(db.ExecModeCodeAuditBatch)
	taskIDInt, _ := strconv.ParseInt(t.ID, 10, 64)

	fr, _ := t.Store.Frontier(50)
	for _, in := range fr {
		meta := db.ParseIntentAssessmentMeta(in.Payload)
		if meta.ExecutionMode == db.ExecModeCodeAuditBatch && runningBatch >= maxBatch {
			continue
		}
		if meta.ObligationID > 0 && taskIDInt > 0 && e.m != nil && e.m.pg != nil {
			executable, reason, err := e.m.pg.IsObligationExecutable(taskIDInt, meta.ObligationID, meta.RoundID, meta.AttemptID)
			if err != nil {
				log.Printf("[assessment-claim] task %s obligation #%d 校验出错: %v", t.ID, meta.ObligationID, err)
				continue
			}
			if !executable {
				log.Printf("[assessment-claim] task %s 跳过暂不可执行意图 #%d (obligation=%d): %s", t.ID, in.ID, meta.ObligationID, reason)
				continue
			}
		}
		claimed, err := t.Store.ClaimIntent(in.ID, name)
		if err != nil || !claimed {
			continue
		}
		if meta.ObligationID > 0 && meta.AttemptID > 0 && taskIDInt > 0 && e.m != nil && e.m.pg != nil {
			marked, markErr := e.m.pg.MarkObligationAttemptRunning(taskIDInt, meta.ObligationID, meta.AttemptID)
			if markErr != nil || !marked {
				log.Printf("[assessment-claim] task %s 尝试 #%d 状态切换失败或已被取代 (ok=%v err=%v)，回退意图 #%d",
					t.ID, meta.AttemptID, marked, markErr, in.ID)
				_ = transitionIntentState(t.Store, in.ID, "running", "stopped")
				continue
			}
		}
		return in
	}
	return nil
}

func (e *Engine) runSpecializedAssessmentExecutor(
	ctx context.Context,
	t *Task,
	slotName string,
	intent *db.Node,
	meta db.IntentAssessmentMeta,
	taskEmit func(db.Activity),
	execFn AssessmentExecutorFunc,
	mode string,
) (AssessmentExecResult, error) {
	if execFn == nil {
		msg := fmt.Sprintf("执行器 %s 尚未启用（等待第 5 步接入），当前不回退到通用动态 Worker", mode)
		taskEmit(db.Activity{
			Kind:    "text",
			IsError: true,
			Summary: msg,
			Detail:  msg,
		})
		return AssessmentExecResult{
			Outcome:       db.AttemptDependencyMissing,
			BlockedReason: msg,
			IntentState:   "blocked",
			Output: map[string]any{
				"executor_mode": mode,
				"unwired":       true,
				"message":       msg,
			},
		}, nil
	}
	return execFn(ctx, t, slotName, intent, meta, taskEmit)
}

func (e *Engine) runAssessmentPlannerRound(ctx context.Context, t *Task, planner *agent.Planner, emit func(db.Activity)) {
	if e.m == nil || e.m.pg == nil {
		return
	}
	taskIDInt, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskIDInt <= 0 {
		return
	}
	round, err := e.m.pg.OpenAssessmentRound(taskIDInt)
	if err != nil {
		log.Printf("[assessment-planner] task %s 读取开放轮次失败: %v", t.ID, err)
		return
	}
	if round == nil {
		return
	}

	phase := t.lifecycleSnapshot().AssessmentPhase
	if (phase == db.AssessmentPhaseProfiling || phase == db.AssessmentPhaseCoveragePlanning) && e.assessmentPlanBuilder != nil {
		if existing, lErr := e.m.pg.ListCoverageObligations(db.CoverageObligationFilter{
			TaskID:  taskIDInt,
			RoundID: round.ID,
			Limit:   1,
		}); lErr == nil && len(existing) == 0 {
			if pErr := e.assessmentPlanBuilder(ctx, t.ID); pErr != nil && ctx.Err() == nil {
				log.Printf("[assessment-planner] task %s 补建覆盖计划失败: %v", t.ID, pErr)
			}
			if refreshed, rErr := e.m.pg.OpenAssessmentRound(taskIDInt); rErr == nil && refreshed != nil {
				round = refreshed
			}
		}
	}

	if e.assessmentHypothesisSync != nil {
		_ = e.assessmentHypothesisSync(ctx, t.ID, round.ID)
	}
	var incTriggers []agent.TriggerEvent
	if e.assessmentEventReconciler != nil {
		var recErr error
		incTriggers, _, recErr = e.assessmentEventReconciler(ctx, t.ID, round.ID)
		if recErr != nil && ctx.Err() == nil {
			log.Printf("[assessment-planner] task %s 增量对账失败: %v", t.ID, recErr)
		}
		if refreshed, rErr := e.m.pg.OpenAssessmentRound(taskIDInt); rErr == nil && refreshed != nil {
			round = refreshed
		}
	}
	_, _, _ = e.m.pg.ReconcileObligationReadiness(taskIDInt, round.ID)

	e.emitActivity(t, db.Activity{
		Worker:  "planner",
		Kind:    "round",
		Summary: fmt.Sprintf("第 %d 轮评估规划", e.nextPlannerRound(t.ID)),
	})
	triggers := t.drainTriggers()
	triggers = append(triggers, incTriggers...)
	var processedEventIDs []int64
	if chunkEvents, evErr := e.m.pg.ListUnprocessedAssessmentEventsByType(taskIDInt, "code_audit_chunk_completed", 30); evErr == nil && len(chunkEvents) > 0 {
		for _, ev := range chunkEvents {
			processedEventIDs = append(processedEventIDs, ev.ID)
			var p struct {
				IntentID             int64  `json:"intent_id"`
				CodeAuditRunID       int64  `json:"code_audit_run_id"`
				ChunkIndex           int    `json:"chunk_index"`
				ChunksTotal          int    `json:"chunks_total"`
				FilesAnalyzed        int    `json:"files_analyzed"`
				FilesTotal           int    `json:"files_total"`
				CandidatesRegistered int    `json:"candidates_registered"`
				Summary              string `json:"summary"`
			}
			_ = json.Unmarshal(ev.Payload, &p)
			detail := fmt.Sprintf("审计 run #%d 分片 %d/%d 完成（已读分析 %d/%d 文件，登记 %d 个候选）",
				p.CodeAuditRunID, p.ChunkIndex, p.ChunksTotal, p.FilesAnalyzed, p.FilesTotal, p.CandidatesRegistered)
			if s := strings.TrimSpace(p.Summary); s != "" {
				detail += "：" + s
			}
			triggers = append(triggers, agent.TriggerEvent{
				Kind:     "code_audit_chunk_completed",
				IntentID: p.IntentID,
				Detail:   detail,
			})
		}
	}
	for _, evType := range []string{"new_asset", "new_entry", "profile_change", "evidence_invalidated", "knowledge_conflict", "code_version_change"} {
		if evs, evErr := e.m.pg.ListUnprocessedAssessmentEventsByType(taskIDInt, evType, 20); evErr == nil && len(evs) > 0 {
			for _, ev := range evs {
				processedEventIDs = append(processedEventIDs, ev.ID)
				triggers = append(triggers, agent.TriggerEvent{
					Kind:   evType,
					Detail: fmt.Sprintf("评估事件[%s]: %s", evType, strings.TrimSpace(string(ev.Payload))),
				})
			}
		}
	}
	lifecycle := t.lifecycleSnapshot()
	cfg := lifecycle.AssessmentConfig
	execMode := strings.TrimSpace(cfg.ExecutionMode)
	if execMode == "" {
		execMode = db.AssessmentExecDynamic
	}
	ac := agent.AssessmentPlannerContext{
		PG:               e.m.pg,
		TaskID:           taskIDInt,
		RoundID:          round.ID,
		RoundNo:          round.RoundNo,
		ProfileVersion:   round.ProfileVersion,
		ExecutionMode:    execMode,
		AssessmentPhase:  lifecycle.AssessmentPhase,
		BusinessOverview: cfg.BusinessOverview,
		BusinessFocus:    cfg.BusinessFocus,
		ScopeNotes:       cfg.ScopeNotes,
		WorkerSlots:      e.taskSlotCount(t),
		RequestCompletion: func(reason string) (bool, *db.AssessmentCompletionReport, error) {
			if len(processedEventIDs) > 0 {
				_ = e.m.pg.MarkAssessmentEventIDsProcessed(taskIDInt, processedEventIDs)
			}
			return e.m.CompleteAssessment(t)
		},
	}

	e.BeginLLMCall(t.ID)
	completed, reason, planErr := planner.PlanAssessment(ctx, ac, e.m.assetsForTask(t), t.Store, triggers, emit)
	e.EndLLMCall(t.ID)
	if planErr == nil && ctx.Err() == nil && len(processedEventIDs) > 0 {
		_ = e.m.pg.MarkAssessmentEventIDsProcessed(taskIDInt, processedEventIDs)
	}

	switch {
	case planErr != nil && ctx.Err() == nil:
		log.Printf("[assessment-planner] task %s 规划出错: %v", t.ID, planErr)
		if e.proxyFailure != nil && isProxyFailure(planErr) {
			e.proxyFailure(t.ID, planErr)
		}
	case completed:
		log.Printf("[assessment-planner] task %s 程序完成契约通过(%s)，取消在跑工作", t.ID, reason)
		e.emitActivity(t, db.Activity{
			Worker:  "system",
			Kind:    "text",
			Summary: "当前轮次全部必需覆盖义务已满足且证据对账完成，完成判定通过，任务结束",
		})
		e.cancelExec(t.ID, agent.AbortGoalMet)
	default:
		log.Printf("[assessment-planner] task %s 本轮评估规划完成", t.ID)
		if active, aErr := t.Store.HasActiveIntent(); aErr == nil && !active {
			if e.completeAssessmentIfEligible(t, "评估规划后复核") {
				e.cancelExec(t.ID, agent.AbortGoalMet)
			}
		}
	}
	e.touch(t.ID)
}

func (e *Engine) settleAssessmentSpecializedResult(
	t *Task,
	intent *db.Node,
	meta db.IntentAssessmentMeta,
	res AssessmentExecResult,
	execErr error,
) (intentState string) {
	intentState = strings.TrimSpace(res.IntentState)
	if intentState == "" {
		if execErr != nil {
			intentState = "blocked"
		} else {
			intentState = "done"
		}
	}
	if e.m == nil || e.m.pg == nil || meta.ObligationID <= 0 || meta.AttemptID <= 0 {
		return intentState
	}
	taskIDInt, _ := strconv.ParseInt(t.ID, 10, 64)
	if taskIDInt <= 0 {
		return intentState
	}

	outcome := strings.TrimSpace(res.Outcome)
	if outcome == "" {
		if execErr != nil {
			outcome = db.AttemptFailed
		} else {
			outcome = db.AttemptUnreproduced
		}
	}
	outMap := map[string]any{}
	for k, v := range res.Output {
		outMap[k] = v
	}
	if execErr != nil {
		outMap["error"] = execErr.Error()
	}
	outJSON, _ := json.Marshal(outMap)

	finalRes, fErr := e.m.pg.FinalizeObligationAttempt(db.FinalizeObligationAttemptInput{
		TaskID:            taskIDInt,
		ObligationID:      meta.ObligationID,
		AttemptID:         meta.AttemptID,
		IntentNodeID:      &intent.ID,
		CodeAuditRunID:    res.CodeAuditRunID,
		Outcome:           outcome,
		EvidenceRefID:     res.EvidenceRefID,
		Output:            outJSON,
		SatisfyObligation: res.SatisfyObligation && execErr == nil,
		BlockedReason:     strings.TrimSpace(res.BlockedReason),
	})
	if fErr != nil {
		if !errors.Is(fErr, db.ErrAttemptStaleOrSuperseded) {
			log.Printf("[assessment-settle] task %s attempt #%d 结算失败: %v", t.ID, meta.AttemptID, fErr)
		}
		return intentState
	}
	if finalRes != nil && finalRes.InsufficientEvidence {
		log.Printf("[assessment-settle] task %s obligation #%d 证据不足，覆盖不推进: %s",
			t.ID, meta.ObligationID, finalRes.RejectionReason)
	}
	return intentState
}

func (e *Engine) settleAssessmentDynamicWorker(t *Task, intent *db.Node, meta db.IntentAssessmentMeta, state string, wrote agent.WriteCounts, runErr error) {
	if e.m == nil || e.m.pg == nil || meta.ObligationID <= 0 || meta.AttemptID <= 0 {
		return
	}
	taskIDInt, _ := strconv.ParseInt(t.ID, 10, 64)
	if taskIDInt <= 0 {
		return
	}

	// Plain dynamic worker completion in Step 4 produces exploration facts/findings/text,
	// not a structured execution_output/traffic EvidenceRefID; do NOT advance obligation to
	// satisfied without verifiable evidence (Step 6 binds explicit dynamic work-order evidence).
	reason := "动态 Worker 结束，但尚未绑定符合验收要求的执行输出或流量证据引用，暂不推进覆盖"
	if runErr != nil {
		reason = runErr.Error()
	} else if state == "blocked" {
		reason = "动态 Worker 阻塞或无进展，未产出有效覆盖证据"
	} else if state == "exhausted" {
		reason = "动态 Worker 步数或超时耗尽，未产出有效覆盖证据"
	}
	outBytes, _ := json.Marshal(map[string]any{
		"worker_intent_state":   state,
		"evidence_insufficient": true,
		"reason":                reason,
		"facts_written":         wrote.Facts,
		"assets_written":        wrote.Assets,
		"findings_written":      wrote.Findings,
	})
	_, fErr := e.m.pg.FinalizeObligationAttempt(db.FinalizeObligationAttemptInput{
		TaskID:            taskIDInt,
		ObligationID:      meta.ObligationID,
		AttemptID:         meta.AttemptID,
		IntentNodeID:      &intent.ID,
		Outcome:           db.AttemptFailed,
		Output:            outBytes,
		SatisfyObligation: false,
	})
	if fErr != nil && !errors.Is(fErr, db.ErrAttemptStaleOrSuperseded) {
		log.Printf("[assessment-settle] task %s dynamic attempt #%d 结算失败: %v", t.ID, meta.AttemptID, fErr)
	}
}
