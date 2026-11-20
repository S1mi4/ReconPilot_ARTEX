package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/agent"
	pgdb "github.com/Autumn-27/artex/db"
)

// errTaskCodeAuditStoppedByUser is the cancellation cause attached to a running
// audit when the user presses "stop" (or the audit agent stops it on request).
var errTaskCodeAuditStoppedByUser = errors.New("task code audit stopped by user")

// auditRunHandle is the live control handle of one running audit worker.
type auditRunHandle struct {
	taskID string
	cancel context.CancelCauseFunc
}

// registerAuditRun derives a cancellable context for one audit run and records it
// so task pause/delete/archive and the stop endpoint can interrupt the run.
//
// A task that is already paused or being deleted gets an already-cancelled
// context, closing the claim -> start race the same way execContextFor does.
// The returned release function must be called when the run ends.
func (e *Engine) registerAuditRun(parent context.Context, taskID string, runID int64) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(parent)
	if e == nil {
		return ctx, func() { cancel(nil) }
	}
	e.auditMu.Lock()
	if e.auditRuns == nil {
		e.auditRuns = map[int64]auditRunHandle{}
	}
	e.auditRuns[runID] = auditRunHandle{taskID: taskID, cancel: cancel}
	e.auditMu.Unlock()
	switch {
	case e.IsDeleting(taskID):
		cancel(agent.AbortTaskDeleted)
	case e.IsPaused(taskID):
		cancel(agent.AbortPausedRaceGuard)
	}
	return ctx, func() {
		e.auditMu.Lock()
		delete(e.auditRuns, runID)
		e.auditMu.Unlock()
		cancel(nil)
	}
}

// cancelAuditRuns interrupts every running audit of a task (pause / delete).
func (e *Engine) cancelAuditRuns(taskID string, cause error) {
	if e == nil {
		return
	}
	e.auditMu.Lock()
	defer e.auditMu.Unlock()
	for _, handle := range e.auditRuns {
		if handle.taskID == taskID {
			handle.cancel(cause)
		}
	}
}

// cancelAuditRun interrupts one running audit; it reports whether a live worker
// for that run existed in this process.
func (e *Engine) cancelAuditRun(taskID string, runID int64, cause error) bool {
	if e == nil {
		return false
	}
	e.auditMu.Lock()
	defer e.auditMu.Unlock()
	handle, ok := e.auditRuns[runID]
	if !ok || handle.taskID != taskID {
		return false
	}
	handle.cancel(cause)
	return true
}

// taskCodeAuditStopText explains why a run's context ended, as the run summary
// and the resumable "incomplete" reason.
func taskCodeAuditStopText(ctx context.Context) (summary, reason string) {
	cause := context.Cause(ctx)
	var abort *agent.AbortCause
	switch {
	case errors.Is(cause, errTaskCodeAuditStoppedByUser):
		return "审计已被用户停止，可从最近检查点续跑。", "用户已停止审计，可续跑"
	case errors.As(cause, &abort) && abort.Code == agent.AbortTaskDeleted.Code:
		return "任务正在删除或归档，审计已停止。", "任务正在删除或归档，审计已停止"
	case errors.As(cause, &abort) && taskExecutionPaused(cause):
		return "任务已暂停，审计已在最近检查点停止；任务恢复后可续跑。", "任务已暂停，审计已停止，可续跑"
	default:
		return "审计因服务停止而暂停，可在重启后从最近检查点恢复。", "服务停止，等待恢复"
	}
}

// stopTaskCodeAudit parks a run whose context was cancelled as a resumable
// "incomplete" run, keeping the progress made so far.
func (s *Server) stopTaskCodeAudit(ctx context.Context, run *pgdb.TaskCodeAuditRun, progress pgdb.TaskCodeAuditProgress,
	outcome taskCodeAuditChunkOutcome) error {
	summary, reason := taskCodeAuditStopText(ctx)
	progress.Summary = appendTaskCodeAuditChunkOutcome(summary, outcome)
	return s.m.pg.IncompleteTaskCodeAudit(run.ID, progress, reason)
}

// requestStopTaskCodeAudit stops a queued or running audit on user request. It
// returns "stopped" for a queued run, "stopping" for a running one.
func (s *Server) requestStopTaskCodeAudit(taskID, runID int64) (string, error) {
	run, err := s.m.pg.GetTaskCodeAudit(taskID, runID)
	if err != nil {
		return "", err
	}
	switch run.Status {
	case "queued":
		stopped, err := s.m.pg.StopQueuedTaskCodeAudit(taskID, runID, "用户已在排队时停止审计，可续跑")
		if err != nil {
			return "", err
		}
		if stopped {
			return "stopped", nil
		}
		// The queue claimed the run between the read and the update.
		fallthrough
	case "running":
		if s.engine.cancelAuditRun(strconv.FormatInt(taskID, 10), runID, errTaskCodeAuditStoppedByUser) {
			return "stopping", nil
		}
		return "", errors.New("审计 Worker 尚未就绪或已结束，请稍后重试")
	default:
		return "", errors.New("只有排队中或运行中的审计可以停止")
	}
}

// taskCodeAuditStopHandler lets the user stop a queued or running audit. The run
// is parked as resumable, keeping its checkpoint, findings and used tokens.
func (s *Server) taskCodeAuditStopHandler(w http.ResponseWriter, r *http.Request) {
	taskNum, ok := s.requireTaskInProject(w, r, r.PathValue("id"), false)
	if !ok {
		return
	}
	if s.m.pg == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	runID, err := strconv.ParseInt(r.PathValue("runID"), 10, 64)
	if err != nil || runID <= 0 {
		writeErr(w, http.StatusNotFound, "审计记录不存在")
		return
	}
	status, err := s.requestStopTaskCodeAudit(taskNum, runID)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "审计记录不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": status})
}
