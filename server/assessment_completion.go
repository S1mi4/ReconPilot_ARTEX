package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

// 白盒驱动评估的程序完成判定入口（docs/whitebox-driven-assessment-design.md §6.3/§8）。
//
// 任务完成由程序统一判定：Planner 和 Worker 只能提交工作、证据和结论建议
//（经 db.TransitionObligationStatus 的证据校验），不能直接把任务标为全覆盖
// 完成。引擎的结束路径（goalless 收尾、planner 判定达成、超时收尾终局）
// 对 assessment_mode 任务都调用本方法；传统任务不走这里，行为不变。

// CompleteAssessment runs the program completion contract for an assessment-mode
// task and, only when every required condition holds, commits the terminal done
// status, closes the open assessment round with the completion report, and
// stamps the assessment phase to completed — all in ONE database transaction
// (db.FinalizeAssessmentCompletion), so a crash between writes can never leave
// a done task without its round report. It never marks a task done on its own
// judgement of goals — the planner's "goals met" is only a suggestion here (§6.3).
//
// Return values:
//   - completed: whether THIS call performed the terminal transition;
//   - report: the machine-judged contract report (nil only on hard errors);
//   - err: infrastructure failures only. A failed contract is completed=false
//     with a report carrying the per-condition reasons, not an error.
//
// 收尾对账与终态写入在 taskStateMu 下串行（与暂停/取消/复活的终态写入互斥），
// 避免"新发现与完成写入并发造成提前结束"；与并发白盒入队的互斥由
// FinalizeAssessmentCompletion 在任务行锁下复核白盒队列保证（§6.4）。
func (m *Manager) CompleteAssessment(t *Task) (completed bool, report *pgdb.AssessmentCompletionReport, err error) {
	if t == nil {
		return false, nil, errors.New("nil task")
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return false, nil, err
	}

	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()

	report, err = m.pg.AssessmentCompletionCheck(id)
	if err != nil {
		return false, report, fmt.Errorf("assessment completion check: %w", err)
	}
	if !report.CanComplete {
		return false, report, nil
	}

	// 原子收尾：任务行锁下复核白盒队列（无 queued/running）→ guarded 终态
	// done → 关闭评估轮次并落完成报告 → 阶段推进 completed，单事务提交。
	// 队列在锁下非空（并发入队）或终态已被他人落下时 won=false，任务继续
	// 运行/保持原状，不产生部分提交。
	reportJSON, mErr := json.Marshal(report)
	if mErr != nil {
		return false, report, fmt.Errorf("marshal completion report: %w", mErr)
	}
	active, started, won, err := m.pg.FinalizeAssessmentCompletionAtVersion(id, report.RoundID, report.ProfileVersion, reportJSON)
	if err != nil {
		return false, report, fmt.Errorf("finalize assessment completion: %w", err)
	}
	if !won {
		return false, report, nil
	}

	// 与 SetTaskStatusGuardedReason 相同的内存镜像：终态即刻生效，不依赖后续
	// hydration；hydration 失败不能在内存里重开一个已完成的任务。
	m.mu.Lock()
	if task := m.tasks[t.ID]; task != nil {
		task.updateLifecycle(func(state *taskLifecycleState) {
			state.Status = "done"
			state.StopReason = ""
			state.ActiveRunSeconds = active
			state.RunSegmentStartedAt = unixOrZero(started)
			state.Paused = false
			state.PauseReason = ""
			if state.CompletedAt == 0 {
				state.CompletedAt = time.Now().Unix()
			}
		})
		task.AssessmentPhase = pgdb.AssessmentPhaseCompleted
	}
	m.mu.Unlock()

	if err := m.syncTaskRuntime(t.ID, id); err != nil {
		return true, report, err
	}
	return true, report, nil
}
