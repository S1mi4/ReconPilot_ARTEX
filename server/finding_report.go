package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) queueWhiteboxFindingReport(f *db.DBFinding, run *db.TaskCodeAuditRun, candidate taskCodeAuditCandidate) (int64, error) {
	if f == nil || f.ID <= 0 || f.NodeID == nil || *f.NodeID <= 0 || f.TaskID == nil || *f.TaskID <= 0 {
		return 0, fmt.Errorf("white-box Finding has no task or exploration node")
	}
	reporter, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		return 0, fmt.Errorf("load report Agent: %w", err)
	}
	if reporter == nil || !reporter.Enabled {
		return 0, fmt.Errorf("report Agent is missing or disabled")
	}
	if s.resolveChatAgent(&db.Conversation{AgentKey: reporter.Key}) == nil {
		return 0, fmt.Errorf("%s", s.chatUnavailableReason())
	}
	if s.ctx != nil && s.ctx.Err() != nil {
		return 0, fmt.Errorf("server is stopping")
	}
	taskID := *f.TaskID
	projectID := s.projectOfTask(taskID)
	if projectID <= 0 {
		return 0, fmt.Errorf("cannot determine project for the report conversation")
	}
	var taskDesc, taskGoal string
	if task := s.m.ResolveTask(strconv.FormatInt(taskID, 10)); task != nil {
		taskDesc, taskGoal = task.Description, task.Goal
	}
	message := whiteboxFindingReportMessage(f, run, candidate)
	conversation, err := s.m.pg.CreateConversation(projectID, "reporter", fmt.Sprintf("白盒审计报告 · finding#%d", f.ID), nil)
	if err != nil {
		return 0, fmt.Errorf("create report conversation: %w", err)
	}
	if err := s.m.pg.SetFindingReportConversationID(f.ID, conversation.ID); err != nil {
		return 0, fmt.Errorf("link report conversation: %w", err)
	}
	s.StartTriggeredRunWithConversation(
		"reporter", fmt.Sprintf("白盒审计报告 · finding#%d", f.ID), message, taskID, false,
		taskDesc, taskGoal, conversation.ID,
	)
	return conversation.ID, nil
}

func whiteboxFindingReportMessage(f *db.DBFinding, run *db.TaskCodeAuditRun, candidate taskCodeAuditCandidate) string {
	var b strings.Builder
	b.WriteString("【白盒静态审计报告任务】请为一个已经登记为 pending / theoretical 的 Finding 生成中文 Markdown 报告。该结果来自静态代码审计与数据流分析，没有进行动态验证。\n")
	fmt.Fprintf(&b, "独立漏洞记录 ID（get_finding_traffic 使用）=%d；探索节点 ID（get_task_node_detail 和 update_finding_report 使用）=%d；任务 ID=%d。\n",
		f.ID, *f.NodeID, *f.TaskID)
	if run != nil {
		fmt.Fprintf(&b, "服务=%s；服务路径=%s；代码版本=%s；审计范围=%s；审计运行=%d。\n",
			run.ServiceName, run.ScopePath, run.VersionID, run.ScopePath, run.ID)
	}
	fmt.Fprintf(&b, "候选摘要：%s；漏洞类型=%s；严重等级=%s。\n", candidate.Title, normalizeTaskCodeAuditVulnClass(candidate.Category), candidate.Severity)
	if taskCodeAuditLocationPresent(candidate.Source) || taskCodeAuditLocationPresent(candidate.Sink) {
		fmt.Fprintf(&b, "Source=%s:%d %s；Sink=%s:%d %s(%s)。\n",
			candidate.Source.File, candidate.Source.Line, candidate.Source.Symbol,
			candidate.Sink.File, candidate.Sink.Line, candidate.Sink.Symbol, candidate.Sink.Parameter)
	}
	for _, anchor := range candidate.Anchors {
		fmt.Fprintf(&b, "锚点[%s]=%s:%d %s。\n", anchor.Role, anchor.File, anchor.Line, anchor.Symbol)
	}
	fmt.Fprintf(&b, "结构化代码证据：\n%s\n", string(f.CodeAuditEvidence))
	b.WriteString("先读取 get_finding_traffic 的清单和 evidence version，再读取 get_task_node_detail 中的完整静态证据；只按真实保存的代码证据写报告。动态请求、响应、命令输出、PoC 执行和运行时影响均未验证，必须明确标为待确认，不能编造。复现步骤写成可核查的静态推理链；污点型问题列出 source-to-sink 路径，列出代码文件和行号，并说明后续动态验证条件。不要创建或更改 Finding。最后使用 node ID 调用 update_finding_report，并传入刚读取的 evidence version。\n")
	return b.String()
}

// generateFindingReport requeues the existing reporter workflow for a finding.
// This is intentionally separate from report_finding: a restart can leave a
// finding persisted while the one-shot trigger conversation is gone.
func (s *Server) generateFindingReport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "bad finding id")
		return
	}
	if !s.requireFindingInProject(w, r, id) {
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if f == nil {
		writeErr(w, http.StatusNotFound, "finding not found")
		return
	}
	if f.NodeID == nil || *f.NodeID <= 0 {
		writeErr(w, http.StatusConflict, "漏洞没有可用的探索节点，无法生成复现步骤")
		return
	}
	reporter, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if reporter == nil || !reporter.Enabled {
		writeErr(w, http.StatusConflict, "报告 Agent 未启用，请在 Agent 管理中启用 reporter")
		return
	}
	if s.resolveChatAgent(&db.Conversation{AgentKey: reporter.Key}) == nil {
		writeErr(w, http.StatusServiceUnavailable, s.chatUnavailableReason())
		return
	}
	if s.ctx.Err() != nil {
		writeErr(w, http.StatusServiceUnavailable, "服务正在停止")
		return
	}

	var taskID int64
	var taskDesc, taskGoal string
	if f.TaskID != nil {
		taskID = *f.TaskID
		if task := s.m.ResolveTask(strconv.FormatInt(taskID, 10)); task != nil {
			taskDesc, taskGoal = task.Description, task.Goal
		}
	}
	message := manualFindingReportMessage(f, taskID)
	reportProject := s.projectOfTask(taskID)
	if reportProject == 0 {
		writeErr(w, http.StatusConflict, "无法确定所属项目：漏洞报告对话必须归属于某个任务")
		return
	}
	conversation, err := s.m.pg.CreateConversation(reportProject, "reporter", fmt.Sprintf("漏洞报告 · finding#%d", f.ID), nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "创建报告对话失败: "+err.Error())
		return
	}
	if err := s.m.pg.SetFindingReportConversationID(f.ID, conversation.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "关联报告对话失败: "+err.Error())
		return
	}
	s.StartTriggeredRunWithConversation(
		"reporter",
		fmt.Sprintf("人工生成步骤与报告 · finding#%d", f.ID),
		message,
		taskID,
		false,
		taskDesc,
		taskGoal, conversation.ID,
	)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"queued":          true,
		"agent_key":       "reporter",
		"finding_id":      f.ID,
		"finding_node_id": *f.NodeID,
		"conversation_id": conversation.ID,
	})
}

func manualFindingReportMessage(f *db.DBFinding, taskID int64) string {
	var b strings.Builder
	b.WriteString("【人工重新生成步骤与报告】这是一个已经登记的漏洞，请补生成该漏洞的结构化复现步骤和完整详细报告；不要创建新的漏洞记录，也不要修改或删除原始证据。\n")
	fmt.Fprintf(&b, "独立漏洞记录 ID（finding_id）=%d；探索节点 ID（finding_node_id）=%d。\n", f.ID, *f.NodeID)
	if taskID > 0 {
		fmt.Fprintf(&b, "来源任务 ID=%d。\n", taskID)
	}
	b.WriteString("先读取 get_finding_traffic(finding_id) 的当前证据清单及 version，再读取节点详情和任务执行记录；只使用实际保存的请求、响应和执行证据，不臆造步骤或数据包。\n")
	b.WriteString("报告必须包含“概述”“影响与危害”“受影响范围”“复现步骤”“根因分析”“修复建议”，并在复现步骤中按“步骤 1、步骤 2 …”完整展开。数据包只能引用该漏洞已绑定的真实流量。\n")
	b.WriteString("最后调用 update_finding_report：finding_id 使用探索节点 ID，evidence_version 使用刚读取的证据版本；报告正文保存为 Markdown。")
	return b.String()
}
