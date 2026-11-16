package agent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// EscalationRecorder 是提案的落库入口。用接口而不是直接依赖 *db.DB，是为了让
// ToolSet 在无库的场景（catalog 的 seed 空壳、单测）仍然构造得出来。
type EscalationRecorder interface {
	CreateEscalation(ctx context.Context, in db.EscalationInput) (*db.FindingEscalation, error)
}

// proposeEscalationSchema 的字段顺序与提示词里的说明一一对应：越靠前的字段越是
// 审核者判断"该不该批"的依据，模型漏填直接被拒。
func (t *ToolSet) proposeEscalation() actool.CoreTool {
	return writeTool("propose_escalation",
		"当验证一个漏洞必须扩大影响才能继续判断时，用它提交一份【理论操作提案】，交给人审批。它不会执行任何动作，只把步骤、影响面、停止条件、回滚方式写进库里，等人在漏洞详情页批准。\n"+
			"什么时候用：你已经用最小手段证明了漏洞存在，但要判断真实风险需要写目标文件、读业务数据、执行命令、提权、持久化、横向或整库导出。\n"+
			"什么时候不要用：能用一个更轻的动作证明就够了——先去试那个，别提案；也不要用它替代上报漏洞（报漏洞用 report_finding）。\n"+
			"提案写完就停手，不要自己先执行一遍：自己执行等于绕过审批，闸门会拒绝，且这条执行不会计入任何授权。",
		obj(map[string]any{
			"finding_id": str("要扩展的漏洞 id（report_finding 返回的 finding_id）"),
			"level":      map[string]any{"type": "string", "enum": []string{"L2", "L3"}, "description": "影响等级：L2=受限读取（批量/非最小读取）；L3=写目标文件、命令执行、持久化、提权、横向、删数据、整库导出。L1（只改自己创建的对象）无需提案；L4（大规模导出/破坏）永远禁止，不要提。"},
			"title":      str("一句话标题，说明这次要验证什么"),
			"objective":  str("为什么需要做这件事：想确认的风险是什么，做完能回答什么"),
			"preconditions": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "执行的前提条件（已确认的入口、需要的权限、依赖的对象）"},
			"steps":           str("理论操作步骤（Markdown，逐条编号）：每条写清命令/请求、预期输出、以及这一步为什么不可替代"),
			"expected_impact": str("预期影响：成功时目标会发生什么"),
			"blast_radius":    str("影响面：最坏情况下会波及什么（数据、服务、其他租户）"),
			"stop_conditions": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "停止条件：出现什么现象必须立刻停（至少一条）"},
			"rollback_plan": str("回滚/止损：做完怎么恢复，或为什么无需恢复"),
			"alternative":   str("更轻的替代方案（如果能想到）：为什么它不足以回答同样的问题"),
		}, "finding_id", "level", "title", "steps", "expected_impact",
			"stop_conditions", "rollback_plan"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				FindingID      json.RawMessage `json:"finding_id"`
				Level          string          `json:"level"`
				Title          string          `json:"title"`
				Objective      string          `json:"objective"`
				Preconditions  []string        `json:"preconditions"`
				Steps          string          `json:"steps"`
				ExpectedImpact string          `json:"expected_impact"`
				BlastRadius    string          `json:"blast_radius"`
				StopConditions []string        `json:"stop_conditions"`
				RollbackPlan   string          `json:"rollback_plan"`
				Alternative    string          `json:"alternative"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if t.escalations == nil {
				return actool.Errorf("当前会话没有可用的提案存储（对话里请说明需要扩大影响，由任务内 agent 提交提案）"), nil
			}
			id := pid(a.FindingID)
			if id <= 0 {
				return actool.Errorf("finding_id 必须是 report_finding 返回的漏洞 id"), nil
			}
			input := db.EscalationInput{
				FindingID: id, TaskID: t.taskID, Level: strings.ToUpper(strings.TrimSpace(a.Level)),
				Title: a.Title, Objective: a.Objective, Preconditions: a.Preconditions,
				Steps: a.Steps, ExpectedImpact: a.ExpectedImpact, BlastRadius: a.BlastRadius,
				StopConditions: a.StopConditions, RollbackPlan: a.RollbackPlan,
				Alternative: a.Alternative, ProposedBy: t.worker,
			}
			e, err := t.escalations.CreateEscalation(ctx, input)
			if err != nil {
				return actool.Errorf("提案未被接受：" + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"escalation_id": e.ID,
				"status":        e.Status,
				"level":         e.Level,
				"finding_id":    e.FindingID,
				"next":          "提案已登记，等人在漏洞详情 → 利用验证 里审核。不要自己执行其中的步骤，也不要换个说法重试——需要补充信息就更新提案。",
			})
		})
}
