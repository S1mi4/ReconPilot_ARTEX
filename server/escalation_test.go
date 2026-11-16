package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

// 提案接口的三条硬约束：审批人不能自报、拒绝必须写理由、跨项目看不见也批不了。
func TestEscalationAPIApproveRejectAndIsolate(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()

	mine := testProjectID(t, m)
	other, err := m.pg.Projects().Create("提案隔离 "+time.Now().Format("150405.000000"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = m.pg.Projects().SoftDelete(other.ID)
		_ = m.pg.Projects().Purge(other.ID)
	})

	marker := "escalation-api-" + t.Name()
	task, err := m.CreateTask(mine, "提案任务", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	findingID, err := m.pg.AddFinding(taskID, 0, marker, "SQLi", pgdb.SeverityHigh, "", "", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	otherTask, err := m.CreateTask(other.ID, "别人项目", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	otherTaskID, _ := strconv.ParseInt(otherTask.ID, 10, 64)
	otherFinding, err := m.pg.AddFinding(otherTaskID, 0, marker, "theirs", pgdb.SeverityHigh, "", "", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM finding_escalations WHERE finding_id IN ($1,$2)`, findingID, otherFinding)
		_, _ = m.pg.Exec(`DELETE FROM findings WHERE vulnclass=$1`, marker)
	})

	s := &Server{m: m}
	s.engine = NewEngine(m)
	projectHeader := strconv.FormatInt(mine, 10)

	// agent 侧先落一条提案（工具路径与 HTTP 路径共用同一个 store）。
	e, err := m.pg.CreateEscalation(t.Context(), pgdb.EscalationInput{
		FindingID: findingID, TaskID: taskID, Level: "L3", Title: "读取应用配置",
		Steps: "1. cat /app/config.yml", ExpectedImpact: "可能读到数据库凭据",
		RollbackPlan: "只读，无残留", StopConditions: []string{"看到凭据即停"}, ProposedBy: "worker",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 列表要能拿到，且只含本项目。
	rec := httptest.NewRecorder()
	req := newReqWithProject(http.MethodGet, "/api/exploration/findings/"+strconv.FormatInt(findingID, 10)+"/escalations", nil)
	req.SetPathValue("id", strconv.FormatInt(findingID, 10))
	req.Header.Set(projectIDHeader, projectHeader)
	s.listFindingEscalations(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "读取应用配置") {
		t.Fatalf("list status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 别项目的漏洞：按 id 取提案列表必须 404，不能因为 id 猜对就泄露。
	rec = httptest.NewRecorder()
	req = newReqWithProject(http.MethodGet, "/api/exploration/findings/"+strconv.FormatInt(otherFinding, 10)+"/escalations", nil)
	req.SetPathValue("id", strconv.FormatInt(otherFinding, 10))
	req.Header.Set(projectIDHeader, projectHeader)
	s.listFindingEscalations(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-project list status=%d, want 404", rec.Code)
	}

	// 拒绝不写理由 → 400。
	rec = httptest.NewRecorder()
	req = newReqWithProject(http.MethodPost, "/api/exploration/escalations/1/decide", strings.NewReader(`{"approve":false,"note":"  "}`))
	req.SetPathValue("id", strconv.FormatInt(e.ID, 10))
	req.Header.Set(projectIDHeader, projectHeader)
	s.decideEscalation(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("reject without note status=%d, want 400 (%s)", rec.Code, rec.Body.String())
	}

	// 批准：写库成功后，请求体里自报的审批人被忽略。
	rec = httptest.NewRecorder()
	req = newReqWithProject(http.MethodPost, "/api/exploration/escalations/"+strconv.FormatInt(e.ID, 10)+"/decide",
		strings.NewReader(`{"approve":true,"note":"同意","ttl_hours":6,"decided_by":"root"}`))
	req.SetPathValue("id", strconv.FormatInt(e.ID, 10))
	req.Header.Set(projectIDHeader, projectHeader)
	s.decideEscalation(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got pgdb.FindingEscalation
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != pgdb.EscalationApproved || got.DecidedBy != "admin" || got.ExpiresAt == nil {
		t.Fatalf("approved = %+v", got)
	}

	// 二次审批是冲突，不是覆盖。
	rec = httptest.NewRecorder()
	req = newReqWithProject(http.MethodPost, "/api/exploration/escalations/"+strconv.FormatInt(e.ID, 10)+"/decide",
		strings.NewReader(`{"approve":false,"note":"改主意"}`))
	req.SetPathValue("id", strconv.FormatInt(e.ID, 10))
	req.Header.Set(projectIDHeader, projectHeader)
	s.decideEscalation(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("double decide status=%d, want 409", rec.Code)
	}

	// 作废后不能再执行。
	rec = httptest.NewRecorder()
	req = newReqWithProject(http.MethodPost, "/api/exploration/escalations/"+strconv.FormatInt(e.ID, 10)+"/cancel",
		strings.NewReader(`{"note":"窗口过了"}`))
	req.SetPathValue("id", strconv.FormatInt(e.ID, 10))
	req.Header.Set(projectIDHeader, projectHeader)
	s.cancelEscalation(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), pgdb.EscalationCancelled) {
		t.Fatalf("cancel status=%d body=%s", rec.Code, rec.Body.String())
	}
}
