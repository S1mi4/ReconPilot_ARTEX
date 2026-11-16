package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

// 利用扩展提案的 HTTP 面：读列表、人工审批、作废，以及一条手工补录的入口（agent
// 走 propose_escalation 工具，人在详情页面对的是同一张表）。
//
// 审批是这个文件里唯一的"写危险结论"的动作，因此额外做了两件事：
//   1. 审批人取自登录身份，不接受请求体自述；
//   2. 拒绝/保留理论也必须留 note —— 审计要能回答"当时为什么没批"。

func (s *Server) registerEscalations(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/exploration/findings/{id}/escalations", s.listFindingEscalations)
	mux.HandleFunc("POST /api/exploration/findings/{id}/escalations", s.createFindingEscalation)
	mux.HandleFunc("POST /api/exploration/escalations/{id}/decide", s.decideEscalation)
	mux.HandleFunc("POST /api/exploration/escalations/{id}/cancel", s.cancelEscalation)
	mux.HandleFunc("POST /api/exploration/escalations/{id}/outcome", s.recordEscalationOutcome)
}

func (s *Server) listFindingEscalations(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	if !s.requireFindingInProject(w, r, id) {
		return
	}
	if s.m.pg == nil {
		writeJSON(w, 200, []*pgdb.FindingEscalation{})
		return
	}
	list, err := s.m.pg.ListEscalations(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if list == nil {
		list = []*pgdb.FindingEscalation{}
	}
	writeJSON(w, 200, list)
}

// createFindingEscalation 是人工补录入口：人自己写一条提案再自己批（或交给别人批）。
// agent 走的是工具那条路，落的是同一张表、同一套校验。
func (s *Server) createFindingEscalation(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	if !s.requireFindingInProject(w, r, id) {
		return
	}
	var body struct {
		Level          string   `json:"level"`
		Title          string   `json:"title"`
		Objective      string   `json:"objective"`
		Preconditions  []string `json:"preconditions"`
		Steps          string   `json:"steps"`
		ExpectedImpact string   `json:"expected_impact"`
		BlastRadius    string   `json:"blast_radius"`
		StopConditions []string `json:"stop_conditions"`
		RollbackPlan   string   `json:"rollback_plan"`
		Alternative    string   `json:"alternative"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if s.m.pg == nil {
		writeErr(w, 503, "数据库不可用")
		return
	}
	projectID, _ := resolveProjectID(r)
	in := pgdb.EscalationInput{
		ProjectID: projectID, FindingID: id, Level: strings.ToUpper(strings.TrimSpace(body.Level)),
		Title: body.Title, Objective: body.Objective, Preconditions: body.Preconditions,
		Steps: body.Steps, ExpectedImpact: body.ExpectedImpact, BlastRadius: body.BlastRadius,
		StopConditions: body.StopConditions, RollbackPlan: body.RollbackPlan,
		Alternative: body.Alternative, ProposedBy: "human",
	}
	e, err := s.m.pg.CreateEscalation(r.Context(), in)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, e)
}

func (s *Server) decideEscalation(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad escalation id")
		return
	}
	if _, ok := s.requireProject(w, r, false); !ok {
		return
	}
	var body struct {
		Approve  bool   `json:"approve"`
		Note     string `json:"note"`
		TTLHours int    `json:"ttl_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if s.m.pg == nil {
		writeErr(w, 503, "数据库不可用")
		return
	}
	cur, err := s.m.pg.GetEscalation(r.Context(), id)
	if err != nil || cur == nil {
		writeErr(w, 404, "提案不存在")
		return
	}
	if pid, ok := resolveProjectID(r); ok && cur.ProjectID != pid {
		writeErr(w, 404, "提案不存在")
		return
	}
	// 拒绝必须写理由：以后回看"为什么没批"比"批了什么"更容易丢。
	if !body.Approve && strings.TrimSpace(body.Note) == "" {
		writeErr(w, 400, "拒绝或仅保留理论时必须填写理由")
		return
	}
	if body.Approve && body.TTLHours > int(pgdb.MaxEscalationApprovalTTL/time.Hour) {
		writeErr(w, http.StatusBadRequest, "批准有效期最长为 24 小时")
		return
	}
	ttl := time.Duration(body.TTLHours) * time.Hour
	if body.TTLHours <= 0 {
		ttl = pgdb.MaxEscalationApprovalTTL
	}
	e, err := s.m.pg.DecideEscalation(r.Context(), id, body.Approve, s.adminActor(r), body.Note, ttl)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, e)
}

func (s *Server) cancelEscalation(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad escalation id")
		return
	}
	if _, ok := s.requireProject(w, r, false); !ok {
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if s.m.pg == nil {
		writeErr(w, 503, "数据库不可用")
		return
	}
	cur, err := s.m.pg.GetEscalation(r.Context(), id)
	if err != nil || cur == nil {
		writeErr(w, 404, "提案不存在")
		return
	}
	if pid, ok := resolveProjectID(r); ok && cur.ProjectID != pid {
		writeErr(w, 404, "提案不存在")
		return
	}
	e, err := s.m.pg.CancelEscalation(r.Context(), id, s.adminActor(r), body.Note)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, e)
}

// recordEscalationOutcome 回填「人工执行」的结果：人按批准的理论步骤自己做完之后，
// 把成败与真实影响记回来。这是让审计闭环的最后一步——没有它，批准过的提案永远停在
// approved，也没人知道那次操作到底造成了什么。
func (s *Server) recordEscalationOutcome(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad escalation id")
		return
	}
	if _, ok := s.requireProject(w, r, false); !ok {
		return
	}
	var body struct {
		Status         string `json:"status"`
		ImpactObserved string `json:"impact_observed"`
		Note           string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if s.m.pg == nil {
		writeErr(w, 503, "数据库不可用")
		return
	}
	cur, err := s.m.pg.GetEscalation(r.Context(), id)
	if err != nil || cur == nil {
		writeErr(w, 404, "提案不存在")
		return
	}
	if pid, ok := resolveProjectID(r); ok && cur.ProjectID != pid {
		writeErr(w, 404, "提案不存在")
		return
	}
	if body.ImpactObserved == "" {
		body.ImpactObserved = "none"
	}
	e, err := s.m.pg.RecordEscalationOutcome(r.Context(), id, strings.TrimSpace(body.Status), body.ImpactObserved, strings.TrimSpace(body.Note))
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, e)
}

// adminActor 是审批人标识。单管理员部署下没有多用户身份，统一记 "admin"；
// 关键是它绝不取自请求体——谁能批必须由服务端决定，不能由调用方自报。
func (s *Server) adminActor(*http.Request) string { return "admin" }

// runEscalationExpiryWorker expires stale approvals promptly after startup and
// then periodically, while the database transition itself remains the final gate.
func (s *Server) runEscalationExpiryWorker() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	expire := func() {
		ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		defer cancel()
		count, err := s.m.pg.ExpireStaleApprovals(ctx)
		if err != nil && s.ctx.Err() == nil {
			log.Printf("[escalations] 过期审批清理失败: %v", err)
			return
		}
		if count > 0 {
			log.Printf("[escalations] 已将 %d 条过期审批标记为 expired", count)
		}
	}
	expire()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			expire()
		}
	}
}
