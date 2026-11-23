package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	pgdb "github.com/Autumn-27/artex/db"
)

func TestStep8MultiRoundPlanProfileCompletionAndMainChatAck(t *testing.T) {
	s, projectID, token := step2TestServer(t)
	h := s.Handler()

	task, round1 := createStartedAssessmentTask(t, s.m, projectID, "step8-workbench-api", pgdb.AssessmentConfig{
		ExecutionMode:    pgdb.AssessmentExecDynamic,
		BusinessOverview: "多轮评估与工作台接口验证",
		Environments: []pgdb.AssessmentEnvironmentInput{
			{Name: "qa", URL: "http://127.0.0.1:18080", IsDefault: true},
		},
		SourceAcknowledged: true,
	}, 2)
	taskNum, _ := strconv.ParseInt(task.ID, 10, 64)

	uploadTestCodebaseOnDraft(t, s, token, task.ID, []codebaseTestFile{
		{path: "order-svc/pom.xml", data: []byte(`<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>order-svc</artifactId><version>1.0.0</version></project>`)},
		{path: "order-svc/src/main/java/com/example/App.java", data: []byte("package com.example;\npublic class App { public void run() {} }\n")},
		{path: "order-svc/application.yml", data: []byte("server:\n  port: 8080\n")},
	})
	if _, _, err := s.BuildAssessmentInitialProfile(t.Context(), task.ID, BuildProfileOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.BuildAssessmentCoveragePlan(t.Context(), task.ID); err != nil {
		t.Fatal(err)
	}

	// Open round 1 should expose completion_check reasons (not yet completed) and code_audits/rounds metadata.
	planR1Before := httpJSON(t, h, token, http.MethodGet, "/api/tasks/"+task.ID+"/coverage-plan", nil)
	if planR1Before.Code != http.StatusOK {
		t.Fatalf("GET coverage-plan failed: %d %s", planR1Before.Code, planR1Before.Body.String())
	}
	var beforeDTO AssessmentCoveragePlanResponse
	if err := json.Unmarshal(planR1Before.Body.Bytes(), &beforeDTO); err != nil {
		t.Fatal(err)
	}
	if beforeDTO.CompletionCheck == nil || beforeDTO.CompletionCheck.CanComplete || len(beforeDTO.CompletionCheck.Reasons) == 0 {
		t.Fatalf("expected non-completable completion_check on open round with unfinished obligations, got %+v", beforeDTO.CompletionCheck)
	}
	if len(beforeDTO.Rounds) != 1 || beforeDTO.Rounds[0].ID != round1.ID {
		t.Fatalf("expected rounds list containing round 1, got %+v", beforeDTO.Rounds)
	}

	// Satisfy all Round 1 obligations and complete Round 1.
	_, _, _ = s.m.pg.ReconcileObligationReadiness(taskNum, round1.ID)
	obs1, _ := s.m.pg.ListCoverageObligations(pgdb.CoverageObligationFilter{TaskID: taskNum, RoundID: round1.ID, Limit: 100})
	for _, ob := range obs1 {
		evKind := pgdb.EvidenceExecution
		switch ob.ExecutionMode {
		case pgdb.ExecModeCodeAuditBatch:
			evKind = pgdb.EvidenceCodeRange
		case pgdb.ExecModeCodeInvestigate:
			evKind = pgdb.EvidenceConfig
		}
		satisfyStep7ObligationWithEvidence(t, s.m.pg, task, taskNum, round1.ID, ob, evKind, "step8:ok-"+strconv.FormatInt(ob.ID, 10))
	}
	for _, evType := range []string{"code_version_change", "evidence_invalidated", "profile_change"} {
		if evs, err := s.m.pg.ListUnprocessedAssessmentEventsByType(taskNum, evType, 50); err == nil && len(evs) > 0 {
			var ids []int64
			for _, ev := range evs {
				ids = append(ids, ev.ID)
			}
			_ = s.m.pg.MarkAssessmentEventIDsProcessed(taskNum, ids)
		}
	}
	completed, report, err := s.m.CompleteAssessment(task)
	if err != nil || !completed {
		t.Fatalf("expected Round 1 completion, completed=%v report=%+v err=%v", completed, report, err)
	}

	// Open Round 2 via HTTP API.
	openResp := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+task.ID+"/assessment-rounds", map[string]any{
		"reason":              "第 2 轮增量复测",
		"environment_version": "env-v2",
	})
	if openResp.Code != http.StatusCreated {
		t.Fatalf("POST assessment-rounds failed: %d %s", openResp.Code, openResp.Body.String())
	}

	// GET /api/tasks/{id}/assessment-rounds returns Round 2 and Round 1 newest first.
	roundsRec := httpJSON(t, h, token, http.MethodGet, "/api/tasks/"+task.ID+"/assessment-rounds", nil)
	if roundsRec.Code != http.StatusOK {
		t.Fatalf("GET assessment-rounds failed: %d %s", roundsRec.Code, roundsRec.Body.String())
	}
	var roundsBody struct {
		Rounds []pgdb.AssessmentRound `json:"rounds"`
	}
	if err := json.Unmarshal(roundsRec.Body.Bytes(), &roundsBody); err != nil {
		t.Fatal(err)
	}
	if len(roundsBody.Rounds) != 2 || roundsBody.Rounds[0].RoundNo != 2 || roundsBody.Rounds[1].RoundNo != 1 {
		t.Fatalf("expected rounds [2, 1], got %+v", roundsBody.Rounds)
	}

	// Inspecting historical Round 1 specifically must return Round 1's completed state and historical completion report!
	histPlanRec := httpJSON(t, h, token, http.MethodGet, "/api/tasks/"+task.ID+"/coverage-plan?round_id="+strconv.FormatInt(round1.ID, 10), nil)
	if histPlanRec.Code != http.StatusOK {
		t.Fatalf("GET coverage-plan?round_id=round1 failed: %d %s", histPlanRec.Code, histPlanRec.Body.String())
	}
	var histDTO AssessmentCoveragePlanResponse
	if err := json.Unmarshal(histPlanRec.Body.Bytes(), &histDTO); err != nil {
		t.Fatal(err)
	}
	if histDTO.Round == nil || histDTO.Round.ID != round1.ID || histDTO.Round.Status != "completed" {
		t.Fatalf("expected historical Round 1 completed metadata, got %+v", histDTO.Round)
	}
	if histDTO.CompletionCheck == nil || !histDTO.CompletionCheck.CanComplete {
		t.Fatalf("expected historical Round 1 persisted completion_check can_complete=true, got %+v", histDTO.CompletionCheck)
	}
	if len(histDTO.EvidenceRefs) == 0 {
		t.Fatalf("expected evidence_refs populated on coverage-plan response")
	}

	// Historical profile query with ?round_id=round1 must return Round 1's Round metadata.
	histProfRec := httpJSON(t, h, token, http.MethodGet, "/api/tasks/"+task.ID+"/profile?round_id="+strconv.FormatInt(round1.ID, 10), nil)
	if histProfRec.Code != http.StatusOK {
		t.Fatalf("GET profile?round_id=round1 failed: %d %s", histProfRec.Code, histProfRec.Body.String())
	}
	if !strings.Contains(histProfRec.Body.String(), `"round_no":1`) {
		t.Fatalf("expected historical round_no 1 in profile response, got %s", histProfRec.Body.String())
	}

	// Verify MainAgent chat route accepts source_acknowledged without breaking legacy tasks.
	chatRec := httpJSON(t, h, token, http.MethodPost, "/api/chat?task="+task.ID, map[string]any{
		"message":             "汇报当前进展",
		"seg":                 0,
		"source_acknowledged": true,
	})
	if chatRec.Code != http.StatusAccepted && chatRec.Code != http.StatusOK {
		t.Fatalf("POST /api/chat failed: %d %s", chatRec.Code, chatRec.Body.String())
	}

	// Legacy assessment_mode=false task rejects assessment-rounds GET with 400 cleanly.
	legacy, err := s.m.CreateTask(projectID, "step8-legacy", "normal goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(legacy.ID, DeleteTaskOptions{}) })
	legacyRec := httpJSON(t, h, token, http.MethodGet, "/api/tasks/"+legacy.ID+"/assessment-rounds", nil)
	if legacyRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for legacy task assessment-rounds, got %d %s", legacyRec.Code, legacyRec.Body.String())
	}
}
