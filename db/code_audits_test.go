package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestTaskCodeAuditIdentityIgnoresLineAndVersionChanges(t *testing.T) {
	evidence := func(version, candidateKey string, sourceLine, sinkLine int, sinkSymbol string) json.RawMessage {
		raw, err := json.Marshal(map[string]any{
			"codebase_id": "codebase", "relative_path": "services/orders",
			"version_id": version, "candidate_key": candidateKey,
			"candidate": map[string]any{
				"source": map[string]any{"file": "src/Controller.java", "line": sourceLine, "symbol": "search", "parameter": "q"},
				"sink":   map[string]any{"file": "src/Query.java", "line": sinkLine, "symbol": sinkSymbol, "parameter": "sql"},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	first, err := taskCodeAuditIdentityKey("SQL_INJECTION", evidence("version-1", "candidate-1", 10, 80, "executeQuery"))
	if err != nil {
		t.Fatal(err)
	}
	moved, err := taskCodeAuditIdentityKey("SQL_INJECTION", evidence("version-2", "candidate-2", 110, 180, "executeQuery"))
	if err != nil {
		t.Fatal(err)
	}
	if first != moved {
		t.Fatalf("source/sink line movement changed finding identity: %s != %s", first, moved)
	}
	changedSink, err := taskCodeAuditIdentityKey("SQL_INJECTION", evidence("version-2", "candidate-3", 110, 180, "executeUpdate"))
	if err != nil {
		t.Fatal(err)
	}
	if first == changedSink {
		t.Fatal("different sink symbols shared a finding identity")
	}
}

func TestTaskCodeAuditEvidenceMergePreservesObservationAndFixHistory(t *testing.T) {
	makeEvidence := func(version, candidateKey string) json.RawMessage {
		raw, err := json.Marshal(map[string]any{
			"candidate_key": candidateKey, "codebase_id": "codebase", "relative_path": "service",
			"version_id": version, "scope_path": ".", "candidate": map[string]any{"title": "SQL injection"},
			"review": map[string]any{"accepted": true},
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	first, _, err := mergeTaskCodeAuditFindingEvidence(nil, makeEvidence("v1", "candidate-v1"), "identity", 11, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	var fixedMap map[string]any
	if err := json.Unmarshal(first, &fixedMap); err != nil {
		t.Fatal(err)
	}
	fixedMap["fixed_in_version_id"] = "v2"
	fixedMap["fixed_audit_run_id"] = 12
	history, _ := fixedMap["history"].([]any)
	history = append(history, map[string]any{"kind": "fixed", "version_id": "v2", "audit_run_id": 12, "scope_path": "."})
	fixedMap["history"] = history
	fixedEvidence, err := json.Marshal(fixedMap)
	if err != nil {
		t.Fatal(err)
	}
	merged, reopened, err := mergeTaskCodeAuditFindingEvidence(fixedEvidence, makeEvidence("v3", "candidate-v3"), "identity", 13, time.Time{}, FindingFixed)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened {
		t.Fatal("a reproduced auto-fixed finding was not reopened")
	}
	var stored struct {
		FirstSeen string           `json:"first_seen_version_id"`
		LastSeen  string           `json:"last_seen_version_id"`
		FixedIn   string           `json:"fixed_in_version_id"`
		History   []map[string]any `json:"history"`
	}
	if err := json.Unmarshal(merged, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.FirstSeen != "v1" || stored.LastSeen != "v3" || stored.FixedIn != "" || len(stored.History) != 3 {
		t.Fatalf("merged evidence lost version or fix history: %+v", stored)
	}
}

func TestTaskCodeAuditQueueProgressAndResume(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask("code audit queue", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	codebaseID := fmt.Sprintf("audit-%d", task.ID)
	versionID := fmt.Sprintf("%032x", task.ID)
	var serviceID int64
	if err := d.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,latest_version_id,latest_present)
VALUES($1,$2,'.','service','confirmed','manual',$3,true) RETURNING id`, task.ID, codebaseID, versionID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	created, err := d.CreateTaskCodeAudit(CreateTaskCodeAudit{
		TaskID: task.ID, CodeServiceID: serviceID, CodebaseID: codebaseID, VersionID: versionID,
		ScopePath: ".", ProfileSource: "task_chain", ProfileName: "test", ProfileFormat: "openai",
		Model: "test-model", Endpoint: "https://llm.example/v1", SourceAcknowledged: true,
		FilesTotal: 5, ChunksTotal: 2, BudgetTokens: 120000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Status != "queued" || created.FilesTotal != 5 || created.ChunksTotal != 2 || !created.SourceAcknowledged {
		t.Fatalf("created audit run = %+v", created)
	}
	claimed, err := d.ClaimNextTaskCodeAudit()
	if err != nil || claimed == nil || claimed.ID != created.ID || claimed.Status != "running" {
		t.Fatalf("claimed audit = %+v err=%v", claimed, err)
	}
	if second, err := d.ClaimNextTaskCodeAudit(); err != nil || second != nil {
		t.Fatalf("unexpected second queued audit = %+v err=%v", second, err)
	}
	candidate := json.RawMessage(`{"title":"taint path","evidence_excerpt":"Source → sink"}`)
	if err := d.AddTaskCodeAuditCandidate(created.ID, "candidate-1", candidate, "source/sink and flow reviewed"); err != nil {
		t.Fatal(err)
	}
	progress := TaskCodeAuditProgress{
		FilesTotal: 5, FilesAnalyzed: 2, FilesSkipped: 1, ChunksTotal: 2, ChunksCompleted: 1,
		NextFileIndex: 2, UsedTokens: 119000, Summary: "first chunk complete",
	}
	if err := d.UpdateTaskCodeAuditProgress(created.ID, progress); err != nil {
		t.Fatal(err)
	}
	if err := d.IncompleteTaskCodeAudit(created.ID, progress, "budget exhausted"); err != nil {
		t.Fatal(err)
	}
	resumed, err := d.ResumeTaskCodeAudit(task.ID, created.ID, 50000)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "queued" || resumed.BudgetTokens != 170000 || resumed.NextFileIndex != 2 || resumed.UsedTokens != 119000 {
		t.Fatalf("resumed audit lost checkpoint: %+v", resumed)
	}
	claimed, err = d.ClaimNextTaskCodeAudit()
	if err != nil || claimed == nil || claimed.ID != created.ID {
		t.Fatalf("reclaimed audit = %+v err=%v", claimed, err)
	}
	progress.FilesAnalyzed = 5
	progress.ChunksCompleted = 2
	progress.NextFileIndex = 5
	progress.UsedTokens = 130000
	progress.Summary = "audit complete"
	if err := d.CompleteTaskCodeAudit(created.ID, progress); err != nil {
		t.Fatal(err)
	}
	listed, err := d.ListTaskCodeAudits(task.ID)
	if err != nil || len(listed) != 1 || listed[0].Status != "completed" || listed[0].CandidateCount != 1 || len(listed[0].Candidates) != 1 {
		t.Fatalf("listed audit runs = %+v err=%v", listed, err)
	}
	if listed[0].Candidates[0].ReviewStatus != "pending_review" || listed[0].Candidates[0].ReviewerSummary != "source/sink and flow reviewed" {
		t.Fatalf("candidate was not retained for human review: %+v", listed[0].Candidates[0])
	}
	if !listed[0].CompletedAt.After(time.Time{}) {
		t.Fatal("completed audit has no completion time")
	}
}

func TestConfirmedTaskCodeAuditCandidateCreatesLinkedFindingOnce(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask("publish code audit finding", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	codebaseID := fmt.Sprintf("publish-%d", task.ID)
	versionID := fmt.Sprintf("%032x", task.ID)
	extra, _ := json.Marshal(map[string]any{"task_id": task.ID, "codebase_id": codebaseID, "relative_path": "service"})
	var assetID, serviceID int64
	if err := d.QueryRow(`INSERT INTO assets(type,task_ids,service_name,extra)
VALUES('code_service',ARRAY[$1]::bigint[],'service',$2) RETURNING id`, task.ID, string(extra)).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,
asset_id,latest_version_id,latest_present) VALUES($1,$2,'service','service','confirmed','manual',$3,$4,true) RETURNING id`,
		task.ID, codebaseID, assetID, versionID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	run, err := d.CreateTaskCodeAudit(CreateTaskCodeAudit{TaskID: task.ID, CodeServiceID: serviceID,
		CodebaseID: codebaseID, VersionID: versionID, ScopePath: ".", ProfileName: "test", Model: "test-model",
		Endpoint: "https://llm.example/v1", SourceAcknowledged: true, FilesTotal: 1, ChunksTotal: 1, BudgetTokens: 120000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimNextTaskCodeAudit(); err != nil {
		t.Fatal(err)
	}
	if err := d.AddTaskCodeAuditCandidate(run.ID, "sql-candidate", json.RawMessage(`{"title":"SQL 注入"}`), "初筛通过"); err != nil {
		t.Fatal(err)
	}
	withCandidate, err := d.GetTaskCodeAudit(task.ID, run.ID)
	if err != nil || len(withCandidate.Candidates) != 1 {
		t.Fatalf("get audit candidate = %+v err=%v", withCandidate, err)
	}
	if err := d.CompleteTaskCodeAudit(run.ID, TaskCodeAuditProgress{FilesTotal: 1, FilesAnalyzed: 1, ChunksTotal: 1, ChunksCompleted: 1, NextFileIndex: 1, UsedTokens: 1000}); err != nil {
		t.Fatal(err)
	}

	structured, _ := json.Marshal(map[string]any{
		"candidate_key": "sql-candidate", "codebase_id": codebaseID, "version_id": versionID, "relative_path": "service",
		"source": map[string]any{"file": "Controller.java", "line": 8}, "sink": map[string]any{"file": "Query.java", "line": 24},
		"flow":                []any{map[string]any{"file": "Controller.java", "line": 8}, map[string]any{"file": "Query.java", "line": 24}},
		"blocking_conditions": "未发现有效阻断", "exploitability": "HTTP 参数可控并到达 SQL 拼接",
	})
	result, err := d.FinalizeTaskCodeAuditCandidateReview(context.Background(), task.ID, run.ID, withCandidate.Candidates[0].ID, TaskCodeAuditCandidateReviewInput{
		Accepted: true, VerificationSummary: "独立复核确认 source 到 SQL sink 可利用。", VulnClass: "SQL_INJECTION",
		Name: "SQL 注入", Severity: SeverityHigh, Summary: "HTTP 参数未经参数化进入 SQL 查询。", Evidence: "Controller.java:8 → Query.java:24",
		CodeAuditEvidence: structured, UsedTokens: 3500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "published" || result.FindingID <= 0 {
		t.Fatalf("review result = %+v", result)
	}
	finding, err := d.GetFinding(result.FindingID)
	if err != nil || finding == nil {
		t.Fatalf("published finding = %+v err=%v", finding, err)
	}
	var persistedEvidence map[string]any
	_ = json.Unmarshal(finding.CodeAuditEvidence, &persistedEvidence)
	if finding.TaskID == nil || *finding.TaskID != task.ID || len(finding.AssetIDs) != 1 || finding.AssetIDs[0] != assetID ||
		persistedEvidence["version_id"] != versionID || persistedEvidence["blocking_conditions"] != "未发现有效阻断" {
		t.Fatalf("finding lost task, code asset, or structured audit evidence: %+v", finding)
	}
	updatedRun, err := d.GetTaskCodeAudit(task.ID, run.ID)
	if err != nil || len(updatedRun.Candidates) != 1 || updatedRun.Candidates[0].ReviewStatus != "published" ||
		updatedRun.Candidates[0].VerificationSummary != "独立复核确认 source 到 SQL sink 可利用。" || updatedRun.UsedTokens != 4500 {
		t.Fatalf("candidate review state = %+v err=%v", updatedRun, err)
	}
	if _, err := d.FinalizeTaskCodeAuditCandidateReview(context.Background(), task.ID, run.ID, withCandidate.Candidates[0].ID, TaskCodeAuditCandidateReviewInput{
		Accepted: true, VerificationSummary: "再次确认", VulnClass: "SQL_INJECTION", Name: "duplicate", Severity: SeverityHigh,
		Summary: "duplicate", Evidence: "duplicate", CodeAuditEvidence: structured,
	}); !errors.Is(err, ErrTaskCodeAuditCandidateReviewConflict) {
		t.Fatalf("repeated publish error = %v; want review conflict", err)
	}
}

func TestTaskCodeAuditFindingHistoryMergesAndMarksFixedOnlyAfterFullAudit(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask("track code audit finding history", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	codebaseID := fmt.Sprintf("history-%d", task.ID)
	servicePath := "service"
	versionTimes := map[string]time.Time{}
	var serviceID, assetID int64
	versionOne := fmt.Sprintf("%032x", task.ID+101)
	versionTimes[versionOne] = time.Now().UTC().Add(-4 * time.Minute)
	extra, _ := json.Marshal(map[string]any{"task_id": task.ID, "codebase_id": codebaseID, "relative_path": servicePath})
	if err := d.QueryRow(`INSERT INTO assets(type,task_ids,service_name,extra)
VALUES('code_service',ARRAY[$1]::bigint[],'service',$2) RETURNING id`, task.ID, string(extra)).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,
asset_id,latest_version_id,latest_present) VALUES($1,$2,$3,'service','confirmed','manual',$4,$5,true) RETURNING id`,
		task.ID, codebaseID, servicePath, assetID, versionOne).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	addVersion := func(versionID string, createdAt time.Time) {
		t.Helper()
		if _, err := d.Exec(`INSERT INTO task_code_service_versions(code_service_id,version_id,version_created_at,present)
VALUES($1,$2,$3,true)`, serviceID, versionID, createdAt); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`UPDATE task_code_services SET latest_version_id=$2,latest_present=true WHERE id=$1`, serviceID, versionID); err != nil {
			t.Fatal(err)
		}
		versionTimes[versionID] = createdAt
	}
	addVersion(versionOne, versionTimes[versionOne])
	createRun := func(versionID string, files int) *TaskCodeAuditRun {
		t.Helper()
		run, err := d.CreateTaskCodeAudit(CreateTaskCodeAudit{TaskID: task.ID, CodeServiceID: serviceID,
			CodebaseID: codebaseID, VersionID: versionID, ScopePath: ".", ProfileName: "test", Model: "test-model",
			Endpoint: "https://llm.example/v1", SourceAcknowledged: true, FilesTotal: files, ChunksTotal: 1, BudgetTokens: 120000})
		if err != nil {
			t.Fatal(err)
		}
		claimed, err := d.ClaimNextTaskCodeAudit()
		if err != nil || claimed == nil || claimed.ID != run.ID {
			t.Fatalf("claim audit run %d = %+v err=%v", run.ID, claimed, err)
		}
		return run
	}
	accept := func(run *TaskCodeAuditRun, candidateKey string, sourceLine, sinkLine int) int64 {
		t.Helper()
		candidate, _ := json.Marshal(map[string]any{"title": "SQL 注入", "category": "SQL_INJECTION"})
		if err := d.AddTaskCodeAuditCandidate(run.ID, candidateKey, candidate, "source 到 sink 初筛通过"); err != nil {
			t.Fatal(err)
		}
		loaded, err := d.GetTaskCodeAudit(task.ID, run.ID)
		if err != nil || len(loaded.Candidates) != 1 {
			t.Fatalf("load candidate for run %d = %+v err=%v", run.ID, loaded, err)
		}
		if err := d.CompleteTaskCodeAudit(run.ID, TaskCodeAuditProgress{FilesTotal: 1, FilesAnalyzed: 1,
			ChunksTotal: 1, ChunksCompleted: 1, NextFileIndex: 1}); err != nil {
			t.Fatal(err)
		}
		evidence, _ := json.Marshal(map[string]any{
			"candidate_key": candidateKey, "codebase_id": codebaseID, "version_id": run.VersionID, "relative_path": servicePath,
			"scope_path": ".", "candidate": map[string]any{
				"category": "SQL_INJECTION",
				"source":   map[string]any{"file": "src/Controller.java", "line": sourceLine, "symbol": "search", "parameter": "q"},
				"sink":     map[string]any{"file": "src/Query.java", "line": sinkLine, "symbol": "executeQuery", "parameter": "sql"},
				"flow":     []any{map[string]any{"file": "src/Controller.java", "line": sourceLine}, map[string]any{"file": "src/Query.java", "line": sinkLine}},
			},
			"review": map[string]any{"accepted": true, "reason": "已复核"},
		})
		result, err := d.FinalizeTaskCodeAuditCandidateReview(context.Background(), task.ID, run.ID, loaded.Candidates[0].ID,
			TaskCodeAuditCandidateReviewInput{Accepted: true, VerificationSummary: "独立复核确认可利用 source-to-sink 路径。",
				VulnClass: "SQL_INJECTION", Name: "SQL 注入", Severity: SeverityHigh, Summary: "用户输入到达 SQL sink。",
				Evidence: "Controller.java → Query.java", CodeAuditEvidence: evidence})
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != "published" || result.FindingID <= 0 {
			t.Fatalf("publish result = %+v", result)
		}
		return result.FindingID
	}

	firstRun := createRun(versionOne, 1)
	findingID := accept(firstRun, "candidate-v1-first", 12, 80)
	secondRun := createRun(versionOne, 1)
	secondFindingID := accept(secondRun, "candidate-v1-rerun", 112, 180)
	if secondFindingID != findingID {
		t.Fatalf("same-version rerun created a second finding: first=%d second=%d", findingID, secondFindingID)
	}

	versionTwo := fmt.Sprintf("%032x", task.ID+102)
	addVersion(versionTwo, versionTimes[versionOne].Add(time.Minute))
	noFindingRun := createRun(versionTwo, 1)
	parallelRun := createRun(versionTwo, 1)
	if err := d.AddTaskCodeAuditCandidate(parallelRun.ID, "pending-parallel-candidate", json.RawMessage(`{"title":"possible SQL injection"}`), "等待独立复核"); err != nil {
		t.Fatal(err)
	}
	parallelWithCandidate, err := d.GetTaskCodeAudit(task.ID, parallelRun.ID)
	if err != nil || len(parallelWithCandidate.Candidates) != 1 {
		t.Fatalf("load parallel audit candidate = %+v err=%v", parallelWithCandidate, err)
	}
	if err := d.CompleteTaskCodeAudit(noFindingRun.ID, TaskCodeAuditProgress{FilesTotal: 1, FilesAnalyzed: 1,
		ChunksTotal: 1, ChunksCompleted: 1, NextFileIndex: 1}); err != nil {
		t.Fatal(err)
	}
	unreconciled, err := d.GetFinding(findingID)
	if err != nil || unreconciled == nil || unreconciled.Status != FindingPending {
		t.Fatalf("active same-version audit caused premature fixed status: %+v err=%v", unreconciled, err)
	}
	if err := d.CompleteTaskCodeAudit(parallelRun.ID, TaskCodeAuditProgress{FilesTotal: 1, FilesAnalyzed: 1,
		ChunksTotal: 1, ChunksCompleted: 1, NextFileIndex: 1}); err != nil {
		t.Fatal(err)
	}
	if err := d.IncompleteTaskCodeAuditReview(parallelRun.ID, 0, "候选复核等待人工判断"); err != nil {
		t.Fatal(err)
	}
	unreviewed, err := d.GetFinding(findingID)
	if err != nil || unreviewed == nil || unreviewed.Status != FindingPending {
		t.Fatalf("pending candidate caused premature fixed status: %+v err=%v", unreviewed, err)
	}
	if _, err := d.FinalizeTaskCodeAuditCandidateReview(context.Background(), task.ID, parallelRun.ID,
		parallelWithCandidate.Candidates[0].ID, TaskCodeAuditCandidateReviewInput{
			Accepted: false, VerificationSummary: "复核确认候选不是可利用路径。",
		}); err != nil {
		t.Fatal(err)
	}
	fixed, err := d.GetFinding(findingID)
	if err != nil || fixed == nil || fixed.Status != FindingFixed {
		t.Fatalf("finding after full audit with no candidate = %+v err=%v", fixed, err)
	}
	var fixedEvidence map[string]any
	if err := json.Unmarshal(fixed.CodeAuditEvidence, &fixedEvidence); err != nil {
		t.Fatal(err)
	}
	if fixedEvidence["fixed_in_version_id"] != versionTwo {
		t.Fatalf("fixed version missing from evidence: %#v", fixedEvidence)
	}

	versionThree := fmt.Sprintf("%032x", task.ID+103)
	addVersion(versionThree, versionTimes[versionTwo].Add(time.Minute))
	reproducedRun := createRun(versionThree, 1)
	reproducedID := accept(reproducedRun, "candidate-v3-lines-moved", 212, 280)
	if reproducedID != findingID {
		t.Fatalf("later version with moved lines created a second finding: first=%d reproduced=%d", findingID, reproducedID)
	}
	reproduced, err := d.GetFinding(findingID)
	if err != nil || reproduced == nil || reproduced.Status != FindingPending {
		t.Fatalf("reproduced finding did not reopen: %+v err=%v", reproduced, err)
	}
	var historyEvidence struct {
		FirstSeenVersion string `json:"first_seen_version_id"`
		LastSeenVersion  string `json:"last_seen_version_id"`
		History          []struct {
			Kind      string `json:"kind"`
			VersionID string `json:"version_id"`
		} `json:"history"`
	}
	if err := json.Unmarshal(reproduced.CodeAuditEvidence, &historyEvidence); err != nil {
		t.Fatal(err)
	}
	if historyEvidence.FirstSeenVersion != versionOne || historyEvidence.LastSeenVersion != versionThree || len(historyEvidence.History) < 4 {
		t.Fatalf("finding history lost earlier observations or state changes: %+v", historyEvidence)
	}
	page, _, err := d.ListFindingsPage(FindingFilter{TaskID: fmt.Sprint(task.ID)}, 1, 20)
	if err != nil || len(page) != 1 || page[0].ID != findingID {
		t.Fatalf("merged finding history is not available as one finding: %+v err=%v", page, err)
	}
	audits, err := d.ListTaskCodeAudits(task.ID)
	if err != nil || len(audits) != 5 {
		t.Fatalf("audit history not retained: count=%d err=%v", len(audits), err)
	}

	versionFour := fmt.Sprintf("%032x", task.ID+104)
	addVersion(versionFour, versionTimes[versionThree].Add(time.Minute))
	partialRun := createRun(versionFour, 2)
	if err := d.CompleteTaskCodeAudit(partialRun.ID, TaskCodeAuditProgress{FilesTotal: 2, FilesAnalyzed: 1,
		ChunksTotal: 1, ChunksCompleted: 1, NextFileIndex: 1}); err != nil {
		t.Fatal(err)
	}
	partial, err := d.GetFinding(findingID)
	if err != nil || partial == nil || partial.Status != FindingPending {
		t.Fatalf("partial audit incorrectly marked finding fixed: %+v err=%v", partial, err)
	}
}

func TestRejectedTaskCodeAuditCandidateStaysOutOfFindings(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask("reject code audit candidate", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	codebaseID := fmt.Sprintf("reject-%d", task.ID)
	versionID := fmt.Sprintf("%032x", task.ID)
	var serviceID int64
	if err := d.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,latest_version_id,latest_present)
VALUES($1,$2,'service','service','confirmed','manual',$3,true) RETURNING id`, task.ID, codebaseID, versionID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	run, err := d.CreateTaskCodeAudit(CreateTaskCodeAudit{TaskID: task.ID, CodeServiceID: serviceID,
		CodebaseID: codebaseID, VersionID: versionID, ScopePath: ".", ProfileName: "test", Model: "test-model",
		Endpoint: "https://llm.example/v1", SourceAcknowledged: true, FilesTotal: 1, ChunksTotal: 1, BudgetTokens: 120000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimNextTaskCodeAudit(); err != nil {
		t.Fatal(err)
	}
	if err := d.AddTaskCodeAuditCandidate(run.ID, "blocked-candidate", json.RawMessage(`{"title":"blocked"}`), "初筛待复核"); err != nil {
		t.Fatal(err)
	}
	withCandidate, err := d.GetTaskCodeAudit(task.ID, run.ID)
	if err != nil || len(withCandidate.Candidates) != 1 {
		t.Fatalf("get audit candidate = %+v err=%v", withCandidate, err)
	}
	if err := d.CompleteTaskCodeAudit(run.ID, TaskCodeAuditProgress{FilesTotal: 1, FilesAnalyzed: 1, ChunksTotal: 1, ChunksCompleted: 1, NextFileIndex: 1, UsedTokens: 1000}); err != nil {
		t.Fatal(err)
	}
	result, err := d.FinalizeTaskCodeAuditCandidateReview(context.Background(), task.ID, run.ID, withCandidate.Candidates[0].ID, TaskCodeAuditCandidateReviewInput{
		Accepted: false, VerificationSummary: "控制器先做了严格 allowlist 校验，候选路径不可利用。", UsedTokens: 1700,
	})
	if err != nil || result.Status != "rejected" || result.FindingID != 0 {
		t.Fatalf("reject result = %+v err=%v", result, err)
	}
	page, _, err := d.ListFindingsPage(FindingFilter{TaskID: fmt.Sprint(task.ID)}, 1, 20)
	if err != nil || len(page) != 0 {
		t.Fatalf("rejected candidate leaked into Findings: %+v err=%v", page, err)
	}
	updatedRun, err := d.GetTaskCodeAudit(task.ID, run.ID)
	if err != nil || len(updatedRun.Candidates) != 1 || updatedRun.Candidates[0].ReviewStatus != "rejected" ||
		updatedRun.Candidates[0].VerificationSummary == "" || updatedRun.UsedTokens != 2700 {
		t.Fatalf("rejected review was not retained: %+v err=%v", updatedRun, err)
	}
}

func TestTaskCodeAuditQueueCapsGloballyRefillsSlotsAndRetriesIndependently(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	taskA, err := d.CreateTask("audit queue cap A", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(taskA.ID) })
	taskB, err := d.CreateTask("audit queue cap B", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(taskB.ID) })

	createRun := func(task *Task, ordinal int) *TaskCodeAuditRun {
		t.Helper()
		codebaseID := fmt.Sprintf("queue-%d-%d", task.ID, ordinal)
		versionID := fmt.Sprintf("%032x", task.ID*100+int64(ordinal))
		var serviceID int64
		if err := d.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,latest_version_id,latest_present)
VALUES($1,$2,'.',$3,'confirmed','manual',$4,true) RETURNING id`, task.ID, codebaseID, fmt.Sprintf("service-%d", ordinal), versionID).Scan(&serviceID); err != nil {
			t.Fatal(err)
		}
		run, err := d.CreateTaskCodeAudit(CreateTaskCodeAudit{TaskID: task.ID, CodeServiceID: serviceID,
			CodebaseID: codebaseID, VersionID: versionID, ScopePath: ".", ProfileName: "test", Model: "test-model",
			Endpoint: "https://llm.example/v1", SourceAcknowledged: true, FilesTotal: 1, ChunksTotal: 1, BudgetTokens: 120000})
		if err != nil {
			t.Fatal(err)
		}
		return run
	}
	runsA := make([]*TaskCodeAuditRun, 6)
	for index := range runsA {
		runsA[index] = createRun(taskA, index+1)
	}
	_ = createRun(taskB, 1)

	const claimers = 8
	claimed := make(chan *TaskCodeAuditRun, claimers)
	errs := make(chan error, claimers)
	var wg sync.WaitGroup
	for range claimers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			run, err := d.ClaimNextTaskCodeAudit()
			if err != nil {
				errs <- err
				return
			}
			claimed <- run
		}()
	}
	wg.Wait()
	close(claimed)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	activeA, activeB := 0, 0
	var completedA *TaskCodeAuditRun
	var runningA []*TaskCodeAuditRun
	for run := range claimed {
		if run == nil {
			continue
		}
		switch run.TaskID {
		case taskA.ID:
			activeA++
			runningA = append(runningA, run)
			if completedA == nil {
				completedA = run
			}
		case taskB.ID:
			activeB++
		}
	}
	if activeA != 4 || activeB != 0 {
		t.Fatalf("concurrent global claims = A:%d B:%d; want exactly four active runs across tasks", activeA, activeB)
	}

	if err := d.CompleteTaskCodeAudit(completedA.ID, TaskCodeAuditProgress{FilesTotal: 1, FilesAnalyzed: 1, ChunksTotal: 1, ChunksCompleted: 1, NextFileIndex: 1}); err != nil {
		t.Fatal(err)
	}
	refill, err := d.ClaimNextTaskCodeAudit()
	if err != nil || refill == nil || refill.TaskID != taskA.ID {
		t.Fatalf("freed slot was not filled by the next queued service: run=%+v err=%v", refill, err)
	}
	serviceRuns, err := d.ListTaskCodeAudits(taskA.ID)
	if err != nil || len(serviceRuns) != len(runsA) {
		t.Fatalf("per-service audit records = %d err=%v; want %d", len(serviceRuns), err, len(runsA))
	}
	coverageByRun := map[int64]TaskCodeAuditRun{}
	for _, serviceRun := range serviceRuns {
		coverageByRun[serviceRun.ID] = serviceRun
	}
	if coverageByRun[completedA.ID].Status != "completed" || coverageByRun[completedA.ID].FilesAnalyzed != 1 ||
		coverageByRun[refill.ID].Status != "running" || coverageByRun[refill.ID].FilesAnalyzed != 0 || coverageByRun[refill.ID].CodeServiceID == completedA.CodeServiceID {
		t.Fatalf("service runs did not keep independent coverage/status: completed=%+v refill=%+v", coverageByRun[completedA.ID], coverageByRun[refill.ID])
	}
	var failedA *TaskCodeAuditRun
	for _, run := range runningA {
		if run.ID != completedA.ID {
			failedA = run
			break
		}
	}
	if failedA == nil {
		t.Fatal("missing running service to fail")
	}
	if err := d.FailTaskCodeAudit(failedA.ID, "temporary provider failure"); err != nil {
		t.Fatal(err)
	}
	failedSlotRefill, err := d.ClaimNextTaskCodeAudit()
	if err != nil || failedSlotRefill == nil || failedSlotRefill.TaskID != taskA.ID {
		t.Fatalf("failure stopped the queue from filling its slot: run=%+v err=%v", failedSlotRefill, err)
	}
	retried, err := d.RetryTaskCodeAudit(taskA.ID, failedA.ID, 25000)
	if err != nil || retried == nil || retried.Status != "queued" || retried.BudgetTokens != 145000 || retried.FilesAnalyzed != 0 {
		t.Fatalf("failed service retry state = %+v err=%v", retried, err)
	}
	if next, err := d.ClaimNextTaskCodeAudit(); err != nil || next != nil {
		t.Fatalf("queue exceeded four active runs while retry was pending: run=%+v err=%v", next, err)
	}
	for _, run := range runningA {
		if run.ID != completedA.ID && run.ID != failedA.ID {
			if err := d.FailTaskCodeAudit(run.ID, "free a slot for the retry"); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	claimedRetry, err := d.ClaimNextTaskCodeAudit()
	if err != nil || claimedRetry == nil || claimedRetry.ID != failedA.ID || claimedRetry.TaskID != taskA.ID {
		t.Fatalf("failed service could not be retried independently: run=%+v err=%v", claimedRetry, err)
	}
}
