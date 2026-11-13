package db

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

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
