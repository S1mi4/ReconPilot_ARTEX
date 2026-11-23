package db

import (
	"encoding/json"
	"testing"
)

func TestStep5EngineCodeAuditRunNullableServiceAndResume(t *testing.T) {
	d, task, round := assessmentFixture(t)

	ent, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "shared_library", Name: "common-auth",
		CodebaseID: "cb-main", VersionID: "v-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	ob, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID:         task.ID,
		RoundID:        &round.ID,
		Dimension:      DimensionCodeAudit,
		TargetEntityID: &ent.ID,
		Purpose:        "白盒审计共享库 common-auth",
		Required:       true,
		DedupeKey:      "code_audit:shared_library:cb-main:common-auth",
		InitialStatus:  ObligationReady,
		ExecutionMode:  ExecModeCodeAuditBatch,
		Origin:         ObligationOriginProgram,
		Priority:       8,
		ProfileVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	run, resumed, err := d.CreateOrResumeEngineCodeAuditRun(CreateEngineCodeAuditInput{
		TaskID:             task.ID,
		ObligationID:       ob.ID,
		TargetEntityID:     &ent.ID,
		CodeServiceID:      nil, // non-service shared_library has no task_code_services row
		TargetName:         "common-auth",
		TargetType:         "shared_library",
		CodebaseID:         "cb-main",
		VersionID:          "v-1",
		RelativePath:       "common-auth",
		ScopePath:          ".",
		Languages:          []string{"java", "python"},
		ProfileSource:      "override",
		ProfileName:        "test-profile",
		ProfileFormat:      "openai",
		Model:              "test-model",
		Endpoint:           "http://localhost",
		SourceAcknowledged: true,
	})
	if err != nil {
		t.Fatalf("CreateOrResumeEngineCodeAuditRun create failed: %v", err)
	}
	if resumed {
		t.Fatal("expected first CreateOrResumeEngineCodeAuditRun resumed=false")
	}
	if run.ExecutionOrigin != "engine" || run.CodeServiceID != 0 || run.TargetType != "shared_library" {
		t.Fatalf("unexpected run metadata: %+v", run)
	}
	if run.ObligationID == nil || *run.ObligationID != ob.ID {
		t.Fatalf("expected obligation_id=%d, got %v", ob.ID, run.ObligationID)
	}

	cov := TaskCodeAuditCoverage{
		Files: []TaskCodeAuditFileCoverage{
			{Path: "TokenParser.java", Language: "java", Read: true, Analyzed: true, LinesRead: 42},
			{Path: "SessionGuard.java", Language: "java", Read: false, Analyzed: false, LinesRead: 0},
		},
		SweepCompleted: false,
	}
	if err := d.SaveTaskCodeAuditCoverage(run.ID, cov); err != nil {
		t.Fatal(err)
	}
	prog := TaskCodeAuditProgress{
		FilesTotal:      2,
		FilesAnalyzed:   1,
		ChunksTotal:     2,
		ChunksCompleted: 1,
		NextFileIndex:   1,
		UsedTokens:      120,
		Summary:         "chunk 1 complete",
	}
	if err := d.UpdateTaskCodeAuditProgress(run.ID, prog); err != nil {
		t.Fatal(err)
	}
	if err := d.IncompleteTaskCodeAudit(run.ID, prog, "任务暂停，保留检查点"); err != nil {
		t.Fatal(err)
	}

	resumedRun, resumedAgain, err := d.CreateOrResumeEngineCodeAuditRun(CreateEngineCodeAuditInput{
		TaskID:             task.ID,
		ObligationID:       ob.ID,
		TargetEntityID:     &ent.ID,
		TargetName:         "common-auth",
		TargetType:         "shared_library",
		CodebaseID:         "cb-main",
		VersionID:          "v-1",
		RelativePath:       "common-auth",
		ScopePath:          ".",
		Languages:          []string{"java", "python"},
		ProfileSource:      "override",
		ProfileName:        "test-profile",
		ProfileFormat:      "openai",
		Model:              "test-model",
		Endpoint:           "http://localhost",
		SourceAcknowledged: true,
	})
	if err != nil {
		t.Fatalf("CreateOrResumeEngineCodeAuditRun resume failed: %v", err)
	}
	if !resumedAgain || resumedRun.ID != run.ID {
		t.Fatalf("expected resumedRun ID=%d resumed=true, got id=%d resumed=%v", run.ID, resumedRun.ID, resumedAgain)
	}
	if resumedRun.Status != "running" || resumedRun.NextFileIndex != 1 || resumedRun.ChunksCompleted != 1 {
		t.Fatalf("checkpoint lost on resume: %+v", resumedRun)
	}
	if resumedRun.Coverage == nil || len(resumedRun.Coverage.Files) != 2 || !resumedRun.Coverage.Files[0].Analyzed || resumedRun.Coverage.Files[1].Analyzed {
		t.Fatalf("unexpected resumed coverage ledger: %+v", resumedRun.Coverage)
	}
}

func TestStep5QueueVsEngineClaimAndRequeueIsolation(t *testing.T) {
	d, task, round := assessmentFixture(t)

	ent, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "module", Name: "engine-mod",
	})
	if err != nil {
		t.Fatal(err)
	}
	ob, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionCodeAudit, TargetEntityID: &ent.ID,
		Purpose: "audit engine-mod", Required: true, DedupeKey: "mod-1",
		InitialStatus: ObligationReady, ExecutionMode: ExecModeCodeAuditBatch, Origin: ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}

	engineRun, _, err := d.CreateOrResumeEngineCodeAuditRun(CreateEngineCodeAuditInput{
		TaskID: task.ID, ObligationID: ob.ID, TargetEntityID: &ent.ID,
		TargetName: "engine-mod", TargetType: "module",
		CodebaseID: "cb-1", VersionID: "v-1", RelativePath: "engine-mod", ScopePath: ".",
		Languages: []string{"java"}, Model: "m", Endpoint: "e", SourceAcknowledged: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// ClaimNextTaskCodeAudit must ONLY claim execution_origin='queue', never 'engine'.
	if _, err := d.Exec(`UPDATE task_code_audit_runs SET status='queued', started_at=NULL WHERE id=$1`, engineRun.ID); err != nil {
		t.Fatal(err)
	}
	if claimed, err := d.ClaimNextTaskCodeAudit(); err != nil {
		t.Fatal(err)
	} else if claimed != nil && claimed.ID == engineRun.ID {
		t.Fatalf("ClaimNextTaskCodeAudit must NOT claim engine run #%d", engineRun.ID)
	}

	// Set engineRun back to 'running' and also insert a legacy 'queue' running row to check RequeueInterruptedTaskCodeAudits.
	if _, err := d.Exec(`UPDATE task_code_audit_runs SET status='running', started_at=now() WHERE id=$1`, engineRun.ID); err != nil {
		t.Fatal(err)
	}
	var svcID int64
	if err := d.QueryRow(`INSERT INTO task_code_services(task_id,codebase_id,relative_path,name,decision,decision_source,latest_version_id,latest_present)
VALUES($1,'cb-1','legacy-svc','legacy-svc','confirmed','manual','v-1',true) RETURNING id`, task.ID).Scan(&svcID); err != nil {
		t.Fatal(err)
	}
	queueRun, err := d.CreateTaskCodeAudit(CreateTaskCodeAudit{
		TaskID: task.ID, CodeServiceID: svcID, CodebaseID: "cb-1", VersionID: "v-1",
		ScopePath: ".", Model: "m", Endpoint: "e", SourceAcknowledged: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE task_code_audit_runs SET status='running', started_at=now() WHERE id=$1`, queueRun.ID); err != nil {
		t.Fatal(err)
	}

	if err := d.RequeueInterruptedTaskCodeAudits(); err != nil {
		t.Fatal(err)
	}
	gotEngine, err := d.GetTaskCodeAudit(task.ID, engineRun.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotEngine.Status != "incomplete" {
		t.Fatalf("expected interrupted engine run -> incomplete, got %q", gotEngine.Status)
	}
	gotQueue, err := d.GetTaskCodeAudit(task.ID, queueRun.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotQueue.Status != "queued" {
		t.Fatalf("expected interrupted queue run -> queued, got %q", gotQueue.Status)
	}
}

func TestStep5CoverageCompletionGate(t *testing.T) {
	if ok, _ := TaskCodeAuditCoverageAllowsCompletion(nil); ok {
		t.Fatal("nil run should fail completion gate")
	}
	if ok, _ := TaskCodeAuditCoverageAllowsCompletion(&TaskCodeAuditRun{Status: "incomplete"}); ok {
		t.Fatal("incomplete run should fail completion gate")
	}
	if ok, _ := TaskCodeAuditCoverageAllowsCompletion(&TaskCodeAuditRun{
		Status: "completed", FilesTotal: 1, FilesAnalyzed: 0,
		Coverage: &TaskCodeAuditCoverage{Files: []TaskCodeAuditFileCoverage{{Path: "a.java", Read: false, Analyzed: false}}, SweepCompleted: true},
	}); ok {
		t.Fatal("unread file should fail completion gate")
	}
	if ok, _ := TaskCodeAuditCoverageAllowsCompletion(&TaskCodeAuditRun{
		Status: "completed", FilesTotal: 1, FilesAnalyzed: 1,
		Coverage: &TaskCodeAuditCoverage{Files: []TaskCodeAuditFileCoverage{{Path: "a.java", Read: true, Analyzed: true, LinesRead: 10}}, SweepCompleted: false},
	}); ok {
		t.Fatal("incomplete sweep should fail completion gate")
	}
	if ok, reason := TaskCodeAuditCoverageAllowsCompletion(&TaskCodeAuditRun{
		Status: "completed", FilesTotal: 1, FilesAnalyzed: 1,
		Coverage: &TaskCodeAuditCoverage{Files: []TaskCodeAuditFileCoverage{{Path: "a.java", Read: true, Analyzed: true, LinesRead: 10}}, SweepCompleted: true},
	}); !ok {
		t.Fatalf("fully read and swept run should pass gate, got reason=%q", reason)
	}
}

func TestStep5ChunkEventsAndRestartAttemptReset(t *testing.T) {
	d, task, round := assessmentFixture(t)
	ts := d.Exploration(task.ExplorationID)
	ent, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "module", Name: "core-mod",
	})
	if err != nil {
		t.Fatal(err)
	}
	ob, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionCodeAudit, TargetEntityID: &ent.ID,
		Purpose: "audit core-mod", Required: true, DedupeKey: "core-1",
		InitialStatus: ObligationReady, ExecutionMode: ExecModeCodeAuditBatch, Origin: ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}

	evPayload, _ := json.Marshal(map[string]any{"chunk_index": 1, "chunks_total": 3, "files_analyzed": 2})
	evID, err := d.RecordAssessmentRoundEvent(task.ID, round.ID, "code_audit_chunk_completed", evPayload)
	if err != nil || evID <= 0 {
		t.Fatalf("RecordAssessmentRoundEvent failed: id=%d err=%v", evID, err)
	}
	evs, err := d.ListUnprocessedAssessmentEventsByType(task.ID, "code_audit_chunk_completed", 10)
	if err != nil || len(evs) != 1 || evs[0].ID != evID {
		t.Fatalf("ListUnprocessedAssessmentEventsByType unexpected: %+v err=%v", evs, err)
	}
	if err := d.MarkAssessmentEventIDsProcessed(task.ID, []int64{evID}); err != nil {
		t.Fatal(err)
	}
	evsAfter, err := d.ListUnprocessedAssessmentEventsByType(task.ID, "code_audit_chunk_completed", 10)
	if err != nil || len(evsAfter) != 0 {
		t.Fatalf("expected 0 unprocessed events after mark, got %+v err=%v", evsAfter, err)
	}

	// Dispatch + mark running -> ResetInterruptedAssessmentAttempts resets to dispatched so restart re-claims cleanly.
	disp, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: ob.ID, ExecutionMode: ExecModeCodeAuditBatch,
		Summary: "audit core-mod", Priority: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	marked, err := d.MarkObligationAttemptRunning(task.ID, ob.ID, disp.AttemptID)
	if err != nil || !marked {
		t.Fatalf("MarkObligationAttemptRunning failed: marked=%v err=%v", marked, err)
	}
	nReset, err := d.ResetInterruptedAssessmentAttempts(task.ID)
	if err != nil || nReset != 1 {
		t.Fatalf("ResetInterruptedAssessmentAttempts expected 1 reset, got %d err=%v", nReset, err)
	}
	okExec, reason, err := d.IsObligationExecutable(task.ID, ob.ID, round.ID, disp.AttemptID)
	if err != nil || !okExec {
		t.Fatalf("expected obligation executable after restart reset, got ok=%v reason=%q err=%v", okExec, reason, err)
	}
	if cov, err := d.ListCodeAuditCoverageSummaries(task.ID, 10); err != nil {
		t.Fatal(err)
	} else if len(cov) != 0 {
		t.Fatalf("expected 0 code audit runs initially, got %d", len(cov))
	}
	_ = ts
}
