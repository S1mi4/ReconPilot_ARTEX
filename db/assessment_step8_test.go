package db

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestStep8AssessmentArchiveAndRestoreRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	projID := testProjectID(t, d)
	task, err := d.CreateTaskWithOptions("step8 archive assessment", "assess", TaskCreateOptions{
		ProjectID:      projID,
		AssessmentMode: true,
		AssessmentConfig: AssessmentConfig{
			ExecutionMode:      AssessmentExecDynamic,
			BusinessOverview:   "归档恢复全评估态校验",
			SourceAcknowledged: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID)
		_ = d.DeleteTask(task.ID)
	})

	round, err := d.CreateAssessmentRound(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	assetID, err := d.Assets(projID).UpsertEndpoint(UpsertEndpointReq{
		URL:    "http://127.0.0.1:18080/api/archive-step8",
		Method: "POST",
		TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	sharedLib, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "shared_library", Name: "auth-common",
		CodebaseID: "cb-1", VersionID: "v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	entryEnt, err := d.CreateTargetEntity(CreateTargetEntityInput{
		TaskID: task.ID, RoundID: &round.ID, EntityType: "entry", Name: "POST /api/archive-step8",
		AssetID: &assetID,
	})
	if err != nil {
		t.Fatal(err)
	}
	evRef, err := d.CreateEvidenceRef(task.ID, EvidenceCodeRange, "auth-common/TokenFilter.java:10-42", json.RawMessage(`{"lines":32}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.CreateProfileClaim(CreateProfileClaimInput{
		TaskID: task.ID, RoundID: &round.ID, Subject: "shared_library:auth-common",
		Relation: "uses_language", ObjectValue: "java", SourceType: ClaimSourceStaticExtraction,
		EvidenceRefID: &evRef, ConfirmationStatus: ClaimStatusConfirmed,
	}); err != nil {
		t.Fatal(err)
	}

	// Shared library audit run with nullable code_service_id (no row in task_code_services!).
	run, _, err := d.CreateOrResumeEngineCodeAuditRun(CreateEngineCodeAuditInput{
		TaskID: task.ID, TargetEntityID: &sharedLib.ID, TargetName: sharedLib.Name, TargetType: sharedLib.EntityType,
		CodebaseID: "cb-1", VersionID: "v1", RelativePath: "auth-common", ScopePath: "auth-common",
		Languages: []string{"java"}, ProfileSource: "test", ProfileName: "p", ProfileFormat: "openai",
		Model: "m", Endpoint: "http://localhost", SourceAcknowledged: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	obAudit, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionCodeAudit, TargetEntityID: &sharedLib.ID,
		Purpose: "审计共享库 auth-common", Required: true, DedupeKey: "s8-arch-lib",
		InitialStatus: ObligationReady, ExecutionMode: ExecModeCodeAuditBatch, Origin: ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}
	obEntry, err := d.CreateCoverageObligation(CreateCoverageObligationInput{
		TaskID: task.ID, RoundID: &round.ID, Dimension: DimensionEntryTest, TargetEntityID: &entryEnt.ID,
		Purpose: "入口动态覆盖", Required: true, DedupeKey: "s8-arch-entry",
		InitialStatus: ObligationReady, ExecutionMode: ExecModeDynamicVerify, Origin: ObligationOriginProgram,
	})
	if err != nil {
		t.Fatal(err)
	}
	dAudit, err := d.DispatchAssessmentIntent(DispatchAssessmentIntentInput{
		TaskID: task.ID, RoundID: round.ID, ObligationID: obAudit.ID, ExecutionMode: ExecModeCodeAuditBatch, Summary: "audit lib",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = d.MarkObligationAttemptRunning(task.ID, obAudit.ID, dAudit.AttemptID)
	if _, err := d.FinalizeObligationAttempt(FinalizeObligationAttemptInput{
		TaskID: task.ID, ObligationID: obAudit.ID, AttemptID: dAudit.AttemptID, CodeAuditRunID: &run.ID,
		Outcome: AttemptSupported, EvidenceRefID: &evRef, SatisfyObligation: true,
	}); err != nil {
		t.Fatal(err)
	}
	_ = d.Exploration(task.ExplorationID).SetIntentState(dAudit.IntentID, "done")
	if _, err := d.RecordAssessmentRoundEvent(task.ID, round.ID, "new_entry", json.RawMessage(`{"url":"/api/archive-step8"}`)); err != nil {
		t.Fatal(err)
	}
	_ = d.SetPaused(task.ID, true)

	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	var llmRecords bytes.Buffer
	snapshot, err := d.SnapshotTaskArchiveWithLLMRecords(task.ID, &llmRecords)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DataCounts["task_assessment_rounds"] != 1 || snapshot.DataCounts["task_target_entities"] != 2 ||
		snapshot.DataCounts["task_coverage_obligations"] != 2 || snapshot.DataCounts["task_test_attempts"] != 1 {
		t.Fatalf("missing assessment tables in snapshot: %+v", snapshot.DataCounts)
	}
	if err := d.CompleteTaskArchive(archive.ID, snapshot, "/tmp/test-step8.tar.zst", "def", 100, 50); err != nil {
		t.Fatal(err)
	}

	// Verify hot rows wiped cleanly on archive completion.
	for _, tbl := range []string{"task_assessment_rounds", "task_target_entities", "task_coverage_obligations", "task_test_attempts", "task_evidence_refs", "task_profile_claims", "task_assessment_events"} {
		var cnt int
		if err := d.QueryRow(`SELECT count(*) FROM `+tbl+` WHERE task_id=$1`, task.ID).Scan(&cnt); err != nil {
			t.Fatal(err)
		}
		if cnt != 0 {
			t.Fatalf("expected %s cleared during archive, remaining=%d", tbl, cnt)
		}
	}

	// Restore and verify all assessment tables + nullable code_service_id audit run came back intact!
	if _, err := d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RestoreTaskArchiveWithLLMRecords(archive.ID, snapshot, int64((5 * time.Minute).Seconds()), bytes.NewReader(llmRecords.Bytes())); err != nil {
		t.Fatalf("RestoreTaskArchiveWithLLMRecords failed: %v", err)
	}

	restoredRounds, err := d.ListAssessmentRounds(task.ID)
	if err != nil || len(restoredRounds) != 1 || restoredRounds[0].ID != round.ID {
		t.Fatalf("expected round #%d restored, got %+v err=%v", round.ID, restoredRounds, err)
	}
	gotObs, err := d.ListCoverageObligations(CoverageObligationFilter{TaskID: task.ID, RoundID: round.ID, Limit: 20})
	if err != nil || len(gotObs) != 2 {
		t.Fatalf("expected 2 restored obligations, got %d err=%v", len(gotObs), err)
	}
	gotEntryOb, err := d.GetCoverageObligation(task.ID, obEntry.ID)
	if err != nil || gotEntryOb == nil || gotEntryOb.Status != ObligationReady {
		t.Fatalf("expected restored entry obligation ready, got %+v err=%v", gotEntryOb, err)
	}
	gotAuditOb, err := d.GetCoverageObligation(task.ID, obAudit.ID)
	if err != nil || gotAuditOb == nil || gotAuditOb.Status != ObligationSatisfied || gotAuditOb.EvidenceRefID == nil {
		t.Fatalf("expected restored satisfied obligation with evidence ref, got %+v err=%v", gotAuditOb, err)
	}
	restoredTask, err := d.GetTask(task.ID)
	if err != nil || restoredTask == nil || !restoredTask.AssessmentMode {
		t.Fatalf("expected restored assessment_mode=true task, got %+v err=%v", restoredTask, err)
	}
	if err := d.MarkAssessmentEventIDsProcessed(task.ID, nil); err != nil {
		t.Fatal(err)
	}
	if evCnt, err := d.CountUnprocessedAssessmentEvents(task.ID); err != nil || evCnt != 1 {
		t.Fatalf("expected restored unprocessed assessment event=1, got %d err=%v", evCnt, err)
	}
}
